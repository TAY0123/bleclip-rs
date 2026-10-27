//! Bounded, integrity-checked per-BLE-link stop-and-wait transfer state machine.
//! Each peer has at most one inbound and one outbound transfer in progress.
//! Outbound updates are retransmitted if their final ACK never arrives.
use crate::message::{Header, Kind, Message, Update, CHUNK_SIZE, COMPRESS_TEXT_ABOVE, MAX_TEXT};
use crate::progress::{Phase, Reporter};
use anyhow::{bail, ensure, Result};
use flate2::{write::ZlibEncoder, Compression, Decompress, FlushDecompress, Status};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    io::Write,
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;

// Clipboard contents supersede earlier waiting contents, while file transfer
// messages must retain their order and cannot be silently replaced.
const MAX_QUEUE: usize = 4;
fn is_clipboard(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Text | Kind::CompressedText | Kind::Png | Kind::FileOffer
    )
}
const ACK_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_ATTEMPTS: u8 = 3;
const INBOUND_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Clone, Copy)]
enum Stage {
    Start,
    Data,
    End,
    AwaitAck,
}
struct Sending {
    update: Update,
    offset: usize,
    stage: Stage,
    started_wait: Instant,
    attempts: u8,
}
impl Sending {
    fn new(update: Update, now: Instant) -> Self {
        Self {
            update,
            offset: 0,
            stage: Stage::Start,
            started_wait: now,
            attempts: 1,
        }
    }
}
#[derive(Default)]
pub struct Outgoing {
    queue: VecDeque<Update>,
    current: Option<Sending>,
    progress: Option<Reporter>,
}
impl Outgoing {
    pub fn set_progress(&mut self, reporter: Reporter) {
        self.progress = Some(reporter);
    }
    fn report(&mut self, phase: Phase) {
        if let (Some(progress), Some(s)) = (&mut self.progress, &self.current) {
            progress.update(
                s.update.id,
                s.update.kind,
                s.offset,
                s.update.bytes.len(),
                phase,
                s.attempts,
            );
        }
    }
    pub fn enqueue(&mut self, mut update: Update) -> Result<()> {
        update.validate()?;
        let clipboard = is_clipboard(update.kind);
        if !clipboard
            && self
                .queue
                .iter()
                .filter(|item| !is_clipboard(item.kind))
                .count()
                >= MAX_QUEUE
        {
            bail!("outgoing file transfer queue full; update dropped");
        }
        if update.kind == Kind::Text && update.bytes.len() > COMPRESS_TEXT_ABOVE {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&update.bytes)?;
            update.bytes = encoder.finish()?.into();
            update.kind = Kind::CompressedText;
            update.validate()?;
        }
        if clipboard {
            self.queue.retain(|item| !is_clipboard(item.kind));
        }
        self.queue.push_back(update);
        Ok(())
    }
    pub fn ack(&mut self, id: Uuid) {
        if self
            .current
            .as_ref()
            .is_some_and(|s| s.update.id == id && matches!(s.stage, Stage::AwaitAck))
        {
            self.report(Phase::Complete);
            self.current = None;
        }
    }
    /// Take only a waiting update, never interrupt a partially sent GATT frame.
    pub fn take_bulk_candidate(&mut self, threshold: usize) -> Option<Update> {
        if self.current.is_none()
            && self
                .queue
                .front()
                .is_some_and(|u| u.bytes.len() > threshold)
        {
            self.queue.pop_front()
        } else {
            None
        }
    }
    /// Retry the identical update before newer queued items after a bulk error.
    pub fn fallback(&mut self, update: Update) {
        assert!(self.current.is_none());
        self.current = Some(Sending::new(update, Instant::now()));
    }
    pub fn next(&mut self, now: Instant) -> Option<Message> {
        if self.current.is_none() {
            self.current = self
                .queue
                .pop_front()
                .map(|update| Sending::new(update, now));
        }
        let s = self.current.as_mut()?;
        if let Some(progress) = &mut self.progress {
            progress.update(
                s.update.id,
                s.update.kind,
                s.offset,
                s.update.bytes.len(),
                if matches!(s.stage, Stage::AwaitAck) {
                    Phase::AwaitingAck
                } else {
                    Phase::Transferring
                },
                s.attempts,
            );
        }
        match s.stage {
            Stage::Start => {
                s.stage = Stage::Data;
                Some(Message::Start(Header::for_update(&s.update)))
            }
            Stage::Data => {
                if s.offset >= s.update.bytes.len() {
                    s.stage = Stage::End;
                    return self.next(now);
                }
                let end = (s.offset + CHUNK_SIZE).min(s.update.bytes.len());
                let msg = Message::Chunk {
                    id: s.update.id,
                    offset: s.offset as u32,
                    bytes: s.update.bytes[s.offset..end].to_vec(),
                };
                s.offset = end;
                if let Some(progress) = &mut self.progress {
                    progress.update(
                        s.update.id,
                        s.update.kind,
                        s.offset,
                        s.update.bytes.len(),
                        Phase::Transferring,
                        s.attempts,
                    );
                }
                Some(msg)
            }
            Stage::End => {
                s.stage = Stage::AwaitAck;
                s.started_wait = now;
                if let Some(progress) = &mut self.progress {
                    progress.update(
                        s.update.id,
                        s.update.kind,
                        s.offset,
                        s.update.bytes.len(),
                        Phase::AwaitingAck,
                        s.attempts,
                    );
                }
                Some(Message::End(s.update.id))
            }
            Stage::AwaitAck if now.duration_since(s.started_wait) >= ACK_TIMEOUT => {
                if s.attempts >= MAX_ATTEMPTS {
                    eprintln!(
                        "BLE transfer {}: no ACK after {} attempts",
                        s.update.id, s.attempts
                    );
                    self.report(Phase::Failed);
                    self.current = None;
                    self.next(now)
                } else {
                    s.attempts += 1;
                    s.stage = Stage::Start;
                    s.offset = 0;
                    self.next(now)
                }
            }
            Stage::AwaitAck => None,
        }
    }
}

struct Receiving {
    header: Header,
    bytes: Vec<u8>,
    last_activity: Instant,
}
#[derive(Default)]
pub struct Incoming {
    active: Option<Receiving>,
    completed: VecDeque<Uuid>,
    duplicate: Option<Uuid>,
    progress: Option<Reporter>,
}
#[derive(Default)]
pub struct Received {
    pub update: Option<Update>,
    pub ack: Option<Uuid>,
}
impl Incoming {
    pub fn set_progress(&mut self, reporter: Reporter) {
        self.progress = Some(reporter);
    }
    pub fn handle(&mut self, message: Message, now: Instant) -> Result<Received> {
        let result = self.receive(message, now);
        if result.is_err() {
            if let Some(progress) = &mut self.progress {
                progress.fail();
            }
        }
        result
    }
    fn receive(&mut self, message: Message, now: Instant) -> Result<Received> {
        if self
            .active
            .as_ref()
            .is_some_and(|r| now.duration_since(r.last_activity) > INBOUND_TIMEOUT)
        {
            if let Some(progress) = &mut self.progress {
                progress.fail();
            }
            self.active = None;
        }
        match message {
            Message::Start(header) => {
                header.validate()?;
                // A repeated start is an ACK retry, not a new file to publish.
                if self.completed.contains(&header.id) {
                    self.duplicate = Some(header.id);
                    self.active = None;
                    return Ok(Received {
                        ack: Some(header.id),
                        update: None,
                    });
                }
                self.duplicate = None;
                if let Some(progress) = &mut self.progress {
                    progress.fail();
                    progress.update(
                        header.id,
                        header.kind,
                        0,
                        header.size as usize,
                        Phase::Transferring,
                        1,
                    );
                }
                self.active = Some(Receiving {
                    bytes: Vec::with_capacity(header.size as usize),
                    header,
                    last_activity: now,
                });
            }
            Message::Chunk { id, offset, bytes } => {
                if self.duplicate == Some(id) {
                    return Ok(Received::default());
                }
                let r = self
                    .active
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("transfer chunk without start"))?;
                ensure!(r.header.id == id, "transfer UUID changed");
                ensure!(
                    r.bytes.len() == offset as usize,
                    "missing, duplicate or out-of-order transfer chunk"
                );
                ensure!(
                    r.bytes.len() + bytes.len() <= r.header.size as usize,
                    "transfer exceeds advertised length"
                );
                r.bytes.extend_from_slice(&bytes);
                r.last_activity = now;
                if let Some(progress) = &mut self.progress {
                    progress.update(
                        r.header.id,
                        r.header.kind,
                        r.bytes.len(),
                        r.header.size as usize,
                        Phase::Transferring,
                        1,
                    );
                }
            }
            Message::End(id) => {
                if self.duplicate == Some(id) {
                    self.duplicate = None;
                    return Ok(Received {
                        ack: Some(id),
                        update: None,
                    });
                }
                let r = self
                    .active
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("end without start"))?;
                ensure!(r.header.id == id, "transfer finish UUID changed");
                ensure!(
                    r.bytes.len() == r.header.size as usize,
                    "truncated transfer"
                );
                let digest: [u8; 32] = Sha256::digest(&r.bytes).into();
                ensure!(digest == r.header.sha256, "transfer SHA-256 mismatch");
                let (kind, bytes) = if r.header.kind == Kind::CompressedText {
                    let mut decoder = Decompress::new(true);
                    let mut decoded = vec![0; MAX_TEXT + 1];
                    let status =
                        decoder.decompress(&r.bytes, &mut decoded, FlushDecompress::Finish)?;
                    ensure!(
                        decoder.total_out() <= MAX_TEXT as u64,
                        "decompressed text exceeds size limit"
                    );
                    ensure!(status == Status::StreamEnd, "incomplete compressed text");
                    ensure!(
                        decoder.total_in() == r.bytes.len() as u64,
                        "trailing compressed text data"
                    );
                    decoded.truncate(decoder.total_out() as usize);
                    (Kind::Text, decoded)
                } else {
                    (r.header.kind, r.bytes)
                };
                let update = Update {
                    id,
                    origin: r.header.origin,
                    hops: r.header.hops,
                    kind,
                    bytes: Arc::from(bytes),
                };
                update.validate()?;
                if let Some(progress) = &mut self.progress {
                    progress.update(
                        id,
                        r.header.kind,
                        r.header.size as usize,
                        r.header.size as usize,
                        Phase::Complete,
                        1,
                    );
                }
                self.completed.push_back(id);
                if self.completed.len() > 64 {
                    self.completed.pop_front();
                }
                return Ok(Received {
                    update: Some(update),
                    ack: Some(id),
                });
            }
            Message::Identity(_) | Message::Ack(_) => bail!("unexpected non-transfer message"),
        }
        Ok(Received::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Kind, MAX_FILES};
    #[test]
    fn latest_clipboard_item_survives_busy_link_without_dropping_files() {
        let origin = Uuid::new_v4();
        let active = Update::text(origin, "already sending".into()).unwrap();
        let old = Update::text(origin, "old clipboard".into()).unwrap();
        let image = Update::new(origin, Kind::Png, vec![1]).unwrap();
        let latest = Update::text(origin, "new clipboard".into()).unwrap();
        let files: Vec<_> = (0..MAX_QUEUE)
            .map(|n| Update::new(origin, Kind::Files, vec![n as u8]).unwrap())
            .collect();
        let mut out = Outgoing::default();
        let now = Instant::now();
        out.enqueue(active.clone()).unwrap();
        assert!(matches!(out.next(now), Some(Message::Start(header)) if header.id == active.id));
        out.enqueue(old).unwrap();
        for file in &files {
            out.enqueue(file.clone()).unwrap();
        }
        out.enqueue(image).unwrap();
        out.enqueue(latest.clone()).unwrap();
        assert!(out
            .enqueue(Update::new(origin, Kind::Files, vec![9]).unwrap())
            .is_err());
        assert_eq!(out.queue.len(), MAX_QUEUE + 1);
        assert_eq!(
            out.queue.iter().map(|item| item.id).collect::<Vec<_>>(),
            files
                .iter()
                .map(|item| item.id)
                .chain([latest.id])
                .collect::<Vec<_>>()
        );
        while out.next(now).is_some() {}
        out.ack(active.id);
        assert!(matches!(out.next(now), Some(Message::Start(header)) if header.id == files[0].id));
    }
    #[test]
    fn invalid_clipboard_update_does_not_replace_waiting_item() {
        let origin = Uuid::new_v4();
        let mut out = Outgoing::default();
        let valid = Update::text(origin, "keep me".into()).unwrap();
        out.enqueue(valid.clone()).unwrap();
        let mut invalid = valid.clone();
        invalid.bytes = vec![0xff].into();
        assert!(out.enqueue(invalid).is_err());
        assert_eq!(out.queue.front(), Some(&valid));
    }
    #[test]
    fn progress_tracks_ack_retries_and_failure() {
        use crate::progress::{Direction, Phase, Transfers};
        let monitor = Transfers::new();
        let view = monitor.subscribe();
        let update = Update::new(Uuid::new_v4(), Kind::Files, vec![1; 2048]).unwrap();
        let mut out = Outgoing::default();
        out.set_progress(monitor.reporter(Uuid::new_v4(), Direction::Sending));
        out.enqueue(update.clone()).unwrap();
        let mut now = Instant::now();
        out.next(now).unwrap();
        out.ack(update.id); // ACK before the end cannot mark a transfer complete.
        assert_eq!(view.borrow()[0].phase, Phase::Transferring);
        for attempt in 1..=MAX_ATTEMPTS {
            while out.next(now).is_some() {}
            assert_eq!(view.borrow()[0].phase, Phase::AwaitingAck);
            assert_eq!(view.borrow()[0].bytes, 2048);
            assert_eq!(view.borrow()[0].attempt, attempt);
            assert_eq!(view.borrow()[0].percent(), 99);
            now += ACK_TIMEOUT;
            let next = out.next(now);
            if attempt < MAX_ATTEMPTS {
                assert!(matches!(next, Some(Message::Start(_))));
                assert_eq!(view.borrow()[0].attempt, attempt + 1);
                assert_eq!(view.borrow()[0].bytes, 0);
            } else {
                assert!(next.is_none());
            }
        }
        assert_eq!(view.borrow()[0].phase, Phase::Failed);
    }
    #[test]
    fn progress_completes_after_integrity_check_and_ack() {
        use crate::progress::{Direction, Phase, Transfers};
        let monitor = Transfers::new();
        let view = monitor.subscribe();
        let mut out = Outgoing::default();
        let mut incoming = Incoming::default();
        out.set_progress(monitor.reporter(Uuid::new_v4(), Direction::Sending));
        incoming.set_progress(monitor.reporter(Uuid::new_v4(), Direction::Receiving));
        let update = Update::new(Uuid::new_v4(), Kind::Files, vec![8; 2048]).unwrap();
        out.enqueue(update).unwrap();
        let now = Instant::now();
        while let Some(message) = out.next(now) {
            let result = incoming.handle(message, now).unwrap();
            if let Some(id) = result.ack {
                out.ack(id);
            }
        }
        assert_eq!(view.borrow().len(), 2);
        assert!(view
            .borrow()
            .iter()
            .all(|v| v.phase == Phase::Complete && v.percent() == 100 && v.bytes == 2048));
        // Disconnect must not turn a completed transfer into a failed one.
        drop(out);
        drop(incoming);
        assert!(view.borrow().iter().all(|v| v.phase == Phase::Complete));
    }
    #[test]
    fn invalid_payload_never_shows_complete() {
        use crate::progress::{Direction, Phase, Transfers};
        let monitor = Transfers::new();
        let view = monitor.subscribe();
        let mut incoming = Incoming::default();
        incoming.set_progress(monitor.reporter(Uuid::new_v4(), Direction::Receiving));
        let update = Update::new(Uuid::new_v4(), Kind::Files, vec![1; 1024]).unwrap();
        let now = Instant::now();
        incoming
            .handle(Message::Start(Header::for_update(&update)), now)
            .unwrap();
        incoming
            .handle(
                Message::Chunk {
                    id: update.id,
                    offset: 0,
                    bytes: vec![2; 1024],
                },
                now,
            )
            .unwrap();
        assert!(incoming.handle(Message::End(update.id), now).is_err());
        assert_eq!(view.borrow()[0].phase, Phase::Failed);
        assert!(view.borrow()[0].percent() < 100);
    }
    #[test]
    fn roundtrip_megabyte_with_ack() {
        let mut out = Outgoing::default();
        let update = Update::new(Uuid::new_v4(), Kind::Files, vec![33; 1024 * 1024]).unwrap();
        out.enqueue(update.clone()).unwrap();
        let mut incoming = Incoming::default();
        let time = Instant::now();
        let mut n = 0;
        loop {
            let Some(message) = out.next(time) else {
                break;
            };
            n += 1;
            let answer = incoming
                .handle(Message::decode(&message.encode().unwrap()).unwrap(), time)
                .unwrap();
            if let Some(item) = answer.update {
                assert_eq!(item, update);
            }
            if let Some(ack) = answer.ack {
                out.ack(ack);
            }
        }
        assert!(n >= 1026);
        assert!(out.next(time).is_none());
    }
    #[test]
    fn roundtrip_maximum_text_with_ack() {
        let update = Update::text(Uuid::new_v4(), "x".repeat(crate::message::MAX_TEXT)).unwrap();
        let monitor = crate::progress::Transfers::new();
        let view = monitor.subscribe();
        let mut out = Outgoing::default();
        let mut incoming = Incoming::default();
        out.set_progress(monitor.reporter(Uuid::new_v4(), crate::progress::Direction::Sending));
        incoming
            .set_progress(monitor.reporter(Uuid::new_v4(), crate::progress::Direction::Receiving));
        out.enqueue(update.clone()).unwrap();
        let now = Instant::now();
        let mut received = None;
        while let Some(message) = out.next(now) {
            let message = Message::decode(&message.encode().unwrap()).unwrap();
            let result = incoming.handle(message, now).unwrap();
            if let Some(item) = result.update {
                received = Some(item);
            }
            if let Some(id) = result.ack {
                out.ack(id);
            }
        }
        assert_eq!(received, Some(update));
        assert!(out.next(now).is_none());
        let views = view.borrow();
        assert_eq!(views.len(), 2);
        assert!(views.iter().all(|v| v.kind == Kind::CompressedText
            && v.phase == Phase::Complete
            && v.percent() == 100
            && v.bytes == v.total
            && v.total < MAX_TEXT));
    }
    #[test]
    fn text_is_compressed_only_above_threshold() {
        let now = Instant::now();
        for (size, expected) in [
            (COMPRESS_TEXT_ABOVE, Kind::Text),
            (COMPRESS_TEXT_ABOVE + 1, Kind::CompressedText),
        ] {
            let update = Update::text(Uuid::new_v4(), "a".repeat(size)).unwrap();
            let mut outgoing = Outgoing::default();
            outgoing.enqueue(update.clone()).unwrap();
            let Message::Start(header) = outgoing.next(now).unwrap() else {
                panic!("expected transfer header");
            };
            assert_eq!(header.kind, expected);
            if expected == Kind::CompressedText {
                assert!((header.size as usize) < size);
            } else {
                assert_eq!(header.size as usize, size);
            }
        }
    }
    #[test]
    fn compressed_text_rejects_bad_or_oversized_data() {
        fn compressed(bytes: &[u8]) -> Vec<u8> {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(bytes).unwrap();
            encoder.finish().unwrap()
        }
        fn rejected(payload: Vec<u8>) {
            let update = Update::new(Uuid::new_v4(), Kind::CompressedText, payload).unwrap();
            let mut outgoing = Outgoing::default();
            let mut incoming = Incoming::default();
            outgoing.enqueue(update).unwrap();
            let now = Instant::now();
            while let Some(message) = outgoing.next(now) {
                if matches!(message, Message::End(_)) {
                    assert!(incoming.handle(message, now).is_err());
                    return;
                }
                incoming.handle(message, now).unwrap();
            }
            panic!("missing transfer end");
        }
        rejected(compressed(&vec![b'a'; MAX_TEXT + 1]));
        rejected(compressed(&[0xff]));
        let valid = compressed(b"hello");
        rejected(valid[..valid.len() - 1].to_vec());
        let mut trailing = valid;
        trailing.push(0);
        rejected(trailing);
        rejected(vec![1, 2, 3]);
    }
    #[test]
    fn corrupted_and_missing_chunks_fail() {
        let id = Uuid::new_v4();
        let upd = Update::new(id, Kind::Text, b"abc".to_vec()).unwrap();
        let time = Instant::now();
        let mut x = Incoming::default();
        x.handle(Message::Start(Header::for_update(&upd)), time)
            .unwrap();
        assert!(x
            .handle(
                Message::Chunk {
                    id: upd.id,
                    offset: 1,
                    bytes: b"abc".to_vec()
                },
                time
            )
            .is_err());
        let mut x = Incoming::default();
        x.handle(Message::Start(Header::for_update(&upd)), time)
            .unwrap();
        x.handle(
            Message::Chunk {
                id: upd.id,
                offset: 0,
                bytes: b"axc".to_vec(),
            },
            time,
        )
        .unwrap();
        assert!(x.handle(Message::End(upd.id), time).is_err());
        assert_eq!(MAX_FILES, 64 * 1024 * 1024);
    }
    #[test]
    fn repeated_transfer_ack_does_not_repeat_update() {
        let upd = Update::text(Uuid::new_v4(), "one".into()).unwrap();
        let time = Instant::now();
        let mut r = Incoming::default();
        r.handle(Message::Start(Header::for_update(&upd)), time)
            .unwrap();
        r.handle(
            Message::Chunk {
                id: upd.id,
                offset: 0,
                bytes: b"one".to_vec(),
            },
            time,
        )
        .unwrap();
        let answer = r.handle(Message::End(upd.id), time).unwrap();
        assert!(answer.update.is_some());
        let second = r
            .handle(Message::Start(Header::for_update(&upd)), time)
            .unwrap();
        assert!(second.update.is_none());
        assert_eq!(second.ack, Some(upd.id));
    }
}
