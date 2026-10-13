//! Bounded, integrity-checked per-BLE-link stop-and-wait transfer state machine.
//! Each peer has at most one inbound and one outbound transfer in progress.
//! Outbound updates are retransmitted if their final ACK never arrives.
use crate::message::{Header, Message, Update, CHUNK_SIZE};
use anyhow::{bail, ensure, Result};
use sha2::{Digest, Sha256};
use std::{collections::VecDeque, sync::Arc, time::{Duration, Instant}};
use uuid::Uuid;

const MAX_QUEUE: usize = 4;
const ACK_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_ATTEMPTS: u8 = 3;
const INBOUND_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Clone, Copy)]
enum Stage { Start, Data, End, AwaitAck }
struct Sending { update: Update, offset: usize, stage: Stage, started_wait: Instant, attempts: u8 }
impl Sending {
    fn new(update: Update, now: Instant) -> Self { Self { update, offset: 0, stage: Stage::Start, started_wait: now, attempts: 1 } }
}
#[derive(Default)]
pub struct Outgoing { queue: VecDeque<Update>, current: Option<Sending> }
impl Outgoing {
    pub fn enqueue(&mut self, update: Update) -> Result<()> {
        if self.queue.len() >= MAX_QUEUE { bail!("outgoing file/image queue full; update dropped"); }
        update.validate()?;
        self.queue.push_back(update);
        Ok(())
    }
    pub fn ack(&mut self, id: Uuid) {
        if self.current.as_ref().is_some_and(|s| s.update.id == id && matches!(s.stage, Stage::AwaitAck)) {
            self.current = None;
        }
    }
    pub fn next(&mut self, now: Instant) -> Option<Message> {
        if self.current.is_none() {
            self.current = self.queue.pop_front().map(|update| Sending::new(update, now));
        }
        let s = self.current.as_mut()?;
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
                let msg = Message::Chunk { id: s.update.id, offset: s.offset as u32,
                    bytes: s.update.bytes[s.offset..end].to_vec() };
                s.offset = end;
                Some(msg)
            }
            Stage::End => {
                s.stage = Stage::AwaitAck;
                s.started_wait = now;
                Some(Message::End(s.update.id))
            }
            Stage::AwaitAck if now.duration_since(s.started_wait) >= ACK_TIMEOUT => {
                if s.attempts >= MAX_ATTEMPTS {
                    eprintln!("BLE transfer {}: no ACK after {} attempts", s.update.id, s.attempts);
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

struct Receiving { header: Header, bytes: Vec<u8>, last_activity: Instant }
#[derive(Default)]
pub struct Incoming {
    active: Option<Receiving>,
    completed: VecDeque<Uuid>,
    duplicate: Option<Uuid>,
}
#[derive(Default)]
pub struct Received { pub update: Option<Update>, pub ack: Option<Uuid> }
impl Incoming {
    pub fn handle(&mut self, message: Message, now: Instant) -> Result<Received> {
        if self.active.as_ref().is_some_and(|r| now.duration_since(r.last_activity) > INBOUND_TIMEOUT) {
            self.active = None;
        }
        match message {
            Message::Start(header) => {
                header.validate()?;
                // A repeated start is an ACK retry, not a new file to publish.
                if self.completed.contains(&header.id) {
                    self.duplicate = Some(header.id);
                    self.active = None;
                    return Ok(Received { ack: Some(header.id), update: None });
                }
                self.duplicate = None;
                self.active = Some(Receiving { bytes: Vec::with_capacity(header.size as usize), header, last_activity: now });
            }
            Message::Chunk { id, offset, bytes } => {
                if self.duplicate == Some(id) { return Ok(Received::default()); }
                let r = self.active.as_mut().ok_or_else(|| anyhow::anyhow!("transfer chunk without start"))?;
                ensure!(r.header.id == id, "transfer UUID changed");
                ensure!(r.bytes.len() == offset as usize, "missing, duplicate or out-of-order transfer chunk");
                ensure!(r.bytes.len() + bytes.len() <= r.header.size as usize, "transfer exceeds advertised length");
                r.bytes.extend_from_slice(&bytes);
                r.last_activity = now;
            }
            Message::End(id) => {
                if self.duplicate == Some(id) { self.duplicate = None; return Ok(Received {ack: Some(id), update: None}); }
                let r = self.active.take().ok_or_else(|| anyhow::anyhow!("end without start"))?;
                ensure!(r.header.id == id, "transfer finish UUID changed");
                ensure!(r.bytes.len() == r.header.size as usize, "truncated transfer");
                let digest: [u8; 32] = Sha256::digest(&r.bytes).into();
                ensure!(digest == r.header.sha256, "transfer SHA-256 mismatch");
                let update = Update { id, origin: r.header.origin, hops: r.header.hops,
                    kind: r.header.kind, bytes: Arc::from(r.bytes) };
                update.validate()?;
                self.completed.push_back(id);
                if self.completed.len() > 64 { self.completed.pop_front(); }
                return Ok(Received { update: Some(update), ack: Some(id) });
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
    fn roundtrip_megabyte_with_ack() {
        let mut out = Outgoing::default();
        let update = Update::new(Uuid::new_v4(), Kind::Files, vec![33; 1024*1024]).unwrap();
        out.enqueue(update.clone()).unwrap();
        let mut incoming = Incoming::default();
        let time = Instant::now();
        let mut n = 0;
        loop {
            let Some(message) = out.next(time) else { break; };
            n += 1;
            let answer = incoming.handle(Message::decode(&message.encode().unwrap()).unwrap(), time).unwrap();
            if let Some(item) = answer.update { assert_eq!(item, update); }
            if let Some(ack) = answer.ack { out.ack(ack); }
        }
        assert!(n >= 1026);
        assert!(out.next(time).is_none());
    }
    #[test]
    fn corrupted_and_missing_chunks_fail() {
        let id = Uuid::new_v4();
        let upd = Update::new(id, Kind::Text, b"abc".to_vec()).unwrap();
        let time = Instant::now();
        let mut x = Incoming::default();
        x.handle(Message::Start(Header::for_update(&upd)), time).unwrap();
        assert!(x.handle(Message::Chunk {id:upd.id,offset:1,bytes:b"abc".to_vec()}, time).is_err());
        let mut x = Incoming::default();
        x.handle(Message::Start(Header::for_update(&upd)), time).unwrap();
        x.handle(Message::Chunk {id:upd.id,offset:0,bytes:b"axc".to_vec()}, time).unwrap();
        assert!(x.handle(Message::End(upd.id), time).is_err());
        assert_eq!(MAX_FILES, 8*1024*1024);
    }
    #[test]
    fn repeated_transfer_ack_does_not_repeat_update() {
        let upd = Update::text(Uuid::new_v4(), "one".into()).unwrap();
        let time = Instant::now();
        let mut r = Incoming::default();
        r.handle(Message::Start(Header::for_update(&upd)), time).unwrap();
        r.handle(Message::Chunk {id:upd.id, offset:0, bytes:b"one".to_vec()}, time).unwrap();
        let answer = r.handle(Message::End(upd.id), time).unwrap();
        assert!(answer.update.is_some());
        let second = r.handle(Message::Start(Header::for_update(&upd)), time).unwrap();
        assert!(second.update.is_none());
        assert_eq!(second.ack, Some(upd.id));
    }
}
