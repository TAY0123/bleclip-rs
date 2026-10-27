//! Transport progress shared with the native tray. Chunk updates are throttled;
//! completion means a checked inbound payload or the sender's final peer ACK.
use crate::message::Kind;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::watch;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Sending,
    Receiving,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Gatt,
    L2cap,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Transferring,
    AwaitingAck,
    Complete,
    Failed,
}
impl Phase {
    pub fn active(self) -> bool {
        matches!(self, Self::Transferring | Self::AwaitingAck)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferView {
    pub id: Uuid,
    pub peer: Uuid,
    pub direction: Direction,
    pub kind: Kind,
    pub bytes: usize,
    pub total: usize,
    pub phase: Phase,
    pub attempt: u8,
    pub transport: Transport,
}
impl TransferView {
    pub fn percent(&self) -> usize {
        if self.phase == Phase::Complete {
            100
        } else {
            (self.bytes.saturating_mul(100) / self.total.max(1)).min(99)
        }
    }
    pub fn label(&self) -> String {
        let action = match self.direction {
            Direction::Sending => "Sending",
            Direction::Receiving => "Receiving",
        };
        let kind = match self.kind {
            Kind::Text | Kind::CompressedText => "text",
            Kind::Png => "image",
            _ => "files",
        };
        let peer = self.peer.simple().to_string();
        let transport = match self.transport {
            Transport::Gatt => "BLE GATT",
            Transport::L2cap => "BLE L2CAP",
        };
        let state = match self.phase {
            Phase::Complete => "complete".into(),
            Phase::Failed => "failed / interrupted".into(),
            Phase::AwaitingAck => "awaiting peer confirmation".into(),
            Phase::Transferring if self.attempt > 1 => format!("retry {}", self.attempt),
            Phase::Transferring => "transferring".into(),
        };
        format!(
            "{action} {kind} · {transport} · {} · {}% ({}/{}) · {state}",
            &peer[..8],
            self.percent(),
            size(self.bytes),
            size(self.total)
        )
    }
}
fn size(n: usize) -> String {
    if n >= 1024 * 1024 {
        format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0))
    } else if n >= 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}
struct Entry {
    view: TransferView,
    changed: Instant,
}
#[derive(Default)]
struct State {
    entries: BTreeMap<(Uuid, Uuid), Entry>,
}
pub struct Transfers {
    state: Mutex<State>,
    tx: watch::Sender<Vec<TransferView>>,
}
impl Transfers {
    pub fn new() -> Arc<Self> {
        let (tx, _) = watch::channel(Vec::new());
        Arc::new(Self {
            state: Mutex::new(State::default()),
            tx,
        })
    }
    pub fn subscribe(&self) -> watch::Receiver<Vec<TransferView>> {
        self.tx.subscribe()
    }
    pub fn reporter(self: &Arc<Self>, peer: Uuid, direction: Direction) -> Reporter {
        Reporter {
            transfers: self.clone(),
            source: Uuid::new_v4(),
            peer,
            direction,
            last: None,
            published: Instant::now(),
            transport: Transport::Gatt,
        }
    }
    fn publish(&self, source: Uuid, view: TransferView) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.entries.insert(
            (source, view.id),
            Entry {
                view,
                changed: Instant::now(),
            },
        );
        let mut finished: Vec<_> = state
            .entries
            .iter()
            .filter(|(_, e)| !e.view.phase.active())
            .map(|(key, e)| (*key, e.changed))
            .collect();
        finished.sort_by_key(|(_, time)| *time);
        let excess = finished.len().saturating_sub(8);
        for (key, _) in finished.into_iter().take(excess) {
            state.entries.remove(&key);
        }
        let mut entries: Vec<_> = state.entries.values().collect();
        entries.sort_by_key(|e| (!e.view.phase.active(), std::cmp::Reverse(e.changed)));
        self.tx
            .send_replace(entries.into_iter().map(|e| e.view.clone()).collect());
    }
}
pub struct Reporter {
    transfers: Arc<Transfers>,
    source: Uuid,
    peer: Uuid,
    direction: Direction,
    last: Option<TransferView>,
    published: Instant,
    transport: Transport,
}
impl Reporter {
    pub fn with_transport(mut self, transport: Transport) -> Self {
        self.transport = transport;
        self
    }
    pub fn update(
        &mut self,
        id: Uuid,
        kind: Kind,
        bytes: usize,
        total: usize,
        phase: Phase,
        attempt: u8,
    ) {
        if !matches!(
            kind,
            Kind::Text | Kind::CompressedText | Kind::Files | Kind::FileResponse | Kind::Png
        ) {
            return;
        }
        let view = TransferView {
            id,
            peer: self.peer,
            direction: self.direction,
            kind,
            bytes: bytes.min(total),
            total,
            phase,
            attempt,
            transport: self.transport,
        };
        let transition = self
            .last
            .as_ref()
            .is_none_or(|old| old.id != id || old.phase != phase || old.attempt != attempt);
        if transition || self.published.elapsed() >= Duration::from_millis(250) {
            self.transfers.publish(self.source, view.clone());
            self.published = Instant::now();
        }
        self.last = Some(view);
    }
    pub fn fail(&mut self) {
        if let Some(mut view) = self.last.take() {
            if view.phase.active() {
                view.phase = Phase::Failed;
                self.transfers.publish(self.source, view);
            }
        }
    }
}
impl Drop for Reporter {
    fn drop(&mut self) {
        self.fail();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn progress_waits_for_confirmation_and_interruption_is_visible() {
        let monitor = Transfers::new();
        let view = monitor.subscribe();
        let id = Uuid::new_v4();
        let mut reporter = monitor.reporter(Uuid::new_v4(), Direction::Sending);
        reporter.update(id, Kind::Files, 1024, 1024, Phase::AwaitingAck, 1);
        assert_eq!(view.borrow()[0].percent(), 99);
        assert!(view.borrow()[0]
            .label()
            .contains("awaiting peer confirmation"));
        drop(reporter);
        assert_eq!(view.borrow()[0].phase, Phase::Failed);
        let mut reporter = monitor.reporter(Uuid::new_v4(), Direction::Receiving);
        reporter.update(Uuid::new_v4(), Kind::Files, 1024, 1024, Phase::Complete, 1);
        assert_eq!(
            view.borrow()
                .iter()
                .find(|v| v.phase == Phase::Complete)
                .unwrap()
                .percent(),
            100
        );
    }
    #[test]
    fn terminal_history_is_bounded_and_text_is_included() {
        let monitor = Transfers::new();
        let view = monitor.subscribe();
        let mut reporter = monitor.reporter(Uuid::new_v4(), Direction::Sending);
        reporter.update(Uuid::new_v4(), Kind::Text, 1, 1, Phase::Complete, 1);
        assert_eq!(view.borrow()[0].kind, Kind::Text);
        assert!(view.borrow()[0].label().contains("text"));
        for _ in 0..20 {
            reporter.update(Uuid::new_v4(), Kind::Files, 1, 1, Phase::Complete, 1);
        }
        assert_eq!(view.borrow().len(), 8);
    }
}
