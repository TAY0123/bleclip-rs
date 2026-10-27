//! Multi-peer fan-out with per-event deduplication. Each completed binary
//! transfer is relayed as a whole (bounded at 64 MiB), not half-written files.
use crate::{
    clipboard::{ClipboardSync, Direction},
    message::{Kind, Update, MAX_HOPS},
};
use std::{
    collections::{HashSet, VecDeque},
    path::PathBuf,
    time::Duration,
};
use tokio::{
    sync::{broadcast, mpsc},
    time::interval,
};
use uuid::Uuid;

const SEEN_LIMIT: usize = 8192;
pub struct Router {
    self_id: Uuid,
    direction: Direction,
    seen: HashSet<Uuid>,
    order: VecDeque<Uuid>,
}
impl Router {
    pub fn new(self_id: Uuid, direction: Direction) -> Self {
        Self {
            self_id,
            direction,
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }
    fn remember(&mut self, id: Uuid) -> bool {
        if !self.seen.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > SEEN_LIMIT {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }
    pub fn local(&mut self, update: Update) -> Option<Update> {
        if (!self.direction.can_send() && !matches!(update.kind, Kind::FileRequest))
            || update.origin != self.self_id
            || update.validate().is_err()
        {
            return None;
        }
        self.remember(update.id).then_some(update)
    }
    /// Returns (accepted update, relay if enabled).
    pub fn remote(&mut self, update: Update) -> Option<(Update, Option<Update>)> {
        if (!self.direction.can_receive() && !matches!(update.kind, Kind::FileRequest))
            || update.origin == self.self_id
            || update.hops > MAX_HOPS
            || update.validate().is_err()
            || !self.remember(update.id)
        {
            return None;
        }
        let relay = if self.direction.can_send() && update.hops > 0 {
            let mut forwarded = update.clone();
            forwarded.hops -= 1;
            Some(forwarded)
        } else {
            None
        };
        Some((update, relay))
    }
}
pub async fn run(
    self_id: Uuid,
    direction: Direction,
    mut from_peers: mpsc::Receiver<Update>,
    to_peers: broadcast::Sender<Update>,
    allow_images: bool,
    allow_files: bool,
    receive_dir: PathBuf,
) -> anyhow::Result<()> {
    let mut clipboard =
        ClipboardSync::new(self_id, direction, allow_images, allow_files, receive_dir)?;
    let mut router = Router::new(self_id, direction);
    let mut poll = interval(Duration::from_millis(500));
    println!("Node {self_id}: desktop clipboard monitor active ({direction:?})");
    loop {
        tokio::select! {
            _ = poll.tick() => {
                if let Some(update) = clipboard.check_local_change(self_id) {
                    if let Some(update) = router.local(update) {
                        println!("Local {:?} update {} ({} bytes)", update.kind, update.id, update.bytes.len());
                        let _ = to_peers.send(update);
                    }
                }
            }
            received = from_peers.recv() => {
                let Some(update) = received else { break; };
                if !clipboard.allows(update.kind) { continue; }
                if let Some((accepted, relay)) = router.remote(update) {
                    match clipboard.apply_remote(&accepted) {
                        Ok(applied) => {
                            if applied { println!("Remote {:?} update {} ({} bytes)", accepted.kind, accepted.id, accepted.bytes.len()); }
                            if let Some(next) = relay { let _ = to_peers.send(next); }
                        }
                        Err(err) => eprintln!("Remote {:?} update {} rejected: {err:#}", accepted.kind, accepted.id),
                    }
                }
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Kind;
    #[test]
    fn one_way_clipboard_still_routes_file_control_messages() {
        let sender = Uuid::new_v4();
        let receiver = Uuid::new_v4();
        let mut a = Router::new(sender, Direction::Send);
        let mut b = Router::new(receiver, Direction::Receive);
        let request = Update::new(receiver, Kind::FileRequest, vec![1; 32]).unwrap();
        assert!(b.local(request.clone()).is_some());
        assert!(a.remote(request).is_some());
        let response = Update::new(sender, Kind::FileResponse, vec![2; 32]).unwrap();
        assert!(a.local(response.clone()).is_some());
        assert!(b.remote(response).is_some());
        assert!(a
            .remote(Update::text(receiver, "blocked".into()).unwrap())
            .is_none());
        assert!(b
            .local(Update::text(receiver, "blocked".into()).unwrap())
            .is_none());
    }
    #[test]
    fn three_peer_file_relay_deduplicates() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        let mut ra = Router::new(a, Direction::Both);
        let mut rb = Router::new(b, Direction::Both);
        let mut rc = Router::new(c, Direction::Both);
        let msg = ra
            .local(Update::new(a, Kind::Files, vec![42; 100_000]).unwrap())
            .unwrap();
        let (_, ab) = rb.remote(msg.clone()).unwrap();
        let (_, bc) = rc.remote(ab.unwrap()).unwrap();
        let bc = bc.unwrap();
        assert_eq!(bc.hops, MAX_HOPS - 2);
        assert!(ra.remote(bc.clone()).is_none());
        assert!(rb.remote(bc.clone()).is_none());
        assert!(rc.remote(bc).is_none());
    }
    #[test]
    fn sixteen_subscribers_receive_one_arc_payload() {
        let (bus, _rx) = broadcast::channel(32);
        let mut subscribers: Vec<_> = (0..16).map(|_| bus.subscribe()).collect();
        let upd = Update::new(Uuid::new_v4(), Kind::Png, vec![1; 2_000]).unwrap();
        bus.send(upd.clone()).unwrap();
        for subscriber in &mut subscribers {
            let received = subscriber.try_recv().unwrap();
            assert_eq!(received, upd);
            assert!(std::sync::Arc::ptr_eq(&received.bytes, &upd.bytes));
        }
    }
}
