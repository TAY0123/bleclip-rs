//! Multi-peer event fan-out. A single clipboard event keeps its UUID and origin
//! across the entire mesh; loops and redundant connections cannot reapply it.

use crate::{clipboard::{ClipboardSync, Direction}, message::{Update, MAX_HOPS}};
use std::{collections::{HashSet, VecDeque}, time::Duration};
use tokio::{sync::{broadcast, mpsc}, time::interval};
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
        Self { self_id, direction, seen: HashSet::new(), order: VecDeque::new() }
    }

    fn remember(&mut self, id: Uuid) -> bool {
        if !self.seen.insert(id) { return false; }
        self.order.push_back(id);
        if self.order.len() > SEEN_LIMIT {
            if let Some(old) = self.order.pop_front() { self.seen.remove(&old); }
        }
        true
    }

    pub fn local(&mut self, text: String) -> Option<Update> {
        if !self.direction.can_send() { return None; }
        let update = Update::new(self.self_id, text).ok()?;
        self.remember(update.id);
        Some(update)
    }

    /// Returns (accepted message for clipboard application, optional relay).
    pub fn remote(&mut self, update: Update) -> Option<(Update, Option<Update>)> {
        if !self.direction.can_receive() || update.origin == self.self_id || update.hops > MAX_HOPS {
            return None;
        }
        if !self.remember(update.id) { return None; }
        let relay = if self.direction.can_send() && update.hops > 0 {
            let mut forwarded = update.clone();
            forwarded.hops -= 1;
            Some(forwarded)
        } else { None };
        Some((update, relay))
    }
}

pub async fn run(
    self_id: Uuid,
    direction: Direction,
    mut from_peers: mpsc::Receiver<Update>,
    to_peers: broadcast::Sender<Update>,
) -> anyhow::Result<()> {
    let mut clipboard = ClipboardSync::new(direction)?;
    let mut router = Router::new(self_id, direction);
    let mut poll = interval(Duration::from_millis(250));
    println!("Peer {}: clipboard monitor active ({direction:?})", self_id);

    loop {
        tokio::select! {
            _ = poll.tick() => {
                if let Some(text) = clipboard.check_local_change() {
                    if let Some(update) = router.local(text) {
                        println!("Local clipboard update {} ({} bytes)", update.id, update.text.len());
                        let _ = to_peers.send(update); // no subscribers when alone is normal
                    }
                }
            }
            maybe_update = from_peers.recv() => {
                let Some(update) = maybe_update else { break; };
                if let Some((accepted, relay)) = router.remote(update) {
                    match clipboard.apply_remote(&accepted.text) {
                        Ok(true) => println!("Remote clipboard update {} ({} bytes)", accepted.id, accepted.text.len()),
                        Ok(false) => {}
                        Err(error) => eprintln!("Remote clipboard write failed: {error:#}"),
                    }
                    if let Some(update) = relay {
                        let _ = to_peers.send(update);
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

    #[test]
    fn three_peer_mesh_relay_is_duplicate_and_loop_safe() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        let mut ra = Router::new(a, Direction::Both);
        let mut rb = Router::new(b, Direction::Both);
        let mut rc = Router::new(c, Direction::Both);

        let original = ra.local("hello mesh".into()).unwrap();
        let (_, ab) = rb.remote(original.clone()).unwrap();
        let ab = ab.unwrap();
        assert_eq!(ab.id, original.id);
        assert_eq!(ab.origin, a);
        assert_eq!(ab.hops, MAX_HOPS - 1);
        let (_, bc) = rc.remote(ab.clone()).unwrap();
        let bc = bc.unwrap();
        assert!(ra.remote(bc.clone()).is_none()); // back to origin
        assert!(rb.remote(bc).is_none()); // already seen
        assert!(rc.remote(ab).is_none()); // duplicate through second link
    }

    #[test]
    fn supports_many_subscribers() {
        let (tx, _) = broadcast::channel(64);
        let mut receivers: Vec<_> = (0..16).map(|_| tx.subscribe()).collect();
        let mut router = Router::new(Uuid::new_v4(), Direction::Both);
        let update = router.local("shared".into()).unwrap();
        tx.send(update.clone()).unwrap();
        for r in &mut receivers {
            assert_eq!(r.try_recv().unwrap(), update);
        }
    }

    #[test]
    fn hop_limit_direction_and_empty_text() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let event = Update::new(a, String::new()).unwrap();
        let mut receive = Router::new(b, Direction::Receive);
        let (received, relay) = receive.remote(event.clone()).unwrap();
        assert!(received.text.is_empty());
        assert!(relay.is_none());
        let mut send = Router::new(b, Direction::Send);
        assert!(send.remote(event.clone()).is_none());
        let mut both = Router::new(b, Direction::Both);
        let mut ttl = event;
        ttl.hops = 0;
        assert!(both.remote(ttl).unwrap().1.is_none());
    }
}
