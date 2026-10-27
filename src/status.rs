//! Authenticated BLE connection tracking shared by central and peripheral roles.
//! Notifications are snapshots rather than transport events, so a late receiver
//! always sees the actual current list of connected peers.
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};
use tokio::sync::watch;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum LinkRole {
    Inbound,
    Outbound,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PeerView {
    pub id: Uuid,
    pub inbound: usize,
    pub outbound: usize,
}

impl PeerView {
    pub fn label(&self) -> String {
        let id = self.id.simple().to_string();
        let role = match (self.inbound > 0, self.outbound > 0) {
            (true, true) => "inbound + outbound",
            (true, false) => "inbound",
            (false, true) => "outbound",
            (false, false) => "disconnected",
        };
        format!("{}…  ({role})", &id[..12])
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ConnectionSnapshot {
    pub scanning: bool,
    pub advertising: bool,
    pub connecting: usize,
    pub peers: Vec<PeerView>,
}

#[derive(Default)]
struct State {
    scanning: bool,
    advertising: bool,
    connecting: BTreeSet<String>,
    links: BTreeMap<(LinkRole, String), Uuid>,
}

impl State {
    fn snapshot(&self) -> ConnectionSnapshot {
        let mut unique = BTreeMap::<Uuid, PeerView>::new();
        for ((role, _link), id) in &self.links {
            let entry = unique.entry(*id).or_insert_with(|| PeerView {
                id: *id,
                inbound: 0,
                outbound: 0,
            });
            match role {
                LinkRole::Inbound => entry.inbound += 1,
                LinkRole::Outbound => entry.outbound += 1,
            }
        }
        ConnectionSnapshot {
            scanning: self.scanning,
            advertising: self.advertising,
            connecting: self.connecting.len(),
            peers: unique.into_values().collect(),
        }
    }
}

/// All data is guarded by a short standard mutex because native tray events run
/// on the UI thread rather than the Tokio runtime.
pub(crate) struct Connections {
    pub transfers: Arc<crate::progress::Transfers>,
    state: Mutex<State>,
    sender: watch::Sender<ConnectionSnapshot>,
}

impl Connections {
    pub fn new() -> Arc<Self> {
        let (sender, _) = watch::channel(ConnectionSnapshot::default());
        Arc::new(Self {
            transfers: crate::progress::Transfers::new(),
            state: Mutex::new(State::default()),
            sender,
        })
    }

    pub fn subscribe(&self) -> watch::Receiver<ConnectionSnapshot> {
        self.sender.subscribe()
    }

    fn change(&self, update: impl FnOnce(&mut State)) {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        update(&mut state);
        let next = state.snapshot();
        if *self.sender.borrow() != next {
            self.sender.send_replace(next);
        }
    }

    pub fn set_roles(&self, scanning: bool, advertising: bool) {
        self.change(|state| {
            state.scanning = scanning;
            state.advertising = advertising;
        });
    }

    pub fn connected(&self, role: LinkRole, link: String, peer: Uuid) {
        self.change(|state| {
            state.links.insert((role, link), peer);
        });
    }

    pub fn disconnected(&self, role: LinkRole, link: &str) {
        self.change(|state| {
            state.links.remove(&(role, link.to_owned()));
        });
    }

    pub fn clear_role(&self, role: LinkRole) {
        self.change(|state| {
            state.links.retain(|(r, _), _| *r != role);
        });
    }

    pub fn reset(&self) {
        self.change(|state| *state = State::default());
    }

    pub fn track(self: &Arc<Self>, role: LinkRole, link: String, peer: Uuid) -> LinkGuard {
        self.connected(role, link.clone(), peer);
        LinkGuard {
            connections: Arc::clone(self),
            role,
            link,
        }
    }

    pub fn track_role(self: &Arc<Self>, role: LinkRole) -> RoleGuard {
        RoleGuard {
            connections: Arc::clone(self),
            role,
        }
    }

    pub fn track_connecting(self: &Arc<Self>, link: String) -> ConnectingGuard {
        self.change(|state| {
            state.connecting.insert(link.clone());
        });
        ConnectingGuard {
            connections: Arc::clone(self),
            link,
        }
    }
}

pub(crate) struct ConnectingGuard {
    connections: Arc<Connections>,
    link: String,
}
impl Drop for ConnectingGuard {
    fn drop(&mut self) {
        self.connections.change(|state| {
            state.connecting.remove(&self.link);
        });
    }
}

/// When an async connection is cancelled, Drop clears its authenticated status
/// immediately rather than leaving a stale "connected" tray item.
pub(crate) struct LinkGuard {
    connections: Arc<Connections>,
    role: LinkRole,
    link: String,
}
impl Drop for LinkGuard {
    fn drop(&mut self) {
        self.connections.disconnected(self.role, &self.link);
    }
}

/// Peripheral server owns multiple clients. Aborting the server task clears all
/// of its connections even when individual disconnect events are unavailable.
pub(crate) struct RoleGuard {
    connections: Arc<Connections>,
    role: LinkRole,
}
impl Drop for RoleGuard {
    fn drop(&mut self) {
        self.connections.clear_role(self.role);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_duplicate_routes_and_disconnects_individually() {
        let peers = Connections::new();
        let mut view = peers.subscribe();
        let id = Uuid::new_v4();
        let a = peers.track(LinkRole::Inbound, "aa".into(), id);
        let b = peers.track(LinkRole::Outbound, "bb".into(), id);
        assert!(view.has_changed().unwrap());
        let snapshot = view.borrow_and_update().clone();
        assert_eq!(snapshot.peers.len(), 1);
        assert_eq!(snapshot.peers[0].inbound, 1);
        assert_eq!(snapshot.peers[0].outbound, 1);
        drop(a);
        let snapshot = view.borrow_and_update().clone();
        assert_eq!(snapshot.peers.len(), 1);
        assert_eq!(snapshot.peers[0].inbound, 0);
        drop(b);
        assert!(view.borrow_and_update().peers.is_empty());
    }

    #[test]
    fn server_task_drop_clears_all_inbound_but_not_outbound() {
        let peers = Connections::new();
        let id = Uuid::new_v4();
        let outbound = peers.track(LinkRole::Outbound, "client".into(), id);
        let role = peers.track_role(LinkRole::Inbound);
        peers.connected(LinkRole::Inbound, "server-peer".into(), id);
        drop(role);
        assert_eq!(peers.subscribe().borrow().peers.len(), 1);
        assert_eq!(peers.subscribe().borrow().peers[0].outbound, 1);
        drop(outbound);
        assert!(peers.subscribe().borrow().peers.is_empty());
    }

    #[test]
    fn paused_state_resets_roles_and_connections() {
        let peers = Connections::new();
        peers.set_roles(true, true);
        peers.connected(LinkRole::Inbound, "aa".into(), Uuid::new_v4());
        peers.reset();
        assert_eq!(*peers.subscribe().borrow(), ConnectionSnapshot::default());
    }

    #[test]
    fn connecting_attempt_is_removed_on_completion_or_cancellation() {
        let peers = Connections::new();
        let view = peers.subscribe();
        let attempt = peers.track_connecting("candidate".into());
        assert_eq!(view.borrow().connecting, 1);
        assert!(view.borrow().peers.is_empty());
        drop(attempt);
        assert_eq!(view.borrow().connecting, 0);
    }

    #[test]
    fn authenticated_peer_label_has_role_and_id() {
        let peer = PeerView {
            id: Uuid::nil(),
            inbound: 1,
            outbound: 0,
        };
        assert!(peer.label().contains("inbound"));
        assert!(peer.label().contains("00000000"));
    }
}
