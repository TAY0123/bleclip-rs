//! BLE peripheral half of peer mode. One advertisement / GATT service serves
//! multiple independently authenticated central connections. Each central has
//! its own handshake, nonce state, framing decoder and bounded transfer queues.

use super::{READ_ID, SERVICE_ID, WRITE_ID};
use crate::{
    crypto::{self, PendingServer, Psk, Session},
    message::{Message, Update},
    status::{Connections, LinkRole},
    transfer::{Incoming, Outgoing},
    wire::{self, Decoder},
};
use anyhow::{bail, Context, Result};
use ble_peripheral_rust::{
    gatt::{
        characteristic::Characteristic,
        peripheral_event::{
            PeripheralEvent, ReadRequestResponse, RequestResponse, WriteRequestResponse,
        },
        properties::{AttributePermission, CharacteristicProperty},
        service::Service,
    },
    Peripheral, PeripheralImpl,
};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{broadcast, mpsc},
    time::{interval, sleep, timeout},
};
use uuid::Uuid;

enum PeerState {
    Unauthenticated,
    WaitingForFinish(PendingServer),
    Authenticated {
        session: Session,
        remote_id: Option<Uuid>,
    },
}

struct Peer {
    rx: Decoder,
    tx: VecDeque<u8>,
    sender: Outgoing,
    receiver: Incoming,
    receipts: VecDeque<Uuid>,
    state: PeerState,
    last_activity: Instant,
}

impl Peer {
    fn new() -> Self {
        Self {
            rx: Decoder::default(),
            tx: VecDeque::new(),
            sender: Outgoing::default(),
            receiver: Incoming::default(),
            receipts: VecDeque::new(),
            state: PeerState::Unauthenticated,
            last_activity: Instant::now(),
        }
    }

    fn remote_id(&self) -> Option<Uuid> {
        match &self.state {
            PeerState::Authenticated { remote_id, .. } => *remote_id,
            _ => None,
        }
    }

    fn on_message(&mut self, psk: &Psk, own_id: Uuid, payload: &[u8]) -> Result<Option<Update>> {
        // A fresh authenticated handshake can reset a stalled connection.
        if payload.first() == Some(&1) {
            let (pending, reply) = crypto::accept(psk, payload)?;
            self.state = PeerState::Unauthenticated;
            self.tx.clear();
            self.sender = Outgoing::default();
            self.receiver = Incoming::default();
            self.receipts.clear();
            wire::queue_frame(&mut self.tx, &reply)?;
            self.state = PeerState::WaitingForFinish(pending);
            return Ok(None);
        }
        if payload.first() == Some(&4) {
            let old = std::mem::replace(&mut self.state, PeerState::Unauthenticated);
            let pending = match old {
                PeerState::WaitingForFinish(pending) => pending,
                _ => bail!("unexpected finish message"),
            };
            let session = pending.finish(psk, payload)?;
            let identity = Message::Identity(own_id).encode()?;
            wire::queue_frame(&mut self.tx, &session.seal(&identity)?)?;
            self.state = PeerState::Authenticated {
                session,
                remote_id: None,
            };
            return Ok(None);
        }
        match &mut self.state {
            PeerState::Authenticated { session, remote_id } => {
                let message = Message::decode(&session.open(payload)?)?;
                match message {
                    Message::Identity(remote) => {
                        if remote == own_id {
                            bail!("self connection rejected");
                        }
                        if remote_id.is_some() && *remote_id != Some(remote) {
                            bail!("node identity changed during session");
                        }
                        *remote_id = Some(remote);
                        Ok(None)
                    }
                    Message::Ack(id) => {
                        self.sender.ack(id);
                        Ok(None)
                    }
                    msg => {
                        if remote_id.is_none() {
                            bail!("content before node identity");
                        }
                        let received = self.receiver.handle(msg, Instant::now())?;
                        if let Some(id) = received.ack {
                            self.receipts.push_back(id);
                        }
                        Ok(received.update)
                    }
                }
            }
            _ => bail!("unauthenticated peer sent clipboard data"),
        }
    }

    fn offer(&mut self, update: &Update) -> Result<()> {
        if let PeerState::Authenticated {
            remote_id: Some(remote_id),
            ..
        } = &self.state
        {
            if *remote_id != update.origin {
                self.sender.enqueue(update.clone())?;
            }
        }
        Ok(())
    }

    /// Produce only one bounded encrypted transfer fragment when polled.
    fn refill(&mut self) -> Result<()> {
        if !self.tx.is_empty() {
            return Ok(());
        }
        if let PeerState::Authenticated {
            session,
            remote_id: Some(_),
            ..
        } = &mut self.state
        {
            let message = if let Some(id) = self.receipts.pop_front() {
                Some(Message::Ack(id))
            } else {
                self.sender.next(Instant::now())
            };
            if let Some(message) = message {
                wire::queue_frame(&mut self.tx, &session.seal(&message.encode()?)?)?;
            }
        }
        Ok(())
    }
}

pub async fn run(
    psk: Psk,
    name: String,
    own_id: Uuid,
    max_inbound: usize,
    from_peers: mpsc::Sender<Update>,
    to_peers: broadcast::Sender<Update>,
    connections: Arc<Connections>,
) -> Result<()> {
    // On task cancellation, remove stale inbound tray entries even if the BLE
    // peripheral SDK does not emit a per-client disconnect event.
    let _role_guard = connections.track_role(LinkRole::Inbound);
    let (sender_tx, mut receiver_rx) = mpsc::channel::<PeripheralEvent>(256);
    let mut peripheral = Peripheral::new(sender_tx)
        .await
        .context("could not initialize local BLE GATT peripheral")?;

    timeout(Duration::from_secs(20), async {
        while !peripheral.is_powered().await? {
            sleep(Duration::from_millis(250)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("Bluetooth peripheral did not power on")??;

    let service = Service {
        uuid: SERVICE_ID,
        primary: true,
        characteristics: vec![
            Characteristic {
                uuid: WRITE_ID,
                properties: vec![CharacteristicProperty::Write],
                permissions: vec![AttributePermission::Writeable],
                value: None,
                descriptors: vec![],
            },
            Characteristic {
                uuid: READ_ID,
                properties: vec![CharacteristicProperty::Read],
                permissions: vec![AttributePermission::Readable],
                value: None,
                descriptors: vec![],
            },
        ],
    };
    peripheral
        .add_service(&service)
        .await
        .context("local GATT registration failed")?;
    peripheral
        .start_advertising(&name, &[SERVICE_ID])
        .await
        .context("BLE advertising failed")?;
    println!("BLE peripheral advertising ({name}); max inbound peers: {max_inbound}");

    let mut peers: HashMap<String, Peer> = HashMap::new();
    let mut updates = to_peers.subscribe();
    let mut cleanup = interval(Duration::from_secs(10));

    let result = async {
        loop {
            tokio::select! {
                _ = cleanup.tick() => {
                    peers.retain(|client, p| {
                        let keep = p.last_activity.elapsed() < Duration::from_secs(25);
                        if !keep { connections.disconnected(LinkRole::Inbound, client); }
                        keep
                    });
                }
                latest = updates.recv() => {
                    match latest {
                        Ok(update) => {
                            for (remote, peer) in peers.iter_mut() {
                                if let Err(error) = peer.offer(&update) {
                                    // Overflow is bounded. Do not break the authenticated
                                    // session or discard half-delivered frames.
                                    eprintln!("Inbound {remote}: update skipped: {error:#}");
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(count)) => {
                            eprintln!("Peripheral delivery lagged by {count} updates");
                        }
                        Err(broadcast::error::RecvError::Closed) => bail!("clipboard bus closed"),
                    }
                }
                event = receiver_rx.recv() => {
                    let Some(event) = event else { bail!("peripheral event stream closed"); };
                    match event {
                        PeripheralEvent::StateUpdate { is_powered } => {
                            if !is_powered { bail!("Bluetooth peripheral powered off"); }
                        }
                        PeripheralEvent::CharacteristicSubscriptionUpdate { .. } => {}
                        PeripheralEvent::ReadRequest { request, offset, responder } => {
                            let answer = if request.service != SERVICE_ID || request.characteristic != READ_ID {
                                ReadRequestResponse { value: vec![], response: RequestResponse::InvalidHandle }
                            } else if offset != 0 {
                                ReadRequestResponse { value: vec![], response: RequestResponse::InvalidOffset }
                            } else {
                                let value = if let Some(p) = peers.get_mut(&request.client) {
                                    p.last_activity = Instant::now();
                                    if let Err(error) = p.refill() { eprintln!("Read transfer refill failed: {error:#}"); }
                                    wire::pop_chunk(&mut p.tx)
                                } else { vec![] };
                                ReadRequestResponse { value, response: RequestResponse::Success }
                            };
                            let _ = responder.send(answer);
                        }
                        PeripheralEvent::WriteRequest { request, offset, value, responder } => {
                            let mut response = RequestResponse::Success;
                            let mut accepted = Vec::<Update>::new();
                            if request.service != SERVICE_ID || request.characteristic != WRITE_ID {
                                response = RequestResponse::InvalidHandle;
                            } else if offset != 0 {
                                response = RequestResponse::InvalidOffset;
                            } else if value.is_empty() || value.len() > wire::ATT_CHUNK {
                                response = RequestResponse::UnlikelyError;
                            } else {
                                // Distinct BLE centrals get distinct crypto sessions.
                                if !peers.contains_key(&request.client) && peers.len() >= max_inbound {
                                    peers.retain(|client, p| {
                                        let keep = p.last_activity.elapsed() < Duration::from_secs(30);
                                        if !keep { connections.disconnected(LinkRole::Inbound, client); }
                                        keep
                                    });
                                }
                                if !peers.contains_key(&request.client) && peers.len() >= max_inbound {
                                    response = RequestResponse::UnlikelyError;
                                } else {
                                    let peer = peers.entry(request.client.clone()).or_insert_with(Peer::new);
                                    peer.last_activity = Instant::now();
                                    let previous_id = peer.remote_id();
                                    let result = peer.rx.push(&value).and_then(|packets| {
                                        for packet in packets {
                                            if let Some(update) = peer.on_message(&psk, own_id, &packet)? {
                                                accepted.push(update);
                                            }
                                        }
                                        Ok(())
                                    });
                                    let current_id = peer.remote_id();
                                    if let Err(error) = result {
                                        eprintln!("Rejected inbound BLE message from {}: {error:#}", request.client);
                                        peers.remove(&request.client);
                                        connections.disconnected(LinkRole::Inbound, &request.client);
                                        response = RequestResponse::UnlikelyError;
                                    } else if current_id != previous_id {
                                        // An authenticated identity, not a raw BLE write, makes
                                        // a peer visible in the tray's connection list.
                                        if let Some(id) = current_id {
                                            peer.sender.set_progress(connections.transfers.reporter(id, crate::progress::Direction::Sending));
                                            peer.receiver.set_progress(connections.transfers.reporter(id, crate::progress::Direction::Receiving));
                                            connections.connected(LinkRole::Inbound, request.client.clone(), id);
                                        } else {
                                            connections.disconnected(LinkRole::Inbound, &request.client);
                                        }
                                    }
                                }
                            }
                            let _ = responder.send(WriteRequestResponse { response });
                            for update in accepted {
                                if from_peers.send(update).await.is_err() {
                                    bail!("clipboard router stopped");
                                }
                            }
                        }
                    }
                }
            }
        }
    }.await;
    let _ = peripheral.stop_advertising().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Initiator;
    use crate::message::Kind;
    #[test]
    fn independent_clients_receive_encrypted_file_chunks() {
        let key = [42u8; 32];
        let server_id = Uuid::new_v4();
        let ids = [Uuid::new_v4(), Uuid::new_v4()];
        let mut peers: Vec<Peer> = (0..2).map(|_| Peer::new()).collect();
        let mut clients = Vec::new();
        for (peer, client_id) in peers.iter_mut().zip(ids) {
            let (initiator, hello) = Initiator::start(&key);
            peer.on_message(&key, server_id, &hello).unwrap();
            let mut decoder = Decoder::default();
            let reply = loop {
                let data = decoder.push(&wire::pop_chunk(&mut peer.tx)).unwrap();
                if let Some(reply) = data.into_iter().next() {
                    break reply;
                }
            };
            let (session, finish) = initiator.finish(&key, &reply).unwrap();
            peer.on_message(&key, server_id, &finish).unwrap();
            peer.on_message(
                &key,
                server_id,
                &session
                    .seal(&Message::Identity(client_id).encode().unwrap())
                    .unwrap(),
            )
            .unwrap();
            clients.push(session);
        }
        assert_eq!(peers[0].remote_id(), Some(ids[0]));
        assert_eq!(peers[1].remote_id(), Some(ids[1]));
        let update = Update::new(server_id, Kind::Files, vec![8; 4000]).unwrap();
        let mut first = None;
        for (index, (peer, session)) in peers.iter_mut().zip(clients.iter_mut()).enumerate() {
            peer.offer(&update).unwrap();
            let mut decoder = Decoder::default();
            let mut incoming = Incoming::default();
            let mut n = 0;
            while n < 6 {
                peer.refill().unwrap();
                let chunk = wire::pop_chunk(&mut peer.tx);
                let frames = decoder.push(&chunk).unwrap();
                for f in frames {
                    if let Some(bytes) = &first {
                        let _ = bytes;
                    }
                    if index == 0 && first.is_none() {
                        first = Some(f.clone());
                    }
                    let message = Message::decode(&session.open(&f).unwrap()).unwrap();
                    match message {
                        Message::Identity(_) => {}
                        msg => {
                            n += 1;
                            let received = incoming.handle(msg, Instant::now()).unwrap();
                            if let Some(got) = received.update {
                                assert_eq!(got, update);
                            }
                        }
                    }
                }
            }
        }
        assert!(clients[1].open(first.as_ref().unwrap()).is_err());
    }
}
