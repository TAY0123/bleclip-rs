//! BLE peripheral half of peer mode. One advertisement / GATT service serves
//! multiple independently authenticated central connections. Each central has
//! its own handshake, nonce state, framing decoder and bounded transfer queues.

use super::{
    bulk::{self, Bulk, BulkSender, EndpointLease},
    Network, BULK_ID, IP_ID, READ_ID, SERVICE_ID, WRITE_ID,
};
use crate::{
    crypto::{self, PendingServer, Psk, Session},
    message::{Kind, Message, Update},
    status::{Connections, LinkRole},
    transfer::{Incoming, Outgoing},
    wire::{self, Decoder},
};
use anyhow::{bail, ensure, Context, Result};
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
    ip_rx: Decoder,
    supports_ip: bool,
    bulk_rx: Decoder,
    bulk_tx: VecDeque<u8>,
    bulk_sender: Option<BulkSender>,
    bulk_lease: Option<EndpointLease>,
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
            ip_rx: Decoder::default(),
            supports_ip: false,
            bulk_rx: Decoder::default(),
            bulk_tx: VecDeque::new(),
            bulk_sender: None,
            bulk_lease: None,
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
            self.bulk_sender = None;
            self.bulk_lease = None;
            self.bulk_rx = Decoder::default();
            self.bulk_tx.clear();
            self.supports_ip = false;
            self.ip_rx = Decoder::default();
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
                let mut update = update.clone();
                if update.kind == Kind::IpEndpoint && !self.supports_ip {
                    return Ok(());
                }
                if update.kind == Kind::FileRequest && !self.supports_ip && update.bytes.len() > 32
                {
                    update.bytes = update.bytes[..32].into();
                }
                self.sender.enqueue(update)?;
            }
        }
        Ok(())
    }

    fn ip_write(&mut self, value: &[u8]) -> Result<()> {
        let PeerState::Authenticated {
            session,
            remote_id: Some(_),
            ..
        } = &mut self.state
        else {
            bail!("IP capability before authentication")
        };
        for packet in self.ip_rx.push(value)? {
            ensure!(session.open(&packet)? == b"IP01", "invalid IP capability");
            self.supports_ip = true;
        }
        Ok(())
    }

    fn on_bulk(&mut self, bulk: &Arc<Bulk>, bytes: &[u8]) -> Result<()> {
        let PeerState::Authenticated {
            session,
            remote_id: Some(remote),
        } = &mut self.state
        else {
            bail!("bulk capability before GATT authentication");
        };
        ensure!(
            self.bulk_sender.is_none(),
            "bulk capability already negotiated"
        );
        let endpoint = bulk::decode_endpoint(&session.open(bytes)?)?;
        let lease = bulk.authorize(*remote);
        let reply = session.seal(&bulk::encode_endpoint(
            lease.as_ref().map(|lease| lease.endpoint()),
        ))?;
        wire::queue_frame(&mut self.bulk_tx, &reply)?;
        self.bulk_lease = lease;
        self.bulk_sender = Some(BulkSender::new(bulk.clone(), *remote, endpoint));
        Ok(())
    }

    fn bulk_write(&mut self, bulk: &Arc<Bulk>, value: &[u8]) -> Result<()> {
        for packet in self.bulk_rx.push(value)? {
            self.on_bulk(bulk, &packet)?;
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
            } else if self
                .bulk_sender
                .as_mut()
                .is_some_and(|sender| sender.step(&mut self.sender))
            {
                None
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
    network: Arc<Network>,
) -> Result<()> {
    let bulk = network.bulk.clone();
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

    let mut service = Service {
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
    service.characteristics.push(Characteristic {
        uuid: IP_ID,
        properties: vec![CharacteristicProperty::Write],
        permissions: vec![AttributePermission::Writeable],
        value: None,
        descriptors: vec![],
    });
    if bulk.available() {
        service.characteristics.push(Characteristic {
            uuid: BULK_ID,
            properties: vec![CharacteristicProperty::Read, CharacteristicProperty::Write],
            permissions: vec![
                AttributePermission::Readable,
                AttributePermission::Writeable,
            ],
            value: None,
            descriptors: vec![],
        });
    }
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
                                if update.kind == Kind::IpEndpoint && !peer.supports_ip { continue; }
                                if peer.remote_id().is_some_and(|id| network.ip.offloaded(id, update.id)) { continue; }
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
                            let answer = if request.service != SERVICE_ID || !matches!(request.characteristic, READ_ID | BULK_ID) {
                                ReadRequestResponse { value: vec![], response: RequestResponse::InvalidHandle }
                            } else if offset != 0 {
                                ReadRequestResponse { value: vec![], response: RequestResponse::InvalidOffset }
                            } else {
                                let value = if let Some(p) = peers.get_mut(&request.client) {
                                    p.last_activity = Instant::now();
                                    if request.characteristic == BULK_ID {
                                        wire::pop_chunk(&mut p.bulk_tx)
                                    } else {
                                        if let Err(error) = p.refill() { eprintln!("Read transfer refill failed: {error:#}"); }
                                        wire::pop_chunk(&mut p.tx)
                                    }
                                } else { vec![] };
                                ReadRequestResponse { value, response: RequestResponse::Success }
                            };
                            let _ = responder.send(answer);
                        }
                        PeripheralEvent::WriteRequest { request, offset, value, responder } => {
                            if request.service == SERVICE_ID && request.characteristic == IP_ID {
                                let result = if offset != 0 || value.is_empty() || value.len() > wire::ATT_CHUNK {
                                    Err(anyhow::anyhow!("invalid IP capability fragment"))
                                } else if let Some(peer) = peers.get_mut(&request.client) {
                                    let supported = peer.supports_ip;
                                    let result = peer.ip_write(&value);
                                    if !supported && peer.supports_ip {
                                        if let Ok(update) = network.ip.announcement() { let _ = to_peers.send(update); }
                                    }
                                    result
                                } else { Err(anyhow::anyhow!("IP capability before authentication")) };
                                let response = if result.is_ok() { RequestResponse::Success } else { RequestResponse::UnlikelyError };
                                let _ = responder.send(WriteRequestResponse { response });
                                continue;
                            }
                            if request.service == SERVICE_ID && request.characteristic == BULK_ID {
                                let result = if offset != 0 || value.is_empty() || value.len() > wire::ATT_CHUNK {
                                    Err(anyhow::anyhow!("invalid bulk capability fragment"))
                                } else if let Some(peer) = peers.get_mut(&request.client) {
                                    peer.last_activity = Instant::now();
                                    peer.bulk_write(&bulk, &value)
                                } else { Err(anyhow::anyhow!("bulk capability before authentication")) };
                                let response = if let Err(error) = result {
                                    eprintln!("Bulk capability rejected: {error:#}; GATT remains available");
                                    RequestResponse::UnlikelyError
                                } else { RequestResponse::Success };
                                let _ = responder.send(WriteRequestResponse { response });
                                continue;
                            }
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

    #[tokio::test]
    async fn optional_bulk_exchange_requires_auth_and_can_decline_without_breaking_gatt() {
        let key = [42; 32];
        let own_id = Uuid::new_v4();
        let remote_id = Uuid::new_v4();
        let (tx, _rx) = mpsc::channel(1);
        let (bulk, _listener) =
            Bulk::start(key, own_id, tx, crate::progress::Transfers::new(), 1, false).await;
        let mut peer = Peer::new();
        assert!(peer.on_bulk(&bulk, &[0; 20]).is_err());
        let (initiator, hello) = Initiator::start(&key);
        peer.on_message(&key, own_id, &hello).unwrap();
        let mut decoder = Decoder::default();
        let reply = loop {
            let packets = decoder.push(&wire::pop_chunk(&mut peer.tx)).unwrap();
            if let Some(packet) = packets.into_iter().next() {
                break packet;
            }
        };
        let (mut session, finish) = initiator.finish(&key, &reply).unwrap();
        peer.on_message(&key, own_id, &finish).unwrap();
        peer.on_message(
            &key,
            own_id,
            &session
                .seal(&Message::Identity(remote_id).encode().unwrap())
                .unwrap(),
        )
        .unwrap();
        // A legacy link receives no unknown IP payloads. The optional,
        // encrypted capability upgrades it without resetting the GATT session.
        let announcement = Update::new(own_id, Kind::IpEndpoint, b"null".to_vec()).unwrap();
        peer.offer(&announcement).unwrap();
        assert!(peer.sender.next(Instant::now()).is_none());
        let packet = session.seal(b"IP01").unwrap();
        for chunk in wire::frame(&packet).unwrap().chunks(wire::ATT_CHUNK) {
            peer.ip_write(chunk).unwrap();
        }
        assert!(peer.supports_ip);
        let packet = session.seal(&bulk::encode_endpoint(None)).unwrap();
        for chunk in wire::frame(&packet).unwrap().chunks(wire::ATT_CHUNK) {
            peer.bulk_write(&bulk, chunk).unwrap();
        }
        let mut decoder = Decoder::default();
        let reply = loop {
            let packets = decoder.push(&wire::pop_chunk(&mut peer.bulk_tx)).unwrap();
            if let Some(packet) = packets.into_iter().next() {
                break packet;
            }
        };
        assert!(bulk::decode_endpoint(&session.open(&reply).unwrap())
            .unwrap()
            .is_none());
        let update = Update::text(remote_id, "GATT still works".into()).unwrap();
        let mut outgoing = Outgoing::default();
        outgoing.enqueue(update.clone()).unwrap();
        let mut received = None;
        while let Some(message) = outgoing.next(Instant::now()) {
            if let Some(item) = peer
                .on_message(
                    &key,
                    own_id,
                    &session.seal(&message.encode().unwrap()).unwrap(),
                )
                .unwrap()
            {
                received = Some(item);
            }
        }
        assert_eq!(received, Some(update));
    }
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
