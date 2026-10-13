//! BLE peripheral half of peer mode. One advertisement / GATT service serves
//! multiple independently authenticated central connections. Each central has
//! its own handshake, nonces, framing decoder, and bounded outgoing queue.

use super::{READ_ID, SERVICE_ID, WRITE_ID};
use crate::{
    crypto::{self, PendingServer, Psk, Session},
    message::{Message, Update},
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
use std::{collections::{HashMap, VecDeque}, time::{Duration, Instant}};
use tokio::{sync::{broadcast, mpsc}, time::{interval, sleep, timeout}};
use uuid::Uuid;

enum PeerState {
    Unauthenticated,
    WaitingForFinish(PendingServer),
    Authenticated { session: Session, remote_id: Option<Uuid> },
}

struct Peer {
    rx: Decoder,
    tx: VecDeque<u8>,
    state: PeerState,
    last_activity: Instant,
}

impl Peer {
    fn new() -> Self {
        Self {
            rx: Decoder::default(),
            tx: VecDeque::new(),
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
            self.state = PeerState::Authenticated { session, remote_id: None };
            return Ok(None);
        }
        match &mut self.state {
            PeerState::Authenticated { session, remote_id } => {
                let message = Message::decode(&session.open(payload)?)?;
                match message {
                    Message::Identity(remote) => {
                        if remote == own_id { bail!("self connection rejected"); }
                        if remote_id.is_some() && *remote_id != Some(remote) {
                            bail!("node identity changed during session");
                        }
                        *remote_id = Some(remote);
                        Ok(None)
                    }
                    Message::Clipboard(update) => {
                        if remote_id.is_none() { bail!("clipboard before node identity"); }
                        Ok(Some(update))
                    }
                }
            }
            _ => bail!("unauthenticated peer sent clipboard data"),
        }
    }

    fn offer(&mut self, update: &Update) -> Result<()> {
        if let PeerState::Authenticated { session, remote_id: Some(remote_id) } = &mut self.state {
            if *remote_id != update.origin {
                let encoded = Message::Clipboard(update.clone()).encode()?;
                wire::queue_frame(&mut self.tx, &session.seal(&encoded)?)?;
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
) -> Result<()> {
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
    peripheral.add_service(&service).await.context("local GATT registration failed")?;
    peripheral.start_advertising(&name, &[SERVICE_ID]).await.context("BLE advertising failed")?;
    println!("BLE peripheral advertising ({name}); max inbound peers: {max_inbound}");

    let mut peers: HashMap<String, Peer> = HashMap::new();
    let mut updates = to_peers.subscribe();
    let mut cleanup = interval(Duration::from_secs(10));

    let result = async {
        loop {
            tokio::select! {
                _ = cleanup.tick() => {
                    peers.retain(|_, p| p.last_activity.elapsed() < Duration::from_secs(25));
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
                                    peers.retain(|_, p| p.last_activity.elapsed() < Duration::from_secs(30));
                                }
                                if !peers.contains_key(&request.client) && peers.len() >= max_inbound {
                                    response = RequestResponse::UnlikelyError;
                                } else {
                                    let peer = peers.entry(request.client.clone()).or_insert_with(Peer::new);
                                    peer.last_activity = Instant::now();
                                    let result = peer.rx.push(&value).and_then(|packets| {
                                        for packet in packets {
                                            if let Some(update) = peer.on_message(&psk, own_id, &packet)? {
                                                accepted.push(update);
                                            }
                                        }
                                        Ok(())
                                    });
                                    if let Err(error) = result {
                                        eprintln!("Rejected inbound BLE message from {}: {error:#}", request.client);
                                        peers.remove(&request.client);
                                        response = RequestResponse::UnlikelyError;
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
    use crate::message::Update;

    #[test]
    fn simultaneous_clients_have_independent_authenticated_sessions() {
        let key = [42u8; 32];
        let server_id = Uuid::new_v4();
        let client1_id = Uuid::new_v4();
        let client2_id = Uuid::new_v4();
        let mut peers: Vec<Peer> = (0..2).map(|_| Peer::new()).collect();
        let ids = [client1_id, client2_id];
        let mut clients = Vec::new();
        for (peer, client_id) in peers.iter_mut().zip(ids) {
            let (initiator, hello) = Initiator::start(&key);
            peer.on_message(&key, server_id, &hello).unwrap();
            let mut decoder = Decoder::default();
            let reply = decoder.push(&wire::pop_chunk(&mut peer.tx)).unwrap();
            // More than one 20-byte chunk required for the server hello.
            let reply = if reply.is_empty() {
                let mut reply = reply;
                while reply.is_empty() { reply = decoder.push(&wire::pop_chunk(&mut peer.tx)).unwrap(); }
                reply.remove(0)
            } else { reply.into_iter().next().unwrap() };
            let (session, finish) = initiator.finish(&key, &reply).unwrap();
            peer.on_message(&key, server_id, &finish).unwrap();
            let identity = Message::Identity(client_id).encode().unwrap();
            peer.on_message(&key, server_id, &session.seal(&identity).unwrap()).unwrap();
            clients.push(session);
        }
        assert_eq!(peers[0].remote_id(), Some(client1_id));
        assert_eq!(peers[1].remote_id(), Some(client2_id));

        let update = Update::new(server_id, "multicast".into()).unwrap();
        for peer in &mut peers { peer.offer(&update).unwrap(); }
        let mut first_peer_packet = None;
        for (index, (peer, session)) in peers.iter_mut().zip(clients.iter_mut()).enumerate() {
            let mut decoder = Decoder::default();
            let mut decoded = Vec::new();
            while !peer.tx.is_empty() {
                decoded.extend(decoder.push(&wire::pop_chunk(&mut peer.tx)).unwrap());
            }
            assert_eq!(decoded.len(), 2); // server identity + clipboard
            if index == 0 { first_peer_packet = Some(decoded[1].clone()); }
            assert_eq!(Message::decode(&session.open(&decoded[1]).unwrap()).unwrap(), Message::Clipboard(update.clone()));
        }
        // Each central has a different session key, even though the PSK is shared.
        assert!(clients[1].open(first_peer_packet.as_ref().unwrap()).is_err());
    }
}
