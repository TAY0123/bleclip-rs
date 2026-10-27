//! BLE central half of peer mode. Scans continuously and maintains multiple
//! concurrent, independently encrypted outgoing GATT connections.

use super::{
    bulk::{self, Bulk, BulkSender, EndpointLease},
    BULK_ID, READ_ID, SERVICE_ID, WRITE_ID,
};
use crate::{
    crypto::{Initiator, Psk, Session},
    message::{Message, Update},
    status::{ConnectingGuard, Connections, LinkRole},
    transfer::{Incoming, Outgoing},
    wire::{self, Decoder},
};
use anyhow::{bail, ensure, Context, Result};
use btleplug::{
    api::{Central, Characteristic, Manager as _, Peripheral as _, ScanFilter, WriteType},
    platform::{Manager, Peripheral},
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{broadcast, mpsc, Mutex},
    task::JoinSet,
    time::{interval, sleep, timeout},
};
use uuid::Uuid;

const ATT_OPERATION_TIMEOUT: Duration = Duration::from_secs(12);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// Keep radio scanning active and inspect its cache promptly. Retry failures
/// less often so unreachable or untrusted devices do not monopolize links.
pub(crate) const DISCOVERY_INTERVAL: Duration = Duration::from_secs(2);
const RETRY_INTERVAL: Duration = Duration::from_secs(15);
const DISCOVERY_OPERATION_TIMEOUT: Duration = Duration::from_secs(3);

fn retry_ready(since_attempt: Duration) -> bool {
    since_attempt >= RETRY_INTERVAL
}

async fn send_packet(peer: &Peripheral, ch: &Characteristic, payload: &[u8]) -> Result<()> {
    let bytes = wire::frame(payload)?;
    for chunk in bytes.chunks(wire::ATT_CHUNK) {
        timeout(
            ATT_OPERATION_TIMEOUT,
            peer.write(ch, chunk, WriteType::WithResponse),
        )
        .await
        .context("GATT write timeout")??;
    }
    Ok(())
}

async fn next_frame(
    peer: &Peripheral,
    ch: &Characteristic,
    decoder: &mut Decoder,
    limit: Duration,
) -> Result<Vec<u8>> {
    let deadline = Instant::now() + limit;
    loop {
        ensure!(
            Instant::now() < deadline,
            "authentication handshake timed out"
        );
        let chunk = timeout(ATT_OPERATION_TIMEOUT, peer.read(ch))
            .await
            .context("BLE GATT read timed out")??;
        let mut decoded = decoder.push(&chunk)?;
        if !decoded.is_empty() {
            return Ok(decoded.remove(0));
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn run_authenticated(
    peer: &Peripheral,
    psk: &Psk,
    own_id: Uuid,
    from_peers: mpsc::Sender<Update>,
    to_peers: broadcast::Sender<Update>,
    active_nodes: Arc<Mutex<HashSet<Uuid>>>,
    connections: Arc<Connections>,
    connecting: ConnectingGuard,
    bulk: Arc<Bulk>,
) -> Result<()> {
    timeout(CONNECT_TIMEOUT, peer.discover_services())
        .await
        .context("BLE service discovery timeout")??;
    let chars = peer.characteristics();
    let write_char = chars
        .iter()
        .find(|ch| ch.uuid == WRITE_ID)
        .cloned()
        .context("no BLEClip WRITE characteristic")?;
    let read_char = chars
        .iter()
        .find(|ch| ch.uuid == READ_ID)
        .cloned()
        .context("no BLEClip READ characteristic")?;

    let (initiator, hello) = Initiator::start(psk);
    send_packet(peer, &write_char, &hello).await?;
    let mut decoder = Decoder::default();
    let response = next_frame(peer, &read_char, &mut decoder, Duration::from_secs(20)).await?;
    let (mut session, finish) = initiator
        .finish(psk, &response)
        .context("remote BLEClip authentication failed")?;
    send_packet(peer, &write_char, &finish).await?;
    let hello = Message::Identity(own_id).encode()?;
    send_packet(peer, &write_char, &session.seal(&hello)?).await?;
    let identity_reply =
        next_frame(peer, &read_char, &mut decoder, Duration::from_secs(20)).await?;
    let remote_id = match Message::decode(&session.open(&identity_reply)?)? {
        Message::Identity(id) => id,
        _ => bail!("peer did not send an authenticated node identity"),
    };
    ensure!(
        remote_id != own_id,
        "ignoring self-discovered BLE advertisement"
    );

    {
        let mut ids = active_nodes.lock().await;
        if !ids.insert(remote_id) {
            bail!("already have an outgoing connection to {remote_id}");
        }
    }
    let _link = connections.track(LinkRole::Outbound, peer.id().to_string(), remote_id);
    drop(connecting);
    println!("Outgoing encrypted BLE connection to {remote_id}");
    // Keep updates copied during optional negotiation in the bounded bus queue.
    let updates = to_peers.subscribe();
    let (bulk_sender, _bulk_lease) = if let Some(ch) = chars.iter().find(|ch| ch.uuid == BULK_ID) {
        match negotiate_bulk(peer, ch, &mut session, &bulk, remote_id).await {
            Ok(pair) => pair,
            Err(error) => {
                eprintln!("L2CAP negotiation with {remote_id} failed: {error:#}; using GATT");
                (None, None)
            }
        }
    } else {
        (None, None)
    };
    let result = connected_loop(
        peer,
        &write_char,
        &read_char,
        &mut decoder,
        &mut session,
        remote_id,
        from_peers,
        updates,
        Arc::clone(&connections.transfers),
        bulk_sender,
    )
    .await;
    active_nodes.lock().await.remove(&remote_id);
    result
}

async fn negotiate_bulk(
    peer: &Peripheral,
    ch: &Characteristic,
    session: &mut Session,
    bulk: &Arc<Bulk>,
    remote: Uuid,
) -> Result<(Option<BulkSender>, Option<EndpointLease>)> {
    let Some(lease) = bulk.authorize(remote) else {
        return Ok((None, None));
    };
    let endpoint = timeout(Duration::from_secs(8), async {
        let packet = session.seal(&bulk::encode_endpoint(Some(lease.endpoint())))?;
        send_packet(peer, ch, &packet).await?;
        let mut decoder = Decoder::default();
        let reply = next_frame(peer, ch, &mut decoder, Duration::from_secs(5)).await?;
        bulk::decode_endpoint(&session.open(&reply)?)
    })
    .await
    .context("bulk capability exchange timed out")??;
    Ok((
        Some(BulkSender::new(bulk.clone(), remote, endpoint)),
        Some(lease),
    ))
}

async fn connected_loop(
    peer: &Peripheral,
    write_char: &Characteristic,
    read_char: &Characteristic,
    decoder: &mut Decoder,
    session: &mut Session,
    remote_id: Uuid,
    from_peers: mpsc::Sender<Update>,
    mut updates: broadcast::Receiver<Update>,
    transfers: Arc<crate::progress::Transfers>,
    mut bulk_sender: Option<BulkSender>,
) -> Result<()> {
    let mut incoming = Incoming::default();
    let mut outgoing = Outgoing::default();
    incoming.set_progress(transfers.reporter(remote_id, crate::progress::Direction::Receiving));
    outgoing.set_progress(transfers.reporter(remote_id, crate::progress::Direction::Sending));
    let mut pending_ack = std::collections::VecDeque::<Uuid>::new();
    let mut poll = interval(Duration::from_millis(15));
    let mut transmit = interval(Duration::from_millis(15));
    let mut count: u32 = 0;
    loop {
        tokio::select! {
            _ = poll.tick() => {
                count = count.wrapping_add(1);
                if count % 500 == 0 && !peer.is_connected().await? { bail!("remote peer disconnected"); }
                let chunk = timeout(ATT_OPERATION_TIMEOUT, peer.read(read_char)).await
                    .context("GATT read timeout")??;
                for data in decoder.push(&chunk)? {
                    match Message::decode(&session.open(&data)?)? {
                        Message::Identity(id) if id == remote_id => {}
                        Message::Identity(_) => bail!("peer node identity changed"),
                        Message::Ack(id) => outgoing.ack(id),
                        message => {
                            let received = incoming.handle(message, Instant::now())?;
                            if let Some(update) = received.update {
                                from_peers.send(update).await.context("clipboard router stopped")?;
                            }
                            if let Some(id) = received.ack { pending_ack.push_back(id); }
                        }
                    }
                }
            }
            _ = transmit.tick() => {
                let message = if let Some(id) = pending_ack.pop_front() {
                    Some(Message::Ack(id))
                } else if bulk_sender.as_mut().is_some_and(|sender| sender.step(&mut outgoing)) {
                    None
                } else {
                    outgoing.next(Instant::now())
                };
                if let Some(message) = message {
                    let packet = message.encode()?;
                    send_packet(peer, write_char, &session.seal(&packet)?).await?;
                }
            }
            change = updates.recv() => {
                match change {
                    Ok(update) => {
                        if update.origin != remote_id {
                            if let Err(error) = outgoing.enqueue(update) {
                                eprintln!("Outgoing {remote_id}: {error:#}");
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        eprintln!("Outgoing {remote_id}: skipped {count} queued updates");
                    }
                    Err(broadcast::error::RecvError::Closed) => bail!("peer event bus closed"),
                }
            }
        }
    }
}

async fn connect_one(
    peer: Peripheral,
    psk: Psk,
    own_id: Uuid,
    from_peers: mpsc::Sender<Update>,
    to_peers: broadcast::Sender<Update>,
    active_nodes: Arc<Mutex<HashSet<Uuid>>>,
    connections: Arc<Connections>,
    bulk: Arc<Bulk>,
) -> Result<()> {
    let connecting = connections.track_connecting(peer.id().to_string());
    let connected = timeout(CONNECT_TIMEOUT, peer.is_connected())
        .await
        .context("BLE connection state timeout")??;
    if !connected {
        let result = timeout(CONNECT_TIMEOUT, peer.connect())
            .await
            .context("BLE connect timeout")
            .and_then(|result| result.map_err(Into::into));
        if let Err(error) = result {
            let _ = timeout(Duration::from_secs(5), peer.disconnect()).await;
            return Err(error);
        }
    }
    let result = run_authenticated(
        &peer,
        &psk,
        own_id,
        from_peers,
        to_peers,
        active_nodes,
        connections,
        connecting,
        bulk,
    )
    .await;
    let _ = timeout(Duration::from_secs(5), peer.disconnect()).await;
    result
}

pub async fn run(
    psk: Psk,
    name: String,
    own_id: Uuid,
    max_outbound: usize,
    from_peers: mpsc::Sender<Update>,
    to_peers: broadcast::Sender<Update>,
    connections: Arc<Connections>,
    bulk: Arc<Bulk>,
) -> Result<()> {
    let manager = Manager::new()
        .await
        .context("BLE central manager unavailable")?;
    let adapter = manager
        .adapters()
        .await?
        .into_iter()
        .next()
        .context("no BLE adapter available for scanning")?;
    adapter
        .start_scan(ScanFilter::default())
        .await
        .context("BLE discovery scan failed")?;
    println!("Scanning for nearby BLEClip peers (max outgoing links: {max_outbound})");

    let active_nodes = Arc::new(Mutex::new(HashSet::<Uuid>::new()));
    let mut active = HashSet::<String>::new();
    let mut retried = HashMap::<String, Instant>::new();
    let mut workers = JoinSet::<(String, Result<()>)>::new();
    let mut worker_ids = HashMap::new();
    let mut tick = interval(DISCOVERY_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if active.len() >= max_outbound { continue; }
                let devices = match timeout(DISCOVERY_OPERATION_TIMEOUT, adapter.peripherals()).await {
                    Ok(Ok(devices)) => devices,
                    Ok(Err(error)) => {
                        eprintln!("BLE scan enumeration failed: {error}");
                        continue;
                    }
                    Err(_) => {
                        eprintln!("BLE scan enumeration timed out");
                        continue;
                    }
                };
                for candidate in devices {
                    if active.len() >= max_outbound { break; }
                    let id = candidate.id().to_string();
                    if active.contains(&id) || retried.get(&id).is_some_and(|t| !retry_ready(t.elapsed())) {
                        continue;
                    }
                    let props = match timeout(DISCOVERY_OPERATION_TIMEOUT, candidate.properties()).await {
                        Ok(Ok(Some(properties))) => properties,
                        _ => continue,
                    };
                    let discovered_by_service = props.services.contains(&SERVICE_ID);
                    let discovered_by_name = props.local_name.as_deref() == Some(name.as_str());
                    // Linux may expose a name without service UUID; Windows can expose
                    // a service UUID without local name. Authentication is mandatory.
                    if !(discovered_by_service || discovered_by_name) { continue; }
                    active.insert(id.clone());
                    retried.insert(id.clone(), Instant::now());
                    let tx = from_peers.clone();
                    let broadcast = to_peers.clone();
                    let nodes = active_nodes.clone();
                    let tracker = Arc::clone(&connections);
                    let bulk = bulk.clone();
                    let candidate_id = id.clone();
                    let handle = workers.spawn(async move {
                        let result = connect_one(candidate, psk, own_id, tx, broadcast, nodes, tracker, bulk).await;
                        (id, result)
                    });
                    worker_ids.insert(handle.id(), candidate_id);
                }
                // Bound retry metadata if adapters report many unrelated devices.
                retried.retain(|id, stamp| active.contains(id) || stamp.elapsed() < Duration::from_secs(180));
            }
            finished = workers.join_next_with_id(), if !workers.is_empty() => {
                match finished {
                    Some(Ok((task_id, (id, result)))) => {
                        worker_ids.remove(&task_id);
                        active.remove(&id);
                        retried.insert(id.clone(), Instant::now());
                        // A disconnected link frees a connection slot: inspect
                        // available peers immediately, then use 15-second retries.
                        tick.reset_immediately();
                        if let Err(error) = result {
                            eprintln!("BLE peer {id} link ended: {error:#}");
                        }
                    }
                    Some(Err(error)) => {
                        if let Some(id) = worker_ids.remove(&error.id()) {
                            active.remove(&id);
                            retried.insert(id, Instant::now());
                        }
                        eprintln!("BLE connection task failed: {error}");
                        tick.reset_immediately();
                    },
                    None => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    #[test]
    fn discovery_is_fast_and_retries_are_rate_limited() {
        assert_eq!(DISCOVERY_INTERVAL, Duration::from_secs(2));
        assert_eq!(RETRY_INTERVAL, Duration::from_secs(15));
        assert!(!retry_ready(Duration::from_secs(14)));
        assert!(!retry_ready(Duration::from_millis(14999)));
        assert!(retry_ready(Duration::from_secs(15)));
        assert!(retry_ready(Duration::from_secs(30)));
    }
}
