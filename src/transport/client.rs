//! BLE central half of peer mode. Scans continuously and maintains multiple
//! concurrent, independently encrypted outgoing GATT connections.

use super::{READ_ID, SERVICE_ID, WRITE_ID};
use crate::{
    crypto::{Initiator, Psk, Session},
    message::{Message, Update},
    wire::{self, Decoder},
};
use anyhow::{bail, ensure, Context, Result};
use btleplug::{
    api::{Central, Characteristic, Manager as _, Peripheral as _, ScanFilter, WriteType},
    platform::{Manager, Peripheral},
};
use std::{collections::{HashMap, HashSet}, sync::Arc, time::{Duration, Instant}};
use tokio::{sync::{broadcast, mpsc, Mutex}, task::JoinSet, time::{interval, sleep, timeout}};
use uuid::Uuid;

const ATT_OPERATION_TIMEOUT: Duration = Duration::from_secs(12);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

async fn send_packet(peer: &Peripheral, ch: &Characteristic, payload: &[u8]) -> Result<()> {
    let bytes = wire::frame(payload)?;
    for chunk in bytes.chunks(wire::ATT_CHUNK) {
        timeout(ATT_OPERATION_TIMEOUT, peer.write(ch, chunk, WriteType::WithResponse))
            .await.context("GATT write timeout")??;
    }
    Ok(())
}

async fn next_frame(peer: &Peripheral, ch: &Characteristic, decoder: &mut Decoder, limit: Duration) -> Result<Vec<u8>> {
    let deadline = Instant::now() + limit;
    loop {
        ensure!(Instant::now() < deadline, "authentication handshake timed out");
        let chunk = timeout(ATT_OPERATION_TIMEOUT, peer.read(ch)).await
            .context("BLE GATT read timed out")??;
        let mut decoded = decoder.push(&chunk)?;
        if !decoded.is_empty() { return Ok(decoded.remove(0)); }
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
) -> Result<()> {
    timeout(CONNECT_TIMEOUT, peer.discover_services()).await
        .context("BLE service discovery timeout")??;
    let chars = peer.characteristics();
    let write_char = chars.iter().find(|ch| ch.uuid == WRITE_ID).cloned()
        .context("no BLEClip WRITE characteristic")?;
    let read_char = chars.iter().find(|ch| ch.uuid == READ_ID).cloned()
        .context("no BLEClip READ characteristic")?;

    let (initiator, hello) = Initiator::start(psk);
    send_packet(peer, &write_char, &hello).await?;
    let mut decoder = Decoder::default();
    let response = next_frame(peer, &read_char, &mut decoder, Duration::from_secs(20)).await?;
    let (mut session, finish) = initiator.finish(psk, &response)
        .context("remote BLEClip authentication failed")?;
    send_packet(peer, &write_char, &finish).await?;
    let hello = Message::Identity(own_id).encode()?;
    send_packet(peer, &write_char, &session.seal(&hello)?).await?;
    let identity_reply = next_frame(peer, &read_char, &mut decoder, Duration::from_secs(20)).await?;
    let remote_id = match Message::decode(&session.open(&identity_reply)?)? {
        Message::Identity(id) => id,
        _ => bail!("peer did not send an authenticated node identity"),
    };
    ensure!(remote_id != own_id, "ignoring self-discovered BLE advertisement");

    {
        let mut ids = active_nodes.lock().await;
        if !ids.insert(remote_id) { bail!("already have an outgoing connection to {remote_id}"); }
    }
    println!("Outgoing encrypted BLE connection to {remote_id}");
    let result = connected_loop(peer, &write_char, &read_char, &mut decoder, &mut session,
        remote_id, from_peers, to_peers).await;
    active_nodes.lock().await.remove(&remote_id);
    result
}

async fn connected_loop(
    peer: &Peripheral,
    write_char: &Characteristic,
    read_char: &Characteristic,
    decoder: &mut Decoder,
    session: &mut Session,
    remote_id: Uuid,
    from_peers: mpsc::Sender<Update>,
    to_peers: broadcast::Sender<Update>,
) -> Result<()> {
    let mut updates = to_peers.subscribe();
    let mut poll = interval(Duration::from_millis(180));
    let mut count: u32 = 0;
    loop {
        tokio::select! {
            _ = poll.tick() => {
                count = count.wrapping_add(1);
                if count % 60 == 0 && !peer.is_connected().await? {
                    bail!("remote peer disconnected");
                }
                let chunk = timeout(ATT_OPERATION_TIMEOUT, peer.read(read_char)).await
                    .context("GATT read timeout")??;
                for data in decoder.push(&chunk)? {
                    match Message::decode(&session.open(&data)?)? {
                        Message::Clipboard(update) => {
                            from_peers.send(update).await.context("clipboard router stopped")?;
                        }
                        Message::Identity(id) if id == remote_id => {}
                        Message::Identity(_) => bail!("peer node identity changed"),
                    }
                }
            }
            change = updates.recv() => {
                match change {
                    Ok(update) => {
                        if update.origin != remote_id {
                            let packet = Message::Clipboard(update).encode()?;
                            send_packet(peer, write_char, &session.seal(&packet)?).await?;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        eprintln!("Outgoing {remote_id}: skipped {count} queued clipboard updates");
                    }
                    Err(broadcast::error::RecvError::Closed) => bail!("clipboard bus closed"),
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
) -> Result<()> {
    if !peer.is_connected().await? {
        timeout(CONNECT_TIMEOUT, peer.connect()).await.context("BLE connect timeout")??;
    }
    let result = run_authenticated(&peer, &psk, own_id, from_peers, to_peers, active_nodes).await;
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
) -> Result<()> {
    let manager = Manager::new().await.context("BLE central manager unavailable")?;
    let adapter = manager.adapters().await?.into_iter().next()
        .context("no BLE adapter available for scanning")?;
    adapter.start_scan(ScanFilter::default()).await.context("BLE discovery scan failed")?;
    println!("Scanning for nearby BLEClip peers (max outgoing links: {max_outbound})");

    let active_nodes = Arc::new(Mutex::new(HashSet::<Uuid>::new()));
    let mut active = HashSet::<String>::new();
    let mut retried = HashMap::<String, Instant>::new();
    let mut workers = JoinSet::<(String, Result<()>)>::new();
    let mut tick = interval(Duration::from_secs(3));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if active.len() >= max_outbound { continue; }
                let devices = match adapter.peripherals().await {
                    Ok(devices) => devices,
                    Err(error) => {
                        eprintln!("BLE scan enumeration failed: {error}");
                        continue;
                    }
                };
                for candidate in devices {
                    if active.len() >= max_outbound { break; }
                    let id = candidate.id().to_string();
                    if active.contains(&id) || retried.get(&id).is_some_and(|t| t.elapsed() < Duration::from_secs(30)) {
                        continue;
                    }
                    let props = match candidate.properties().await {
                        Ok(Some(properties)) => properties,
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
                    workers.spawn(async move {
                        let result = connect_one(candidate, psk, own_id, tx, broadcast, nodes).await;
                        (id, result)
                    });
                }
                // Bound retry metadata if adapters report many unrelated devices.
                retried.retain(|id, stamp| active.contains(id) || stamp.elapsed() < Duration::from_secs(180));
            }
            finished = workers.join_next(), if !workers.is_empty() => {
                match finished {
                    Some(Ok((id, result))) => {
                        active.remove(&id);
                        retried.insert(id.clone(), Instant::now());
                        if let Err(error) = result {
                            eprintln!("BLE peer {id} link ended: {error:#}");
                        }
                    }
                    Some(Err(error)) => eprintln!("BLE connection task failed: {error}"),
                    None => {}
                }
            }
        }
    }
}
