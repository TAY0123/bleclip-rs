//! Optional LE L2CAP bulk transfer. GATT negotiates a per-link capability; each
//! stream then performs a fresh, domain-separated PSK handshake and proves that
//! capability before any payload allocation. GATT remains available throughout.
#[cfg(any(target_os = "linux", test))]
use crate::transfer::Incoming;
use crate::{
    crypto::{Initiator, Psk, Session},
    message::{Message, Update},
    progress::{Direction, Transfers, Transport},
    transfer::Outgoing,
    wire::{self, MAX_FRAME},
};
use anyhow::{bail, ensure, Context, Result};
use rand::{rngs::OsRng, RngCore};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
#[cfg(target_os = "linux")]
use tokio::task::JoinSet;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
    time::timeout,
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const THRESHOLD: usize = 1024 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
const RETRY_COOLDOWN: Duration = Duration::from_secs(60);
const MAGIC: &[u8; 4] = b"BL2\x01";

// Address bytes use display/network order, independently of the OS sockaddr.
#[derive(Clone, PartialEq, Eq)]
pub struct Endpoint {
    address: [u8; 6],
    address_type: u8,
    psm: u16,
    token: [u8; 32],
}

pub fn encode_endpoint(endpoint: Option<&Endpoint>) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.push(u8::from(endpoint.is_some()));
    if let Some(endpoint) = endpoint {
        bytes.extend_from_slice(&endpoint.address);
        bytes.push(endpoint.address_type);
        bytes.extend_from_slice(&endpoint.psm.to_be_bytes());
        bytes.extend_from_slice(&endpoint.token);
    }
    bytes
}

pub fn decode_endpoint(bytes: &[u8]) -> Result<Option<Endpoint>> {
    ensure!(
        bytes.len() >= 5 && &bytes[..4] == MAGIC,
        "invalid bulk capability"
    );
    match bytes[4] {
        0 if bytes.len() == 5 => Ok(None),
        1 if bytes.len() == 46 => {
            let endpoint = Endpoint {
                address: bytes[5..11].try_into()?,
                address_type: bytes[11],
                psm: u16::from_be_bytes(bytes[12..14].try_into()?),
                token: bytes[14..46].try_into()?,
            };
            ensure!(
                endpoint.address != [0; 6]
                    && matches!(endpoint.address_type, 1 | 2)
                    && (0x80..=0xff).contains(&endpoint.psm)
                    && endpoint.token != [0; 32],
                "invalid LE L2CAP endpoint"
            );
            Ok(Some(endpoint))
        }
        _ => bail!("invalid bulk capability length/flags"),
    }
}

#[derive(Clone)]
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
struct Authorization {
    peer: Uuid,
    cancelled: watch::Receiver<()>,
    busy: Arc<AtomicBool>,
}

pub struct Bulk {
    own_id: Uuid,
    psk: Zeroizing<Psk>,
    local: Option<Endpoint>,
    available: AtomicBool,
    authorizations: Mutex<HashMap<[u8; 32], Authorization>>,
    transfers: Arc<Transfers>,
}

/// Own this beside the GATT tasks; dropping it aborts all accepted streams too.
pub struct ListenerGuard {
    task: JoinHandle<()>,
    bulk: Arc<Bulk>,
}
impl Drop for ListenerGuard {
    fn drop(&mut self) {
        self.bulk.available.store(false, Ordering::Release);
        self.task.abort();
    }
}

pub struct EndpointLease {
    endpoint: Endpoint,
    bulk: Arc<Bulk>,
    _lifetime: watch::Sender<()>,
}
impl EndpointLease {
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
}
impl Drop for EndpointLease {
    fn drop(&mut self) {
        self.bulk
            .authorizations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.endpoint.token);
    }
}

impl Bulk {
    pub async fn start(
        psk: Psk,
        own_id: Uuid,
        from_peers: mpsc::Sender<Update>,
        transfers: Arc<Transfers>,
        max_streams: usize,
        enabled: bool,
    ) -> (Arc<Self>, Option<ListenerGuard>) {
        #[cfg(target_os = "linux")]
        let listener = if !enabled {
            None
        } else {
            match timeout(Duration::from_secs(3), linux::listen()).await {
                Ok(Ok(listener)) => Some(listener),
                Ok(Err(error)) => {
                    eprintln!("BLE L2CAP unavailable: {error:#}; using GATT");
                    None
                }
                Err(_) => {
                    eprintln!("BLE L2CAP initialization timed out; using GATT");
                    None
                }
            }
        };
        #[cfg(target_os = "linux")]
        let local = listener.as_ref().map(|(_, endpoint)| endpoint.clone());
        #[cfg(not(target_os = "linux"))]
        let local = None;
        let bulk = Arc::new(Self {
            own_id,
            psk: Zeroizing::new(psk),
            available: AtomicBool::new(local.is_some()),
            local,
            authorizations: Mutex::new(HashMap::new()),
            transfers,
        });
        #[cfg(target_os = "linux")]
        if let Some((listener, _)) = listener {
            let context = bulk.clone();
            let task = tokio::spawn(async move {
                let mut workers = JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept(), if workers.len() < max_streams.min(4) => {
                            let (stream, _) = match accepted {
                                Ok(accepted) => accepted,
                                Err(error) => { eprintln!("L2CAP listener stopped: {error}"); break; }
                            };
                            let context = context.clone();
                            let sender = from_peers.clone();
                            workers.spawn(async move {
                                if let Err(error) = receive(stream, context, sender).await {
                                    eprintln!("L2CAP receive failed: {error:#}");
                                }
                            });
                        }
                        _ = workers.join_next(), if !workers.is_empty() => {}
                    }
                }
                context.available.store(false, Ordering::Release);
            });
            println!("BLE L2CAP bulk channel available for payloads over 1 MiB");
            return (bulk.clone(), Some(ListenerGuard { task, bulk }));
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (from_peers, max_streams, enabled);
        (bulk, None)
    }

    pub fn available(&self) -> bool {
        self.available.load(Ordering::Acquire)
    }

    pub fn authorize(self: &Arc<Self>, peer: Uuid) -> Option<EndpointLease> {
        if !self.available() {
            return None;
        }
        let mut endpoint = self.local.clone()?;
        OsRng.fill_bytes(&mut endpoint.token);
        let (lifetime, cancelled) = watch::channel(());
        self.authorizations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                endpoint.token,
                Authorization {
                    peer,
                    cancelled,
                    busy: Arc::new(AtomicBool::new(false)),
                },
            );
        Some(EndpointLease {
            endpoint,
            bulk: self.clone(),
            _lifetime: lifetime,
        })
    }
}

struct Attempt {
    update: Update,
    result: oneshot::Receiver<Result<()>>,
    task: JoinHandle<()>,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One bulk attempt per GATT link; retain the original update until its ACK.
pub struct BulkSender {
    bulk: Arc<Bulk>,
    remote: Uuid,
    endpoint: Option<Endpoint>,
    attempt: Option<Attempt>,
    retry_at: Option<Instant>,
}
impl BulkSender {
    pub fn new(bulk: Arc<Bulk>, remote: Uuid, endpoint: Option<Endpoint>) -> Self {
        Self {
            bulk,
            remote,
            endpoint,
            attempt: None,
            retry_at: None,
        }
    }

    /// True means the outbound data slot is occupied by L2CAP. GATT reads and
    /// receipt ACKs must continue, so bulk errors never take down the GATT link.
    pub fn step(&mut self, outgoing: &mut Outgoing) -> bool {
        if let Some(attempt) = &mut self.attempt {
            match attempt.result.try_recv() {
                Ok(result) => {
                    let attempt = self.attempt.take().unwrap();
                    if let Err(error) = result {
                        eprintln!(
                            "L2CAP to {} failed: {error:#}; retrying {} over BLE GATT",
                            self.remote, attempt.update.id
                        );
                        self.retry_at = Some(Instant::now() + RETRY_COOLDOWN);
                        outgoing.fallback(attempt.update.clone());
                        return false;
                    }
                }
                Err(oneshot::error::TryRecvError::Empty) => return true,
                Err(oneshot::error::TryRecvError::Closed) => {
                    let attempt = self.attempt.take().unwrap();
                    self.retry_at = Some(Instant::now() + RETRY_COOLDOWN);
                    outgoing.fallback(attempt.update.clone());
                    return false;
                }
            }
        }
        if !self.bulk.available() || self.retry_at.is_some_and(|at| Instant::now() < at) {
            return false;
        }
        let Some(endpoint) = self.endpoint.clone() else {
            return false;
        };
        let Some(update) = outgoing.take_bulk_candidate(THRESHOLD) else {
            return false;
        };
        let (tx, result) = oneshot::channel();
        let bulk = self.bulk.clone();
        let remote = self.remote;
        let payload = update.clone();
        let task = tokio::spawn(async move {
            let result = async {
                let stream = timeout(HANDSHAKE_TIMEOUT, connect(&endpoint))
                    .await
                    .context("L2CAP connection timed out")??;
                send(stream, &bulk, remote, &endpoint, payload).await
            }
            .await;
            let _ = tx.send(result);
        });
        self.attempt = Some(Attempt {
            update,
            result,
            task,
        });
        true
    }
}

pub(super) async fn write_frame<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> Result<()> {
    timeout(IDLE_TIMEOUT, stream.write_all(&wire::frame(bytes)?))
        .await
        .context("data channel write timed out")??;
    Ok(())
}
pub(super) async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    timeout(IDLE_TIMEOUT, async {
        let len = stream.read_u32().await? as usize;
        ensure!(
            (1..=MAX_FRAME).contains(&len),
            "invalid data channel frame size"
        );
        let mut bytes = vec![0; len];
        stream.read_exact(&mut bytes).await?;
        Ok(bytes)
    })
    .await
    .context("data channel read timed out")?
}
pub(super) async fn write_message<S: AsyncWrite + Unpin>(
    stream: &mut S,
    session: &Session,
    message: Message,
) -> Result<()> {
    write_frame(stream, &session.seal(&message.encode()?)?).await
}
pub(super) async fn read_message<S: AsyncRead + Unpin>(
    stream: &mut S,
    session: &mut Session,
) -> Result<Message> {
    Message::decode(&session.open(&read_frame(stream).await?)?)
}

async fn send<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    bulk: &Bulk,
    remote: Uuid,
    endpoint: &Endpoint,
    update: Update,
) -> Result<()> {
    let mut session = timeout(HANDSHAKE_TIMEOUT, async {
        let (initiator, hello) = Initiator::start_l2cap(&bulk.psk);
        write_frame(&mut stream, &hello).await?;
        let (mut session, finish) = initiator.finish(&bulk.psk, &read_frame(&mut stream).await?)?;
        write_frame(&mut stream, &finish).await?;
        let mut binding = MAGIC.to_vec();
        binding.extend_from_slice(bulk.own_id.as_bytes());
        binding.extend_from_slice(remote.as_bytes());
        binding.extend_from_slice(&endpoint.token);
        write_frame(&mut stream, &session.seal(&binding)?).await?;
        ensure!(
            read_message(&mut stream, &mut session).await? == Message::Identity(remote),
            "L2CAP peer identity does not match GATT peer"
        );
        Ok::<_, anyhow::Error>(session)
    })
    .await
    .context("L2CAP authentication timed out")??;
    let mut outgoing = Outgoing::default();
    outgoing.set_progress(
        bulk.transfers
            .reporter(remote, Direction::Sending)
            .with_transport(Transport::L2cap),
    );
    let id = update.id;
    outgoing.enqueue(update)?;
    while let Some(message) = outgoing.next(Instant::now()) {
        let end = matches!(message, Message::End(_));
        write_message(&mut stream, &session, message).await?;
        if end {
            ensure!(
                read_message(&mut stream, &mut session).await? == Message::Ack(id),
                "invalid L2CAP receipt"
            );
            outgoing.ack(id);
            return Ok(());
        }
    }
    bail!("L2CAP transfer ended without receipt")
}

#[cfg(any(target_os = "linux", test))]
struct Busy(Arc<AtomicBool>);
#[cfg(any(target_os = "linux", test))]
impl Drop for Busy {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(any(target_os = "linux", test))]
async fn receive<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    bulk: Arc<Bulk>,
    from_peers: mpsc::Sender<Update>,
) -> Result<()> {
    let (mut session, mut authorization, _busy) = timeout(HANDSHAKE_TIMEOUT, async {
        let (pending, reply) =
            crate::crypto::accept_l2cap(&bulk.psk, &read_frame(&mut stream).await?)?;
        write_frame(&mut stream, &reply).await?;
        let mut session = pending.finish(&bulk.psk, &read_frame(&mut stream).await?)?;
        let binding = session.open(&read_frame(&mut stream).await?)?;
        ensure!(
            binding.len() == 68 && &binding[..4] == MAGIC,
            "invalid L2CAP channel binding"
        );
        let peer = Uuid::from_slice(&binding[4..20])?;
        ensure!(
            Uuid::from_slice(&binding[20..36])? == bulk.own_id,
            "wrong L2CAP destination"
        );
        let token: [u8; 32] = binding[36..68].try_into()?;
        let authorization = bulk
            .authorizations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&token)
            .cloned()
            .context("L2CAP has no authenticated GATT authorization")?;
        ensure!(
            authorization.peer == peer && !peer.is_nil() && peer != bulk.own_id,
            "L2CAP identity does not match authorized GATT peer"
        );
        ensure!(
            !authorization.cancelled.has_changed().unwrap_or(true),
            "GATT authorization expired"
        );
        ensure!(
            authorization
                .busy
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "L2CAP channel already in use"
        );
        let busy = Busy(authorization.busy.clone());
        write_message(&mut stream, &session, Message::Identity(bulk.own_id)).await?;
        Ok::<_, anyhow::Error>((session, authorization, busy))
    })
    .await
    .context("L2CAP authentication timed out")??;
    let transfer = async {
        let mut incoming = Incoming::default();
        incoming.set_progress(
            bulk.transfers
                .reporter(authorization.peer, Direction::Receiving)
                .with_transport(Transport::L2cap),
        );
        let first = read_message(&mut stream, &mut session).await?;
        ensure!(
            matches!(first, Message::Start(_)),
            "L2CAP transfer missing start"
        );
        incoming.handle(first, Instant::now())?;
        loop {
            let message = read_message(&mut stream, &mut session).await?;
            ensure!(
                matches!(message, Message::Chunk { .. } | Message::End(_)),
                "unexpected L2CAP transfer message"
            );
            let received = incoming.handle(message, Instant::now())?;
            if let Some(update) = received.update {
                timeout(IDLE_TIMEOUT, from_peers.send(update))
                    .await
                    .context("clipboard router stalled")?
                    .context("clipboard router stopped")?;
            }
            if let Some(id) = received.ack {
                write_message(&mut stream, &session, Message::Ack(id)).await?;
                return Ok(());
            }
        }
    };
    tokio::select! {
        result = transfer => result,
        _ = authorization.cancelled.changed() => bail!("GATT authorization ended during L2CAP transfer"),
    }
}

#[cfg(target_os = "linux")]
async fn connect(endpoint: &Endpoint) -> Result<bluer::l2cap::Stream> {
    linux::connect(endpoint).await
}
#[cfg(not(target_os = "linux"))]
async fn connect(_: &Endpoint) -> Result<tokio::io::DuplexStream> {
    bail!("LE L2CAP sockets unavailable on this backend")
}

#[cfg(target_os = "linux")]
mod linux;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        clipboard::Direction as ClipboardDirection,
        message::{Header, Kind},
        router::Router,
    };
    use std::{
        io,
        pin::Pin,
        task::{Context as TaskContext, Poll},
    };
    use tokio::io::{DuplexStream, ReadBuf};

    fn context(id: Uuid, key: Psk) -> Arc<Bulk> {
        Arc::new(Bulk {
            own_id: id,
            psk: Zeroizing::new(key),
            local: Some(Endpoint {
                address: [1, 2, 3, 4, 5, 6],
                address_type: 1,
                psm: 0x80,
                token: [0; 32],
            }),
            available: AtomicBool::new(true),
            authorizations: Mutex::new(HashMap::new()),
            transfers: Transfers::new(),
        })
    }

    #[test]
    fn capability_is_bounded_and_only_accepts_le_dynamic_psms() {
        let bulk = context(Uuid::new_v4(), [1; 32]);
        let lease = bulk.authorize(Uuid::new_v4()).unwrap();
        let encoded = encode_endpoint(Some(lease.endpoint()));
        assert!(decode_endpoint(&encoded).unwrap().as_ref() == Some(lease.endpoint()));
        assert!(decode_endpoint(&encode_endpoint(None)).unwrap().is_none());
        for len in 0..encoded.len() {
            assert!(decode_endpoint(&encoded[..len]).is_err());
        }
        let mut invalid = encoded;
        invalid[12..14].copy_from_slice(&0x1001u16.to_be_bytes());
        assert!(decode_endpoint(&invalid).is_err());
    }

    #[tokio::test]
    async fn encrypted_stream_transfers_large_payload_and_acknowledges() {
        let a = context(Uuid::new_v4(), [9; 32]);
        let b = context(Uuid::new_v4(), [9; 32]);
        let lease = b.authorize(a.own_id).unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        let (client, server) = tokio::io::duplex(4096);
        let update = Update::new(a.own_id, Kind::Files, vec![42; THRESHOLD + 1]).unwrap();
        let (sent, received) = tokio::join!(
            send(client, &a, b.own_id, lease.endpoint(), update.clone()),
            receive(server, b.clone(), tx),
        );
        sent.unwrap();
        received.unwrap();
        assert_eq!(rx.recv().await, Some(update));
        for context in [&a, &b] {
            let views = context.transfers.subscribe().borrow().clone();
            assert_eq!(views.len(), 1);
            assert_eq!(views[0].transport, Transport::L2cap);
            assert_eq!(views[0].percent(), 100);
        }
    }

    #[tokio::test]
    async fn wrong_key_peer_or_revoked_gatt_lease_cannot_deliver() {
        for case in 0..4 {
            let a = context(Uuid::new_v4(), [9; 32]);
            let b = context(Uuid::new_v4(), if case == 0 { [8; 32] } else { [9; 32] });
            let lease = b
                .authorize(if case == 1 { Uuid::new_v4() } else { a.own_id })
                .unwrap();
            let mut endpoint = lease.endpoint().clone();
            if case == 2 {
                endpoint.token[0] ^= 1;
            }
            if case == 3 {
                drop(lease);
            }
            let (tx, mut rx) = mpsc::channel(1);
            let (client, server) = tokio::io::duplex(4096);
            let update = Update::text(a.own_id, "private".into()).unwrap();
            let (sent, received) = tokio::join!(
                send(client, &a, b.own_id, &endpoint, update),
                receive(server, b, tx),
            );
            assert!(sent.is_err());
            assert!(received.is_err());
            assert!(rx.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn cancelling_gatt_aborts_partial_bulk_transfer() {
        let a = context(Uuid::new_v4(), [9; 32]);
        let b = context(Uuid::new_v4(), [9; 32]);
        let lease = b.authorize(a.own_id).unwrap();
        let endpoint = lease.endpoint().clone();
        let (tx, mut rx) = mpsc::channel(1);
        let (client, server) = tokio::io::duplex(256);
        let update = Update::new(a.own_id, Kind::Files, vec![1; THRESHOLD + 1]).unwrap();
        let remote = b.own_id;
        let mut progress = b.transfers.subscribe();
        let receiver = tokio::spawn(receive(server, b.clone(), tx));
        let sender = tokio::spawn(async move { send(client, &a, remote, &endpoint, update).await });
        timeout(Duration::from_secs(3), progress.changed())
            .await
            .unwrap()
            .unwrap();
        drop(lease);
        assert!(receiver.await.unwrap().is_err());
        assert!(sender.await.unwrap().is_err());
        assert!(rx.try_recv().is_err());
    }

    // Receiver writes server hello, authenticated identity, then final ACK.
    struct DropAck(DuplexStream, usize);
    impl AsyncRead for DropAck {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for DropAck {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.1 == 2 {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "lost ACK")));
            }
            let result = Pin::new(&mut self.0).poll_write(cx, bytes);
            if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
                self.1 += 1;
            }
            result
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn lost_bulk_ack_falls_back_with_same_id_and_router_applies_once() {
        let a = context(Uuid::new_v4(), [9; 32]);
        let b = context(Uuid::new_v4(), [9; 32]);
        let lease = b.authorize(a.own_id).unwrap();
        let endpoint = lease.endpoint().clone();
        let update = Update::new(a.own_id, Kind::Files, vec![7; THRESHOLD + 1]).unwrap();
        let (client, server) = tokio::io::duplex(65536);
        let (tx, mut rx) = mpsc::channel(1);
        let (sent, received) = tokio::join!(
            send(client, &a, b.own_id, &endpoint, update.clone()),
            receive(DropAck(server, 0), b.clone(), tx),
        );
        assert!(sent.is_err());
        assert!(received.is_err());
        let delivered = rx.recv().await.unwrap();
        let mut router = Router::new(b.own_id, ClipboardDirection::Both);
        assert!(router.remote(delivered).is_some());
        let (tx, result) = oneshot::channel();
        tx.send(sent).unwrap();
        let mut bulk_sender = BulkSender::new(a.clone(), b.own_id, Some(endpoint));
        bulk_sender.attempt = Some(Attempt {
            update: update.clone(),
            result,
            task: tokio::spawn(async {}),
        });
        let mut outgoing = Outgoing::default();
        let newer = Update::text(a.own_id, "newer".into()).unwrap();
        outgoing.enqueue(newer.clone()).unwrap();
        assert!(!bulk_sender.step(&mut outgoing));
        let now = Instant::now();
        let mut incoming = Incoming::default();
        assert_eq!(
            outgoing.next(now),
            Some(Message::Start(Header::for_update(&update)))
        );
        incoming
            .handle(Message::Start(Header::for_update(&update)), now)
            .unwrap();
        while let Some(message) = outgoing.next(now) {
            let result = incoming.handle(message, now).unwrap();
            if let Some(item) = result.update {
                assert_eq!(item.id, update.id);
                assert!(router.remote(item).is_none());
            }
            if let Some(id) = result.ack {
                outgoing.ack(id);
                break;
            }
        }
        assert_eq!(
            outgoing.next(now),
            Some(Message::Start(Header::for_update(&newer)))
        );
    }

    #[test]
    fn older_or_unsupported_peers_use_gatt_and_small_updates_stay_on_gatt() {
        let a = context(Uuid::new_v4(), [9; 32]);
        let remote = Uuid::new_v4();
        let mut sender = BulkSender::new(a.clone(), remote, None);
        let mut outgoing = Outgoing::default();
        let update = Update::new(a.own_id, Kind::Files, vec![1; THRESHOLD + 1]).unwrap();
        outgoing.enqueue(update.clone()).unwrap();
        assert!(!sender.step(&mut outgoing));
        assert_eq!(
            outgoing.next(Instant::now()),
            Some(Message::Start(Header::for_update(&update)))
        );
        assert!(outgoing.take_bulk_candidate(0).is_none()); // never steal an active GATT transfer
        let lease = a.authorize(remote).unwrap();
        let mut sender = BulkSender::new(a.clone(), remote, Some(lease.endpoint().clone()));
        let mut outgoing = Outgoing::default();
        outgoing
            .enqueue(Update::text(a.own_id, "small".into()).unwrap())
            .unwrap();
        assert!(!sender.step(&mut outgoing));
        assert!(sender.attempt.is_none());
    }

    #[tokio::test]
    async fn oversized_stream_frame_rejected_before_allocation() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_u32((MAX_FRAME + 1) as u32).await.unwrap();
        assert!(read_frame(&mut server).await.is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires a powered Bluetooth adapter and LE L2CAP socket support"]
    async fn linux_l2cap_listener_smoke() {
        let (_listener, endpoint) = timeout(Duration::from_secs(5), linux::listen())
            .await
            .unwrap()
            .unwrap();
        assert!((0x80..=0xff).contains(&endpoint.psm));
    }
}
