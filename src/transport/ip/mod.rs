//! Authenticated TCP data exchange, advertised over BLE. TCP has no configured
//! byte-size cap. Files stream into a private staging directory; BLE fallback
//! retains its bounded protocol and uses the original event UUID.
pub mod settings;
mod wire;
use crate::{
    crypto::Psk,
    files::{self, FileMetadata},
    logging,
    message::{Kind, Update, MAX_HOPS},
    progress::Transfers,
    status::Connections,
};
use anyhow::{ensure, Context, Result};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{broadcast, mpsc, watch, Semaphore},
    task::{AbortHandle, JoinHandle, JoinSet},
    time::{sleep, timeout},
};
use uuid::Uuid;
use zeroize::Zeroizing;

const REQUEST_TTL: Duration = Duration::from_secs(10 * 60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAGIC: &[u8; 4] = b"BIP1";

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub address: SocketAddr,
    pub token: [u8; 32],
}
impl Endpoint {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.address.port() != 0
                && settings::valid_ip(self.address.ip())
                && self.token != [0; 32],
            "invalid IP receiving endpoint"
        );
        Ok(())
    }
}
pub fn encode_endpoint(endpoint: Option<&Endpoint>) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&endpoint)?)
}
pub fn decode_endpoint(bytes: &[u8]) -> Result<Option<Endpoint>> {
    ensure!(bytes.len() <= 512, "IP endpoint too large");
    let endpoint: Option<Endpoint> = serde_json::from_slice(bytes)?;
    if let Some(endpoint) = &endpoint {
        endpoint.validate()?;
    }
    Ok(endpoint)
}
pub fn encode_request(offer: Uuid, owner: Uuid, endpoint: Option<&Endpoint>) -> Result<Vec<u8>> {
    let mut bytes = offer.as_bytes().to_vec();
    bytes.extend_from_slice(owner.as_bytes());
    if let Some(endpoint) = endpoint {
        bytes.extend_from_slice(MAGIC);
        bytes.extend(encode_endpoint(Some(endpoint))?);
    }
    Ok(bytes)
}
pub fn decode_request(bytes: &[u8]) -> Result<(Uuid, Uuid, Option<Endpoint>)> {
    ensure!(
        (32..=512).contains(&bytes.len()),
        "invalid file request length"
    );
    let offer = Uuid::from_slice(&bytes[..16])?;
    let owner = Uuid::from_slice(&bytes[16..32])?;
    ensure!(
        !offer.is_nil() && !owner.is_nil(),
        "nil file offer/owner identifier"
    );
    let endpoint = if bytes.len() == 32 {
        None
    } else {
        ensure!(
            bytes.len() > 36 && &bytes[32..36] == MAGIC,
            "invalid IP request extension"
        );
        decode_endpoint(&bytes[36..])?
    };
    Ok((offer, owner, endpoint))
}

struct Ready {
    endpoint: Endpoint,
    settings: settings::Settings,
}
#[derive(Clone)]
struct Request {
    owner: Uuid,
    entries: Vec<FileMetadata>,
    token: [u8; 32],
    expires: Instant,
}
struct Received {
    request: Option<Uuid>,
    paths: Vec<PathBuf>,
}
#[derive(Default)]
struct State {
    ready: Option<Ready>,
    requests: HashMap<Uuid, Request>,
    peers: HashMap<Uuid, Option<Endpoint>>,
    offloaded: HashMap<(Uuid, Uuid), Instant>,
    order: VecDeque<(Uuid, Uuid)>,
    received: HashMap<Uuid, Received>,
}
pub struct IpService {
    own_id: Uuid,
    psk: Zeroizing<Psk>,
    pub control: Arc<settings::Control>,
    state: Mutex<State>,
    announced: watch::Sender<Option<Endpoint>>,
    from_peers: mpsc::Sender<Update>,
    to_peers: broadcast::Sender<Update>,
    pub(super) transfers: Arc<Transfers>,
    connections: Arc<Connections>,
    receive_dir: PathBuf,
    slots: Arc<Semaphore>,
    tasks: Mutex<Vec<AbortHandle>>,
    policy: (bool, bool, bool),
}
pub struct Runtime {
    service: Arc<IpService>,
    task: JoinHandle<()>,
}
impl Drop for Runtime {
    fn drop(&mut self) {
        self.task.abort();
        for handle in self
            .service
            .tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            handle.abort();
        }
        self.service.clear();
        self.service
            .control
            .set_status("IP listener: sharing stopped".into());
    }
}

#[derive(Clone)]
enum Job {
    Update(Update),
    Files {
        id: Uuid,
        request: Option<Uuid>,
        paths: Vec<PathBuf>,
        entries: Vec<FileMetadata>,
        versions: Vec<(u64, Option<std::time::SystemTime>)>,
    },
}
impl Job {
    fn id(&self) -> Uuid {
        match self {
            Self::Update(u) => u.id,
            Self::Files { id, .. } => *id,
        }
    }
    fn request(&self) -> Option<Uuid> {
        match self {
            Self::Files { request, .. } => *request,
            _ => None,
        }
    }
    async fn ble(&self, origin: Uuid) -> Result<Update> {
        if let Self::Update(update) = self {
            update.validate()?;
            return Ok(update.clone());
        }
        let Self::Files {
            id,
            request,
            paths,
            entries,
            versions,
        } = self
        else {
            unreachable!()
        };
        files::validate_metadata(entries)?;
        ensure!(files::versions(paths)? == *versions, "source files changed");
        let selected = paths.clone();
        let data = tokio::task::spawn_blocking(move || files::encode_paths(&selected)).await??;
        files::validate_offered_bundle(&data, entries)?;
        ensure!(
            files::versions(paths)? == *versions,
            "source files changed while reading"
        );
        let mut bytes = Vec::new();
        if let Some(request) = request {
            bytes.extend_from_slice(request.as_bytes());
        }
        bytes.extend(data);
        let mut update = Update::new(
            origin,
            if request.is_some() {
                Kind::FileResponse
            } else {
                Kind::Files
            },
            bytes,
        )?;
        update.id = *id;
        Ok(update)
    }
}

impl IpService {
    pub fn start(
        psk: Psk,
        own_id: Uuid,
        from_peers: mpsc::Sender<Update>,
        to_peers: broadcast::Sender<Update>,
        connections: Arc<Connections>,
        receive_dir: PathBuf,
        control: Arc<settings::Control>,
        policy: (bool, bool, bool),
    ) -> (Arc<Self>, Runtime) {
        let (announced, _) = watch::channel(None);
        let service = Arc::new(Self {
            own_id,
            psk: Zeroizing::new(psk),
            control,
            state: Mutex::new(State::default()),
            announced,
            from_peers,
            to_peers,
            transfers: connections.transfers.clone(),
            connections,
            receive_dir,
            slots: Arc::new(Semaphore::new(4)),
            tasks: Mutex::new(Vec::new()),
            policy,
        });
        let context = service.clone();
        let task = tokio::spawn(async move {
            context.listen().await;
        });
        (service.clone(), Runtime { service, task })
    }
    fn clear(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.ready = None;
        state.requests.clear();
        self.announced.send_replace(None);
    }
    pub fn enabled(&self) -> bool {
        self.control.snapshot().enabled
    }
    fn allow(&self, kind: Kind) -> Result<()> {
        ensure!(self.policy.0, "receiving disabled");
        ensure!(
            kind != Kind::Png || self.policy.1,
            "image receiving disabled"
        );
        ensure!(
            !matches!(kind, Kind::Files | Kind::FileResponse) || self.policy.2,
            "file receiving disabled"
        );
        Ok(())
    }
    pub fn subscribe(&self) -> watch::Receiver<Option<Endpoint>> {
        self.announced.subscribe()
    }
    pub fn announcement(&self) -> Result<Update> {
        Update::new(
            self.own_id,
            Kind::IpEndpoint,
            encode_endpoint(self.announced.borrow().as_ref())?,
        )
    }
    pub fn register(&self, peer: Uuid, endpoint: Option<Endpoint>) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.peers.get(&peer) != Some(&endpoint) {
            if let Some(endpoint) = &endpoint {
                logging::event(&format!(
                    "Peer {peer} receives IP data at {}",
                    endpoint.address
                ));
            }
            state.peers.insert(peer, endpoint);
        }
    }
    pub fn supports(&self, peer: Uuid) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .peers
            .contains_key(&peer)
    }
    pub fn peer(&self, peer: Uuid) -> Option<Endpoint> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .peers
            .get(&peer)
            .cloned()
            .flatten()
    }
    pub fn offloaded(&self, peer: Uuid, id: Uuid) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .offloaded
            .contains_key(&(peer, id))
    }
    pub fn has_ble_recipients(&self) -> bool {
        self.connections
            .subscribe()
            .borrow()
            .peers
            .iter()
            .any(|p| self.peer(p.id).is_none())
    }
    pub fn prepare(&self, id: Uuid, owner: Uuid, entries: Vec<FileMetadata>) -> Option<Endpoint> {
        let settings = self.control.snapshot();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let ready = state.ready.as_ref()?;
        if !settings.enabled || settings != ready.settings {
            return None;
        }
        let mut endpoint = ready.endpoint.clone();
        OsRng.fill_bytes(&mut endpoint.token);
        state.requests.retain(|_, r| Instant::now() < r.expires);
        if state.requests.len() >= 4 {
            return None;
        }
        state.requests.insert(
            id,
            Request {
                owner,
                entries,
                token: endpoint.token,
                expires: Instant::now() + REQUEST_TTL,
            },
        );
        Some(endpoint)
    }
    pub fn revoke(&self, request: Uuid) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .requests
            .remove(&request);
    }
    pub fn take_files(&self, id: Uuid, request: Option<Uuid>) -> Option<Vec<PathBuf>> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.received.get(&id)?.request != request {
            return None;
        }
        state.received.remove(&id).map(|r| r.paths)
    }
    pub fn route(self: &Arc<Self>, update: &Update) {
        if !matches!(
            update.kind,
            Kind::Text | Kind::Png | Kind::Files | Kind::CompressedText
        ) || !self.enabled()
        {
            return;
        }
        let peers: Vec<_> = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .peers
            .iter()
            .filter_map(|(peer, ep)| ep.clone().map(|ep| (*peer, ep)))
            .collect();
        for (peer, endpoint) in peers {
            if peer != update.origin {
                self.spawn(peer, endpoint, Job::Update(update.clone()));
            }
        }
    }
    pub fn send_files(
        self: &Arc<Self>,
        id: Uuid,
        request: Option<Uuid>,
        peer: Uuid,
        endpoint: Endpoint,
        paths: Vec<PathBuf>,
        entries: Vec<FileMetadata>,
    ) -> Result<bool> {
        let versions = files::versions(&paths)?;
        Ok(self.spawn(
            peer,
            endpoint,
            Job::Files {
                id,
                request,
                paths,
                entries,
                versions,
            },
        ))
    }
    pub fn broadcast_files(
        self: &Arc<Self>,
        id: Uuid,
        paths: Vec<PathBuf>,
        entries: Vec<FileMetadata>,
    ) -> Result<usize> {
        let peers: Vec<_> = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .peers
            .iter()
            .filter_map(|(peer, ep)| ep.clone().map(|ep| (*peer, ep)))
            .collect();
        let mut sent = 0;
        for (peer, endpoint) in peers {
            sent += usize::from(self.send_files(
                id,
                None,
                peer,
                endpoint,
                paths.clone(),
                entries.clone(),
            )?);
        }
        Ok(sent)
    }
    fn spawn(self: &Arc<Self>, peer: Uuid, endpoint: Endpoint, job: Job) -> bool {
        if !self.enabled() {
            return false;
        }
        if self.offloaded(peer, job.id()) {
            return true;
        }
        let Ok(permit) = self.slots.clone().try_acquire_owned() else {
            return false;
        };
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let key = (peer, job.id());
            if state.offloaded.contains_key(&key) {
                return true;
            }
            state.offloaded.insert(key, Instant::now());
            state.order.push_back(key);
            while state.order.len() > 4096 {
                if let Some(old) = state.order.pop_front() {
                    state.offloaded.remove(&old);
                }
            }
        }
        let service = self.clone();
        let mut changes = service.control.subscribe();
        changes.borrow_and_update();
        let task = tokio::spawn(async move {
            let _permit = permit;
            logging::event(&format!(
                "IP sending {} to {peer} at {}",
                job.id(),
                endpoint.address
            ));
            let result = tokio::select! {
                result = async {
                    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(endpoint.address)).await.context("IP connection timed out")??;
                    stream.set_nodelay(true)?;
                    wire::send(stream, &service, peer, &endpoint, &job).await
                } => result,
                _ = changes.changed() => Err(anyhow::anyhow!("IP settings changed")),
            };
            if let Err(error) = result {
                service
                    .state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .offloaded
                    .remove(&(peer, job.id()));
                logging::event(&format!(
                    "IP transfer {} failed: {error:#}; trying BLE fallback",
                    job.id()
                ));
                match job.ble(service.own_id).await {
                    Ok(update) => {
                        let _ = service.to_peers.send(update);
                    }
                    Err(error) => {
                        let message = format!("IP failed and BLE cannot send this item: {error:#}");
                        logging::event(&message);
                        if let Some(request) = job.request() {
                            let mut bytes = request.as_bytes().to_vec();
                            bytes.extend(message.as_bytes());
                            if let Ok(update) = Update::new(service.own_id, Kind::FileError, bytes)
                            {
                                let _ = service.to_peers.send(update);
                            }
                        } else {
                            crate::desktop::notify("Transfer failed", &message);
                        }
                    }
                }
            }
        });
        let mut tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        tasks.retain(|t| !t.is_finished());
        tasks.push(task.abort_handle());
        true
    }
    async fn listen(self: Arc<Self>) {
        let mut settings = self.control.subscribe();
        loop {
            let config = settings.borrow_and_update().clone();
            self.clear();
            if !config.enabled {
                self.control.set_status("IP listener: disabled".into());
                if settings.changed().await.is_err() {
                    return;
                }
                continue;
            }
            let bound = async {
                let (bind, advertised) = config.addresses()?;
                let listener = TcpListener::bind(bind).await?;
                let address = SocketAddr::new(advertised, listener.local_addr()?.port());
                Ok::<_, anyhow::Error>((listener, address))
            }
            .await;
            let (listener, address) = match bound {
                Ok(bound) => bound,
                Err(error) => {
                    let status = format!("IP listener unavailable: {error:#}; using BLE");
                    self.control.set_status(status.clone());
                    logging::event(&status);
                    tokio::select! { _ = settings.changed() => {}, _ = sleep(Duration::from_secs(5)) => {} }
                    continue;
                }
            };
            let mut token = [0; 32];
            OsRng.fill_bytes(&mut token);
            let endpoint = Endpoint { address, token };
            self.state.lock().unwrap_or_else(|e| e.into_inner()).ready = Some(Ready {
                endpoint: endpoint.clone(),
                settings: config,
            });
            self.announced.send_replace(Some(endpoint));
            let status = format!("IP listening on {address}");
            self.control.set_status(status.clone());
            logging::event(&status);
            let mut workers = JoinSet::new();
            loop {
                tokio::select! {
                    _ = settings.changed() => break,
                    accepted = listener.accept(), if workers.len() < 4 => {
                        match accepted {
                            Ok((stream,_)) => { let context = self.clone(); workers.spawn(async move {
                                if let Err(error) = wire::receive(stream, context).await { logging::event(&format!("IP receive failed: {error:#}")); }
                            }); }
                            Err(error) => { logging::event(&format!("IP listener failed: {error}")); break; }
                        }
                    }
                    _ = workers.join_next(), if !workers.is_empty() => {},
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{MAX_FILES, MAX_TEXT};
    use std::{
        fs,
        net::{IpAddr, Ipv4Addr},
    };

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("bleclip-ip-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn config() -> settings::Settings {
        settings::Settings {
            enabled: true,
            receive_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: 0,
        }
    }
    fn start(
        root: &Temp,
        key: Psk,
        policy: (bool, bool, bool),
    ) -> (
        Arc<IpService>,
        Runtime,
        mpsc::Receiver<Update>,
        broadcast::Receiver<Update>,
    ) {
        let (tx, rx) = mpsc::channel(16);
        let (bus, fallback) = broadcast::channel(16);
        let (service, runtime) = IpService::start(
            key,
            Uuid::new_v4(),
            tx,
            bus,
            Connections::new(),
            root.0.join(Uuid::new_v4().to_string()),
            settings::Control::memory(config()),
            policy,
        );
        (service, runtime, rx, fallback)
    }
    async fn endpoint(service: &IpService) -> Endpoint {
        let mut updates = service.subscribe();
        timeout(Duration::from_secs(3), async {
            loop {
                if let Some(endpoint) = updates.borrow_and_update().clone() {
                    return endpoint;
                }
                updates.changed().await.unwrap();
            }
        })
        .await
        .unwrap()
    }
    async fn direct(a: &IpService, b: &IpService, endpoint: &Endpoint, job: &Job) -> Result<()> {
        let stream = TcpStream::connect(endpoint.address).await?;
        wire::send(stream, a, b.own_id, endpoint, job).await
    }

    #[test]
    fn settings_persist_and_invalid_updates_leave_previous_config() {
        let root = Temp::new();
        let path = root.0.join("settings.json");
        let control = settings::Control::load(path.clone());
        assert!(!control.snapshot().enabled);
        control.update(|s| *s = config()).unwrap();
        control.update(|s| s.port = 12345).unwrap();
        assert_eq!(settings::Control::load(path).snapshot(), control.snapshot());
        let previous = control.snapshot();
        assert!(control
            .update(|s| s.receive_ip = Some(Ipv4Addr::UNSPECIFIED.into()))
            .is_err());
        assert_eq!(control.snapshot(), previous);
    }
    #[test]
    fn endpoint_extensions_preserve_legacy_request_format() {
        let offer = Uuid::new_v4();
        let owner = Uuid::new_v4();
        let legacy = encode_request(offer, owner, None).unwrap();
        assert_eq!(legacy.len(), 32);
        assert!(decode_request(&legacy).unwrap().2.is_none());
        let endpoint = Endpoint {
            address: "127.0.0.1:12345".parse().unwrap(),
            token: [7; 32],
        };
        let extended = encode_request(offer, owner, Some(&endpoint)).unwrap();
        assert_eq!(
            decode_request(&extended).unwrap().2.unwrap().address,
            endpoint.address
        );
        assert!(decode_request(&extended[..35]).is_err());
        let mut invalid = endpoint;
        invalid.token = [0; 32];
        assert!(decode_endpoint(&encode_endpoint(Some(&invalid)).unwrap()).is_err());
    }
    #[tokio::test]
    async fn encrypted_ip_text_exceeds_ble_limit_and_can_transfer_images() {
        let root = Temp::new();
        let (a, _ar, _ax, _af) = start(&root, [11; 32], (true, true, true));
        let (b, _br, mut received, _bf) = start(&root, [11; 32], (true, true, true));
        let ep = endpoint(&b).await;
        let text = Update::new_ip(a.own_id, Kind::Text, vec![b'a'; MAX_TEXT + 1]).unwrap();
        assert!(text.validate().is_err());
        direct(&a, &b, &ep, &Job::Update(text.clone()))
            .await
            .unwrap();
        let actual = received.recv().await.unwrap();
        assert_eq!(actual, text);
        let png =
            Update::new_ip(a.own_id, Kind::Png, vec![5; crate::message::MAX_PNG + 1]).unwrap();
        direct(&a, &b, &ep, &Job::Update(png.clone()))
            .await
            .unwrap();
        assert_eq!(received.recv().await.unwrap(), png);
    }
    #[tokio::test]
    async fn files_stream_beyond_ble_cap_and_paste_checks_metadata() {
        let root = Temp::new();
        let (a, _ar, _ax, _af) = start(&root, [12; 32], (true, true, true));
        let (b, _br, mut received, _bf) = start(&root, [12; 32], (true, true, true));
        endpoint(&b).await;
        let source = root.0.join("large.bin");
        fs::File::create(&source)
            .unwrap()
            .set_len((MAX_FILES + 1) as u64)
            .unwrap();
        let paths = vec![source];
        let entries = files::metadata_ip(&paths).unwrap();
        assert!(files::validate_metadata(&entries).is_err());
        let request = Uuid::new_v4();
        let ep = b.prepare(request, a.own_id, entries.clone()).unwrap();
        let id = Uuid::new_v4();
        let job = Job::Files {
            id,
            request: Some(request),
            versions: files::versions(&paths).unwrap(),
            paths,
            entries,
        };
        direct(&a, &b, &ep, &job).await.unwrap();
        let actual = received.recv().await.unwrap();
        assert_eq!(actual.kind, Kind::FileResponse);
        assert!(actual.via_ip);
        let saved = b.take_files(id, Some(request)).unwrap();
        assert_eq!(
            fs::metadata(&saved[0]).unwrap().len(),
            (MAX_FILES + 1) as u64
        );
        assert!(b.take_files(id, Some(request)).is_none());
        b.revoke(request);
        assert!(direct(&a, &b, &ep, &job).await.is_err());
    }
    #[tokio::test]
    async fn wrong_key_token_identity_and_disabled_content_cannot_deliver() {
        let root = Temp::new();
        let (a, _ar, _ax, _af) = start(&root, [13; 32], (true, true, true));
        let (bad, _bad_r, _bad_x, _bad_f) = start(&root, [99; 32], (true, true, true));
        let (b, _br, mut received, _bf) = start(&root, [13; 32], (true, false, false));
        let ep = endpoint(&b).await;
        let job = Job::Update(Update::text(a.own_id, "hello".into()).unwrap());
        assert!(direct(&bad, &b, &ep, &job).await.is_err());
        let mut wrong = ep.clone();
        wrong.token = [2; 32];
        assert!(direct(&a, &b, &wrong, &job).await.is_err());
        let stream = TcpStream::connect(ep.address).await.unwrap();
        assert!(wire::send(stream, &a, Uuid::new_v4(), &ep, &job)
            .await
            .is_err());
        let image = Job::Update(Update::new(a.own_id, Kind::Png, vec![1; 10]).unwrap());
        assert!(direct(&a, &b, &ep, &image).await.is_err());
        assert!(received.try_recv().is_err());
        direct(&a, &b, &ep, &job).await.unwrap();
        assert!(received.recv().await.is_some());
    }
    #[tokio::test]
    async fn failed_ip_send_retries_ble_with_same_id() {
        let root = Temp::new();
        let (a, _ar, _ax, mut fallback) = start(&root, [14; 32], (true, true, true));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let peer = Uuid::new_v4();
        let update = Update::text(a.own_id, "fallback".into()).unwrap();
        assert!(a.spawn(
            peer,
            Endpoint {
                address,
                token: [1; 32]
            },
            Job::Update(update.clone())
        ));
        assert_eq!(
            timeout(Duration::from_secs(3), fallback.recv())
                .await
                .unwrap()
                .unwrap(),
            update
        );
        assert!(!a.offloaded(peer, update.id));
    }
    #[tokio::test]
    async fn listener_rebinds_and_disable_revokes_pending_pastes() {
        let root = Temp::new();
        let (b, _br, _bx, _bf) = start(&root, [15; 32], (true, true, true));
        let first = endpoint(&b).await;
        let request = Uuid::new_v4();
        b.prepare(
            request,
            Uuid::new_v4(),
            vec![FileMetadata {
                name: "a".into(),
                size: 1,
            }],
        )
        .unwrap();
        let mut changes = b.subscribe();
        changes.borrow_and_update();
        b.control.update(|s| s.enabled = false).unwrap();
        timeout(Duration::from_secs(3), async {
            loop {
                changes.changed().await.unwrap();
                if changes.borrow_and_update().is_none() {
                    break;
                }
            }
        })
        .await
        .unwrap();
        assert!(b.state.lock().unwrap().requests.is_empty());
        assert!(TcpStream::connect(first.address).await.is_err());
        b.control.update(|s| s.enabled = true).unwrap();
        let second = endpoint(&b).await;
        assert!(first.token != second.token);
    }
    #[tokio::test]
    async fn paste_token_cannot_deliver_different_content_or_unoffered_files() {
        let root = Temp::new();
        let (a, _ar, _ax, _af) = start(&root, [16; 32], (true, true, true));
        let (b, _br, mut received, _bf) = start(&root, [16; 32], (true, true, true));
        endpoint(&b).await;
        let request = Uuid::new_v4();
        let ep = b
            .prepare(
                request,
                a.own_id,
                vec![FileMetadata {
                    name: "expected".into(),
                    size: 1,
                }],
            )
            .unwrap();
        assert!(direct(
            &a,
            &b,
            &ep,
            &Job::Update(Update::text(a.own_id, "not a file".into()).unwrap())
        )
        .await
        .is_err());
        let source = root.0.join("different");
        fs::write(&source, b"x").unwrap();
        let paths = vec![source];
        let job = Job::Files {
            id: Uuid::new_v4(),
            request: Some(request),
            entries: files::metadata_ip(&paths).unwrap(),
            versions: files::versions(&paths).unwrap(),
            paths,
        };
        assert!(direct(&a, &b, &ep, &job).await.is_err());
        assert!(received.try_recv().is_err());
        assert!(!b.receive_dir.exists());
    }
}
