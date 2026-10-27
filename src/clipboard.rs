//! Desktop clipboard synchronization for text, lossless PNG images and file lists.
//! Copied files are offered as metadata; native clipboard rendering fetches on demand.
use crate::file_clipboard::LazyFiles;
use crate::{
    files,
    message::{Kind, Update, MAX_PNG, MAX_TEXT},
};
use anyhow::{bail, Context, Result};
use arboard::{Clipboard, ImageData};
use clap::ValueEnum;
use image::{
    codecs::png::PngEncoder, ExtendedColorType, ImageEncoder, ImageFormat, ImageReader, Limits,
};
use sha2::{Digest, Sha256};
use std::{
    borrow::Cow,
    collections::{HashMap, VecDeque},
    io::Cursor,
    path::{Path, PathBuf},
    time::{Duration, Instant, UNIX_EPOCH},
};

type PasteReply = std::sync::mpsc::SyncSender<Result<Vec<PathBuf>, String>>;
struct PasteRequest {
    offer: Uuid,
    origin: Uuid,
    entries: Vec<files::FileMetadata>,
    reply: PasteReply,
}
struct PendingPaste {
    request: PasteRequest,
    started: Instant,
}
struct LocalOffer {
    id: Uuid,
    paths: Vec<PathBuf>,
    signature: [u8; 32],
    entries: Vec<files::FileMetadata>,
    created: Instant,
}
const OFFER_TTL: Duration = Duration::from_secs(30 * 60);
const PASTE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
use uuid::Uuid;

const MAX_PIXELS: usize = 8 * 1024 * 1024; // <= 32 MiB RGBA

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum Direction {
    Both,
    Send,
    Receive,
}
impl Direction {
    pub fn can_send(self) -> bool {
        self != Self::Receive
    }
    pub fn can_receive(self) -> bool {
        self != Self::Send
    }
}

enum Observation {
    Files(Vec<PathBuf>, [u8; 32]),
    Image(ImageData<'static>, [u8; 32]),
    Text(String, [u8; 32]),
}
impl Observation {
    fn digest(&self) -> [u8; 32] {
        match self {
            Self::Files(_, d) | Self::Image(_, d) | Self::Text(_, d) => *d,
        }
    }
}
fn signature(prefix: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(bytes);
    hasher.finalize().into()
}
fn files_signature(paths: &[PathBuf]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"files-v3");
    for path in paths {
        let name = path.to_string_lossy();
        hasher.update((name.len() as u64).to_be_bytes());
        hasher.update(name.as_bytes());
        if let Ok(meta) = std::fs::metadata(path) {
            hasher.update(meta.len().to_be_bytes());
            if let Some(time) = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            {
                hasher.update(time.as_nanos().to_be_bytes());
            }
        }
    }
    hasher.finalize().into()
}
fn image_signature(image: &ImageData<'_>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"image-v3");
    hasher.update((image.width as u64).to_be_bytes());
    hasher.update((image.height as u64).to_be_bytes());
    hasher.update(image.bytes.as_ref());
    hasher.finalize().into()
}
fn observe(
    clipboard: &mut Clipboard,
    allow_images: bool,
    allow_files: bool,
) -> Option<Observation> {
    // File managers often expose both text/URI and file-list formats; prefer files.
    if allow_files {
        if let Ok(paths) = clipboard.get().file_list() {
            if !paths.is_empty() {
                return Some(Observation::Files(paths.clone(), files_signature(&paths)));
            }
        }
    }
    if allow_images {
        if let Ok(img) = clipboard.get_image() {
            let dig = image_signature(&img);
            return Some(Observation::Image(img, dig));
        }
    }
    clipboard.get_text().ok().map(|s| {
        let dig = signature(b"text-v3", s.as_bytes());
        Observation::Text(s, dig)
    })
}
fn png_encode(img: &ImageData<'_>) -> Result<Vec<u8>> {
    let pixels = img
        .width
        .checked_mul(img.height)
        .context("image dimensions overflow")?;
    if pixels == 0 || pixels > MAX_PIXELS || img.bytes.len() != pixels * 4 {
        bail!("invalid/oversized clipboard image");
    }
    let width = u32::try_from(img.width)?;
    let height = u32::try_from(img.height)?;
    let mut png = Vec::new();
    PngEncoder::new(&mut png).write_image(&img.bytes, width, height, ExtendedColorType::Rgba8)?;
    if png.len() > MAX_PNG {
        bail!(
            "PNG compressed image {} bytes exceeds {}-byte limit",
            png.len(),
            MAX_PNG
        );
    }
    Ok(png)
}
fn png_decode(png: &[u8]) -> Result<ImageData<'static>> {
    if png.len() > MAX_PNG {
        bail!("oversized image");
    }
    let mut reader = ImageReader::with_format(Cursor::new(png), ImageFormat::Png);
    let mut limits = Limits::default();
    limits.max_alloc = Some((MAX_PIXELS * 4) as u64);
    limits.max_image_width = Some(8192);
    limits.max_image_height = Some(8192);
    reader.limits(limits);
    let rgba = reader.decode()?.to_rgba8();
    let (width, height) = rgba.dimensions();
    if (width as usize)
        .checked_mul(height as usize)
        .unwrap_or(usize::MAX)
        > MAX_PIXELS
    {
        bail!("decoded image exceeds pixel limit");
    }
    Ok(ImageData {
        width: width as usize,
        height: height as usize,
        bytes: Cow::Owned(rgba.into_raw()),
    })
}

pub struct ClipboardSync {
    self_id: Uuid,
    clipboard: Clipboard,
    last_signature: Option<[u8; 32]>,
    direction: Direction,
    allow_images: bool,
    allow_files: bool,
    receive_dir: PathBuf,
    local_offers: VecDeque<LocalOffer>,
    outgoing: VecDeque<Update>,
    lazy_files: Option<LazyFiles>,
    paste_tx: tokio::sync::mpsc::UnboundedSender<PasteRequest>,
    paste_rx: tokio::sync::mpsc::UnboundedReceiver<PasteRequest>,
    pending: HashMap<Uuid, PendingPaste>,
    file_commands: tokio::sync::broadcast::Receiver<Vec<PathBuf>>,
}
impl ClipboardSync {
    pub fn new(
        self_id: Uuid,
        direction: Direction,
        allow_images: bool,
        allow_files: bool,
        receive_dir: PathBuf,
    ) -> Result<Self> {
        let mut clipboard =
            Clipboard::new().context("cannot access desktop clipboard; run in a GUI session")?;
        let last_signature = observe(&mut clipboard, allow_images, allow_files).map(|o| o.digest());
        let (paste_tx, paste_rx) = tokio::sync::mpsc::unbounded_channel();
        Ok(Self {
            self_id,
            clipboard,
            last_signature,
            direction,
            allow_images,
            allow_files,
            receive_dir,
            local_offers: VecDeque::new(),
            outgoing: VecDeque::new(),
            lazy_files: None,
            paste_tx,
            paste_rx,
            pending: HashMap::new(),
            file_commands: crate::tray::file_commands().subscribe(),
        })
    }
    pub fn check_local_change(&mut self, self_id: Uuid) -> Option<Update> {
        self.poll_file_actions(self_id);
        if let Some(update) = self.outgoing.pop_front() {
            return Some(update);
        }
        if !self.direction.can_send() {
            return None;
        }
        // Reading our own delayed file-list would itself trigger a download.
        if self
            .lazy_files
            .as_ref()
            .is_some_and(LazyFiles::owns_clipboard)
        {
            return None;
        }
        self.lazy_files = None;
        let value = observe(&mut self.clipboard, self.allow_images, self.allow_files)?;
        let hash = value.digest();
        if self.last_signature == Some(hash) {
            return None;
        }
        self.last_signature = Some(hash); // skip repeated oversize/error messages
        let result = match value {
            Observation::Text(text, _) => {
                if text.len() > MAX_TEXT {
                    bail_local("text exceeds 8 MiB")
                } else {
                    Update::text(self_id, text)
                }
            }
            Observation::Image(img, _) => {
                png_encode(&img).and_then(|png| Update::new(self_id, Kind::Png, png))
            }
            Observation::Files(paths, hash) => self.offer_files(self_id, paths, hash),
        };
        match result {
            Ok(u) => Some(u),
            Err(e) => {
                eprintln!("Local clipboard skipped: {e:#}");
                None
            }
        }
    }
    pub fn apply_remote(&mut self, update: &Update) -> Result<bool> {
        if !self.direction.can_receive() && update.kind != Kind::FileRequest {
            return Ok(false);
        }
        match update.kind {
            Kind::CompressedText => bail!("compressed text must be decoded before applying"),
            Kind::Text => {
                let value = std::str::from_utf8(&update.bytes)?;
                let hash = signature(b"text-v3", value.as_bytes());
                if self.last_signature == Some(hash) {
                    return Ok(false);
                }
                self.lazy_files = None;
                self.clipboard
                    .set_text(value.to_owned())
                    .context("failed to copy remote text")?;
                self.last_signature = Some(hash);
            }
            Kind::Png => {
                if !self.allow_images {
                    return Ok(false);
                }
                let img = png_decode(&update.bytes)?;
                let hash = image_signature(&img);
                if self.last_signature == Some(hash) {
                    return Ok(false);
                }
                self.lazy_files = None;
                self.clipboard
                    .set_image(img)
                    .context("failed to copy remote image")?;
                self.last_signature = Some(hash);
            }
            Kind::Files => {
                if !self.allow_files {
                    return Ok(false);
                }
                let paths =
                    files::save_bundle(&update.bytes, Path::new(&self.receive_dir), update.id)?;
                crate::desktop::notify(
                    "Files received",
                    &format!(
                        "Saved {} file(s) to {}",
                        paths.len(),
                        self.receive_dir.join(update.id.to_string()).display()
                    ),
                );
            }
            Kind::FileOffer => {
                if !self.allow_files {
                    return Ok(false);
                }
                let entries: Vec<files::FileMetadata> = serde_json::from_slice(&update.bytes)?;
                files::validate_metadata(&entries)?;
                let summary = entries
                    .iter()
                    .map(|e| format!("{} ({} bytes)", e.name, e.size))
                    .collect::<Vec<_>>()
                    .join("\n");
                self.last_signature = None;
                let tx = self.paste_tx.clone();
                let offer = update.id;
                let origin = update.origin;
                self.lazy_files = None;
                self.lazy_files = Some(LazyFiles::offer(Box::new(move || {
                    let (reply, answer) = std::sync::mpsc::sync_channel(1);
                    tx.send(PasteRequest {
                        offer,
                        origin,
                        entries: entries.clone(),
                        reply,
                    })
                    .map_err(|_| anyhow::anyhow!("clipboard sharing stopped"))?;
                    answer
                        .recv_timeout(PASTE_TIMEOUT)
                        .context("file download timed out; check peer connection")?
                        .map_err(anyhow::Error::msg)
                }))?);
                crate::desktop::notify("Files available in clipboard", &format!("{summary}\nPaste in a file manager to download. Offer expires in 30 minutes."));
            }
            Kind::FileRequest => {
                anyhow::ensure!(update.bytes.len() == 32, "invalid file request");
                let offer_id = Uuid::from_slice(&update.bytes[..16])?;
                let owner = Uuid::from_slice(&update.bytes[16..])?;
                if owner != self.self_id {
                    return Ok(false);
                }
                anyhow::ensure!(
                    self.outgoing.len() < 4,
                    "outgoing file response queue is full"
                );
                let result = (|| -> Result<Vec<u8>> {
                    let offer = self
                        .local_offers
                        .iter()
                        .find(|o| o.id == offer_id)
                        .context("file offer expired or replaced; copy the files again")?;
                    anyhow::ensure!(
                        offer.created.elapsed() < OFFER_TTL,
                        "file offer expired; copy the files again"
                    );
                    anyhow::ensure!(
                        files_signature(&offer.paths) == offer.signature,
                        "source files changed; copy them again"
                    );
                    let bytes = files::encode_paths(&offer.paths)?;
                    files::validate_offered_bundle(&bytes, &offer.entries)?;
                    anyhow::ensure!(
                        files_signature(&offer.paths) == offer.signature,
                        "source files changed while reading"
                    );
                    Ok(bytes)
                })();
                let (kind, data) = match result {
                    Ok(bytes) => (Kind::FileResponse, bytes),
                    Err(err) => (Kind::FileError, format!("{err:#}").into_bytes()),
                };
                let mut bytes = update.id.as_bytes().to_vec();
                bytes.extend(data);
                self.outgoing
                    .push_back(Update::new(self.self_id, kind, bytes)?);
            }
            Kind::FileResponse | Kind::FileError => {
                anyhow::ensure!(update.bytes.len() >= 16, "missing file request identifier");
                let request_id = Uuid::from_slice(&update.bytes[..16])?;
                let Some(pending) = self.pending.get(&request_id) else {
                    return Ok(false);
                };
                anyhow::ensure!(
                    update.origin == pending.request.origin,
                    "file response came from a different origin"
                );
                let pending = self.pending.remove(&request_id).unwrap();
                let result = (|| -> Result<Vec<PathBuf>> {
                    anyhow::ensure!(
                        pending.started.elapsed() < PASTE_TIMEOUT,
                        "file request expired"
                    );
                    if update.kind == Kind::FileError {
                        anyhow::bail!("{}", String::from_utf8_lossy(&update.bytes[16..]));
                    }
                    files::validate_offered_bundle(&update.bytes[16..], &pending.request.entries)?;
                    files::save_bundle(&update.bytes[16..], &self.receive_dir, update.id)
                })();
                let _ = pending
                    .request
                    .reply
                    .send(result.map_err(|e| format!("{e:#}")));
            }
        }
        Ok(true)
    }
    fn offer_files(
        &mut self,
        self_id: Uuid,
        paths: Vec<PathBuf>,
        signature: [u8; 32],
    ) -> Result<Update> {
        let entries = files::metadata(&paths)?;
        let update = Update::new(self_id, Kind::FileOffer, serde_json::to_vec(&entries)?)?;
        if self.local_offers.len() == 4 {
            self.local_offers.pop_front();
        }
        self.local_offers.push_back(LocalOffer {
            id: update.id,
            paths,
            signature,
            entries,
            created: Instant::now(),
        });
        Ok(update)
    }
    fn poll_file_actions(&mut self, self_id: Uuid) {
        self.pending
            .retain(|_, pending| pending.started.elapsed() < PASTE_TIMEOUT);
        while let Ok(request) = self.paste_rx.try_recv() {
            // Bounded independently of native clipboard readers.
            if !self.allow_files || self.pending.len() >= 4 {
                let _ = request
                    .reply
                    .send(Err("too many pending file pastes".into()));
                continue;
            }
            let mut bytes = request.offer.as_bytes().to_vec();
            bytes.extend_from_slice(request.origin.as_bytes());
            match Update::new(self_id, Kind::FileRequest, bytes) {
                Ok(update) => {
                    self.pending.insert(
                        update.id,
                        PendingPaste {
                            request,
                            started: Instant::now(),
                        },
                    );
                    self.outgoing.push_back(update);
                }
                Err(err) => {
                    let _ = request.reply.send(Err(err.to_string()));
                }
            }
        }
        loop {
            match self.file_commands.try_recv() {
                Ok(paths)
                    if self.allow_files && self.direction.can_send() && self.outgoing.len() < 4 =>
                {
                    let result = files::encode_paths(&paths)
                        .and_then(|bytes| Update::new(self_id, Kind::Files, bytes));
                    match result {
                        Ok(update) => self.outgoing.push_back(update),
                        Err(err) => {
                            crate::desktop::notify("Cannot send files", &format!("{err:#}"))
                        }
                    }
                }
                Ok(_) => crate::desktop::notify(
                    "Cannot send files",
                    "File sending is disabled or the outgoing queue is full.",
                ),
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
    }
    pub fn allows(&self, kind: Kind) -> bool {
        match kind {
            Kind::Text => true,
            Kind::Png => self.allow_images,
            _ => self.allow_files,
        }
    }
}
fn bail_local<T>(message: &str) -> Result<T> {
    bail!("{message}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rgba_png_roundtrip() {
        let img = ImageData {
            width: 2,
            height: 1,
            bytes: Cow::Owned(vec![255, 0, 0, 255, 0, 255, 0, 127]),
        };
        let blob = png_encode(&img).unwrap();
        let out = png_decode(&blob).unwrap();
        assert_eq!(out.width, 2);
        assert_eq!(out.height, 1);
        assert_eq!(out.bytes.as_ref(), img.bytes.as_ref());
    }
    #[test]
    fn images_reject_dimension_bombs() {
        let img = ImageData {
            width: MAX_PIXELS + 1,
            height: 1,
            bytes: Cow::Borrowed(&[]),
        };
        assert!(png_encode(&img).is_err());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod lazy_file_tests {
    use super::*;
    #[test]
    #[ignore = "requires an isolated X11 display; run with xvfb-run and WAYLAND_DISPLAY unset"]
    fn native_file_paste_fetches_once_after_metadata_offer() {
        let root = std::env::temp_dir().join(format!("bleclip-lazy-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let source = root.join("hello world.txt");
        std::fs::write(&source, b"on-demand contents").unwrap();
        let a_id = Uuid::new_v4();
        let b_id = Uuid::new_v4();
        let mut a =
            ClipboardSync::new(a_id, Direction::Send, false, true, root.join("a-downloads"))
                .unwrap();
        a.clipboard.set().file_list(&[source.clone()]).unwrap();
        let offer = a.check_local_change(a_id).unwrap();
        assert_eq!(offer.kind, Kind::FileOffer);
        let mut b = ClipboardSync::new(
            b_id,
            Direction::Receive,
            false,
            true,
            root.join("b-downloads"),
        )
        .unwrap();
        b.apply_remote(&offer).unwrap();
        assert!(!root.join("b-downloads").exists());
        // Own polling must not ask the native backend to render the file list.
        assert!(b.check_local_change(b_id).is_none());
        assert!(b.paste_rx.try_recv().is_err());
        let paste = std::thread::spawn(|| Clipboard::new().unwrap().get().file_list().unwrap());
        let deadline = Instant::now() + Duration::from_secs(5);
        let request = loop {
            if let Some(request) = b.check_local_change(b_id) {
                break request;
            }
            assert!(
                Instant::now() < deadline,
                "native paste did not request files"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(request.kind, Kind::FileRequest);
        assert!(!root.join("b-downloads").exists());
        a.apply_remote(&request).unwrap();
        let response = a.check_local_change(a_id).unwrap();
        assert_eq!(response.kind, Kind::FileResponse);
        // An unrelated origin cannot complete this request.
        let mut impostor = response.clone();
        impostor.origin = Uuid::new_v4();
        assert!(b.apply_remote(&impostor).is_err());
        b.apply_remote(&response).unwrap();
        let paths = paste.join().unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].file_name().unwrap(), "hello world.txt");
        assert_eq!(std::fs::read(&paths[0]).unwrap(), b"on-demand contents");
        // Repeated pastes reuse the downloaded data and do not retransmit.
        assert_eq!(Clipboard::new().unwrap().get().file_list().unwrap(), paths);
        assert!(b.check_local_change(b_id).is_none());
        assert!(b.pending.is_empty());
        // A changed source is reported as an error rather than served under stale metadata.
        std::fs::write(&source, b"changed").unwrap();
        let mut bytes = offer.id.as_bytes().to_vec();
        bytes.extend_from_slice(a_id.as_bytes());
        a.apply_remote(&Update::new(b_id, Kind::FileRequest, bytes).unwrap())
            .unwrap();
        assert_eq!(a.check_local_change(a_id).unwrap().kind, Kind::FileError);
        // Explicit sends save to Downloads without taking over the user's clipboard.
        b.clipboard
            .set_text("keep local clipboard".to_string())
            .unwrap();
        let direct =
            Update::new(a_id, Kind::Files, files::encode_paths(&[source]).unwrap()).unwrap();
        b.apply_remote(&direct).unwrap();
        assert!(root
            .join("b-downloads")
            .join(direct.id.to_string())
            .join("hello world.txt")
            .is_file());
        assert_eq!(b.clipboard.get_text().unwrap(), "keep local clipboard");
        drop(b);
        drop(a);
        std::fs::remove_dir_all(root).unwrap();
    }
}
