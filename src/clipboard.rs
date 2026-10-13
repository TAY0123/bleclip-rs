//! Desktop clipboard synchronization for text, lossless PNG images and file lists.
//! File reception is explicitly opt-in because peers will write local files.
use crate::{files, message::{Kind, Update, MAX_PNG, MAX_TEXT}};
use anyhow::{bail, Context, Result};
use arboard::{Clipboard, ImageData};
use clap::ValueEnum;
use image::{codecs::png::PngEncoder, ExtendedColorType, ImageEncoder, ImageFormat, ImageReader, Limits};
use sha2::{Digest, Sha256};
use std::{borrow::Cow, io::Cursor, path::{Path, PathBuf}, time::UNIX_EPOCH};
use uuid::Uuid;

const MAX_PIXELS: usize = 8 * 1024 * 1024; // <= 32 MiB RGBA

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum Direction { Both, Send, Receive }
impl Direction {
    pub fn can_send(self) -> bool { self != Self::Receive }
    pub fn can_receive(self) -> bool { self != Self::Send }
}

enum Observation {
    Files(Vec<PathBuf>, [u8; 32]),
    Image(ImageData<'static>, [u8; 32]),
    Text(String, [u8; 32]),
}
impl Observation {
    fn digest(&self) -> [u8; 32] {
        match self { Self::Files(_, d) | Self::Image(_, d) | Self::Text(_, d) => *d }
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
            if let Some(time) = meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()) {
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
fn observe(clipboard: &mut Clipboard, allow_images: bool, allow_files: bool) -> Option<Observation> {
    // File managers often expose both text/URI and file-list formats; prefer files.
    if allow_files {
        if let Ok(paths) = clipboard.get().file_list() {
            if !paths.is_empty() { return Some(Observation::Files(paths.clone(), files_signature(&paths))); }
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
    let pixels = img.width.checked_mul(img.height).context("image dimensions overflow")?;
    if pixels == 0 || pixels > MAX_PIXELS || img.bytes.len() != pixels * 4 { bail!("invalid/oversized clipboard image"); }
    let width = u32::try_from(img.width)?;
    let height = u32::try_from(img.height)?;
    let mut png = Vec::new();
    PngEncoder::new(&mut png).write_image(&img.bytes, width, height, ExtendedColorType::Rgba8)?;
    if png.len() > MAX_PNG { bail!("PNG compressed image {} bytes exceeds {}-byte limit", png.len(), MAX_PNG); }
    Ok(png)
}
fn png_decode(png: &[u8]) -> Result<ImageData<'static>> {
    if png.len() > MAX_PNG { bail!("oversized image"); }
    let mut reader = ImageReader::with_format(Cursor::new(png), ImageFormat::Png);
    let mut limits = Limits::default();
    limits.max_alloc = Some((MAX_PIXELS * 4) as u64);
    limits.max_image_width = Some(8192);
    limits.max_image_height = Some(8192);
    reader.limits(limits);
    let rgba = reader.decode()?.to_rgba8();
    let (width, height) = rgba.dimensions();
    if (width as usize).checked_mul(height as usize).unwrap_or(usize::MAX) > MAX_PIXELS { bail!("decoded image exceeds pixel limit"); }
    Ok(ImageData { width: width as usize, height: height as usize, bytes: Cow::Owned(rgba.into_raw()) })
}

pub struct ClipboardSync {
    clipboard: Clipboard,
    last_signature: Option<[u8; 32]>,
    direction: Direction,
    allow_images: bool,
    allow_files: bool,
    receive_dir: PathBuf,
}
impl ClipboardSync {
    pub fn new(direction: Direction, allow_images: bool, allow_files: bool, receive_dir: PathBuf) -> Result<Self> {
        let mut clipboard = Clipboard::new().context("cannot access desktop clipboard; run in a GUI session")?;
        let last_signature = observe(&mut clipboard, allow_images, allow_files).map(|o| o.digest());
        Ok(Self { clipboard, last_signature, direction, allow_images, allow_files, receive_dir })
    }
    pub fn check_local_change(&mut self, self_id: Uuid) -> Option<Update> {
        if !self.direction.can_send() { return None; }
        let value = observe(&mut self.clipboard, self.allow_images, self.allow_files)?;
        let hash = value.digest();
        if self.last_signature == Some(hash) { return None; }
        self.last_signature = Some(hash); // skip repeated oversize/error messages
        let result = match value {
            Observation::Text(text, _) => {
                if text.len() > MAX_TEXT { bail_local("text exceeds 16 KiB") }
                else { Update::text(self_id, text) }
            }
            Observation::Image(img, _) => png_encode(&img).and_then(|png| Update::new(self_id, Kind::Png, png)),
            Observation::Files(paths, _) => files::encode_paths(&paths).and_then(|bytes| Update::new(self_id, Kind::Files, bytes)),
        };
        match result { Ok(u) => Some(u), Err(e) => { eprintln!("Local clipboard skipped: {e:#}"); None } }
    }
    pub fn apply_remote(&mut self, update: &Update) -> Result<bool> {
        if !self.direction.can_receive() { return Ok(false); }
        match update.kind {
            Kind::Text => {
                let value = std::str::from_utf8(&update.bytes)?;
                let hash = signature(b"text-v3", value.as_bytes());
                if self.last_signature == Some(hash) { return Ok(false); }
                self.clipboard.set_text(value.to_owned()).context("failed to copy remote text")?;
                self.last_signature = Some(hash);
            }
            Kind::Png => {
                if !self.allow_images { return Ok(false); }
                let img = png_decode(&update.bytes)?;
                let hash = image_signature(&img);
                if self.last_signature == Some(hash) { return Ok(false); }
                self.clipboard.set_image(img).context("failed to copy remote image")?;
                self.last_signature = Some(hash);
            }
            Kind::Files => {
                if !self.allow_files { return Ok(false); }
                let paths = files::save_bundle(&update.bytes, Path::new(&self.receive_dir), update.id)?;
                let hash = files_signature(&paths);
                self.clipboard.set().file_list(&paths).context("file saved, but setting clipboard file list failed")?;
                self.last_signature = Some(hash);
                println!("Received {} file(s) into {}", paths.len(), self.receive_dir.display());
            }
        }
        Ok(true)
    }
    pub fn allows(&self, kind: Kind) -> bool {
        match kind { Kind::Text => true, Kind::Png => self.allow_images, Kind::Files => self.allow_files }
    }
}
fn bail_local<T>(message: &str) -> Result<T> { bail!("{message}") }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rgba_png_roundtrip() {
        let img = ImageData { width: 2, height: 1,
            bytes: Cow::Owned(vec![255,0,0,255,0,255,0,127]) };
        let blob = png_encode(&img).unwrap();
        let out = png_decode(&blob).unwrap();
        assert_eq!(out.width, 2);
        assert_eq!(out.height, 1);
        assert_eq!(out.bytes.as_ref(), img.bytes.as_ref());
    }
    #[test]
    fn images_reject_dimension_bombs() {
        let img = ImageData { width: MAX_PIXELS + 1, height: 1, bytes: Cow::Borrowed(&[]) };
        assert!(png_encode(&img).is_err());
    }
}
