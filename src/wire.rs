//! Delimiting application messages across the minimum-size BLE ATT payload (20 bytes).
//! The decoder rejects unbounded/zero-length frames, and accepts multiple frames per write.

use anyhow::{bail, Result};
use std::collections::VecDeque;

pub const ATT_CHUNK: usize = 20; // Valid even at the minimum LE ATT MTU of 23.
pub const MAX_TEXT: usize = 16 * 1024;
pub const MAX_FRAME: usize = MAX_TEXT + 128;
pub const MAX_PENDING: usize = 4 * (MAX_FRAME + 4);

pub fn frame(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.is_empty() || payload.len() > MAX_FRAME {
        bail!("frame is empty or exceeds maximum size");
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

#[derive(Default)]
pub struct Decoder {
    pending: Vec<u8>,
}

impl Decoder {
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
        if bytes.len() > MAX_FRAME + 4 || self.pending.len() + bytes.len() > MAX_FRAME + 4 {
            bail!("framing buffer limit exceeded");
        }
        self.pending.extend_from_slice(bytes);
        let mut decoded = Vec::new();
        loop {
            if self.pending.len() < 4 {
                break;
            }
            let size = u32::from_be_bytes(self.pending[..4].try_into()?) as usize;
            if size == 0 || size > MAX_FRAME {
                bail!("invalid frame length");
            }
            if self.pending.len() < size + 4 {
                break;
            }
            decoded.push(self.pending[4..4 + size].to_vec());
            self.pending.drain(..size + 4);
        }
        Ok(decoded)
    }
}

/// Atomically queue a whole frame; never discard a half-delivered frame.
pub fn queue_frame(queue: &mut VecDeque<u8>, payload: &[u8]) -> Result<()> {
    let bytes = frame(payload)?;
    if queue.len() + bytes.len() > MAX_PENDING {
        bail!("outgoing queue full (peer may have stopped reading)");
    }
    queue.extend(bytes);
    Ok(())
}

pub fn pop_chunk(queue: &mut VecDeque<u8>) -> Vec<u8> {
    let len = queue.len().min(ATT_CHUNK);
    queue.drain(..len).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragmentation_and_coalescing() {
        let mut combined = frame(b"first").unwrap();
        combined.extend(frame(&vec![17; 145]).unwrap());
        let mut d = Decoder::default();
        let mut messages = Vec::new();
        for chunk in combined.chunks(ATT_CHUNK) {
            messages.extend(d.push(chunk).unwrap());
        }
        assert_eq!(messages, vec![b"first".to_vec(), vec![17; 145]]);
    }
    #[test]
    fn malformed_length_is_rejected() {
        let mut d = Decoder::default();
        assert!(d.push(&u32::MAX.to_be_bytes()).is_err());
        let mut d = Decoder::default();
        assert!(d.push(&0u32.to_be_bytes()).is_err());
    }
    #[test]
    fn queue_preserves_frame() {
        let mut q = VecDeque::new();
        queue_frame(&mut q, b"hello").unwrap();
        let out = pop_chunk(&mut q);
        let mut d = Decoder::default();
        assert_eq!(d.push(&out).unwrap(), vec![b"hello".to_vec()]);
    }
}
