//! Application messages are encrypted *before* BLE fragmentation.
//! All UUIDs are random identifiers, not evidence of identity by themselves.
//! Authentication comes from the out-of-band PSK handshake.

use crate::wire::MAX_TEXT;
use anyhow::{bail, ensure, Result};
use uuid::Uuid;

pub const MAX_HOPS: u8 = 8;
const IDENTITY: u8 = 0x10;
const CLIPBOARD: u8 = 0x11;
const UPDATE_HEADER: usize = 1 + 16 + 16 + 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub id: Uuid,
    pub origin: Uuid,
    pub hops: u8,
    pub text: String,
}

impl Update {
    pub fn new(origin: Uuid, text: String) -> Result<Self> {
        ensure!(text.len() <= MAX_TEXT, "text exceeds clipboard limit");
        Ok(Self { id: Uuid::new_v4(), origin, hops: MAX_HOPS, text })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Identity(Uuid),
    Clipboard(Update),
}

impl Message {
    pub fn encode(&self) -> Result<Vec<u8>> {
        match self {
            Self::Identity(id) => {
                ensure!(!id.is_nil(), "node identity is nil");
                let mut bytes = vec![IDENTITY];
                bytes.extend_from_slice(id.as_bytes());
                Ok(bytes)
            }
            Self::Clipboard(update) => {
                ensure!(!update.origin.is_nil() && !update.id.is_nil(), "invalid update identity");
                ensure!(update.hops <= MAX_HOPS, "update hop limit invalid");
                ensure!(update.text.len() <= MAX_TEXT, "clipboard exceeds size limit");
                let mut bytes = Vec::with_capacity(UPDATE_HEADER + update.text.len());
                bytes.push(CLIPBOARD);
                bytes.extend_from_slice(update.id.as_bytes());
                bytes.extend_from_slice(update.origin.as_bytes());
                bytes.push(update.hops);
                bytes.extend_from_slice(update.text.as_bytes());
                Ok(bytes)
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        match bytes.first().copied() {
            Some(IDENTITY) if bytes.len() == 17 => {
                let id = Uuid::from_slice(&bytes[1..17])?;
                ensure!(!id.is_nil(), "node identity is nil");
                Ok(Self::Identity(id))
            }
            Some(CLIPBOARD) if bytes.len() >= UPDATE_HEADER && bytes.len() <= UPDATE_HEADER + MAX_TEXT => {
                let id = Uuid::from_slice(&bytes[1..17])?;
                let origin = Uuid::from_slice(&bytes[17..33])?;
                let hops = bytes[33];
                ensure!(!id.is_nil() && !origin.is_nil(), "invalid update identifiers");
                ensure!(hops <= MAX_HOPS, "excessive relay hop count");
                let text = String::from_utf8(bytes[34..].to_vec())?;
                Ok(Self::Clipboard(Update { id, origin, hops, text }))
            }
            _ => bail!("unknown or malformed encrypted protocol message"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_and_large_update_roundtrip() {
        let id = Uuid::new_v4();
        assert_eq!(Message::decode(&Message::Identity(id).encode().unwrap()).unwrap(), Message::Identity(id));
        let update = Update::new(id, "日".repeat(5120)).unwrap();
        let encoded = Message::Clipboard(update.clone()).encode().unwrap();
        assert_eq!(Message::decode(&encoded).unwrap(), Message::Clipboard(update));
    }

    #[test]
    fn invalid_hop_and_utf8_rejected() {
        let mut encoded = Message::Clipboard(Update::new(Uuid::new_v4(), "a".into()).unwrap()).encode().unwrap();
        encoded[33] = 9;
        assert!(Message::decode(&encoded).is_err());
        encoded[33] = 1;
        encoded[34] = 0xff;
        assert!(Message::decode(&encoded).is_err());
    }
}
