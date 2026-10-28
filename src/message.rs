//! Version 3 encrypted application protocol. Binary content is transferred in
//! bounded chunks; per-hop integrity covers the *entire* original byte stream.
use anyhow::{bail, ensure, Result};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

pub const MAX_HOPS: u8 = 8;
pub const MAX_TEXT: usize = 8 * 1024 * 1024;
pub const COMPRESS_TEXT_ABOVE: usize = 16 * 1024;
pub const MAX_COMPRESSED_TEXT: usize = 2 * MAX_TEXT;
pub const MAX_PNG: usize = 4 * 1024 * 1024;
pub const MAX_FILES: usize = 64 * 1024 * 1024;
pub const CHUNK_SIZE: usize = 1024;
const MAX_FILE_CONTROL: usize = 16 * 1024;
const IDENTITY: u8 = 0x10;
const START: u8 = 0x20;
const CHUNK: u8 = 0x21;
const END: u8 = 0x22;
const ACK: u8 = 0x23;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Text = 1,
    Png = 2,
    Files = 3,
    FileOffer = 4,
    FileRequest = 5,
    FileResponse = 6,
    FileError = 7,
    CompressedText = 8,
    IpEndpoint = 9,
}
impl Kind {
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            1 => Ok(Self::Text),
            2 => Ok(Self::Png),
            3 => Ok(Self::Files),
            4 => Ok(Self::FileOffer),
            5 => Ok(Self::FileRequest),
            6 => Ok(Self::FileResponse),
            7 => Ok(Self::FileError),
            8 => Ok(Self::CompressedText),
            9 => Ok(Self::IpEndpoint),
            _ => bail!("unknown payload type"),
        }
    }
    pub fn limit(self) -> usize {
        match self {
            Self::Text => MAX_TEXT,
            Self::CompressedText => MAX_COMPRESSED_TEXT,
            Self::Png => MAX_PNG,
            Self::Files => MAX_FILES,
            Self::FileOffer | Self::FileError => MAX_FILE_CONTROL,
            Self::FileRequest | Self::IpEndpoint => 512,
            Self::FileResponse => MAX_FILES + 16,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub id: Uuid,
    pub origin: Uuid,
    pub hops: u8,
    pub kind: Kind,
    pub bytes: Arc<[u8]>,
    /// Local delivery metadata only; never accepted from a BLE header.
    pub via_ip: bool,
}
impl Update {
    pub fn new(origin: Uuid, kind: Kind, bytes: Vec<u8>) -> Result<Self> {
        let update = Self {
            id: Uuid::new_v4(),
            origin,
            hops: MAX_HOPS,
            kind,
            bytes: bytes.into(),
            via_ip: false,
        };
        update.validate()?;
        Ok(update)
    }
    pub fn text(origin: Uuid, text: String) -> Result<Self> {
        Self::new(origin, Kind::Text, text.into_bytes())
    }
    pub fn new_ip(origin: Uuid, kind: Kind, bytes: Vec<u8>) -> Result<Self> {
        let update = Self {
            id: Uuid::new_v4(),
            origin,
            hops: MAX_HOPS,
            kind,
            bytes: bytes.into(),
            via_ip: true,
        };
        update.validate_ip()?;
        Ok(update)
    }
    pub fn validate_ip(&self) -> Result<()> {
        self.validate_inner(true)
    }
    pub fn validate(&self) -> Result<()> {
        self.validate_inner(false)
    }
    fn validate_inner(&self, ip: bool) -> Result<()> {
        ensure!(
            !self.id.is_nil() && !self.origin.is_nil(),
            "nil update identifier"
        );
        ensure!(self.hops <= MAX_HOPS, "invalid remaining hops");
        ensure!(
            (ip && matches!(
                self.kind,
                Kind::Text | Kind::Png | Kind::Files | Kind::CompressedText | Kind::FileResponse
            )) || self.bytes.len() <= self.kind.limit(),
            "payload exceeds type limit"
        );
        match self.kind {
            Kind::Text => {
                std::str::from_utf8(&self.bytes)?;
            }
            Kind::FileRequest => {
                crate::transport::ip::decode_request(&self.bytes)?;
            }
            Kind::IpEndpoint => {
                crate::transport::ip::decode_endpoint(&self.bytes)?;
            }
            Kind::FileResponse | Kind::FileError => {
                ensure!(self.bytes.len() >= 16, "missing file request identifier");
                ensure!(
                    !Uuid::from_slice(&self.bytes[..16])?.is_nil(),
                    "nil file request identifier"
                );
                if self.kind == Kind::FileError {
                    std::str::from_utf8(&self.bytes[16..])?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.bytes).into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub id: Uuid,
    pub origin: Uuid,
    pub hops: u8,
    pub kind: Kind,
    pub size: u32,
    pub sha256: [u8; 32],
}
impl Header {
    pub fn for_update(update: &Update) -> Self {
        Self {
            id: update.id,
            origin: update.origin,
            hops: update.hops,
            kind: update.kind,
            size: update.bytes.len() as u32,
            sha256: update.digest(),
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.id.is_nil() && !self.origin.is_nil(),
            "nil update identifier"
        );
        ensure!(
            self.hops <= MAX_HOPS && self.size as usize <= self.kind.limit(),
            "invalid payload size/hops"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Identity(Uuid),
    Start(Header),
    Chunk {
        id: Uuid,
        offset: u32,
        bytes: Vec<u8>,
    },
    End(Uuid),
    Ack(Uuid),
}
impl Message {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            Self::Identity(id) => {
                ensure!(!id.is_nil(), "nil node identity");
                out.push(IDENTITY);
                out.extend_from_slice(id.as_bytes());
            }
            Self::Start(h) => {
                h.validate()?;
                out.push(START);
                out.extend_from_slice(h.id.as_bytes());
                out.extend_from_slice(h.origin.as_bytes());
                out.push(h.hops);
                out.push(h.kind as u8);
                out.extend_from_slice(&h.size.to_be_bytes());
                out.extend_from_slice(&h.sha256);
            }
            Self::Chunk { id, offset, bytes } => {
                ensure!(
                    !id.is_nil() && !bytes.is_empty() && bytes.len() <= CHUNK_SIZE,
                    "invalid transfer chunk"
                );
                out.push(CHUNK);
                out.extend_from_slice(id.as_bytes());
                out.extend_from_slice(&offset.to_be_bytes());
                out.extend_from_slice(bytes);
            }
            Self::End(id) => {
                ensure!(!id.is_nil(), "nil end id");
                out.push(END);
                out.extend_from_slice(id.as_bytes());
            }
            Self::Ack(id) => {
                ensure!(!id.is_nil(), "nil ack id");
                out.push(ACK);
                out.extend_from_slice(id.as_bytes());
            }
        }
        Ok(out)
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        match b.first().copied() {
            Some(IDENTITY) if b.len() == 17 => {
                let id = Uuid::from_slice(&b[1..17])?;
                ensure!(!id.is_nil(), "nil node identity");
                Ok(Self::Identity(id))
            }
            Some(START) if b.len() == 1 + 16 + 16 + 1 + 1 + 4 + 32 => {
                let h = Header {
                    id: Uuid::from_slice(&b[1..17])?,
                    origin: Uuid::from_slice(&b[17..33])?,
                    hops: b[33],
                    kind: Kind::from_byte(b[34])?,
                    size: u32::from_be_bytes(b[35..39].try_into()?),
                    sha256: b[39..71].try_into()?,
                };
                h.validate()?;
                Ok(Self::Start(h))
            }
            Some(CHUNK) if b.len() > 21 && b.len() <= 21 + CHUNK_SIZE => {
                let id = Uuid::from_slice(&b[1..17])?;
                ensure!(!id.is_nil(), "nil chunk id");
                Ok(Self::Chunk {
                    id,
                    offset: u32::from_be_bytes(b[17..21].try_into()?),
                    bytes: b[21..].to_vec(),
                })
            }
            Some(END) if b.len() == 17 => Ok(Self::End(Uuid::from_slice(&b[1..17])?)),
            Some(ACK) if b.len() == 17 => Ok(Self::Ack(Uuid::from_slice(&b[1..17])?)),
            _ => bail!("unknown or malformed encrypted v3 message"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn text_limit_is_eight_mib_of_utf8() {
        let origin = Uuid::new_v4();
        let update = Update::text(origin, "é".repeat(MAX_TEXT / 2)).unwrap();
        assert_eq!(update.bytes.len(), 8 * 1024 * 1024);
        assert!(Header::for_update(&update).validate().is_ok());
        assert!(Update::text(origin, "a".repeat(MAX_TEXT + 1)).is_err());
        let mut header = Header::for_update(&update);
        header.size += 1;
        assert!(header.validate().is_err());
    }
    #[test]
    fn file_header_accepts_sixty_four_mib_and_rejects_more() {
        let update = Update::new(Uuid::new_v4(), Kind::Files, vec![]).unwrap();
        let mut header = Header::for_update(&update);
        header.size = MAX_FILES as u32;
        assert!(header.validate().is_ok());
        header.size += 1;
        assert!(header.validate().is_err());
    }
    #[test]
    fn file_control_types_roundtrip_and_reject_invalid_identifiers() {
        let origin = Uuid::new_v4();
        let offer = Uuid::new_v4();
        let mut request = offer.as_bytes().to_vec();
        request.extend_from_slice(origin.as_bytes());
        for (kind, payload) in [
            (Kind::FileOffer, br#"[{"name":"a.txt","size":3}]"#.to_vec()),
            (Kind::FileRequest, request),
            (Kind::FileResponse, offer.as_bytes().to_vec()),
            (
                Kind::FileError,
                [offer.as_bytes().as_slice(), b"source changed"].concat(),
            ),
        ] {
            let update = Update::new(origin, kind, payload).unwrap();
            let encoded = Message::Start(Header::for_update(&update))
                .encode()
                .unwrap();
            assert_eq!(
                Message::decode(&encoded).unwrap(),
                Message::Start(Header::for_update(&update))
            );
        }
        assert!(Update::new(origin, Kind::FileRequest, vec![0; 32]).is_err());
        assert!(Update::new(origin, Kind::FileResponse, vec![1; 15]).is_err());
        assert!(Update::new(
            origin,
            Kind::FileError,
            [offer.as_bytes().as_slice(), &[255]].concat()
        )
        .is_err());
    }
    #[test]
    fn all_message_types_roundtrip() {
        let id = Uuid::new_v4();
        let update = Update::text(id, "hello 世界".to_string()).unwrap();
        let cases = vec![
            Message::Identity(id),
            Message::Start(Header::for_update(&update)),
            Message::Chunk {
                id: update.id,
                offset: 0,
                bytes: update.bytes.to_vec(),
            },
            Message::End(update.id),
            Message::Ack(update.id),
        ];
        for value in cases {
            assert_eq!(value, Message::decode(&value.encode().unwrap()).unwrap());
        }
    }
    #[test]
    fn bounds_and_malformed_bytes() {
        assert!(Update::new(Uuid::new_v4(), Kind::Png, vec![7; MAX_PNG + 1]).is_err());
        assert!(Message::decode(&[START]).is_err());
        assert!(Message::Chunk {
            id: Uuid::new_v4(),
            offset: 0,
            bytes: vec![]
        }
        .encode()
        .is_err());
        let mut raw = Message::Start(Header::for_update(
            &Update::text(Uuid::new_v4(), "a".into()).unwrap(),
        ))
        .encode()
        .unwrap();
        raw[33] = 9;
        assert!(Message::decode(&raw).is_err());
    }
}
