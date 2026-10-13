//! Authenticated, ephemeral X25519 key exchange using a pre-shared random 256-bit key.
//!
//! Only public ephemeral keys and HMAC proofs are sent during the handshake.
//! Clipboard messages are XChaCha20-Poly1305 with distinct directional session keys.
//! Sessions are unique even across disconnects; old ciphertext cannot be decrypted
//! on a new connection. Replay of a nonce in an active session is rejected.

use crate::wire::MAX_FRAME;
use anyhow::{anyhow, bail, ensure, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

const HELLO_CLIENT: u8 = 1;
const HELLO_SERVER: u8 = 2;
const ENCRYPTED: u8 = 3;
const HELLO_FINISH: u8 = 4;
const HELLO_SIZE: usize = 1 + 32 + 32;
const ASSOCIATED_DATA: &[u8] = b"bleclip-v3/content";
const RECENT_NONCES: usize = 1024;

pub type Psk = [u8; 32];
type HmacSha256 = Hmac<Sha256>;

fn mac(psk: &Psk, domain: &[u8], a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(psk).expect("32-byte HMAC key");
    m.update(domain);
    m.update(a);
    m.update(b);
    let tag = m.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

fn verify(psk: &Psk, domain: &[u8], a: &[u8], b: &[u8], provided: &[u8]) -> Result<()> {
    let mut m = <HmacSha256 as Mac>::new_from_slice(psk).expect("32-byte HMAC key");
    m.update(domain);
    m.update(a);
    m.update(b);
    m.verify_slice(provided)
        .map_err(|_| anyhow!("handshake authentication failed"))
}

pub struct Initiator {
    secret: EphemeralSecret,
    public: [u8; 32],
}

impl Initiator {
    pub fn start(psk: &Psk) -> (Self, Vec<u8>) {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = *PublicKey::from(&secret).as_bytes();
        let mut hello = Vec::with_capacity(HELLO_SIZE);
        hello.push(HELLO_CLIENT);
        hello.extend_from_slice(&public);
        hello.extend_from_slice(&mac(psk, b"bleclip/v3/client", &public, &[]));
        (Self { secret, public }, hello)
    }

    pub fn finish(self, psk: &Psk, reply: &[u8]) -> Result<(Session, Vec<u8>)> {
        ensure!(reply.len() == HELLO_SIZE && reply[0] == HELLO_SERVER, "invalid server hello");
        let remote: [u8; 32] = reply[1..33].try_into()?;
        verify(psk, b"bleclip/v3/server", &self.public, &remote, &reply[33..])?;
        let session = derive(psk, self.secret, &self.public, &remote, true)?;
        let mut finish = vec![HELLO_FINISH];
        finish.extend_from_slice(&mac(psk, b"bleclip/v3/finish", &self.public, &remote));
        Ok((session, finish))
    }
}

/// Authentication is not complete until the client proves knowledge of the
/// PSK over the server's *fresh* public key. This prevents replaying old HELLOs.
pub struct PendingServer {
    session: Session,
    client_public: [u8; 32],
    server_public: [u8; 32],
}

impl PendingServer {
    pub fn finish(self, psk: &Psk, packet: &[u8]) -> Result<Session> {
        ensure!(packet.len() == 33 && packet[0] == HELLO_FINISH,
            "invalid client finished message");
        verify(psk, b"bleclip/v3/finish", &self.client_public, &self.server_public, &packet[1..])?;
        Ok(self.session)
    }
}

pub fn accept(psk: &Psk, hello: &[u8]) -> Result<(PendingServer, Vec<u8>)> {
    ensure!(hello.len() == HELLO_SIZE && hello[0] == HELLO_CLIENT, "invalid client hello");
    let client_pub: [u8; 32] = hello[1..33].try_into()?;
    verify(psk, b"bleclip/v3/client", &client_pub, &[], &hello[33..])?;
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let server_pub = *PublicKey::from(&secret).as_bytes();
    let session = derive(psk, secret, &client_pub, &server_pub, false)?;
    let mut response = Vec::with_capacity(HELLO_SIZE);
    response.push(HELLO_SERVER);
    response.extend_from_slice(&server_pub);
    response.extend_from_slice(&mac(psk, b"bleclip/v3/server", &client_pub, &server_pub));
    Ok((PendingServer { session, client_public: client_pub, server_public: server_pub }, response))
}

fn derive(
    psk: &Psk,
    private: EphemeralSecret,
    client_public: &[u8; 32],
    server_public: &[u8; 32],
    initiator: bool,
) -> Result<Session> {
    let their_pub = if initiator { server_public } else { client_public };
    let shared = private.diffie_hellman(&PublicKey::from(*their_pub));
    ensure!(!shared.as_bytes().iter().all(|&b| b == 0), "invalid ephemeral public key");

    let mut hash = Sha256::new();
    hash.update(b"bleclip/v3/salt");
    hash.update(client_public);
    hash.update(server_public);
    let salt = hash.finalize();
    let mut material = [0u8; 64];
    material[..32].copy_from_slice(psk);
    material[32..].copy_from_slice(shared.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt), &material);
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    hk.expand(b"bleclip/v3/client-to-server", &mut c2s)
        .map_err(|_| anyhow!("key derivation failed"))?;
    hk.expand(b"bleclip/v3/server-to-client", &mut s2c)
        .map_err(|_| anyhow!("key derivation failed"))?;
    material.zeroize();
    let (send_key, recv_key) = if initiator { (c2s, s2c) } else { (s2c, c2s) };
    let session = Session {
        send_cipher: XChaCha20Poly1305::new_from_slice(&send_key).expect("key length"),
        recv_cipher: XChaCha20Poly1305::new_from_slice(&recv_key).expect("key length"),
        seen: VecDeque::new(),
    };
    // Arrays go out of scope, but explicitly erase the intermediate copies.
    let mut send_key = send_key;
    let mut recv_key = recv_key;
    send_key.zeroize();
    recv_key.zeroize();
    Ok(session)
}

pub struct Session {
    send_cipher: XChaCha20Poly1305,
    recv_cipher: XChaCha20Poly1305,
    seen: VecDeque<[u8; 24]>,
}

impl Session {
    /// Encrypt a typed binary application payload (identity or clipboard update).
    pub fn seal(&self, payload: &[u8]) -> Result<Vec<u8>> {
        ensure!(payload.len() + 1 + 24 + 16 <= MAX_FRAME, "payload too large");
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let encrypted = self
            .send_cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: payload, aad: ASSOCIATED_DATA })
            .map_err(|_| anyhow!("encryption failed"))?;
        let mut packet = Vec::with_capacity(1 + nonce.len() + encrypted.len());
        packet.push(ENCRYPTED);
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&encrypted);
        Ok(packet)
    }

    pub fn open(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        ensure!(packet.len() >= 1 + 24 + 16 && packet[0] == ENCRYPTED,
            "invalid encrypted protocol packet");
        ensure!(packet.len() <= MAX_FRAME, "encrypted payload exceeds size limit");
        let nonce: [u8; 24] = packet[1..25].try_into()?;
        if self.seen.contains(&nonce) {
            bail!("replayed encrypted protocol packet");
        }
        let plaintext = self.recv_cipher
            .decrypt(XNonce::from_slice(&nonce), Payload { msg: &packet[25..], aad: ASSOCIATED_DATA })
            .map_err(|_| anyhow!("authentication/decryption failed"))?;
        self.seen.push_back(nonce);
        if self.seen.len() > RECENT_NONCES {
            self.seen.pop_front();
        }
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutually_authenticated_bidirectional_exchange() {
        let psk: Psk = [73; 32];
        let (handshake, hello) = Initiator::start(&psk);
        let (pending, reply) = accept(&psk, &hello).unwrap();
        let (mut client, finish) = handshake.finish(&psk, &reply).unwrap();
        let mut server = pending.finish(&psk, &finish).unwrap();
        let packet = client.seal("Hello from Windows 🖥".as_bytes()).unwrap();
        assert_eq!(server.open(&packet).unwrap().as_slice(), "Hello from Windows 🖥".as_bytes());
        assert!(server.open(&packet).is_err(), "replay must be rejected");
        assert_eq!(client.open(&server.seal(b"Hello from Linux").unwrap()).unwrap().as_slice(), &b"Hello from Linux"[..]);
    }

    #[test]
    fn invalid_psk_and_modified_packet_fail() {
        let correct = [2; 32];
        let incorrect = [3; 32];
        let (handshake, hello) = Initiator::start(&correct);
        assert!(accept(&incorrect, &hello).is_err());
        let (pending, reply) = accept(&correct, &hello).unwrap();
        let (client, finish) = handshake.finish(&correct, &reply).unwrap();
        let mut server = pending.finish(&correct, &finish).unwrap();
        let mut packet = client.seal(b"secret").unwrap();
        *packet.last_mut().unwrap() ^= 1;
        assert!(server.open(&packet).is_err());
    }

    #[test]
    fn replayed_client_hello_does_not_finish_new_session() {
        let psk = [13; 32];
        let (first, hello) = Initiator::start(&psk);
        let (_pending, response) = accept(&psk, &hello).unwrap();
        let (_session, old_finish) = first.finish(&psk, &response).unwrap();
        let (new_pending, _new_response) = accept(&psk, &hello).unwrap();
        assert!(new_pending.finish(&psk, &old_finish).is_err());
    }

    #[test]
    fn changed_reply_cannot_impersonate_peer() {
        let psk = [7; 32];
        let (handshake, hello) = Initiator::start(&psk);
        let (_server, mut reply) = accept(&psk, &hello).unwrap();
        reply[22] ^= 1;
        assert!(handshake.finish(&psk, &reply).is_err());
    }
}
