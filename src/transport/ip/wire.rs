use super::*;
use crate::{
    crypto::{self, Initiator, Session},
    message::COMPRESS_TEXT_ABOVE,
    progress::{Direction, Phase, Transport},
    transport::bulk,
};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const CHUNK: usize = 64 * 1024;
const MAX_FRAME: usize = CHUNK + 1024;
const HANDSHAKE: Duration = Duration::from_secs(8);
const IDLE: Duration = Duration::from_secs(30);
const DATA: u8 = 1;
const FILE_END: u8 = 2;
const END: u8 = 3;
const ACK: u8 = 4;

#[derive(Serialize, Deserialize)]
struct Header {
    id: Uuid,
    origin: Uuid,
    hops: u8,
    #[serde(flatten)]
    body: Body,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum Body {
    Data {
        kind: u8,
        size: u64,
        decoded_size: u64,
        sha256: [u8; 32],
    },
    Files {
        request: Option<Uuid>,
        entries: Vec<FileMetadata>,
    },
}

async fn write<S: AsyncWrite + Unpin>(
    stream: &mut S,
    session: &Session,
    bytes: &[u8],
) -> Result<()> {
    let packet = session.seal_limited(bytes, MAX_FRAME)?;
    timeout(IDLE, async {
        stream.write_u32(packet.len() as u32).await?;
        stream.write_all(&packet).await?;
        Ok::<_, std::io::Error>(())
    })
    .await
    .context("IP write timed out")??;
    Ok(())
}
async fn read<S: AsyncRead + Unpin>(stream: &mut S, session: &mut Session) -> Result<Vec<u8>> {
    timeout(IDLE, async {
        let size = stream.read_u32().await? as usize;
        ensure!((41..=MAX_FRAME).contains(&size), "invalid IP frame length");
        let mut bytes = vec![0; size];
        stream.read_exact(&mut bytes).await?;
        session.open_limited(&bytes, MAX_FRAME)
    })
    .await
    .context("IP read timed out")?
}

pub(super) async fn send<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    service: &IpService,
    peer: Uuid,
    endpoint: &Endpoint,
    job: &Job,
) -> Result<()> {
    let mut session = timeout(HANDSHAKE, async {
        let (initiator, hello) = Initiator::start_ip(&service.psk);
        bulk::write_frame(&mut stream, &hello).await?;
        let (mut session, finish) =
            initiator.finish(&service.psk, &bulk::read_frame(&mut stream).await?)?;
        bulk::write_frame(&mut stream, &finish).await?;
        let mut binding = MAGIC.to_vec();
        binding.extend_from_slice(service.own_id.as_bytes());
        binding.extend_from_slice(peer.as_bytes());
        binding.extend_from_slice(&endpoint.token);
        bulk::write_frame(&mut stream, &session.seal(&binding)?).await?;
        ensure!(
            bulk::read_message(&mut stream, &mut session).await?
                == crate::message::Message::Identity(peer),
            "IP peer identity mismatch"
        );
        Ok::<_, anyhow::Error>(session)
    })
    .await
    .context("IP authentication timed out")??;
    let mut progress = service
        .transfers
        .reporter(peer, Direction::Sending)
        .with_transport(Transport::Ip);
    match job {
        Job::Update(update) => {
            update.validate_ip()?;
            let mut kind = update.kind;
            let decoded_size = update.bytes.len() as u64;
            let compressed = if kind == Kind::Text && update.bytes.len() > COMPRESS_TEXT_ABOVE {
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(&update.bytes)?;
                kind = Kind::CompressedText;
                Some(encoder.finish()?)
            } else {
                None
            };
            let bytes = compressed.as_deref().unwrap_or(&update.bytes);
            let header = Header {
                id: update.id,
                origin: update.origin,
                hops: update.hops,
                body: Body::Data {
                    kind: kind as u8,
                    size: bytes.len() as u64,
                    decoded_size,
                    sha256: Sha256::digest(bytes).into(),
                },
            };
            write(&mut stream, &session, &serde_json::to_vec(&header)?).await?;
            progress.update(update.id, kind, 0, bytes.len(), Phase::Transferring, 1);
            let mut sent = 0;
            for chunk in bytes.chunks(CHUNK) {
                let mut packet = Vec::with_capacity(chunk.len() + 1);
                packet.push(DATA);
                packet.extend_from_slice(chunk);
                write(&mut stream, &session, &packet).await?;
                sent += chunk.len();
                progress.update(update.id, kind, sent, bytes.len(), Phase::Transferring, 1);
            }
            write(&mut stream, &session, &[END]).await?;
            progress.update(
                update.id,
                kind,
                bytes.len(),
                bytes.len(),
                Phase::AwaitingAck,
                1,
            );
        }
        Job::Files {
            id,
            request,
            paths,
            entries,
            versions,
        } => {
            ensure!(
                files::versions(paths)? == *versions && files::metadata_ip(paths)? == *entries,
                "source files changed"
            );
            let header = Header {
                id: *id,
                origin: service.own_id,
                hops: MAX_HOPS,
                body: Body::Files {
                    request: *request,
                    entries: entries.clone(),
                },
            };
            write(&mut stream, &session, &serde_json::to_vec(&header)?).await?;
            let total = total(entries)?;
            let mut sent = 0;
            let kind = if request.is_some() {
                Kind::FileResponse
            } else {
                Kind::Files
            };
            progress.update(*id, kind, 0, total, Phase::Transferring, 1);
            let mut buffer = vec![0; CHUNK + 1];
            buffer[0] = DATA;
            for (path, entry) in paths.iter().zip(entries) {
                let mut file = tokio::fs::File::from_std(files::open_regular(path)?);
                let mut remaining = entry.size;
                let mut hash = Sha256::new();
                while remaining > 0 {
                    let limit = remaining.min(CHUNK as u64) as usize;
                    let n = file.read(&mut buffer[1..limit + 1]).await?;
                    ensure!(n > 0, "source file truncated");
                    hash.update(&buffer[1..n + 1]);
                    write(&mut stream, &session, &buffer[..n + 1]).await?;
                    remaining -= n as u64;
                    sent += n;
                    progress.update(*id, kind, sent, total, Phase::Transferring, 1);
                }
                ensure!(
                    file.read(&mut buffer[..1]).await? == 0,
                    "source file grew during transfer"
                );
                buffer[0] = DATA;
                let mut end = vec![FILE_END];
                end.extend_from_slice(&hash.finalize());
                write(&mut stream, &session, &end).await?;
            }
            ensure!(
                files::versions(paths)? == *versions,
                "source files changed during transfer"
            );
            write(&mut stream, &session, &[END]).await?;
            progress.update(*id, kind, total, total, Phase::AwaitingAck, 1);
        }
    }
    let ack = read(&mut stream, &mut session).await?;
    ensure!(
        ack.len() == 17 && ack[0] == ACK && Uuid::from_slice(&ack[1..])? == job.id(),
        "invalid IP transfer receipt"
    );
    // Keep the same reporter/source through completion so the tray has one row.
    progress.complete();
    Ok(())
}

fn total(entries: &[FileMetadata]) -> Result<usize> {
    let total = entries
        .iter()
        .try_fold(0u64, |n, e| n.checked_add(e.size))
        .context("file size overflow")?;
    Ok(total
        .try_into()
        .context("file sizes exceed platform address range")?)
}

pub(super) async fn receive<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    service: Arc<IpService>,
) -> Result<()> {
    let mut changes = service.control.subscribe();
    let settings = changes.borrow_and_update().clone();
    ensure!(settings.enabled, "IP exchange disabled");
    let (mut session, peer, request_scope) = timeout(HANDSHAKE, async {
        let (pending, reply) =
            crypto::accept_ip(&service.psk, &bulk::read_frame(&mut stream).await?)?;
        bulk::write_frame(&mut stream, &reply).await?;
        let mut session = pending.finish(&service.psk, &bulk::read_frame(&mut stream).await?)?;
        let binding = session.open(&bulk::read_frame(&mut stream).await?)?;
        ensure!(
            binding.len() == 68 && &binding[..4] == MAGIC,
            "invalid IP binding"
        );
        let peer = Uuid::from_slice(&binding[4..20])?;
        ensure!(
            !peer.is_nil()
                && peer != service.own_id
                && Uuid::from_slice(&binding[20..36])? == service.own_id,
            "wrong IP destination/identity"
        );
        let token: [u8; 32] = binding[36..68].try_into()?;
        let request_scope = {
            let state = service.state.lock().unwrap_or_else(|e| e.into_inner());
            let ready = state.ready.as_ref().context("IP listener is not ready")?;
            ensure!(ready.settings == settings, "IP settings changed");
            if token == ready.endpoint.token {
                None
            } else {
                Some(
                    *state
                        .requests
                        .iter()
                        .find(|(_, r)| {
                            r.token == token && r.owner == peer && Instant::now() < r.expires
                        })
                        .context("IP capability expired or unauthorized")?
                        .0,
                )
            }
        };
        bulk::write_message(
            &mut stream,
            &session,
            crate::message::Message::Identity(service.own_id),
        )
        .await?;
        Ok::<_, anyhow::Error>((session, peer, request_scope))
    })
    .await
    .context("IP authentication timed out")??;
    let transfer = async {
        let bytes = read(&mut stream, &mut session).await?;
        ensure!(bytes.len() <= 16 * 1024, "IP transfer header too large");
        let header: Header = serde_json::from_slice(&bytes)?;
        ensure!(
            !header.id.is_nil() && !header.origin.is_nil() && header.hops <= MAX_HOPS,
            "invalid IP transfer header"
        );
        let mut progress = service
            .transfers
            .reporter(peer, Direction::Receiving)
            .with_transport(Transport::Ip);
        let update = match header.body {
            Body::Data {
                kind,
                size,
                decoded_size,
                sha256,
            } => {
                ensure!(
                    request_scope.is_none(),
                    "paste capability only permits its requested files"
                );
                let kind = Kind::from_byte(kind)?;
                ensure!(
                    matches!(
                        kind,
                        Kind::Text | Kind::Png | Kind::CompressedText | Kind::Files
                    ),
                    "invalid IP data type"
                );
                service.allow(kind)?;
                let expected: usize = size
                    .try_into()
                    .context("payload exceeds platform address range")?;
                let mut bytes = Vec::new();
                let mut hash = Sha256::new();
                progress.update(header.id, kind, 0, expected, Phase::Transferring, 1);
                while bytes.len() < expected {
                    let packet = read(&mut stream, &mut session).await?;
                    ensure!(
                        packet.len() > 1
                            && packet[0] == DATA
                            && packet.len() - 1 <= expected - bytes.len(),
                        "invalid IP data chunk"
                    );
                    bytes
                        .try_reserve(packet.len() - 1)
                        .context("not enough memory for clipboard data")?;
                    hash.update(&packet[1..]);
                    bytes.extend_from_slice(&packet[1..]);
                    progress.update(
                        header.id,
                        kind,
                        bytes.len(),
                        expected,
                        Phase::Transferring,
                        1,
                    );
                }
                ensure!(
                    read(&mut stream, &mut session).await? == [END],
                    "IP data missing completion"
                );
                let actual: [u8; 32] = hash.finalize().into();
                ensure!(actual == sha256, "IP payload digest mismatch");
                let kind = if kind == Kind::CompressedText {
                    let decoded: usize = decoded_size
                        .try_into()
                        .context("text exceeds platform address range")?;
                    let mut decoder = ZlibDecoder::new(bytes.as_slice());
                    let mut text = Vec::new();
                    let mut buffer = vec![0; CHUNK];
                    loop {
                        let n = decoder.read(&mut buffer)?;
                        if n == 0 {
                            break;
                        }
                        ensure!(
                            n <= decoded.saturating_sub(text.len()),
                            "compressed text exceeds advertised decoded size"
                        );
                        text.try_reserve(n).context("not enough memory for text")?;
                        text.extend_from_slice(&buffer[..n]);
                    }
                    ensure!(
                        text.len() == decoded && decoder.total_in() == bytes.len() as u64,
                        "invalid compressed IP text length"
                    );
                    bytes = text;
                    Kind::Text
                } else {
                    kind
                };
                Update {
                    id: header.id,
                    origin: header.origin,
                    hops: header.hops,
                    kind,
                    bytes: bytes.into(),
                    via_ip: true,
                }
            }
            Body::Files { request, entries } => {
                service.allow(Kind::Files)?;
                files::validate_metadata_ip(&entries)?;
                if let Some(scope) = request_scope {
                    ensure!(request == Some(scope), "IP request identifier mismatch");
                }
                if let Some(request) = request {
                    let state = service.state.lock().unwrap_or_else(|e| e.into_inner());
                    let pending = state
                        .requests
                        .get(&request)
                        .context("file paste no longer pending")?;
                    ensure!(
                        pending.owner == peer
                            && header.origin == peer
                            && Instant::now() < pending.expires
                            && pending.entries == entries,
                        "IP file response differs from paste request"
                    );
                }
                let save = files::StreamSave::new(&service.receive_dir, header.id, &entries)?;
                let total = total(&entries)?;
                let mut received = 0;
                let kind = if request.is_some() {
                    Kind::FileResponse
                } else {
                    Kind::Files
                };
                progress.update(header.id, kind, 0, total, Phase::Transferring, 1);
                for (index, entry) in entries.iter().enumerate() {
                    let mut file = tokio::fs::File::from_std(save.create(index)?);
                    let mut remaining = entry.size;
                    let mut hash = Sha256::new();
                    while remaining > 0 {
                        let packet = read(&mut stream, &mut session).await?;
                        ensure!(
                            packet.len() > 1
                                && packet[0] == DATA
                                && (packet.len() - 1) as u64 <= remaining,
                            "invalid IP file chunk"
                        );
                        file.write_all(&packet[1..]).await?;
                        hash.update(&packet[1..]);
                        remaining -= (packet.len() - 1) as u64;
                        received += packet.len() - 1;
                        progress.update(header.id, kind, received, total, Phase::Transferring, 1);
                    }
                    let end = read(&mut stream, &mut session).await?;
                    let digest: [u8; 32] = hash.finalize().into();
                    ensure!(
                        end.len() == 33 && end[0] == FILE_END && end[1..] == digest,
                        "IP file digest mismatch"
                    );
                    file.sync_all().await?;
                }
                ensure!(
                    read(&mut stream, &mut session).await? == [END],
                    "IP file transfer missing completion"
                );
                let paths = save.finish()?;
                service
                    .state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .received
                    .insert(header.id, Received { request, paths });
                Update {
                    id: header.id,
                    origin: header.origin,
                    hops: header.hops,
                    kind,
                    bytes: request
                        .map_or_else(Vec::new, |id| id.as_bytes().to_vec())
                        .into(),
                    via_ip: true,
                }
            }
        };
        update.validate_ip()?;
        timeout(IDLE, service.from_peers.send(update))
            .await
            .context("clipboard router stalled")?
            .context("clipboard router stopped")?;
        let mut ack = vec![ACK];
        ack.extend_from_slice(header.id.as_bytes());
        write(&mut stream, &session, &ack).await?;
        progress.complete();
        Ok(())
    };
    tokio::select! { result=transfer=>result, _=changes.changed()=>anyhow::bail!("IP settings changed during receive") }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn interrupted_and_bad_digest_streams_never_publish_files() {
        let root = std::env::temp_dir().join(format!("bleclip-partial-{}", Uuid::new_v4()));
        let (tx, mut rx) = mpsc::channel(8);
        let (bus, _) = broadcast::channel(8);
        let control = settings::Control::memory(settings::Settings {
            enabled: true,
            receive_ip: Some("127.0.0.1".parse().unwrap()),
            port: 0,
        });
        let (service, _runtime) = IpService::start(
            [21; 32],
            Uuid::new_v4(),
            tx,
            bus,
            Connections::new(),
            root.clone(),
            control,
            (true, true, true),
        );
        let mut changes = service.subscribe();
        let endpoint = timeout(Duration::from_secs(3), async {
            loop {
                if let Some(endpoint) = changes.borrow_and_update().clone() {
                    break endpoint;
                }
                changes.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        for corrupt in [false, true] {
            let mut stream = TcpStream::connect(endpoint.address).await.unwrap();
            let (initiator, hello) = Initiator::start_ip(&service.psk);
            bulk::write_frame(&mut stream, &hello).await.unwrap();
            let (mut session, finish) = initiator
                .finish(&service.psk, &bulk::read_frame(&mut stream).await.unwrap())
                .unwrap();
            bulk::write_frame(&mut stream, &finish).await.unwrap();
            let mut binding = MAGIC.to_vec();
            binding.extend(Uuid::new_v4().as_bytes());
            binding.extend(service.own_id.as_bytes());
            binding.extend(endpoint.token);
            bulk::write_frame(&mut stream, &session.seal(&binding).unwrap())
                .await
                .unwrap();
            bulk::read_message(&mut stream, &mut session).await.unwrap();
            let header = Header {
                id: Uuid::new_v4(),
                origin: Uuid::new_v4(),
                hops: MAX_HOPS,
                body: Body::Files {
                    request: None,
                    entries: vec![FileMetadata {
                        name: "partial.txt".into(),
                        size: 2,
                    }],
                },
            };
            write(&mut stream, &session, &serde_json::to_vec(&header).unwrap())
                .await
                .unwrap();
            if corrupt {
                write(&mut stream, &session, &[DATA, b'a', b'b'])
                    .await
                    .unwrap();
                let mut bad = vec![FILE_END];
                bad.extend([0; 32]);
                write(&mut stream, &session, &bad).await.unwrap();
                assert!(read(&mut stream, &mut session).await.is_err());
            } else {
                write(&mut stream, &session, &[DATA, b'a']).await.unwrap();
            }
            drop(stream);
            // Let the receiver observe EOF and drop its private staging directory.
            timeout(Duration::from_secs(3), async {
                loop {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    if root.exists() && std::fs::read_dir(&root).unwrap().next().is_none() {
                        break;
                    }
                }
            })
            .await
            .unwrap();
            assert!(rx.try_recv().is_err());
        }
        drop(_runtime);
        std::fs::remove_dir_all(root).unwrap();
    }
}
