mod clipboard;
mod crypto;
mod identity;
mod message;
mod router;
mod transport;
mod wire;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use clipboard::Direction;
use crypto::Psk;
use rand::{rngs::OsRng, RngCore};
use std::{fs, io::Write, path::{Path, PathBuf}, time::Duration};
use tokio::{sync::{broadcast, mpsc}, time::sleep};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(name = "bleclip", version, about = "Serverless multi-peer encrypted clipboard mesh over BLE")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a random PSK. Provision the same key to every trusted peer.
    Keygen {
        #[arg(long)]
        output: PathBuf,
    },
    /// Symmetric peer: advertise a GATT service and scan/connect to other peers.
    Peer {
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long, default_value = "BLEClip")]
        name: String,
        #[arg(long, value_enum, default_value_t = Direction::Both)]
        direction: Direction,
        /// Independently generated per-device ID file (auto-created on first run).
        #[arg(long)]
        identity_file: Option<PathBuf>,
        #[arg(long, default_value_t = 16)]
        max_inbound: usize,
        #[arg(long, default_value_t = 8)]
        max_outbound: usize,
        /// Skip GATT peripheral role (use if advertising isn't supported).
        #[arg(long, conflicts_with = "no_scan")]
        no_advertise: bool,
        /// Skip BLE central role (use if simultaneous scanning isn't supported).
        #[arg(long)]
        no_scan: bool,
    },
    /// Compatibility shortcut for peer --no-scan (protocol v2; no v1 interop).
    Serve {
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long, default_value = "BLEClip")]
        name: String,
        #[arg(long, value_enum, default_value_t = Direction::Both)]
        direction: Direction,
    },
    /// Compatibility shortcut for peer --no-advertise (protocol v2; no v1 interop).
    Connect {
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long, default_value = "BLEClip")]
        name: String,
        #[arg(long, value_enum, default_value_t = Direction::Both)]
        direction: Direction,
    },
}

fn create_key(path: &Path) -> Result<()> {
    let mut psk: Psk = [0; 32];
    OsRng.fill_bytes(&mut psk);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)
        .with_context(|| format!("cannot create {} (no overwriting)", path.display()))?;
    file.write_all(hex::encode(psk).as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    psk.zeroize();
    println!("Key saved to {}; transfer it to each trusted peer via a secure channel", path.display());
    Ok(())
}

fn read_key(path: &Path) -> Result<Psk> {
    let contents = fs::read_to_string(path).with_context(|| format!("read key {}", path.display()))?;
    let bytes = hex::decode(contents.trim()).context("key must contain 64 hex characters")?;
    if bytes.len() != 32 { bail!("key must be exactly 32 bytes"); }
    let mut psk = [0u8; 32];
    psk.copy_from_slice(&bytes);
    Ok(psk)
}

async fn run_peer(
    key_file: PathBuf,
    name: String,
    direction: Direction,
    identity_file: Option<PathBuf>,
    max_inbound: usize,
    max_outbound: usize,
    advertise: bool,
    scan: bool,
) -> Result<()> {
    if !(1..=32).contains(&max_inbound) || !(1..=32).contains(&max_outbound) {
        bail!("max-inbound and max-outbound must both be between 1 and 32");
    }
    if !advertise && !scan { bail!("peer needs at least one BLE role"); }
    let psk = read_key(&key_file)?;
    let id_path = match identity_file {
        Some(path) => path,
        None => identity::default_path()?,
    };
    let own_id = identity::load_or_create(&id_path)?;
    let (from_peers_tx, from_peers_rx) = mpsc::channel(256);
    let (to_peers_tx, _) = broadcast::channel(256);

    println!("BLEClip v2, node {own_id}, encrypted mesh enabled. Press Ctrl+C to quit.");
    println!("Discovery: {}, advertising: {}", scan, advertise);

    if advertise {
        let updates = to_peers_tx.clone();
        let sender = from_peers_tx.clone();
        let name = name.clone();
        tokio::spawn(async move {
            loop {
                if let Err(error) = transport::server::run(
                    psk, name.clone(), own_id, max_inbound, sender.clone(), updates.clone(),
                ).await {
                    eprintln!("BLE advertising unavailable: {error:#}; retrying");
                }
                sleep(Duration::from_secs(8)).await;
            }
        });
    }
    if scan {
        let updates = to_peers_tx.clone();
        let sender = from_peers_tx.clone();
        tokio::spawn(async move {
            loop {
                if let Err(error) = transport::client::run(
                    psk, name.clone(), own_id, max_outbound, sender.clone(), updates.clone(),
                ).await {
                    eprintln!("BLE scanning unavailable: {error:#}; retrying");
                }
                sleep(Duration::from_secs(8)).await;
            }
        });
    }

    // Exactly one owner of the desktop clipboard, even if many BLE links exist.
    tokio::select! {
        result = router::run(own_id, direction, from_peers_rx, to_peers_tx) => result,
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen { output } => create_key(&output),
        Command::Peer { key_file, name, direction, identity_file, max_inbound, max_outbound, no_advertise, no_scan } => {
            run_peer(key_file, name, direction, identity_file, max_inbound, max_outbound, !no_advertise, !no_scan).await
        }
        Command::Serve { key_file, name, direction } => {
            run_peer(key_file, name, direction, None, 16, 8, true, false).await
        }
        Command::Connect { key_file, name, direction } => {
            run_peer(key_file, name, direction, None, 16, 8, false, true).await
        }
    }
}
