#![cfg_attr(all(windows, feature = "tray-gui"), windows_subsystem = "windows")]
mod clipboard;
mod crypto;
mod files;
mod identity;
mod message;
mod router;
mod transfer;
mod transport;
mod tray;
mod wire;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use clipboard::Direction;
use crypto::Psk;
use rand::{rngs::OsRng, RngCore};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    sync::{broadcast, mpsc, watch},
    time::sleep,
};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    name = "bleclip",
    version,
    about = "Encrypted serverless BLE text, image and file clipboard mesh"
)]
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
    /// Symmetric peer: advertise and scan, synchronizing with other peers (headless).
    Peer(PeerOptions),
    /// System tray peer: left-click the icon to pause/resume all clipboard sharing.
    Tray(PeerOptions),
    /// Compatibility shortcut for peer --no-scan (protocol v3; no v2 interop).
    Serve {
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long, default_value = "BLEClip")]
        name: String,
        #[arg(long, value_enum, default_value_t = Direction::Both)]
        direction: Direction,
        #[arg(long)]
        sync_files: bool,
        #[arg(long)]
        no_images: bool,
        #[arg(long)]
        receive_dir: Option<PathBuf>,
    },
    /// Compatibility shortcut for peer --no-advertise (protocol v3; no v2 interop).
    Connect {
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long, default_value = "BLEClip")]
        name: String,
        #[arg(long, value_enum, default_value_t = Direction::Both)]
        direction: Direction,
        #[arg(long)]
        sync_files: bool,
        #[arg(long)]
        no_images: bool,
        #[arg(long)]
        receive_dir: Option<PathBuf>,
    },
}

#[derive(Args, Clone)]
pub(crate) struct PeerOptions {
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
    /// Permit automatic file-list transfer (off by default to avoid unexpected disk writes).
    #[arg(long)]
    sync_files: bool,
    /// Disable automatic clipboard image synchronization.
    #[arg(long)]
    no_images: bool,
    /// Directory where received files are saved in individual transfer subdirectories.
    #[arg(long)]
    receive_dir: Option<PathBuf>,
}

fn create_key(path: &Path) -> Result<()> {
    let mut psk: Psk = [0; 32];
    OsRng.fill_bytes(&mut psk);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot create {} (no overwriting)", path.display()))?;
    file.write_all(hex::encode(psk).as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    psk.zeroize();
    println!(
        "Key saved to {}; transfer it to each trusted peer via a secure channel",
        path.display()
    );
    Ok(())
}

fn read_key(path: &Path) -> Result<Psk> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("read key {}", path.display()))?;
    let bytes = hex::decode(contents.trim()).context("key must contain 64 hex characters")?;
    if bytes.len() != 32 {
        bail!("key must be exactly 32 bytes");
    }
    let mut psk = [0u8; 32];
    psk.copy_from_slice(&bytes);
    Ok(psk)
}

pub(crate) async fn run_peer(
    config: PeerOptions,
    mut shutdown: Option<watch::Receiver<tray::TrayState>>,
) -> Result<()> {
    let PeerOptions {
        key_file,
        name,
        direction,
        identity_file,
        max_inbound,
        max_outbound,
        no_advertise,
        no_scan,
        sync_files: allow_files,
        no_images,
        receive_dir,
    } = config;
    let advertise = !no_advertise;
    let scan = !no_scan;
    let allow_images = !no_images;
    if !(1..=32).contains(&max_inbound) || !(1..=32).contains(&max_outbound) {
        bail!("max-inbound and max-outbound must both be between 1 and 32");
    }
    if !advertise && !scan {
        bail!("peer needs at least one BLE role");
    }
    let psk = read_key(&key_file)?;
    let id_path = match identity_file {
        Some(path) => path,
        None => identity::default_path()?,
    };
    let own_id = identity::load_or_create(&id_path)?;
    let (from_peers_tx, from_peers_rx) = mpsc::channel(256);
    let (to_peers_tx, _) = broadcast::channel(256);

    let receive_dir = match receive_dir {
        Some(path) => path,
        None => default_receive_dir()?,
    };
    println!("BLEClip v3, node {own_id}, encrypted mesh enabled. Press Ctrl+C to quit.");
    println!(
        "Images: {allow_images}; files: {allow_files}; incoming files: {}",
        receive_dir.display()
    );
    println!("Discovery: {}, advertising: {}", scan, advertise);

    let advertising = if advertise {
        let updates = to_peers_tx.clone();
        let sender = from_peers_tx.clone();
        let name = name.clone();
        Some(tokio::spawn(async move {
            loop {
                if let Err(error) = transport::server::run(
                    psk,
                    name.clone(),
                    own_id,
                    max_inbound,
                    sender.clone(),
                    updates.clone(),
                )
                .await
                {
                    eprintln!("BLE advertising unavailable: {error:#}; retrying");
                }
                sleep(Duration::from_secs(8)).await;
            }
        }))
    } else {
        None
    };
    let scanning = if scan {
        let updates = to_peers_tx.clone();
        let sender = from_peers_tx.clone();
        Some(tokio::spawn(async move {
            loop {
                if let Err(error) = transport::client::run(
                    psk,
                    name.clone(),
                    own_id,
                    max_outbound,
                    sender.clone(),
                    updates.clone(),
                )
                .await
                {
                    eprintln!("BLE scanning unavailable: {error:#}; retrying");
                }
                sleep(Duration::from_secs(8)).await;
            }
        }))
    } else {
        None
    };

    // Exactly one owner of the desktop clipboard, even if many BLE links exist.
    let result = tokio::select! {
        result = router::run(own_id, direction, from_peers_rx, to_peers_tx, allow_images, allow_files, receive_dir) => result,
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = async {
            match shutdown.as_mut() {
                Some(rx) => loop {
                    let state = *rx.borrow_and_update();
                    if !state.enabled || state.quit { break; }
                    if rx.changed().await.is_err() { break; }
                },
                None => std::future::pending::<()>().await,
            }
        } => Ok(()),
    };
    // Stop both BLE roles before returning: pause also drops in-flight transfers.
    if let Some(task) = advertising {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = scanning {
        task.abort();
        let _ = task.await;
    }
    result
}

fn default_receive_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE").context("USERPROFILE not set")?;
    #[cfg(not(windows))]
    let home = std::env::var_os("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home).join("Downloads").join("BLEClip"))
}

#[tokio::main]
async fn main() -> Result<()> {
    // The GUI-subsystem Windows build can be launched directly by double-click.
    // Place bleclip.key beside bleclip-tray.exe; other arguments are still supported.
    #[cfg(all(windows, feature = "tray-gui"))]
    let cli = if std::env::args_os().len() == 1 {
        let key_file = std::env::current_exe()?.with_file_name("bleclip.key");
        if !key_file.is_file() {
            tray::show_error("No bleclip.key found next to bleclip-tray.exe. Generate it using bleclip.exe keygen --output bleclip.key and copy the key beside the tray launcher.");
            bail!("no bleclip.key file beside the tray launcher");
        }
        Cli {
            command: Command::Tray(PeerOptions {
                key_file,
                name: "BLEClip".into(),
                direction: Direction::Both,
                identity_file: None,
                max_inbound: 16,
                max_outbound: 8,
                no_advertise: false,
                no_scan: false,
                sync_files: false,
                no_images: false,
                receive_dir: None,
            }),
        }
    } else {
        Cli::parse()
    };
    #[cfg(not(all(windows, feature = "tray-gui")))]
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen { output } => create_key(&output),
        Command::Peer(options) => run_peer(options, None).await,
        Command::Tray(options) => tray::run(options),
        Command::Serve {
            key_file,
            name,
            direction,
            sync_files,
            no_images,
            receive_dir,
        } => {
            run_peer(
                PeerOptions {
                    key_file,
                    name,
                    direction,
                    identity_file: None,
                    max_inbound: 16,
                    max_outbound: 8,
                    no_advertise: false,
                    no_scan: true,
                    sync_files,
                    no_images,
                    receive_dir,
                },
                None,
            )
            .await
        }
        Command::Connect {
            key_file,
            name,
            direction,
            sync_files,
            no_images,
            receive_dir,
        } => {
            run_peer(
                PeerOptions {
                    key_file,
                    name,
                    direction,
                    identity_file: None,
                    max_inbound: 16,
                    max_outbound: 8,
                    no_advertise: true,
                    no_scan: false,
                    sync_files,
                    no_images,
                    receive_dir,
                },
                None,
            )
            .await
        }
    }
}
