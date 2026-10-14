#![cfg_attr(all(windows, feature = "tray-gui"), windows_subsystem = "windows")]
mod clipboard;
mod crypto;
mod files;
mod identity;
mod message;
mod platform;
mod router;
mod status;
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
    sync::Arc,
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
    /// Symmetric peer; automatically uses scan-only mode on Windows adapters without BLE peripheral support.
    Peer(PeerOptions),
    /// Tray peer; auto-detects supported Bluetooth roles (left-click to pause/resume).
    Tray(PeerOptions),
    /// Report Bluetooth LE radio role capabilities (especially on Windows).
    Diagnose,
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
    connections: Arc<status::Connections>,
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
    let mut advertise = !no_advertise;
    let scan = !no_scan;
    let allow_images = !no_images;
    if !(1..=32).contains(&max_inbound) || !(1..=32).contains(&max_outbound) {
        bail!("max-inbound and max-outbound must both be between 1 and 32");
    }
    if !advertise && !scan {
        bail!("peer needs at least one BLE role");
    }
    // Windows can scan/connect even when a GATT peripheral cannot advertise.
    // Check the actual adapter rather than repeatedly invoking unsupported APIs.
    if advertise {
        match platform::capabilities().await {
            Ok(capability) => {
                let (selected_advertise, _) = platform::select_roles(advertise, scan, capability)?;
                if !selected_advertise {
                    eprintln!(
                        "BLEClip: this Bluetooth adapter cannot advertise a connectable BLE GATT service (HRESULT 0x8007013C). \n                         Continuing in central-only mode; clipboard sharing stays bidirectional. \n                         Another BLEClip peer must advertise (for example, Linux)."
                    );
                }
                advertise = selected_advertise;
            }
            Err(err) => {
                // If the capability API is unavailable, prefer the working
                // central/client mode when it is allowed.
                if scan {
                    eprintln!(
                        "BLEClip: cannot query Bluetooth peripheral support ({err:#}). \n                         Using central-only mode to avoid unsupported advertising; \n                         run 'bleclip diagnose' for details."
                    );
                    advertise = false;
                } else {
                    eprintln!(
                        "BLEClip: cannot query Bluetooth peripheral support ({err:#}); \n                         attempting peripheral-only mode."
                    );
                }
            }
        }
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
    println!(
        "BLEClip {}, node {own_id}, encrypted mesh enabled. Press Ctrl+C to quit.",
        env!("CARGO_PKG_VERSION")
    );
    println!(
        "Images: {allow_images}; files: {allow_files}; incoming files: {}",
        receive_dir.display()
    );
    println!("Discovery: {}, advertising: {}", scan, advertise);
    connections.set_roles(scan, advertise);

    let advertising = if advertise {
        let updates = to_peers_tx.clone();
        let sender = from_peers_tx.clone();
        let name = name.clone();
        let server_connections = Arc::clone(&connections);
        Some(tokio::spawn(async move {
            loop {
                if let Err(error) = transport::server::run(
                    psk,
                    name.clone(),
                    own_id,
                    max_inbound,
                    sender.clone(),
                    updates.clone(),
                    Arc::clone(&server_connections),
                )
                .await
                {
                    let details = format!("{error:#}");
                    if platform::is_unsupported_peripheral_error(&details) {
                        eprintln!(
                            "BLEClip: GATT advertising unsupported (HRESULT 0x8007013C). \n                             Disabling peripheral advertising; central scanning remains active. \n                             Connect to another BLEClip peer advertising its service."
                        );
                        break;
                    }
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
        let client_connections = Arc::clone(&connections);
        Some(tokio::spawn(async move {
            loop {
                if let Err(error) = transport::client::run(
                    psk,
                    name.clone(),
                    own_id,
                    max_outbound,
                    sender.clone(),
                    updates.clone(),
                    Arc::clone(&client_connections),
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
    connections.reset();
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
        Command::Diagnose => {
            match platform::capabilities().await {
                Ok(Some(info)) => {
                    println!("Windows BLE adapter capabilities:");
                    println!("  LE supported: {}", info.low_energy);
                    println!("  Central/client role supported: {}", info.central);
                    println!("  Peripheral/GATT server role supported: {}", info.peripheral);
                    if !info.peripheral {
                        println!("Windows cannot host connectable GATT services with this adapter (possible 0x8007013C).");
                        println!("BLEClip peer and tray will scan/connect automatically, but need another advertising peer.");
                    }
                }
                Ok(None) => println!(
                    "Non-Windows adapter: peripheral capabilities are driver-dependent. \n                     BLEClip uses BlueZ and tries both advertising and scanning."
                ),
                Err(err) => eprintln!("Unable to query Bluetooth capabilities: {err:#}"),
            }
            Ok(())
        }
        Command::Peer(options) => run_peer(options, None, status::Connections::new()).await,
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
                status::Connections::new(),
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
                status::Connections::new(),
            )
            .await
        }
    }
}
