use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};
use tokio::sync::watch;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    /// None selects the address of the default IPv4 route.
    pub receive_ip: Option<IpAddr>,
    /// Zero lets the operating system select a free port.
    pub port: u16,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            receive_ip: None,
            port: 38471,
        }
    }
}
pub fn valid_ip(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && ip != IpAddr::V4(Ipv4Addr::BROADCAST)
        && !matches!(ip, IpAddr::V6(addr) if addr.is_unicast_link_local())
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.receive_ip.is_none_or(valid_ip), "enter a unicast local IP address or 'auto' (IPv6 link-local needs a scope and is unsupported)");
        Ok(())
    }
    pub fn addresses(&self) -> Result<(SocketAddr, IpAddr)> {
        self.validate()?;
        if let Some(ip) = self.receive_ip {
            return Ok((SocketAddr::new(ip, self.port), ip));
        }
        // UDP connect selects a route but sends no packets. No DNS or Internet
        // service is contacted; 192.0.2.1 is a documentation-only address.
        let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        probe.connect((Ipv4Addr::new(192, 0, 2, 1), 9))?;
        let ip = probe.local_addr()?.ip();
        ensure!(
            valid_ip(ip),
            "cannot detect a receiving IP; set it in the tray menu"
        );
        Ok((SocketAddr::from((Ipv4Addr::UNSPECIFIED, self.port)), ip))
    }
    pub fn ip_label(&self) -> String {
        self.receive_ip
            .map_or_else(|| "Auto".into(), |ip| ip.to_string())
    }
}

pub struct Control {
    settings: watch::Sender<Settings>,
    status: watch::Sender<String>,
    path: Option<PathBuf>,
    write: Mutex<()>,
}
impl Control {
    pub fn load(path: PathBuf) -> Arc<Self> {
        let settings = (|| -> Result<Settings> {
            if !path.exists() {
                return Ok(Settings::default());
            }
            let bytes = fs::read(&path)?;
            let settings: Settings = serde_json::from_slice(&bytes)?;
            settings.validate()?;
            Ok(settings)
        })()
        .unwrap_or_else(|error| {
            crate::logging::event(&format!("Cannot load IP settings: {error:#}; IP disabled"));
            Settings::default()
        });
        Self::new(settings, Some(path))
    }
    fn new(settings: Settings, path: Option<PathBuf>) -> Arc<Self> {
        let (settings, _) = watch::channel(settings);
        let (status, _) = watch::channel("IP listener: waiting for sharing".into());
        Arc::new(Self {
            settings,
            status,
            path,
            write: Mutex::new(()),
        })
    }
    #[cfg(test)]
    pub(crate) fn memory(settings: Settings) -> Arc<Self> {
        Self::new(settings, None)
    }
    pub fn snapshot(&self) -> Settings {
        self.settings.borrow().clone()
    }
    pub fn subscribe(&self) -> watch::Receiver<Settings> {
        self.settings.subscribe()
    }
    pub fn status(&self) -> String {
        self.status.borrow().clone()
    }
    pub(super) fn set_status(&self, status: String) {
        self.status.send_replace(status);
    }
    pub fn update(&self, change: impl FnOnce(&mut Settings)) -> Result<()> {
        let _lock = self.write.lock().unwrap_or_else(|e| e.into_inner());
        let mut settings = self.snapshot();
        change(&mut settings);
        settings.validate()?;
        if let Some(path) = &self.path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let temp = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
            let result = (|| -> Result<()> {
                fs::write(&temp, serde_json::to_vec_pretty(&settings)?)?;
                fs::rename(&temp, path).context("save IP settings")?;
                Ok(())
            })();
            if result.is_err() {
                let _ = fs::remove_file(&temp);
            }
            result?;
        }
        if self.snapshot() != settings {
            crate::logging::event(&format!(
                "IP settings: enabled={}, receiving IP={}, port={}",
                settings.enabled,
                settings.ip_label(),
                settings.port
            ));
            self.settings.send_replace(settings);
        }
        Ok(())
    }
}
pub fn global() -> Arc<Control> {
    static CONTROL: OnceLock<Arc<Control>> = OnceLock::new();
    CONTROL
        .get_or_init(|| {
            Control::load(
                dirs::config_dir()
                    .unwrap_or_else(std::env::temp_dir)
                    .join("bleclip")
                    .join("ip-transfer.json"),
            )
        })
        .clone()
}
