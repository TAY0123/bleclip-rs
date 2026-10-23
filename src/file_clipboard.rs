//! Native delayed file-list rendering. The callback runs on a desktop worker,
//! while the router remains free to receive the requested BLE file contents.
use anyhow::{Context, Result};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

pub type Fetch = Box<dyn Fn() -> Result<Vec<PathBuf>> + Send>;
pub struct LazyFiles {
    alive: Arc<AtomicBool>,
}
impl LazyFiles {
    pub fn offer(fetch: Fetch) -> Result<Self> {
        let alive = Arc::new(AtomicBool::new(true));
        let worker_alive = alive.clone();
        let (ready, started) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("bleclip-file-clipboard".into())
            .spawn(move || {
                #[cfg(target_os = "linux")]
                let result = linux::run(fetch, worker_alive.clone(), ready.clone());
                #[cfg(windows)]
                let result = windows::run(fetch, worker_alive.clone(), ready.clone());
                worker_alive.store(false, Ordering::SeqCst);
                if let Err(err) = result {
                    let _ = ready.send(Err(format!("{err:#}")));
                    eprintln!("Delayed file clipboard: {err:#}");
                }
            })?;
        let owner = Self { alive };
        started
            .recv_timeout(Duration::from_secs(10))
            .context("starting delayed file clipboard")?
            .map_err(anyhow::Error::msg)?;
        Ok(owner)
    }
    pub fn owns_clipboard(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}
impl Drop for LazyFiles {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
    }
}
