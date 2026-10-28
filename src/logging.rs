//! Transfer metadata only: no clipboard contents, authentication tokens or keys.
use std::path::PathBuf;
#[cfg(not(test))]
use std::{
    fs::{self, OpenOptions},
    io::Write,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

pub fn path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("bleclip")
        .join("transfers.log")
}

pub fn event(message: &str) {
    println!("{message}");
    #[cfg(not(test))]
    {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _lock = LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let destination = path();
        let result = (|| -> std::io::Result<()> {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            if fs::metadata(&destination).is_ok_and(|m| m.len() > 5 * 1024 * 1024) {
                let previous = destination.with_extension("log.1");
                if previous.exists() {
                    fs::remove_file(&previous)?;
                }
                fs::rename(&destination, previous)?;
            }
            let mut options = OpenOptions::new();
            options.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(destination)?;
            let time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            writeln!(file, "{time} {message}")
        })();
        if let Err(error) = result {
            eprintln!("Cannot write transfer log: {error}");
        }
    }
}
