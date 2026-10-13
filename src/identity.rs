//! Per-installation, persistent public node identifier. Do not copy this file
//! when provisioning the same PSK onto other computers.
use anyhow::{bail, Context, Result};
use std::{env, fs, io::Write, path::{Path, PathBuf}};
use uuid::Uuid;

pub fn default_path() -> Result<PathBuf> {
    if cfg!(windows) {
        let root = env::var_os("APPDATA").or_else(|| env::var_os("USERPROFILE"))
            .context("APPDATA/USERPROFILE unavailable; specify --identity-file")?;
        Ok(PathBuf::from(root).join("bleclip").join("node-id"))
    } else {
        let config = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .context("HOME/XDG_CONFIG_HOME unavailable; specify --identity-file")?;
        Ok(config.join("bleclip").join("node-id"))
    }
}

pub fn load_or_create(path: &Path) -> Result<Uuid> {
    if path.exists() {
        return read(path);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let id = Uuid::new_v4();
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(id.to_string().as_bytes())?;
            file.write_all(b"\n")?;
            file.flush()?;
            println!("Created node identity at {}", path.display());
            Ok(id)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => read(path),
        Err(error) => Err(error).with_context(|| format!("create identity file {}", path.display())),
    }
}

fn read(path: &Path) -> Result<Uuid> {
    let value = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let id = Uuid::parse_str(value.trim()).context("invalid identity UUID")?;
    if id.is_nil() { bail!("nil node id is not permitted"); }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_is_stable() {
        let filename = env::temp_dir().join(format!("bleclip-test-{}", Uuid::new_v4()));
        let first = load_or_create(&filename).unwrap();
        assert_eq!(first, load_or_create(&filename).unwrap());
        fs::remove_file(filename).unwrap();
    }
}
