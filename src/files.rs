//! Safe serialization and extraction of copied desktop file lists.
//! Files are regular files only (no directories or symlinks), and are stored
//! in a uniquely named directory beneath the configured receive directory.
use crate::message::MAX_FILES;
use anyhow::{ensure, Context, Result};
use std::{
    collections::HashSet,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

const MAX_ENTRIES: usize = 16;
const MAX_NAME: usize = 240;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    pub name: String,
    pub data: Vec<u8>,
}

fn name_for(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "received-file".to_string());
    safe_name(&name)
}

/// Removes path separators, control characters and Windows reserved basenames.
pub fn safe_name(raw: &str) -> String {
    let mut name: String = raw
        .chars()
        .map(|ch| {
            if ch.is_control() || matches!(ch, '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*')
            {
                '_'
            } else {
                ch
            }
        })
        .collect();
    name = name
        .trim_matches(|ch: char| ch == ' ' || ch == '.')
        .to_string();
    if name.is_empty() || name == "." || name == ".." {
        name = "received-file".to_string();
    }
    while name.len() > MAX_NAME {
        name.pop();
    }
    let basename = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    if matches!(
        basename.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    ) {
        name.insert(0, '_');
    }
    name
}

pub fn encode_paths(paths: &[PathBuf]) -> Result<Vec<u8>> {
    ensure!(
        !paths.is_empty() && paths.len() <= MAX_ENTRIES,
        "too many files selected (max 16)"
    );
    let mut out = Vec::new();
    out.extend_from_slice(&(paths.len() as u16).to_be_bytes());
    for path in paths {
        let info =
            fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
        ensure!(
            info.file_type().is_file(),
            "only regular, non-symlink files are supported: {}",
            path.display()
        );
        let name = name_for(path);
        ensure!(name.len() <= MAX_NAME, "filename too long");
        ensure!(
            info.len() <= (MAX_FILES - out.len()) as u64,
            "file bundle exceeds {} bytes",
            MAX_FILES
        );
        let available = MAX_FILES.saturating_sub(out.len() + name.len() + 6);
        let file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        ensure!(
            file.metadata()?.is_file(),
            "not a regular file: {}",
            path.display()
        );
        let mut data = Vec::new();
        file.take(available as u64 + 1).read_to_end(&mut data)?;
        ensure!(data.len() <= available, "file bundle too large");
        out.extend_from_slice(&(name.len() as u16).to_be_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&data);
    }
    Ok(out)
}

pub fn decode_entries(bytes: &[u8]) -> Result<Vec<FileEntry>> {
    ensure!(
        bytes.len() >= 2 && bytes.len() <= MAX_FILES,
        "invalid file bundle size"
    );
    let count = u16::from_be_bytes(bytes[..2].try_into()?) as usize;
    ensure!((1..=MAX_ENTRIES).contains(&count), "invalid file count");
    let mut i = 2;
    let mut files = Vec::new();
    for _ in 0..count {
        ensure!(i + 2 <= bytes.len(), "truncated filename length");
        let name_len = u16::from_be_bytes(bytes[i..i + 2].try_into()?) as usize;
        i += 2;
        ensure!(
            name_len > 0 && name_len <= MAX_NAME && i + name_len + 4 <= bytes.len(),
            "invalid filename length"
        );
        let name = std::str::from_utf8(&bytes[i..i + name_len])?;
        ensure!(safe_name(name) == name, "unsafe filename");
        i += name_len;
        let data_len = u32::from_be_bytes(bytes[i..i + 4].try_into()?) as usize;
        i += 4;
        ensure!(data_len <= bytes.len() - i, "truncated file contents");
        files.push(FileEntry {
            name: name.to_owned(),
            data: bytes[i..i + data_len].to_vec(),
        });
        i += data_len;
    }
    ensure!(i == bytes.len(), "trailing file bundle bytes");
    Ok(files)
}

pub fn save_bundle(bytes: &[u8], root: &Path, id: Uuid) -> Result<Vec<PathBuf>> {
    let entries = decode_entries(bytes)?; // validate everything before writing
    fs::create_dir_all(root)
        .with_context(|| format!("create receive directory {}", root.display()))?;
    let temp = root.join(format!(".partial-{id}"));
    let dest = root.join(id.to_string());
    ensure!(!dest.exists(), "transfer {id} was already saved");
    fs::create_dir(&temp)
        .with_context(|| format!("create staging directory {}", temp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o700))?;
    }
    let result = (|| -> Result<Vec<PathBuf>> {
        let mut paths = Vec::new();
        let mut seen = HashSet::new();
        for (index, entry) in entries.iter().enumerate() {
            let mut name = entry.name.clone();
            let mut suffix = index;
            while !seen.insert(name.to_ascii_lowercase()) {
                name = format!("{suffix}-{}", entry.name);
                suffix += 1;
            }
            let path = temp.join(&name);
            let mut options = fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&path)?;
            file.write_all(&entry.data)?;
            file.sync_all()?;
            paths.push(dest.join(name));
        }
        fs::rename(&temp, &dest)?;
        Ok(paths)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blocks_path_traversal_and_truncated_files() {
        assert!(!safe_name("../../evil\\file.txt").contains('/'));
        assert!(!safe_name("../../evil\\file.txt").contains('\\'));
        assert_eq!(safe_name("CON.txt"), "_CON.txt");
        let mut bytes = vec![0, 1, 0, 7];
        bytes.extend_from_slice(b"bad.txt");
        bytes.extend_from_slice(&10u32.to_be_bytes());
        bytes.extend_from_slice(b"hello");
        assert!(decode_entries(&bytes).is_err());
    }
    #[test]
    fn extract_two_files_and_do_not_overwrite() {
        let tmp = std::env::temp_dir().join(format!("bleclip-test-{}", Uuid::new_v4()));
        fs::create_dir(&tmp).unwrap();
        let a = tmp.join("photo.png");
        let b = tmp.join("readme.txt");
        fs::write(&a, [1, 2, 3]).unwrap();
        fs::write(&b, "Test").unwrap();
        let encoded = encode_paths(&[a, b]).unwrap();
        assert_eq!(decode_entries(&encoded).unwrap().len(), 2);
        let id = Uuid::new_v4();
        let result = save_bundle(&encoded, &tmp.join("recv"), id).unwrap();
        assert_eq!(fs::read(&result[0]).unwrap(), vec![1, 2, 3]);
        assert_eq!(fs::read(&result[1]).unwrap(), b"Test");
        assert!(save_bundle(&encoded, &tmp.join("recv"), id).is_err());
        fs::remove_dir_all(&tmp).unwrap();
    }
}

/// Announcements contain no file contents or local paths.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileMetadata {
    pub name: String,
    pub size: u64,
}

pub fn metadata(paths: &[PathBuf]) -> Result<Vec<FileMetadata>> {
    ensure!(
        !paths.is_empty() && paths.len() <= MAX_ENTRIES,
        "select 1–16 files"
    );
    let entries = paths
        .iter()
        .map(|path| {
            let stat = fs::symlink_metadata(path)?;
            ensure!(
                stat.file_type().is_file(),
                "only regular files are supported: {}",
                path.display()
            );
            Ok(FileMetadata {
                name: name_for(path),
                size: stat.len(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    validate_metadata(&entries)?;
    Ok(entries)
}

pub fn validate_metadata(entries: &[FileMetadata]) -> Result<()> {
    ensure!(
        !entries.is_empty() && entries.len() <= MAX_ENTRIES,
        "invalid file count"
    );
    let mut total = 2u64;
    for entry in entries {
        ensure!(
            !entry.name.is_empty()
                && entry.name.len() <= MAX_NAME
                && safe_name(&entry.name) == entry.name,
            "unsafe filename"
        );
        total = total
            .checked_add(entry.size)
            .and_then(|n| n.checked_add(entry.name.len() as u64 + 6))
            .context("file size overflow")?;
        ensure!(total <= MAX_FILES as u64, "file bundle exceeds 8 MiB");
    }
    Ok(())
}

pub fn validate_offered_bundle(bytes: &[u8], expected: &[FileMetadata]) -> Result<()> {
    let entries = decode_entries(bytes)?;
    ensure!(
        entries.len() == expected.len(),
        "file count differs from offer"
    );
    for (file, meta) in entries.iter().zip(expected) {
        ensure!(
            file.name == meta.name && file.data.len() as u64 == meta.size,
            "file differs from advertised name/size"
        );
    }
    Ok(())
}

#[cfg(test)]
mod offer_tests {
    use super::*;
    #[test]
    fn offer_contains_only_names_and_sizes_and_checks_bundle() {
        let root = std::env::temp_dir().join(format!("bleclip-offer-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let path = root.join("private.txt");
        fs::write(&path, b"secret file contents").unwrap();
        let offered = metadata(&[path.clone()]).unwrap();
        let encoded = serde_json::to_string(&offered).unwrap();
        assert_eq!(encoded, r#"[{"name":"private.txt","size":20}]"#);
        assert!(!encoded.contains(&root.to_string_lossy().to_string()));
        let bundle = encode_paths(&[path]).unwrap();
        validate_offered_bundle(&bundle, &offered).unwrap();
        let mut wrong = offered.clone();
        wrong[0].size += 1;
        assert!(validate_offered_bundle(&bundle, &wrong).is_err());
        wrong[0].name = "different.txt".into();
        assert!(validate_offered_bundle(&bundle, &wrong).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn rejects_unsafe_and_oversized_metadata() {
        for name in ["../evil", "", "CON", "a/b", "a\\b"] {
            assert!(validate_metadata(&[FileMetadata {
                name: name.into(),
                size: 0
            }])
            .is_err());
        }
        assert!(validate_metadata(&[]).is_err());
        assert!(validate_metadata(&[FileMetadata {
            name: "huge".into(),
            size: u64::MAX
        }])
        .is_err());
        assert!(validate_metadata(&[FileMetadata {
            name: "full".into(),
            size: MAX_FILES as u64
        }])
        .is_err());
    }
}
