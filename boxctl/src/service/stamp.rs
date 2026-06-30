use super::*;

pub(super) fn file_stamp(path: &Path) -> Option<String> {
    let metadata = fs::metadata(path).ok()?;
    let modified = metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(ownership_stamp(&metadata, metadata.len(), modified))
}

#[cfg(unix)]
fn ownership_stamp(metadata: &fs::Metadata, len: u64, modified: u64) -> String {
    use std::os::unix::fs::MetadataExt;
    format!(
        "{}:{}:{:o}:{len}:{modified}",
        metadata.uid(),
        metadata.gid(),
        metadata.mode() & 0o7777,
    )
}

#[cfg(not(unix))]
fn ownership_stamp(_metadata: &fs::Metadata, len: u64, modified: u64) -> String {
    format!("{len}:{modified}")
}
