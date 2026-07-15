use super::*;
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

pub(super) fn write_atomic_runtime_config(
    source: &Path,
    runtime: &Path,
    text: &str,
) -> Result<bool> {
    match fs::read_to_string(runtime) {
        Ok(current) if current == text => return Ok(false),
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!(
                "read runtime config {} failed: {err}",
                runtime.display()
            ));
        }
    }

    let parent = runtime.parent().ok_or_else(|| {
        format!(
            "runtime config {} has no parent directory",
            runtime.display()
        )
    })?;
    let file_name = runtime
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("runtime config {} has no file name", runtime.display()))?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "create runtime config directory {} failed: {err}",
            parent.display()
        )
    })?;
    let metadata = fs::metadata(source).map_err(|err| {
        format!(
            "read source config metadata {} failed: {err}",
            source.display()
        )
    })?;
    let temporary = unique_sibling_path(parent, file_name, "tmp");

    let result = (|| -> Result<()> {
        write_synced_file(&temporary, text.as_bytes())?;
        fs::set_permissions(&temporary, metadata.permissions()).map_err(|err| {
            format!(
                "preserve config permissions {} failed: {err}",
                temporary.display()
            )
        })?;
        fs::rename(&temporary, runtime).map_err(|err| {
            format!(
                "atomically replace runtime config {} with {} failed: {err}",
                runtime.display(),
                temporary.display()
            )
        })?;
        sync_directory(parent)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map(|()| true)
}

fn unique_sibling_path(parent: &Path, file_name: &str, suffix: &str) -> PathBuf {
    let sequence = NEXT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(
        ".{file_name}.boxctl-{}-{sequence}.{suffix}",
        process::id()
    ))
}

fn write_synced_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|err| format!("create temporary config {} failed: {err}", path.display()))?;
    file.write_all(contents)
        .map_err(|err| format!("write temporary config {} failed: {err}", path.display()))?;
    file.sync_all()
        .map_err(|err| format!("sync temporary config {} failed: {err}", path.display()))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|err| format!("sync config directory {} failed: {err}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn writes_only_the_runtime_config() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("boxctl-runtime-config-{nonce}"));
        let source = root.join("source.yaml");
        let runtime = root.join("run/state/startup-config");
        let original = "dns:\n  listen: 127.0.0.1:1053\n";
        let generated = "dns:\n  listen: 0.0.0.0:1053\n";

        fs::create_dir_all(&root).unwrap();
        fs::write(&source, original).unwrap();

        assert!(write_atomic_runtime_config(&source, &runtime, generated).unwrap());
        assert_eq!(fs::read_to_string(&source).unwrap(), original);
        assert_eq!(fs::read_to_string(&runtime).unwrap(), generated);
        assert!(!write_atomic_runtime_config(&source, &runtime, generated).unwrap());

        fs::remove_dir_all(root).unwrap();
    }
}

pub(super) fn find_sing_box_inbound<'a>(
    inbounds: &'a [Value],
    inbound_type: &str,
) -> Option<&'a Value> {
    inbounds
        .iter()
        .find(|value| json_field_string(value, "type").as_deref() == Some(inbound_type))
}

pub(super) fn json_field_string(value: &Value, key: &str) -> Option<String> {
    value.as_object()?.get(key)?.as_str().map(ToOwned::to_owned)
}

pub(super) fn json_field_bool(value: &Value, key: &str) -> Option<bool> {
    value.as_object()?.get(key)?.as_bool()
}

pub(super) fn normalized_text_values(values: &[String]) -> Vec<String> {
    let mut values: Vec<String> = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    values.sort();
    values.dedup();
    values
}

pub(super) fn empty_default<'a>(value: &'a str, default: &'a str) -> &'a str {
    if value.trim().is_empty() {
        default
    } else {
        value.trim()
    }
}
