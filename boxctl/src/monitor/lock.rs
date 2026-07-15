use super::*;
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::Path;
#[cfg(not(unix))]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(not(unix))]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(not(unix))]
static TOKEN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}

#[cfg(unix)]
const LOCK_EX: i32 = 2;
#[cfg(unix)]
const LOCK_NB: i32 = 4;

pub(super) fn acquire_monitor_lock(config: &Config) -> Result<Option<MonitorLock>> {
    let path = monitor_lock_path(config);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create monitor lock directory {} failed: {err}",
                parent.display()
            )
        })?;
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|err| format!("open monitor lock {} failed: {err}", path.display()))?;

    if !try_lock_exclusive(&file) {
        return Ok(None);
    }

    let token = match env::var(MONITOR_TOKEN_ENV) {
        Ok(token) if valid_monitor_token(&token) => token,
        _ => {
            let token = generate_monitor_token()?;
            env::set_var(MONITOR_TOKEN_ENV, &token);
            token
        }
    };
    let identity = MonitorIdentity {
        pid: process::id(),
        start_time: process_start_time(process::id())
            .ok_or_else(|| "read monitor process start time from /proc failed".to_string())?,
        token,
    };

    file.set_len(0)
        .map_err(|err| format!("reset monitor lock {} failed: {err}", path.display()))?;
    write_monitor_identity(&mut file, &identity)
        .map_err(|err| format!("write monitor lock {} failed: {err}", path.display()))?;
    file.sync_all()
        .map_err(|err| format!("sync monitor lock {} failed: {err}", path.display()))?;

    Ok(Some(MonitorLock { _file: file }))
}

#[cfg(unix)]
fn try_lock_exclusive(file: &fs::File) -> bool {
    unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) == 0 }
}

#[cfg(not(unix))]
fn try_lock_exclusive(_file: &fs::File) -> bool {
    true
}

pub(super) fn monitor_lock_path(config: &Config) -> PathBuf {
    config.paths.state.join("network_monitor.pid")
}

pub(super) fn read_monitor_identity(path: &Path) -> Option<MonitorIdentity> {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| parse_monitor_identity(&text))
}

pub(super) fn monitor_lock_is_held(path: &Path) -> bool {
    let Ok(file) = OpenOptions::new().read(true).write(true).open(path) else {
        return false;
    };
    !try_lock_exclusive(&file)
}

pub(super) fn monitor_identity_matches(identity: &MonitorIdentity) -> bool {
    if process_start_time(identity.pid) != Some(identity.start_time) {
        return false;
    }

    process_environment_value(identity.pid, MONITOR_TOKEN_ENV).as_deref()
        == Some(identity.token.as_str())
}

fn process_start_time(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, fields) = stat.rsplit_once(')')?;
    fields.split_whitespace().nth(19)?.parse().ok()
}

fn process_environment_value(pid: u32, key: &str) -> Option<String> {
    let environ = fs::read(format!("/proc/{pid}/environ")).ok()?;
    environ.split(|byte| *byte == 0).find_map(|entry| {
        let entry = std::str::from_utf8(entry).ok()?;
        let (name, value) = entry.split_once('=')?;
        (name == key).then(|| value.to_string())
    })
}

pub(super) fn generate_monitor_token() -> Result<String> {
    #[cfg(unix)]
    {
        let mut bytes = [0_u8; 16];
        fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut bytes))
            .map_err(|err| format!("read monitor token entropy failed: {err}"))?;
        return Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect());
    }

    #[cfg(not(unix))]
    {
        let sequence = TOKEN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        Ok(format!(
            "{now:032x}{:016x}",
            process::id() as u64 ^ sequence
        ))
    }
}

fn valid_monitor_token(token: &str) -> bool {
    token.len() == 32 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn write_monitor_identity(
    handle: &mut fs::File,
    identity: &MonitorIdentity,
) -> std::io::Result<()> {
    writeln!(handle, "pid={}", identity.pid)?;
    writeln!(handle, "start_time={}", identity.start_time)?;
    writeln!(handle, "token={}", identity.token)
}

fn parse_monitor_identity(text: &str) -> Option<MonitorIdentity> {
    let mut pid = None;
    let mut start_time = None;
    let mut token = None;
    for line in text.lines() {
        let (key, value) = line.split_once('=')?;
        match key {
            "pid" if pid.is_none() => pid = value.parse().ok(),
            "start_time" if start_time.is_none() => start_time = value.parse().ok(),
            "token" if token.is_none() && valid_monitor_token(value) => {
                token = Some(value.to_string())
            }
            _ => return None,
        }
    }
    Some(MonitorIdentity {
        pid: pid?,
        start_time: start_time?,
        token: token?,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct MonitorIdentity {
    pub(super) pid: u32,
    start_time: u64,
    token: String,
}

pub(super) struct MonitorLock {
    _file: fs::File,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monitor_lock_requires_all_identity_fields() {
        let token = "0123456789abcdef0123456789abcdef";
        let text = format!("pid=12\nstart_time=34\ntoken={token}\n");
        assert_eq!(
            parse_monitor_identity(&text),
            Some(MonitorIdentity {
                pid: 12,
                start_time: 34,
                token: token.to_string(),
            })
        );
        assert!(parse_monitor_identity("12\n").is_none());
        assert!(parse_monitor_identity("pid=12\nstart_time=34\ntoken=short\n").is_none());
    }
}
