use super::*;
use crate::control;

pub(super) fn apply_network_control_policy(
    config: &Config,
    runner: &Runner,
    mut observation: WifiObservation,
) -> Result<NetworkPolicyResult> {
    if !config.wifi_network_control_enabled {
        return Ok(NetworkPolicyResult {
            observation,
            handled: true,
        });
    }

    if observation.connected {
        refresh_connected_ip(runner, &mut observation);
        if observation.ip.is_none() {
            control_log_key(
                config,
                LogKey::WifiPending,
                &[observation_arg(&observation)],
            );
            return Ok(NetworkPolicyResult {
                observation,
                handled: false,
            });
        }
    }

    let should_enable = should_enable_service(config, &observation);
    let action = if should_enable {
        start_service_if_needed(config, runner)
    } else {
        stop_service_if_needed(config, runner)
    };

    match action {
        Ok(action) => control_log_key(
            config,
            LogKey::WifiPolicyApplied,
            &[
                observation_arg(&observation),
                policy_arg(should_enable),
                action_arg(action),
            ],
        ),
        Err(err) => {
            control_log_key(
                config,
                LogKey::WifiPolicyFailed,
                &[
                    observation_arg(&observation),
                    policy_arg(should_enable),
                    arg("error", &err),
                ],
            );
            return Err(err);
        }
    }

    Ok(NetworkPolicyResult {
        observation,
        handled: true,
    })
}

pub(super) fn refresh_connected_ip(runner: &Runner, observation: &mut WifiObservation) {
    if observation.ip.is_some() {
        return;
    }

    for attempt in 1..WIFI_IP_RETRIES {
        thread::sleep(Duration::from_millis(WIFI_IP_RETRY_DELAY_MS));
        observation.ip = get_wifi_ip(runner, &observation.iface);
        if observation.ip.is_some() || attempt + 1 >= WIFI_IP_RETRIES {
            break;
        }
    }
}

pub(super) fn run_ip_monitor_once(config: &Config, runner: &Runner) -> Result<()> {
    let mut socket = open_route_event_socket()?;
    let (tx, rx) = mpsc::channel::<Result<()>>();
    let reader_handle = thread::spawn(move || {
        let mut buffer = [0_u8; 32 * 1024];
        loop {
            match wait_for_route_event(&mut socket, &mut buffer) {
                Ok(()) => {
                    if tx.send(Ok(())).is_err() {
                        break;
                    }
                }
                Err(err) => {
                    let _ = tx.send(Err(err));
                    break;
                }
            }
        }
    });

    let mut live = LiveConfigCache::new();
    let mut iface_cache: Option<String> = None;

    reconcile_network_state(config, runner, &mut live, &mut iface_cache);

    while let Ok(event) = rx.recv() {
        event?;
        wait_for_network_event_quiet(&rx)?;
        reconcile_network_state(config, runner, &mut live, &mut iface_cache);
    }

    let _ = reader_handle.join();
    Err("route netlink event stream ended".to_string())
}

fn reconcile_network_state(
    config: &Config,
    runner: &Runner,
    live: &mut LiveConfigCache,
    iface_cache: &mut Option<String>,
) {
    let live_config = live.get(config);
    if let Err(err) = handle_network_change(live_config, runner, iface_cache) {
        logger::warn_key(
            live_config,
            LogKey::NetworkRecalcFailed,
            &[arg("error", err)],
        );
    }
}

const LIVE_CONFIG_RECHECK_INTERVAL: Duration = Duration::from_secs(1);

struct LiveConfigCache {
    cached: Option<Config>,
    revision: Option<RuntimeConfigRevision>,
    checked_at: Option<Instant>,
}

impl LiveConfigCache {
    fn new() -> Self {
        Self {
            cached: None,
            revision: None,
            checked_at: None,
        }
    }

    fn get(&mut self, base: &Config) -> &Config {
        let should_check = self.cached.is_none()
            || self
                .checked_at
                .map(|at| at.elapsed() >= LIVE_CONFIG_RECHECK_INTERVAL)
                .unwrap_or(true);
        if should_check {
            let revision = runtime_config_revision(&base.paths.db);
            if self.cached.is_none() {
                self.cached = Some(base.clone());
            } else if self.revision.as_ref() != Some(&revision) {
                self.cached = Some(load_live_config(base));
            }
            self.revision = Some(revision);
            self.checked_at = Some(Instant::now());
        }
        self.cached.as_ref().unwrap()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RuntimeConfigRevision {
    database: FileRevision,
    wal: FileRevision,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileRevision {
    modified: Option<std::time::SystemTime>,
    len: Option<u64>,
}

fn runtime_config_revision(path: &std::path::Path) -> RuntimeConfigRevision {
    RuntimeConfigRevision {
        database: file_revision(path),
        wal: file_revision(&sqlite_sidecar_path(path, "-wal")),
    }
}

fn file_revision(path: &std::path::Path) -> FileRevision {
    let metadata = fs::metadata(path).ok();
    FileRevision {
        modified: metadata
            .as_ref()
            .and_then(|metadata| metadata.modified().ok()),
        len: metadata.as_ref().map(|metadata| metadata.len()),
    }
}

fn sqlite_sidecar_path(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    value.into()
}

pub(super) fn wait_for_network_event_quiet(rx: &mpsc::Receiver<Result<()>>) -> Result<()> {
    let started = Instant::now();
    let quiet = Duration::from_millis(WIFI_EVENT_DEBOUNCE_MS);
    let max_wait = Duration::from_millis(WIFI_EVENT_MAX_DEBOUNCE_MS);
    loop {
        match rx.recv_timeout(quiet) {
            Ok(Ok(())) if started.elapsed() < max_wait => continue,
            Ok(Ok(())) => break,
            Ok(Err(err)) => return Err(err),
            Err(mpsc::RecvTimeoutError::Timeout) => break,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Ok(())
}

pub(super) fn start_service_if_needed(config: &Config, runner: &Runner) -> Result<ServiceAction> {
    if service::is_running(config, runner) {
        return Ok(ServiceAction::AlreadyRunning);
    }

    control::up_from_monitor(config, runner)?;
    Ok(ServiceAction::Started)
}

pub(super) fn stop_service_if_needed(config: &Config, runner: &Runner) -> Result<ServiceAction> {
    if !service::is_running(config, runner) {
        return Ok(ServiceAction::AlreadyStopped);
    }

    control::down_from_monitor(config, runner)?;
    Ok(ServiceAction::Stopped)
}

pub(super) fn refresh_local_ip_rules_if_running(config: &Config, runner: &Runner) -> Result<()> {
    if !service::is_running(config, runner) {
        return Ok(());
    }
    rules::refresh_local_ip_rules(config, runner)
}

pub(super) fn should_enable_service(config: &Config, observation: &WifiObservation) -> bool {
    if !observation.connected {
        return config.wifi_use_on_disconnect;
    }

    if !config.wifi_use_on_connect {
        return false;
    }

    if !config.wifi_enable_ssid_matching {
        return true;
    }

    let matched = if !config.wifi_bssids.is_empty() && observation.bssid != "unknown" {
        contains_exact(&config.wifi_bssids, &observation.bssid)
    } else if !config.wifi_ssids.is_empty() {
        contains_exact(&config.wifi_ssids, &observation.ssid)
    } else {
        false
    };

    if matched {
        config.wifi_list_mode == "whitelist"
    } else {
        config.wifi_list_mode != "whitelist"
    }
}

pub(super) fn observation_arg(observation: &WifiObservation) -> logger::LogArg {
    logger::wifi_observation_arg(
        "observation",
        observation.connected,
        &observation.ssid,
        &observation.bssid,
        &observation.iface,
        observation.ip.as_deref(),
    )
}

pub(super) fn policy_arg(enabled: bool) -> logger::LogArg {
    logger::wifi_policy_arg("policy", enabled)
}

pub(super) fn action_arg(action: ServiceAction) -> logger::LogArg {
    logger::wifi_action_arg("action", action.log_id())
}
