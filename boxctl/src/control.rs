use crate::config::Config;
use crate::core_config;
use crate::exec::Runner;
use crate::{logger, monitor, rules, service, wifi, Result};
use logger::{arg, LogKey};
use std::thread;

pub fn up(config: &Config, runner: &Runner) -> Result<()> {
    up_inner(config, runner, true)
}

pub(crate) fn up_from_monitor(config: &Config, runner: &Runner) -> Result<()> {
    up_inner(config, runner, false)
}

fn up_inner(config: &Config, runner: &Runner, manage_monitor: bool) -> Result<()> {
    logger::info_key(config, LogKey::StartupBegin, &logger::startup_args(config));
    if let Err(err) = core_config::sync(config) {
        log_startup_failed(config, &err);
        return Err(err);
    }

    let (service_result, rules_result) = thread::scope(|scope| {
        let rules_handle = scope.spawn(|| rules::apply(config, runner));
        let service_result = service::start(config, runner);
        let rules_result = join_result(rules_handle.join(), "inbound rules thread panicked");
        (service_result, rules_result)
    });

    if service_result.is_err() || rules_result.is_err() {
        let mut failures = Vec::new();
        if let Err(err) = service_result {
            failures.push(format!("start core failed: {err}"));
        }
        if let Err(err) = rules_result {
            failures.push(format!("apply rules failed: {err}"));
        }

        let error = rollback_startup(config, runner, failures.join("; "));
        log_startup_failed(config, &error);
        return Err(error);
    }
    if manage_monitor {
        if let Err(err) = monitor::run(config, runner) {
            let error = rollback_startup(config, runner, format!("start monitor failed: {err}"));
            log_startup_failed(config, &error);
            return Err(error);
        }
    }
    logger::info_key(config, LogKey::StartupCompleted, &[]);
    Ok(())
}

fn rollback_startup(config: &Config, runner: &Runner, primary: String) -> String {
    let (service_result, rules_result) = thread::scope(|scope| {
        let rules_handle = scope.spawn(|| rules::clear(config, runner));
        let service_result = service::stop(config, runner);
        let rules_result = join_result(rules_handle.join(), "rules rollback thread panicked");
        (service_result, rules_result)
    });

    let mut rollback_failures = Vec::new();
    if let Err(err) = service_result {
        rollback_failures.push(format!("stop core: {err}"));
    }
    if let Err(err) = rules_result {
        rollback_failures.push(format!("clear rules: {err}"));
    }

    startup_failure_with_rollback(&primary, &rollback_failures)
}

fn startup_failure_with_rollback(primary: &str, rollback_failures: &[String]) -> String {
    if rollback_failures.is_empty() {
        primary.to_string()
    } else {
        format!(
            "{primary}; rollback failed: {}",
            rollback_failures.join("; ")
        )
    }
}

pub fn boot(config: &Config, runner: &Runner) -> Result<()> {
    if config.wifi_network_control_enabled {
        wifi::apply(config, runner)?;
        monitor::run(config, runner)?;
        return Ok(());
    }

    up(config, runner)
}

pub fn down(config: &Config, runner: &Runner) -> Result<()> {
    down_inner(config, runner, true)
}

pub(crate) fn down_from_monitor(config: &Config, runner: &Runner) -> Result<()> {
    down_inner(config, runner, false)
}

fn down_inner(config: &Config, runner: &Runner, manage_monitor: bool) -> Result<()> {
    logger::warn_key(
        config,
        LogKey::StopBegin,
        &[
            arg("core", &config.bin_name),
            arg("mode", &config.network_mode),
        ],
    );

    let (rules_result, service_result) = thread::scope(|scope| {
        let service_handle = scope.spawn(|| service::stop(config, runner));
        let rules_result = rules::clear(config, runner);
        let service_result = join_result(service_handle.join(), "service stop thread panicked");
        (rules_result, service_result)
    });

    rules_result?;
    service_result?;
    if manage_monitor {
        monitor::run(config, runner)?;
    }
    logger::warn_key(config, LogKey::StopCompleted, &[]);
    Ok(())
}

pub fn restart(config: &Config, runner: &Runner) -> Result<()> {
    logger::warn_key(
        config,
        LogKey::RestartBegin,
        &[
            arg("core", &config.bin_name),
            arg("mode", &config.network_mode),
        ],
    );
    down(config, runner)?;
    up(config, runner)
}

pub fn status(config: &Config, runner: &Runner) -> Result<()> {
    logger::info_key(
        config,
        LogKey::StatusSummary,
        &[
            arg("core", &config.bin_name),
            arg("mode", &config.network_mode),
            arg("tun", &config.tun_device),
            arg("tproxy", &config.tproxy_port),
            arg("redir", &config.redir_port),
            arg(
                "dns",
                format!("{}:{}", config.dns_hijack_mode, config.mihomo_dns_port),
            ),
            logger::enabled_arg("performance", config.performance_mode),
        ],
    );
    logger::info_key(
        config,
        LogKey::CoreConfigRead,
        &logger::core_config_args(config),
    );
    service::status(config, runner)
}

fn join_result(joined: std::thread::Result<Result<()>>, message: &str) -> Result<()> {
    match joined {
        Ok(result) => result,
        Err(_) => Err(message.to_string()),
    }
}

fn log_startup_failed(config: &Config, error: &str) {
    logger::error_key(config, LogKey::StartupFailed, &[arg("error", error)]);
}

#[cfg(test)]
mod tests {
    use super::startup_failure_with_rollback;

    #[test]
    fn rollback_error_keeps_the_startup_failure() {
        let error = startup_failure_with_rollback(
            "apply rules failed: iptables failed",
            &[
                "stop core: process remains".to_string(),
                "clear rules: restore failed".to_string(),
            ],
        );

        assert!(error.contains("apply rules failed: iptables failed"));
        assert!(error.contains("stop core: process remains"));
        assert!(error.contains("clear rules: restore failed"));
    }
}
