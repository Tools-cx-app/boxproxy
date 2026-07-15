use crate::config::Config;
use crate::{logger, Result};
use jsonc_parser::ParseOptions;
use logger::{arg, LogKey};
use serde_json::{Map, Value};
use std::fs;
use std::path::Path;

mod common;
mod mihomo;
mod sing_box;
mod util;
use common::*;
use mihomo::sync_mihomo;
use sing_box::sync_sing_box;
use util::*;

const MANAGED_TUN_BEGIN: &str = "# boxctl managed tun begin";
const MANAGED_TUN_END: &str = "# boxctl managed tun end";

pub fn sync(config: &Config) -> Result<()> {
    if !config.auto_sync_config {
        logger::info_key(config, LogKey::CoreConfigSyncDisabled, &[]);
    }

    match config.bin_name.as_str() {
        "mihomo" => sync_mihomo(config),
        "sing-box" => sync_sing_box(config),
        "hysteria" => sync_hysteria(config),
        "xray" | "v2fly" => {
            if config.auto_sync_config {
                logger::warn_key(
                    config,
                    LogKey::CoreConfigSyncUnsupported,
                    &[arg("core", &config.bin_name)],
                );
            }
            Ok(())
        }
        other => Err(format!("unknown core: {other}")),
    }
}

fn sync_hysteria(config: &Config) -> Result<()> {
    let source = config.source_config_path();
    let source_text = fs::read_to_string(source)
        .map_err(|err| format!("read hysteria config {} failed: {err}", source.display()))?;
    let text = format_yaml_runtime_config(&source_text, "hysteria", source)?;
    let runtime = config.runtime_config_path();

    logger::info_key(
        config,
        LogKey::CoreConfigSyncBegin,
        &[
            arg("core", "hysteria"),
            arg("mode", &config.network_mode),
            arg("config", runtime.display()),
        ],
    );

    if write_atomic_runtime_config(source, runtime, &text)? {
        logger::info_key(
            config,
            LogKey::CoreConfigSyncUpdated,
            &[arg("core", "hysteria")],
        );
    } else {
        logger::debug_key(
            config,
            LogKey::CoreConfigSyncNoChange,
            &[arg("core", "hysteria")],
        );
    }
    Ok(())
}

fn format_yaml_runtime_config(text: &str, core: &str, source: &Path) -> Result<String> {
    let value = parse_yaml_runtime_value(text, core, source)?;
    format_yaml_runtime_value(&value, core, source)
}

fn parse_yaml_runtime_value(text: &str, core: &str, source: &Path) -> Result<serde_norway::Value> {
    let mut value = serde_norway::from_str::<serde_norway::Value>(text)
        .map_err(|err| format!("parse {core} config {} failed: {err}", source.display()))?;
    value
        .apply_merge()
        .map_err(|err| format!("expand {core} config {} failed: {err}", source.display()))?;
    Ok(value)
}

fn format_yaml_runtime_value(
    value: &serde_norway::Value,
    core: &str,
    source: &Path,
) -> Result<String> {
    let mut formatted = serde_norway::to_string(value)
        .map_err(|err| format!("format {core} config {} failed: {err}", source.display()))?;
    if !formatted.ends_with('\n') {
        formatted.push('\n');
    }
    Ok(formatted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_yaml_startup_config_without_comments() {
        let formatted = format_yaml_runtime_config(
            "# source comment\ndns:\n  listen: 0.0.0.0:1053 # trailing comment\n",
            "mihomo",
            Path::new("source.yaml"),
        )
        .unwrap();

        assert!(!formatted.contains("comment"));
        assert!(formatted.ends_with('\n'));
        assert!(serde_norway::from_str::<serde_norway::Value>(&formatted).is_ok());
    }

    #[test]
    fn formats_yaml_startup_config_with_expanded_merge_aliases() {
        let formatted = format_yaml_runtime_config(
            "templates:\n  selectall: &selectall\n    type: select\nproxy-groups:\n  - name: first\n    <<: *selectall\n",
            "mihomo",
            Path::new("source.yaml"),
        )
        .unwrap();

        assert!(!formatted.contains("&selectall"));
        assert!(!formatted.contains("*selectall"));
        assert!(!formatted.contains("<<:"));
        assert!(formatted.contains("name: first"));
        assert!(formatted.contains("type: select"));
    }
}
