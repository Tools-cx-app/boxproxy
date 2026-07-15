use std::fs;
use std::path::Path;

use jsonc_parser::ParseOptions;

#[derive(Clone, Default)]
pub(super) struct CoreConfigValues {
    pub(super) read_status: String,
    pub(super) mihomo_dns_port: Option<String>,
    pub(super) tun_device: Option<String>,
    pub(super) fake_ip_range: Option<String>,
    pub(super) fake_ip6_range: Option<String>,
}

impl CoreConfigValues {
    pub(super) fn skipped() -> Self {
        Self {
            read_status: "not read (higher-priority values are configured)".to_string(),
            ..Self::default()
        }
    }

    pub(super) fn read(bin_name: &str, network_mode: &str, config_path: &Path) -> Self {
        let text = match fs::read_to_string(config_path) {
            Ok(text) => text,
            Err(err) => {
                return Self {
                    read_status: format!("read failed: {err}"),
                    ..Self::default()
                };
            }
        };
        match bin_name {
            "mihomo" => Self::read_mihomo(&text, network_mode),
            "sing-box" => Self::read_sing_box(&text, network_mode),
            _ => Self {
                read_status: format!("{bin_name} does not support automatic parsing"),
                ..Self::default()
            },
        }
    }

    fn read_mihomo(text: &str, network_mode: &str) -> Self {
        let mut values: serde_norway::Value = match serde_norway::from_str(text) {
            Ok(values) => values,
            Err(err) => {
                return Self {
                    read_status: format!("parse failed: {err}"),
                    ..Self::default()
                };
            }
        };
        if let Err(err) = values.apply_merge() {
            return Self {
                read_status: format!("parse failed: {err}"),
                ..Self::default()
            };
        }
        let dns = values.get("dns");
        Self {
            read_status: "read mihomo config".to_string(),
            mihomo_dns_port: dns
                .and_then(|value| value.get("listen"))
                .and_then(yaml_string)
                .and_then(|value| value.rsplit_once(':').map(|(_, port)| port.to_string())),
            tun_device: if matches!(network_mode, "tun" | "mixed") {
                values
                    .get("tun")
                    .and_then(|value| value.get("device"))
                    .and_then(yaml_string)
                    .map(ToOwned::to_owned)
            } else {
                None
            },
            fake_ip_range: dns
                .and_then(|value| value.get("fake-ip-range"))
                .and_then(yaml_string)
                .map(ToOwned::to_owned),
            fake_ip6_range: dns
                .and_then(|value| value.get("fake-ip-range6"))
                .and_then(yaml_string)
                .map(ToOwned::to_owned),
        }
    }

    fn read_sing_box(text: &str, network_mode: &str) -> Self {
        let values: serde_json::Value =
            match jsonc_parser::parse_to_serde_value(text, &ParseOptions::default()) {
                Ok(values) => values,
                Err(err) => {
                    return Self {
                        read_status: format!("parse failed: {err}"),
                        ..Self::default()
                    };
                }
            };
        let dns_servers = values
            .get("dns")
            .and_then(|value| value.get("servers"))
            .and_then(serde_json::Value::as_array);
        Self {
            read_status: "read sing-box config".to_string(),
            mihomo_dns_port: None,
            tun_device: if matches!(network_mode, "tun" | "mixed") {
                values
                    .get("inbounds")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .find(|v| v.get("interface_name").is_some())
                    .and_then(|value| value.get("interface_name"))
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned)
            } else {
                None
            },
            fake_ip_range: dns_servers
                .into_iter()
                .flatten()
                .find_map(|value| value.get("inet4_range"))
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
            fake_ip6_range: dns_servers
                .into_iter()
                .flatten()
                .find_map(|value| value.get("inet6_range"))
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
        }
    }
}

fn yaml_string(value: &serde_norway::Value) -> Option<&str> {
    value.as_str()
}

pub(super) fn value_source(
    override_value: &Option<String>,
    db_value: &Option<String>,
    core_value: &Option<String>,
    default_value: &str,
    applicable: bool,
    prefer_db: bool,
) -> &'static str {
    if override_value
        .as_deref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        return "CLI";
    }
    if core_value
        .as_deref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        return "core config";
    }
    if prefer_db
        && db_value
            .as_deref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    {
        return "App config";
    }
    if !applicable {
        return "not applicable";
    }
    if !default_value.trim().is_empty() {
        return "default";
    }
    "unset"
}

pub(super) fn non_empty_value(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

pub(super) fn default_mihomo_dns_port(bin_name: &str) -> String {
    if bin_name == "mihomo" {
        "1053".to_string()
    } else {
        String::new()
    }
}

pub(super) fn default_tun_device(bin_name: &str, network_mode: &str) -> String {
    if !matches!(network_mode, "tun" | "mixed") {
        return String::new();
    }
    match bin_name {
        "mihomo" => "meta".to_string(),
        "sing-box" => "sing".to_string(),
        _ => String::new(),
    }
}

pub(super) fn default_fake_ip_range(bin_name: &str) -> String {
    if bin_name == "mihomo" {
        "198.18.0.1/16".to_string()
    } else {
        String::new()
    }
}

pub(super) fn default_fake_ip6_range(bin_name: &str) -> String {
    if bin_name == "mihomo" {
        "fc00::/18".to_string()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_mihomo_config_returns_status_instead_of_panicking() {
        let values = CoreConfigValues::read_mihomo("dns: [", "tun");
        assert!(values.read_status.starts_with("parse failed:"));
    }

    #[test]
    fn flow_mihomo_config_reads_scalar_values() {
        let values = CoreConfigValues::read_mihomo(
            "dns: { listen: \"0.0.0.0:1053\", fake-ip-range: 198.18.0.1/16 }\ntun: { device: meta }\n",
            "tun",
        );
        assert_eq!(values.mihomo_dns_port.as_deref(), Some("1053"));
        assert_eq!(values.tun_device.as_deref(), Some("meta"));
        assert_eq!(values.fake_ip_range.as_deref(), Some("198.18.0.1/16"));
    }

    #[test]
    fn merged_mihomo_config_reads_effective_values() {
        let values = CoreConfigValues::read_mihomo(
            "defaults: &defaults\n  listen: \"0.0.0.0:1053\"\n  fake-ip-range: 198.18.0.1/16\ndns:\n  <<: *defaults\ntun: &tun\n  device: meta\n",
            "tun",
        );

        assert_eq!(values.mihomo_dns_port.as_deref(), Some("1053"));
        assert_eq!(values.fake_ip_range.as_deref(), Some("198.18.0.1/16"));
        assert_eq!(values.tun_device.as_deref(), Some("meta"));
    }
}
