use std::fs;
use std::path::Path;

#[derive(Default)]
pub(super) struct CoreConfigValues {
    pub(super) read_status: String,
    pub(super) mihomo_dns_port: Option<String>,
    pub(super) tun_device: Option<String>,
    pub(super) fake_ip_range: Option<String>,
    pub(super) fake_ip6_range: Option<String>,
}

impl CoreConfigValues {
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
        Self {
            read_status: "read mihomo config".to_string(),
            mihomo_dns_port: mihomo_dns_port(text),
            tun_device: if matches!(network_mode, "tun" | "mixed") {
                nested_yaml_scalar(text, "tun", "device")
                    .or_else(|| yaml_scalar(text, "device"))
                    .filter(|value| !value.is_empty())
            } else {
                None
            },
            fake_ip_range: nested_yaml_scalar(text, "dns", "fake-ip-range")
                .or_else(|| yaml_scalar(text, "fake-ip-range"))
                .filter(|value| !value.is_empty()),
            fake_ip6_range: nested_yaml_scalar(text, "dns", "fake-ip-range6")
                .or_else(|| yaml_scalar(text, "fake-ip-range6"))
                .filter(|value| !value.is_empty()),
        }
    }

    fn read_sing_box(text: &str, network_mode: &str) -> Self {
        Self {
            read_status: "read sing-box config".to_string(),
            mihomo_dns_port: None,
            tun_device: if matches!(network_mode, "tun" | "mixed") {
                json_string_value(text, "interface_name").filter(|value| !value.is_empty())
            } else {
                None
            },
            fake_ip_range: json_string_value(text, "inet4_range").filter(|value| !value.is_empty()),
            fake_ip6_range: json_string_value(text, "inet6_range")
                .filter(|value| !value.is_empty()),
        }
    }
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

fn mihomo_dns_port(text: &str) -> Option<String> {
    nested_yaml_scalar(text, "dns", "listen").and_then(|listen| port_from_listen(&listen))
}

fn port_from_listen(value: &str) -> Option<String> {
    let value = value.trim().trim_matches('"').trim_matches('\'');
    let port = value.rsplit(':').next()?.trim();
    if !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) {
        Some(port.to_string())
    } else {
        None
    }
}

fn yaml_scalar(text: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }
        if let Some(value) = trimmed.strip_prefix(&prefix) {
            return Some(clean_yaml_scalar(value));
        }
    }
    None
}

fn nested_yaml_scalar(text: &str, block: &str, key: &str) -> Option<String> {
    let block_prefix = format!("{block}:");
    let key_prefix = format!("{key}:");
    let mut in_block = false;
    let mut block_indent = 0usize;

    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }

        let indent = leading_indent(line);
        if !trimmed.is_empty() && indent <= block_indent && !trimmed.starts_with('-') {
            in_block = trimmed.starts_with(&block_prefix);
            block_indent = if in_block { indent } else { 0 };
            if in_block {
                continue;
            }
        }

        if in_block && indent > block_indent {
            if let Some(value) = trimmed.strip_prefix(&key_prefix) {
                return Some(clean_yaml_scalar(value));
            }
        }
    }
    None
}

fn clean_yaml_scalar(value: &str) -> String {
    value
        .split('#')
        .next()
        .unwrap_or_default()
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

fn json_string_value(text: &str, key: &str) -> Option<String> {
    let quoted = format!("\"{key}\"");
    let mut pos = 0usize;
    while let Some(relative) = text[pos..].find(&quoted) {
        let key_start = pos + relative;
        let colon = text[key_start + quoted.len()..].find(':')? + key_start + quoted.len();
        let value_start = text[colon + 1..].find(|ch: char| !ch.is_whitespace())? + colon + 1;
        if text.as_bytes().get(value_start).copied()? != b'"' {
            pos = value_start + 1;
            continue;
        }
        return read_json_string(text, value_start);
    }
    None
}

fn read_json_string(text: &str, start: usize) -> Option<String> {
    let bytes = text.as_bytes();
    if bytes.get(start).copied()? != b'"' {
        return None;
    }
    let mut escape = false;
    let mut output = String::new();
    let mut i = start + 1;
    while i < bytes.len() {
        let ch = bytes[i] as char;
        if escape {
            output.push(ch);
            escape = false;
        } else if ch == '\\' {
            escape = true;
        } else if ch == '"' {
            return Some(output);
        } else {
            output.push(ch);
        }
        i += 1;
    }
    None
}

fn leading_indent(line: &str) -> usize {
    line.chars()
        .take_while(|ch| *ch == ' ' || *ch == '\t')
        .count()
}
