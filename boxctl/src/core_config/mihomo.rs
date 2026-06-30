use super::*;

pub(super) fn sync_mihomo(config: &Config) -> Result<()> {
    let path = config.config_path();
    let mut text = fs::read_to_string(path)
        .map_err(|err| format!("read mihomo config {} failed: {err}", path.display()))?;
    let before = text.clone();

    logger::info_key(
        config,
        LogKey::CoreConfigSyncBegin,
        &[
            arg("core", "mihomo"),
            arg("mode", &config.network_mode),
            arg("config", path.display()),
        ],
    );

    text = set_top_level_scalar(text, "redir-port", &config.redir_port);
    text = set_top_level_scalar(text, "tproxy-port", &config.tproxy_port);
    text = ensure_dns_enhanced_mode(text, config);
    text = sync_mihomo_tun(text, config);

    if text != before {
        fs::write(path, text)
            .map_err(|err| format!("write mihomo config {} failed: {err}", path.display()))?;
        logger::info_key(
            config,
            LogKey::CoreConfigSyncUpdated,
            &[arg("core", "mihomo")],
        );
    } else {
        logger::debug_key(
            config,
            LogKey::CoreConfigSyncNoChange,
            &[arg("core", "mihomo")],
        );
    }

    Ok(())
}

pub(super) fn set_top_level_scalar(text: String, key: &str, value: &str) -> String {
    let mut lines = Vec::new();
    let mut replaced = false;
    let prefix = format!("{key}:");

    for line in text.lines() {
        let trimmed = line.trim_start();
        let is_top_level = !line.starts_with(' ') && !line.starts_with('\t');
        if is_top_level && trimmed.starts_with(&prefix) {
            lines.push(format!("{key}: {value}"));
            replaced = true;
        } else {
            lines.push(line.to_string());
        }
    }

    if !replaced {
        lines.push(format!("{key}: {value}"));
    }

    finish_lines(lines)
}

pub(super) fn ensure_dns_enhanced_mode(text: String, config: &Config) -> String {
    let force_redir_host = app_proxy_filter_enabled(config);

    if !has_top_level_key(&text, "dns") {
        let mut lines: Vec<String> = text.lines().map(ToOwned::to_owned).collect();
        lines.push("dns:".to_string());
        if force_redir_host {
            lines.push("  enhanced-mode: redir-host".to_string());
        }
        lines.push(format!(
            "  fake-ip-range: {}",
            empty_default(&config.fake_ip_range, "198.18.0.1/16")
        ));
        if !config.fake_ip6_range.trim().is_empty() {
            lines.push(format!(
                "  fake-ip-range6: {}",
                config.fake_ip6_range.trim()
            ));
        }
        lines.push(format!(
            "  listen: 0.0.0.0:{}",
            empty_default(&config.mihomo_dns_port, "1053")
        ));
        return finish_lines(lines);
    }

    let text = if force_redir_host {
        set_nested_scalar_in_block(text, "dns", "enhanced-mode", "redir-host")
    } else {
        text
    };
    let text = set_nested_scalar_in_block(
        text,
        "dns",
        "fake-ip-range",
        empty_default(&config.fake_ip_range, "198.18.0.1/16"),
    );
    let text = if config.fake_ip6_range.trim().is_empty() {
        text
    } else {
        set_nested_scalar_in_block(text, "dns", "fake-ip-range6", config.fake_ip6_range.trim())
    };
    set_nested_scalar_in_block(
        text,
        "dns",
        "listen",
        &format!("0.0.0.0:{}", empty_default(&config.mihomo_dns_port, "1053")),
    )
}

pub(super) fn sync_mihomo_tun(text: String, config: &Config) -> String {
    let mut text = remove_managed_block(text);
    if !matches!(config.network_mode.as_str(), "tun" | "mixed") {
        text = set_tun_enable_false(text);
        return text;
    }

    let tun = MihomoTunConfig::from(config, &text);
    if has_top_level_key(&text, "tun") {
        update_mihomo_tun_block(text, &tun)
    } else {
        append_mihomo_tun_block(text, &tun)
    }
}

pub(super) struct MihomoTunConfig {
    stack: String,
    device: String,
    auto_route: &'static str,
    strict_route: Option<&'static str>,
    auto_redirect: Option<&'static str>,
    auto_detect_interface: &'static str,
    include_uid: Vec<String>,
    exclude_uid: Vec<String>,
    exclude_interface: Vec<String>,
}

impl MihomoTunConfig {
    fn from(config: &Config, text: &str) -> Self {
        let box_managed_route = tun_route_managed_by_box(config);
        let (include_uid, exclude_uid) = tun_uid_lists(config);
        Self {
            stack: tun_stack_value(
                config,
                nested_scalar_in_block(text, "tun", "stack"),
                "gvisor",
            ),
            device: empty_default(&config.tun_device, "meta").to_string(),
            auto_route: if box_managed_route { "false" } else { "true" },
            strict_route: box_managed_route.then_some("false"),
            auto_redirect: box_managed_route.then_some("false"),
            auto_detect_interface: if box_managed_route { "false" } else { "true" },
            include_uid,
            exclude_uid,
            exclude_interface: tun_exclude_interfaces(config),
        }
    }

    fn new_block(&self) -> Vec<String> {
        let mut block = vec![
            "tun:".to_string(),
            "  enable: true".to_string(),
            "  mtu: 1500".to_string(),
            format!("  device: {}", self.device),
            format!("  stack: {}", self.stack),
            "  dns-hijack:".to_string(),
            "    - any:53".to_string(),
            "    - tcp://any:53".to_string(),
            format!("  auto-route: {}", self.auto_route),
            format!("  auto-detect-interface: {}", self.auto_detect_interface),
        ];
        if let Some(strict_route) = self.strict_route {
            block.push(format!("  strict-route: {strict_route}"));
        }
        if let Some(auto_redirect) = self.auto_redirect {
            block.push(format!("  auto-redirect: {auto_redirect}"));
        }
        self.push_interface_lines(&mut block);
        self.push_uid_lines(&mut block);
        block
    }

    fn push_interface_lines(&self, lines: &mut Vec<String>) {
        if !self.exclude_interface.is_empty() {
            lines.push(format!(
                "  exclude-interface: [{}]",
                yaml_inline_string_list(&self.exclude_interface)
            ));
        }
    }

    fn push_uid_lines(&self, lines: &mut Vec<String>) {
        if !self.include_uid.is_empty() {
            lines.push(format!("  include-uid: [{}]", self.include_uid.join(", ")));
        }
        if !self.exclude_uid.is_empty() {
            lines.push(format!("  exclude-uid: [{}]", self.exclude_uid.join(", ")));
        }
    }
}

pub(super) fn append_mihomo_tun_block(text: String, tun: &MihomoTunConfig) -> String {
    let mut lines: Vec<String> = text.lines().map(ToOwned::to_owned).collect();
    lines.extend(tun.new_block());
    finish_lines(lines)
}

pub(super) fn update_mihomo_tun_block(text: String, tun: &MihomoTunConfig) -> String {
    let mut output = Vec::new();
    let mut block = Vec::new();
    let mut in_tun = false;

    for line in text.lines() {
        let is_top_level = !line.starts_with(' ') && !line.starts_with('\t');
        if is_top_level && line.trim_start().starts_with("tun:") {
            if in_tun {
                output.extend(rewrite_mihomo_tun_block(block, tun));
                block = Vec::new();
            }
            in_tun = true;
            block.push(line.to_string());
            continue;
        }

        if in_tun && is_top_level && !line.trim().is_empty() {
            output.extend(rewrite_mihomo_tun_block(block, tun));
            block = Vec::new();
            in_tun = false;
        }

        if in_tun {
            block.push(line.to_string());
        } else {
            output.push(line.to_string());
        }
    }

    if in_tun {
        output.extend(rewrite_mihomo_tun_block(block, tun));
    }

    finish_lines(output)
}

pub(super) fn rewrite_mihomo_tun_block(block: Vec<String>, tun: &MihomoTunConfig) -> Vec<String> {
    let mut output = Vec::new();
    let mut seen_enable = false;
    let mut seen_mtu = false;
    let mut seen_device = false;
    let mut seen_stack = false;
    let mut seen_dns_hijack = false;
    let mut seen_auto_route = false;
    let mut seen_strict_route = false;
    let mut seen_auto_redirect = false;
    let mut seen_auto_detect_interface = false;
    let mut seen_exclude_interface = false;
    let mut seen_include_uid = false;
    let mut seen_exclude_uid = false;
    let mut skip_nested_indent: Option<usize> = None;

    for line in block {
        if let Some(indent) = skip_nested_indent {
            let current_indent = leading_indent(&line);
            if current_indent > indent && !line.trim().is_empty() {
                continue;
            }
            skip_nested_indent = None;
        }

        let Some(key) = nested_yaml_key(&line) else {
            output.push(line);
            continue;
        };

        match key.as_str() {
            "enable" => {
                output.push("  enable: true".to_string());
                seen_enable = true;
                skip_nested_indent = nested_value_skip_indent(&line);
            }
            "mtu" => {
                output.push("  mtu: 1500".to_string());
                seen_mtu = true;
                skip_nested_indent = nested_value_skip_indent(&line);
            }
            "device" => {
                output.push(format!("  device: {}", tun.device));
                seen_device = true;
                skip_nested_indent = nested_value_skip_indent(&line);
            }
            "stack" => {
                output.push(format!("  stack: {}", tun.stack));
                seen_stack = true;
                skip_nested_indent = nested_value_skip_indent(&line);
            }
            "dns-hijack" => {
                output.push(line);
                seen_dns_hijack = true;
            }
            "auto-route" => {
                output.push(format!("  auto-route: {}", tun.auto_route));
                seen_auto_route = true;
                skip_nested_indent = nested_value_skip_indent(&line);
            }
            "strict-route" => {
                if let Some(strict_route) = tun.strict_route {
                    output.push(format!("  strict-route: {strict_route}"));
                    skip_nested_indent = nested_value_skip_indent(&line);
                } else {
                    output.push(line);
                }
                seen_strict_route = true;
            }
            "auto-redirect" => {
                if let Some(auto_redirect) = tun.auto_redirect {
                    output.push(format!("  auto-redirect: {auto_redirect}"));
                    skip_nested_indent = nested_value_skip_indent(&line);
                } else {
                    output.push(line);
                }
                seen_auto_redirect = true;
            }
            "auto-detect-interface" => {
                output.push(format!(
                    "  auto-detect-interface: {}",
                    tun.auto_detect_interface
                ));
                seen_auto_detect_interface = true;
                skip_nested_indent = nested_value_skip_indent(&line);
            }
            "include-android-user" => {
                skip_nested_indent = nested_value_skip_indent(&line);
            }
            "include-interface" => {
                skip_nested_indent = nested_value_skip_indent(&line);
            }
            "exclude-interface" => {
                if !tun.exclude_interface.is_empty() {
                    output.push(format!(
                        "  exclude-interface: [{}]",
                        yaml_inline_string_list(&tun.exclude_interface)
                    ));
                }
                seen_exclude_interface = true;
                skip_nested_indent = nested_value_skip_indent(&line);
            }
            "include-uid" => {
                if !tun.include_uid.is_empty() {
                    output.push(format!("  include-uid: [{}]", tun.include_uid.join(", ")));
                }
                seen_include_uid = true;
                skip_nested_indent = nested_value_skip_indent(&line);
            }
            "exclude-uid" => {
                if !tun.exclude_uid.is_empty() {
                    output.push(format!("  exclude-uid: [{}]", tun.exclude_uid.join(", ")));
                }
                seen_exclude_uid = true;
                skip_nested_indent = nested_value_skip_indent(&line);
            }
            _ => output.push(line),
        }
    }

    if !seen_enable {
        output.push("  enable: true".to_string());
    }
    if !seen_mtu {
        output.push("  mtu: 1500".to_string());
    }
    if !seen_device {
        output.push(format!("  device: {}", tun.device));
    }
    if !seen_stack {
        output.push(format!("  stack: {}", tun.stack));
    }
    if !seen_dns_hijack {
        output.push("  dns-hijack:".to_string());
        output.push("    - any:53".to_string());
        output.push("    - tcp://any:53".to_string());
    }
    if !seen_auto_route {
        output.push(format!("  auto-route: {}", tun.auto_route));
    }
    if !seen_strict_route {
        if let Some(strict_route) = tun.strict_route {
            output.push(format!("  strict-route: {strict_route}"));
        }
    }
    if !seen_auto_redirect {
        if let Some(auto_redirect) = tun.auto_redirect {
            output.push(format!("  auto-redirect: {auto_redirect}"));
        }
    }
    if !seen_auto_detect_interface {
        output.push(format!(
            "  auto-detect-interface: {}",
            tun.auto_detect_interface
        ));
    }
    if !seen_exclude_interface && !tun.exclude_interface.is_empty() {
        output.push(format!(
            "  exclude-interface: [{}]",
            yaml_inline_string_list(&tun.exclude_interface)
        ));
    }
    if !seen_include_uid && !tun.include_uid.is_empty() {
        output.push(format!("  include-uid: [{}]", tun.include_uid.join(", ")));
    }
    if !seen_exclude_uid && !tun.exclude_uid.is_empty() {
        output.push(format!("  exclude-uid: [{}]", tun.exclude_uid.join(", ")));
    }

    output
}

pub(super) fn remove_managed_block(text: String) -> String {
    let mut output = Vec::new();
    let mut in_block = false;

    for line in text.lines() {
        if line.trim() == MANAGED_TUN_BEGIN {
            in_block = true;
            continue;
        }
        if line.trim() == MANAGED_TUN_END {
            in_block = false;
            continue;
        }
        if !in_block {
            output.push(line.to_string());
        }
    }

    finish_lines(output)
}

pub(super) fn set_tun_enable_false(text: String) -> String {
    let mut lines = Vec::new();
    let mut in_tun = false;

    for line in text.lines() {
        let is_top_level = !line.starts_with(' ') && !line.starts_with('\t');
        if is_top_level {
            in_tun = line.trim_start().starts_with("tun:");
        } else if in_tun && line.trim_start().starts_with("enable:") {
            lines.push("  enable: false".to_string());
            continue;
        }
        lines.push(line.to_string());
    }

    finish_lines(lines)
}

pub(super) fn set_nested_scalar_in_block(
    text: String,
    block: &str,
    key: &str,
    value: &str,
) -> String {
    let block_prefix = format!("{block}:");
    let key_prefix = format!("{key}:");
    let mut lines = Vec::new();
    let mut in_block = false;
    let mut key_written = false;

    for line in text.lines() {
        let is_top_level = !line.starts_with(' ') && !line.starts_with('\t');
        if is_top_level {
            if in_block && !key_written {
                lines.push(format!("  {key}: {value}"));
                key_written = true;
            }
            in_block = line.trim_start().starts_with(&block_prefix);
        }

        if in_block && !is_top_level && line.trim_start().starts_with(&key_prefix) {
            lines.push(format!("  {key}: {value}"));
            key_written = true;
            continue;
        }

        lines.push(line.to_string());
    }

    if in_block && !key_written {
        lines.push(format!("  {key}: {value}"));
    }

    finish_lines(lines)
}

pub(super) fn nested_scalar_in_block(text: &str, block: &str, key: &str) -> Option<String> {
    let block_prefix = format!("{block}:");
    let key_prefix = format!("{key}:");
    let mut in_block = false;

    for line in text.lines() {
        let is_top_level = !line.starts_with(' ') && !line.starts_with('\t');
        if is_top_level {
            in_block = line.trim_start().starts_with(&block_prefix);
            continue;
        }
        if in_block && line.trim_start().starts_with(&key_prefix) {
            return line.trim_start().strip_prefix(&key_prefix).map(|value| {
                value
                    .split('#')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            });
        }
    }

    None
}
