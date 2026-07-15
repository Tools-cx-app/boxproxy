use super::*;

pub(super) fn tun_uid_lists(config: &Config) -> (Vec<String>, Vec<String>) {
    let uids = config.selected_uids.clone();
    match config.proxy_mode.as_str() {
        "whitelist" | "white" => (uids, Vec::new()),
        "blacklist" | "black" => (Vec::new(), uids),
        _ => (Vec::new(), Vec::new()),
    }
}

pub(super) fn tun_route_managed_by_box(config: &Config) -> bool {
    config.network_mode == "tun" && (config.bypass_cn_ip || config.mac_filter)
}

pub(super) fn tun_exclude_interfaces(config: &Config) -> Vec<String> {
    normalized_text_values(&config.blocked_interfaces)
}

pub(super) fn tun_stack_value(
    config: &Config,
    current_stack: Option<String>,
    default_stack: &str,
) -> String {
    if config.bypass_cn_ip {
        return "gvisor".to_string();
    }

    current_stack
        .map(|value| {
            value
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default_stack.to_string())
}
