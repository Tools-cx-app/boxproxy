use super::{
    arg, arg_i18n, display_value, performance_reason_list_en, performance_reason_list_zh,
    uid_fallback_en, uid_fallback_zh, LogArg,
};
use crate::config::Config;

pub fn enabled_arg(key: &'static str, value: bool) -> LogArg {
    if value {
        arg_i18n(key, "enabled", "启用")
    } else {
        arg_i18n(key, "disabled", "禁用")
    }
}

pub fn family_arg(key: &'static str, value: &str) -> LogArg {
    match value {
        "IPv4" => arg_i18n(key, "IPv4", "IPv4"),
        "IPv6" => arg_i18n(key, "IPv6", "IPv6"),
        _ => arg(key, value),
    }
}

pub fn quic_arg(key: &'static str, value: &str) -> LogArg {
    if value.trim().eq_ignore_ascii_case("enable") {
        arg_i18n(key, "enabled", "启用")
    } else {
        arg_i18n(key, "disabled", "禁用")
    }
}

pub fn config_source_arg(key: &'static str, value: &str) -> LogArg {
    match value {
        "CLI" => arg_i18n(key, "CLI", "命令行"),
        "core config" => arg_i18n(key, "core config", "核心配置"),
        "App config" => arg_i18n(key, "App config", "App 配置"),
        "not applicable" => arg_i18n(key, "not applicable", "不适用"),
        "default" => arg_i18n(key, "default", "默认值"),
        "unset" => arg_i18n(key, "unset", "未设置"),
        _ => arg(key, value),
    }
}

pub fn core_config_status_arg(key: &'static str, value: &str) -> LogArg {
    if value == "read mihomo config" {
        arg_i18n(key, "read mihomo config", "已读取 mihomo 配置")
    } else if value == "read sing-box config" {
        arg_i18n(key, "read sing-box config", "已读取 sing-box 配置")
    } else if let Some(err) = value.strip_prefix("read failed: ") {
        arg_i18n(
            key,
            format!("read failed: {err}"),
            format!("读取失败: {err}"),
        )
    } else if let Some(core) = value.strip_suffix(" does not support automatic parsing") {
        arg_i18n(
            key,
            format!("{core} does not support automatic parsing"),
            format!("{core} 不支持自动解析"),
        )
    } else {
        arg(key, value)
    }
}

pub fn command_stage_arg(key: &'static str, value: &str) -> LogArg {
    match value {
        "iptables rule failed" => arg_i18n(key, value, "iptables 规则失败"),
        "iptables insert rule failed" => arg_i18n(key, value, "iptables 插入规则失败"),
        "iptables-restore batch failed" => arg_i18n(key, value, "iptables-restore 批量失败"),
        "ip policy route failed" => arg_i18n(key, value, "ip 策略路由失败"),
        "ipset import failed" => arg_i18n(key, value, "ipset 导入失败"),
        "eBPF matcher execution failed" => arg_i18n(key, value, "eBPF 匹配器执行失败"),
        _ => arg(key, value),
    }
}

pub fn rule_kind_arg(key: &'static str, value: &str) -> LogArg {
    match value {
        "REDIRECT" => arg_i18n(key, "REDIRECT", "REDIRECT"),
        "TPROXY" => arg_i18n(key, "TPROXY", "TPROXY"),
        "Enhance" => arg_i18n(key, "Enhance", "增强"),
        "Enhance TPROXY" => arg_i18n(key, "Enhance TPROXY", "增强 TPROXY"),
        "TUN" => arg_i18n(key, "TUN", "TUN"),
        "TUN CNIP bypass" => arg_i18n(key, "TUN CNIP bypass", "TUN CNIP 绕过"),
        _ => arg(key, value),
    }
}

pub fn nat_target_arg(key: &'static str, value: &str) -> LogArg {
    match value {
        "REDIRECT" => arg_i18n(key, "REDIRECT", "REDIRECT"),
        "DNS redirect" => arg_i18n(key, "DNS redirect", "DNS 重定向"),
        _ => arg(key, value),
    }
}

pub fn dns_nat_target_arg(key: &'static str, value: &str) -> LogArg {
    match value {
        "hijack" => arg_i18n(key, "DNS", "DNS"),
        "forward" => arg_i18n(key, "DNS forward", "DNS 转发"),
        _ => arg(key, value),
    }
}

pub fn wifi_observation_arg(
    key: &'static str,
    connected: bool,
    ssid: &str,
    bssid: &str,
    iface: &str,
    ip: Option<&str>,
) -> LogArg {
    if !connected {
        return arg_i18n(
            key,
            format!("Wi-Fi disconnected: interface {iface}"),
            format!("Wi-Fi 已断开: 接口 {iface}"),
        );
    }

    arg_i18n(
        key,
        format!(
            "Wi-Fi connected: SSID {ssid}, BSSID {bssid}, interface {iface}, IP {}",
            ip.unwrap_or("getting")
        ),
        format!(
            "Wi-Fi 已连接: SSID {ssid}, BSSID {bssid}, 接口 {iface}, IP {}",
            ip.unwrap_or("获取中")
        ),
    )
}

pub fn wifi_policy_arg(key: &'static str, enabled: bool) -> LogArg {
    if enabled {
        arg_i18n(key, "policy enabled", "策略启用")
    } else {
        arg_i18n(key, "policy disabled", "策略禁用")
    }
}

pub fn wifi_action_arg(key: &'static str, action: &str) -> LogArg {
    match action {
        "already_running" => arg_i18n(key, "service already running", "服务已在运行"),
        "started" => arg_i18n(key, "service started", "服务已启动"),
        "already_stopped" | "stopped" => arg_i18n(key, "service stopped", "服务已停止"),
        _ => arg(key, action),
    }
}

#[derive(Clone, Copy, Debug)]
pub enum PerformanceFallbackReason {
    MissingConntrack,
    MissingConnmark,
    MissingConnmarkTarget,
    MissingSocketTransparent,
    UdpNotEnabled,
    ConditionsNotMet,
}

#[derive(Clone, Copy, Debug)]
pub enum PerformanceUidFallback {
    BpfMatchUnavailable,
    BoxbpfMissing,
    Ipv4ProgramMissing,
    Ipv6ProgramMissing,
}

#[derive(Clone, Copy, Debug)]
pub enum EbpfFailureReason {
    ProgramRejected,
    PermissionDenied,
    PinnedPathUnavailable,
}

pub fn ebpf_failure_reason_arg(key: &'static str, reason: EbpfFailureReason) -> LogArg {
    match reason {
        EbpfFailureReason::ProgramRejected => arg_i18n(
            key,
            "kernel rejected the eBPF socket-filter program, usually because xt_bpf/BPF verifier support is incomplete on this ROM",
            "内核拒绝加载 eBPF socket filter 程序, 通常是当前 ROM 的 xt_bpf/BPF verifier 能力不完整",
        ),
        EbpfFailureReason::PermissionDenied => arg_i18n(
            key,
            "missing permission to load or pin eBPF objects, possibly blocked by SELinux or kernel policy",
            "缺少加载或固定 eBPF 对象的权限, 可能被 SELinux 或内核策略限制",
        ),
        EbpfFailureReason::PinnedPathUnavailable => arg_i18n(
            key,
            "eBPF pinned object or bpffs path is unavailable",
            "eBPF pinned 对象或 bpffs 路径不可用",
        ),
    }
}

pub fn performance_reply_arg(
    key: &'static str,
    network_mode: &str,
    conntrack_match: bool,
) -> LogArg {
    if network_mode == "tun" {
        arg_i18n(key, "reply bypass not applicable", "响应旁路不适用")
    } else if conntrack_match {
        arg_i18n(key, "reply bypass enabled", "响应旁路已启用")
    } else {
        arg_i18n(
            key,
            "reply bypass fallback(missing conntrack)",
            "响应旁路回退(缺少 conntrack)",
        )
    }
}

pub fn performance_chain_arg(
    key: &'static str,
    network_mode: &str,
    tproxy_performance_enabled: bool,
    reasons: &[PerformanceFallbackReason],
) -> LogArg {
    match network_mode {
        "tproxy" | "enhance" if tproxy_performance_enabled => arg_i18n(
            key,
            "TPROXY performance chain enabled",
            "TPROXY 性能链已启用",
        ),
        "tproxy" | "enhance" => arg_i18n(
            key,
            format!(
                "TPROXY performance chain fallback to standard chain({})",
                performance_reason_list_en(reasons)
            ),
            format!(
                "TPROXY 性能链回退到标准链({})",
                performance_reason_list_zh(reasons)
            ),
        ),
        "redirect" | "mixed" => {
            arg_i18n(key, "REDIRECT uses standard chain", "REDIRECT 使用标准链")
        }
        "tun" => arg_i18n(key, "TUN uses standard chain", "TUN 使用标准链"),
        _ => arg_i18n(
            key,
            "current mode uses standard chain",
            "当前模式使用标准链",
        ),
    }
}

pub fn performance_uid_rule_arg(
    key: &'static str,
    count: usize,
    proxy_mode_applicable: bool,
    fallback: Option<PerformanceUidFallback>,
    ebpf_requested: bool,
) -> LogArg {
    if count == 0 {
        return arg_i18n(key, "UID rules no entries", "UID 规则无条目");
    }
    if !proxy_mode_applicable {
        return arg_i18n(
            key,
            format!("UID rules not applicable to current proxy mode({count} items)"),
            format!("UID 规则不适用于当前代理模式({count} 个)"),
        );
    }
    if let Some(fallback) = fallback {
        return arg_i18n(
            key,
            format!(
                "UID rules owner({count} items, eBPF fallback: {})",
                uid_fallback_en(fallback)
            ),
            format!(
                "UID 规则 owner({count} 个, eBPF 回退: {})",
                uid_fallback_zh(fallback)
            ),
        );
    }
    if ebpf_requested {
        arg_i18n(
            key,
            format!("UID rules eBPF({count} items)"),
            format!("UID 规则 eBPF({count} 个)"),
        )
    } else {
        arg_i18n(
            key,
            format!("UID rules owner({count} items)"),
            format!("UID 规则 owner({count} 个)"),
        )
    }
}

pub fn performance_gid_rule_arg(key: &'static str, count: usize) -> LogArg {
    if count == 0 {
        arg_i18n(key, "GID rules no entries", "GID 规则无条目")
    } else {
        arg_i18n(
            key,
            format!("GID rules owner({count} items)"),
            format!("GID 规则 owner({count} 个)"),
        )
    }
}

pub struct LocalIpLoopSummary {
    pub table: &'static str,
    pub family: &'static str,
    pub count: usize,
    pub cidrs: String,
    pub ok: usize,
    pub failed: usize,
}

pub fn local_ip_loop_summary_arg(key: &'static str, summaries: &[LocalIpLoopSummary]) -> LogArg {
    let en = summaries
        .iter()
        .map(|item| {
            format!(
                "{} {} CIDR({}): [{}], success {}, failed {}",
                item.table, item.family, item.count, item.cidrs, item.ok, item.failed
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let zh = summaries
        .iter()
        .map(|item| {
            format!(
                "{} {} CIDR({}): [{}], 成功 {}, 失败 {}",
                item.table, item.family, item.count, item.cidrs, item.ok, item.failed
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    arg_i18n(key, en, zh)
}

pub fn startup_args(config: &Config) -> Vec<LogArg> {
    vec![
        arg("workdir", config.paths.home.display()),
        arg("core", &config.bin_name),
        arg("mode", &config.network_mode),
        arg("config", config.launch_config_path().display()),
        arg("tun", display_value(&config.tun_device)),
        arg("tproxy", display_value(&config.tproxy_port)),
        arg("redir", display_value(&config.redir_port)),
        arg("dns_mode", &config.dns_hijack_mode),
        arg("dns_port", display_value(&config.mihomo_dns_port)),
        ipv6_mode_arg("ipv6", &config.ipv6_mode),
        enabled_arg("cnip", config.bypass_cn_ip),
        arg("cnip_mode", &config.cnip_mode),
    ]
}

pub fn ipv6_mode_arg(key: &'static str, value: &str) -> LogArg {
    match value {
        "enable" => arg_i18n(key, "enabled", "启用"),
        "disable" => arg_i18n(key, "system IPv6 disabled", "禁用系统 IPv6"),
        _ => arg_i18n(key, "bypassed", "不进核心"),
    }
}

pub fn core_config_args(config: &Config) -> Vec<LogArg> {
    vec![
        core_config_status_arg("status", &config.core_config_sources.read_status),
        arg("config", config.source_config_path().display()),
        arg("dns_port", display_value(&config.mihomo_dns_port)),
        config_source_arg(
            "dns_port_source",
            config.core_config_sources.mihomo_dns_port,
        ),
        arg("tun", display_value(&config.tun_device)),
        config_source_arg("tun_source", config.core_config_sources.tun_device),
        arg("fake4", display_value(&config.fake_ip_range)),
        config_source_arg("fake4_source", config.core_config_sources.fake_ip_range),
        arg("fake6", display_value(&config.fake_ip6_range)),
        config_source_arg("fake6_source", config.core_config_sources.fake_ip6_range),
    ]
}
