use super::*;

impl<'a> RuleManager<'a> {
    pub(super) fn prepare_context(&self) -> RuleContext {
        let (default_uid, default_gid) = split_user_group(&self.config.box_user_group);
        let (box_uid, box_gid) = self
            .probe_user_group()
            .unwrap_or_else(|| (default_uid.to_string(), default_gid.to_string()));
        RuleContext {
            box_uid,
            box_gid,
            selected_uids: normalized_list(&self.config.selected_uids),
            selected_gids: normalized_list(&self.config.gid_list),
            cnip_force_uids: normalized_list(&self.config.cnip_force_uids),
        }
    }

    pub(super) fn probe_user_group(&self) -> Option<(String, String)> {
        if self.runner.dry_run() {
            return None;
        }
        let pid = fs::read_to_string(&self.config.box_pid)
            .ok()
            .map(|text| text.trim().to_string())
            .filter(|pid| proc_pid_matches_name(pid, &self.config.bin_name))
            .or_else(|| find_proc_pid_by_name(&self.config.bin_name))?;
        let status = fs::read_to_string(Path::new("/proc").join(pid).join("status")).ok()?;
        let uid = proc_status_first_value(&status, "Uid:")?;
        let gid = proc_status_first_value(&status, "Gid:")?;
        Some((uid, gid))
    }

    pub(super) fn log_apply_context(&self, context: &RuleContext, capabilities: &Capabilities) {
        logger::info_key(
            self.config,
            LogKey::RuleContext,
            &[
                arg("mode", &self.config.network_mode),
                arg("core", &self.config.bin_name),
                logger::enabled_arg("tcp", self.config.proxy_tcp),
                logger::enabled_arg("udp", self.config.proxy_udp),
                logger::quic_arg("quic", &self.config.quic),
                arg("dns_mode", &self.config.dns_hijack_mode),
                logger::enabled_arg("dns_tcp", self.config.dns_hijack_tcp),
                logger::enabled_arg("dns_udp", self.config.dns_hijack_udp),
                logger::enabled_arg("cnip", self.config.bypass_cn_ip),
                arg("cnip_mode", &self.config.cnip_mode),
                arg("uid", &context.box_uid),
                arg("gid", &context.box_gid),
                arg("uid_count", context.selected_uids.len()),
                arg("gid_count", context.selected_gids.len()),
                arg("force_uid_count", context.cnip_force_uids.len()),
                logger::enabled_arg("tproxy4", capabilities.tproxy4),
                logger::enabled_arg("tproxy6", capabilities.tproxy6),
                logger::enabled_arg("ipset", capabilities.ipset),
                logger::enabled_arg("ip6_nat", capabilities.ip6_nat),
            ],
        );
    }

    pub(super) fn log_performance_mode_context(
        &self,
        context: &RuleContext,
        capabilities: &Capabilities,
    ) {
        if !self.config.performance_mode {
            logger::info_key(self.config, LogKey::PerformanceModeDisabled, &[]);
            return;
        }

        let reply_text = logger::performance_reply_arg(
            "reply",
            &self.config.network_mode,
            capabilities.conntrack_match,
        );
        let reasons = self.tproxy_performance_fallback_reasons(capabilities);
        let chain_text = logger::performance_chain_arg(
            "chain",
            &self.config.network_mode,
            self.tproxy_performance_chain_enabled(capabilities),
            &reasons,
        );
        let uid_rule = self.performance_uid_rule_arg(context, capabilities);
        let gid_rule = logger::performance_gid_rule_arg("gid_rule", context.selected_gids.len());

        logger::info_key(
            self.config,
            LogKey::PerformanceModeEnabled,
            &[logger::arg_i18n(
                "detail",
                format!(
                    "{}, {}, {}, {}",
                    reply_text.en_value(),
                    chain_text.en_value(),
                    uid_rule.en_value(),
                    gid_rule.en_value(),
                ),
                format!(
                    "{}, {}, {}, {}",
                    reply_text.zh_value(),
                    chain_text.zh_value(),
                    uid_rule.zh_value(),
                    gid_rule.zh_value(),
                ),
            )],
        );
    }

    pub(super) fn tproxy_performance_fallback_reasons(
        &self,
        capabilities: &Capabilities,
    ) -> Vec<logger::PerformanceFallbackReason> {
        let mut reasons = Vec::new();
        if !capabilities.conntrack_match {
            reasons.push(logger::PerformanceFallbackReason::MissingConntrack);
        }
        if !capabilities.connmark_match {
            reasons.push(logger::PerformanceFallbackReason::MissingConnmark);
        }
        if !capabilities.connmark_target {
            reasons.push(logger::PerformanceFallbackReason::MissingConnmarkTarget);
        }
        if self.config.network_mode != "enhance" && !capabilities.socket_transparent {
            reasons.push(logger::PerformanceFallbackReason::MissingSocketTransparent);
        }
        if self.config.network_mode == "enhance" && !self.config.proxy_udp {
            reasons.push(logger::PerformanceFallbackReason::UdpNotEnabled);
        }
        if reasons.is_empty() {
            reasons.push(logger::PerformanceFallbackReason::ConditionsNotMet);
        }
        reasons
    }

    pub(super) fn performance_uid_rule_arg(
        &self,
        context: &RuleContext,
        capabilities: &Capabilities,
    ) -> logger::LogArg {
        let count = context.selected_uids.len();
        let applicable = matches!(
            self.config.proxy_mode.as_str(),
            "blacklist" | "black" | "whitelist" | "white"
        );

        let fallback = if count == 0 || !applicable {
            None
        } else if !capabilities.bpf_match {
            Some(logger::PerformanceUidFallback::BpfMatchUnavailable)
        } else if !self.config.bpf_matcher_path.is_file() {
            Some(logger::PerformanceUidFallback::BoxbpfMissing)
        } else if !self.app_uid_ebpf_pin_loaded(Family::V4) {
            Some(logger::PerformanceUidFallback::Ipv4ProgramMissing)
        } else if self.config.ipv6 && !self.app_uid_ebpf_pin_loaded(Family::V6) {
            Some(logger::PerformanceUidFallback::Ipv6ProgramMissing)
        } else {
            None
        };

        logger::performance_uid_rule_arg(
            "uid_rule",
            count,
            applicable,
            fallback,
            self.app_uid_ebpf_requested(context),
        )
    }
}
