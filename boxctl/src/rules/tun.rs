use super::*;

impl<'a> RuleManager<'a> {
    pub(super) fn tun_route_managed_by_box(&self) -> bool {
        self.config.bypass_cn_ip || self.config.mac_filter
    }

    pub(super) fn append_tun_external_interface_policy_rules(
        &self,
        family: Family,
        chain: &str,
    ) -> Result<()> {
        for iface in &self.config.blocked_interfaces {
            self.append_mark_return(
                family,
                chain,
                TUN_BYPASS_MARK,
                vec!["-i".into(), iface.clone()],
            )?;
        }

        if !self.config.mac_filter {
            return Ok(());
        }

        let macs = valid_macs(&self.config.macs_list);
        for iface in &self.config.hotspot_ap_interfaces {
            if self.config.mac_mode == "whitelist" {
                if macs.is_empty() && family == Family::V4 {
                    logger::warn_key(
                        self.config,
                        LogKey::HotspotWhitelistEmpty,
                        &[arg("iface", iface)],
                    );
                }
                for mac in &macs {
                    self.ensure_rule_append_owned(
                        family,
                        "mangle",
                        chain,
                        vec![
                            "-i".into(),
                            iface.clone(),
                            "-m".into(),
                            "mac".into(),
                            "--mac-source".into(),
                            mac.clone(),
                            "-j".into(),
                            "MARK".into(),
                            "--set-xmark".into(),
                            TUN_ROUTE_MARK.into(),
                        ],
                    )?;
                }
                self.append_mark_return(
                    family,
                    chain,
                    TUN_BYPASS_MARK,
                    vec!["-i".into(), iface.clone()],
                )?;
            } else {
                for mac in &macs {
                    self.append_mark_return(
                        family,
                        chain,
                        TUN_BYPASS_MARK,
                        vec![
                            "-i".into(),
                            iface.clone(),
                            "-m".into(),
                            "mac".into(),
                            "--mac-source".into(),
                            mac.clone(),
                        ],
                    )?;
                }
                self.ensure_rule_append_owned(
                    family,
                    "mangle",
                    chain,
                    vec![
                        "-i".into(),
                        iface.clone(),
                        "-j".into(),
                        "MARK".into(),
                        "--set-xmark".into(),
                        TUN_ROUTE_MARK.into(),
                    ],
                )?;
            }
        }

        self.ensure_rule_append(
            family,
            "mangle",
            chain,
            &["-m", "mark", "--mark", TUN_BYPASS_MARK, "-j", "RETURN"],
        )
    }

    pub(super) fn append_tun_dns_rules(&self, family: Family, chain: &str) -> Result<()> {
        if self.dns_mode_is_disable() {
            return Ok(());
        }
        if self.dns_tcp_enabled() {
            self.append_mark_return(
                family,
                chain,
                TUN_ROUTE_MARK,
                vec!["-p".into(), "tcp".into(), "--dport".into(), "53".into()],
            )?;
        }
        if self.dns_udp_enabled() {
            self.append_mark_return(
                family,
                chain,
                TUN_ROUTE_MARK,
                vec!["-p".into(), "udp".into(), "--dport".into(), "53".into()],
            )?;
        }
        Ok(())
    }

    pub(super) fn append_tun_force_proxy_destination_rules(
        &self,
        family: Family,
        chain: &str,
    ) -> Result<()> {
        let cidrs = match family {
            Family::V4 => &self.config.tun_force_proxy_cidrs,
            Family::V6 => &self.config.tun_force_proxy_cidrs6,
        };
        for cidr in cidrs {
            if cidr.trim().is_empty() {
                continue;
            }
            self.append_mark_return(
                family,
                chain,
                TUN_ROUTE_MARK,
                vec!["-d".into(), cidr.clone()],
            )?;
        }
        Ok(())
    }

    pub(super) fn append_tun_bypass_destination_rules(
        &self,
        family: Family,
        chain: &str,
    ) -> Result<()> {
        self.append_tun_fake_ip_route_rules(family, chain)?;

        for subnet in self.bypass_subnets(family) {
            self.ensure_rule_append_owned(
                family,
                "mangle",
                chain,
                vec!["-d".into(), subnet, "-j".into(), "RETURN".into()],
            )?;
        }

        if let Some(mut args) = self.cnip_match_args(family, chain, Vec::new()) {
            args.extend([
                "-j".into(),
                "MARK".into(),
                "--set-xmark".into(),
                TUN_BYPASS_MARK.into(),
            ]);
            self.ensure_rule_append_owned(family, "mangle", chain, args)?;
        }

        self.ensure_rule_append(
            family,
            "mangle",
            chain,
            &["-m", "mark", "--mark", TUN_BYPASS_MARK, "-j", "RETURN"],
        )?;
        self.ensure_rule_append(
            family,
            "mangle",
            chain,
            &["-j", "MARK", "--set-xmark", TUN_ROUTE_MARK],
        )
    }

    pub(super) fn append_tun_fake_ip_route_rules(&self, family: Family, chain: &str) -> Result<()> {
        let range = match family {
            Family::V4 => self.config.fake_ip_range.trim(),
            Family::V6 => self.config.fake_ip6_range.trim(),
        };
        if range.is_empty() {
            return Ok(());
        }
        self.ensure_rule_append(
            family,
            "mangle",
            chain,
            &["-d", range, "-j", "MARK", "--set-xmark", TUN_ROUTE_MARK],
        )?;
        self.ensure_rule_append(family, "mangle", chain, &["-d", range, "-j", "RETURN"])
    }

    pub(super) fn append_tun_proxy_mode_rules(
        &self,
        family: Family,
        chain: &str,
        context: &RuleContext,
    ) -> Result<()> {
        match self.config.proxy_mode.as_str() {
            "blacklist" | "black" => {
                for uid in &context.selected_uids {
                    self.ensure_rule_append_owned(
                        family,
                        "mangle",
                        chain,
                        vec![
                            "-m".into(),
                            "owner".into(),
                            "--uid-owner".into(),
                            uid.clone(),
                            "-j".into(),
                            "RETURN".into(),
                        ],
                    )?;
                }
                for gid in &context.selected_gids {
                    self.ensure_rule_append_owned(
                        family,
                        "mangle",
                        chain,
                        vec![
                            "-m".into(),
                            "owner".into(),
                            "--gid-owner".into(),
                            gid.clone(),
                            "-j".into(),
                            "RETURN".into(),
                        ],
                    )?;
                }
            }
            "whitelist" | "white" => {
                let mut has_list = false;
                for uid in &context.selected_uids {
                    has_list = true;
                    self.ensure_rule_append_owned(
                        family,
                        "mangle",
                        chain,
                        vec![
                            "-m".into(),
                            "owner".into(),
                            "--uid-owner".into(),
                            uid.clone(),
                            "-j".into(),
                            "MARK".into(),
                            "--set-xmark".into(),
                            TUN_ROUTE_MARK.into(),
                        ],
                    )?;
                }
                for gid in &context.selected_gids {
                    has_list = true;
                    self.ensure_rule_append_owned(
                        family,
                        "mangle",
                        chain,
                        vec![
                            "-m".into(),
                            "owner".into(),
                            "--gid-owner".into(),
                            gid.clone(),
                            "-j".into(),
                            "MARK".into(),
                            "--set-xmark".into(),
                            TUN_ROUTE_MARK.into(),
                        ],
                    )?;
                }
                if has_list {
                    self.ensure_rule_append(family, "mangle", chain, &["-j", "RETURN"])?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn append_cnip_force_proxy_tun_rules(
        &self,
        family: Family,
        chain: &str,
        context: &RuleContext,
    ) -> Result<()> {
        if !self.config.bypass_cn_ip
            || context.cnip_force_uids.is_empty()
            || !self.cnip_matcher_enabled_for_family(family)
        {
            return Ok(());
        }

        if self.cnip_uses_ebpf() {
            for proto in ["tcp", "udp"] {
                if proto == "tcp" && !self.config.proxy_tcp {
                    continue;
                }
                if proto == "udp" && !self.config.proxy_udp {
                    continue;
                }
                let Some(base) =
                    self.cnip_force_match_args(family, vec!["-p".into(), proto.into()])
                else {
                    continue;
                };
                let mut mark = base.clone();
                mark.extend([
                    "-j".into(),
                    "MARK".into(),
                    "--set-xmark".into(),
                    TUN_ROUTE_MARK.into(),
                ]);
                self.ensure_rule_append_owned(family, "mangle", chain, mark)?;
                let mut ret = base;
                ret.extend(["-j".into(), "RETURN".into()]);
                self.ensure_rule_append_owned(family, "mangle", chain, ret)?;
            }
            return Ok(());
        }

        for uid in &context.cnip_force_uids {
            for proto in ["tcp", "udp"] {
                if proto == "tcp" && !self.config.proxy_tcp {
                    continue;
                }
                if proto == "udp" && !self.config.proxy_udp {
                    continue;
                }
                let Some(base) = self.cnip_match_args(
                    family,
                    chain,
                    vec![
                        "-p".into(),
                        proto.into(),
                        "-m".into(),
                        "owner".into(),
                        "--uid-owner".into(),
                        uid.clone(),
                    ],
                ) else {
                    continue;
                };
                let mut mark = base.clone();
                mark.extend([
                    "-j".into(),
                    "MARK".into(),
                    "--set-xmark".into(),
                    TUN_ROUTE_MARK.into(),
                ]);
                self.ensure_rule_append_owned(family, "mangle", chain, mark)?;
                let mut ret = base;
                ret.extend(["-j".into(), "RETURN".into()]);
                self.ensure_rule_append_owned(family, "mangle", chain, ret)?;
            }
        }
        Ok(())
    }

    pub(super) fn append_tun_core_bypass_rules(
        &self,
        family: Family,
        chain: &str,
        context: &RuleContext,
    ) {
        if !self.add_core_bypass_rule(family, "mangle", chain, "-A", context)
            && family == Family::V4
        {
            logger::warn_key(self.config, LogKey::TunCoreBypassFailed, &[]);
        }
    }

    pub(super) fn append_mark_return(
        &self,
        family: Family,
        chain: &str,
        mark: &str,
        mut args: Vec<String>,
    ) -> Result<()> {
        let mut mark_args = args.clone();
        mark_args.extend([
            "-j".into(),
            "MARK".into(),
            "--set-xmark".into(),
            mark.into(),
        ]);
        self.ensure_rule_append_owned(family, "mangle", chain, mark_args)?;
        args.extend(["-j".into(), "RETURN".into()]);
        self.ensure_rule_append_owned(family, "mangle", chain, args)
    }
}
