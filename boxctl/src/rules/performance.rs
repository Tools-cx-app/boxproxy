use super::*;

impl<'a> RuleManager<'a> {
    pub(super) fn performance_conntrack_enabled(&self) -> bool {
        if !self.config.performance_mode {
            return false;
        }
        let caps = self.probe_capabilities();
        caps.conntrack_match
    }

    pub(super) fn performance_connmark_enabled(&self, capabilities: &Capabilities) -> bool {
        self.config.performance_mode
            && capabilities.conntrack_match
            && capabilities.connmark_match
            && capabilities.connmark_target
    }

    pub(super) fn tproxy_performance_chain_enabled(&self, capabilities: &Capabilities) -> bool {
        if !self.performance_connmark_enabled(capabilities) {
            return false;
        }
        if self.config.network_mode != "enhance" && !capabilities.socket_transparent {
            return false;
        }
        if self.config.network_mode == "enhance" && !self.config.proxy_udp {
            return false;
        }
        true
    }

    pub(super) fn setup_perf_dest_chain(
        &self,
        family: Family,
        table: &str,
        chain: &str,
    ) -> Result<()> {
        self.ensure_chain(family, table, chain)?;

        let bypass_subnets = self.bypass_subnets(family);
        for subnet in &bypass_subnets {
            self.append_perf_bypass_target(
                family,
                table,
                chain,
                vec!["-d".into(), subnet.clone()],
            )?;
        }

        if let Some(args) = self.cnip_match_args(family, chain, Vec::new()) {
            self.append_perf_bypass_target(family, table, chain, args)?;
        }

        self.append_perf_addrtype_bypass_target(family, table, chain)?;

        let loopback = match family {
            Family::V4 => "127.0.0.0/8",
            Family::V6 => "::1/128",
        };
        if !bypass_subnets.iter().any(|subnet| subnet == loopback) {
            self.append_perf_bypass_target(
                family,
                table,
                chain,
                vec!["-d".into(), loopback.into()],
            )?;
        }
        Ok(())
    }

    pub(super) fn append_perf_bypass_target(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        base: Vec<String>,
    ) -> Result<()> {
        let mut udp_non_dns = base.clone();
        udp_non_dns.extend([
            "-p".into(),
            "udp".into(),
            "!".into(),
            "--dport".into(),
            "53".into(),
            "-j".into(),
            "ACCEPT".into(),
        ]);
        self.ensure_rule_append_owned(family, table, chain, udp_non_dns)?;

        let mut non_udp = base;
        non_udp.extend([
            "!".into(),
            "-p".into(),
            "udp".into(),
            "-j".into(),
            "ACCEPT".into(),
        ]);
        self.ensure_rule_append_owned(family, table, chain, non_udp)
    }

    pub(super) fn append_perf_addrtype_bypass_target(
        &self,
        family: Family,
        table: &str,
        chain: &str,
    ) -> Result<()> {
        if !self.probe_capabilities().addrtype {
            self.warn_perf_addrtype_fallback(family);
            return Ok(());
        }

        let base = vec![
            "-m".into(),
            "addrtype".into(),
            "--dst-type".into(),
            "LOCAL".into(),
        ];
        if self.append_perf_bypass_target_try_skip(family, table, chain, base) {
            return Ok(());
        }

        self.warn_perf_addrtype_fallback(family);
        Ok(())
    }

    pub(super) fn warn_perf_addrtype_fallback(&self, family: Family) {
        let warned = match family {
            Family::V4 => &self.addrtype_v4_fallback_warned,
            Family::V6 => &self.addrtype_v6_fallback_warned,
        };
        if warned.set(()).is_ok() {
            logger::warn_key(
                self.config,
                LogKey::PerformanceAddrtypeFallback,
                &[family_arg(family)],
            );
        }
    }

    pub(super) fn append_perf_bypass_target_try_skip(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        base: Vec<String>,
    ) -> bool {
        let mut udp_non_dns = base.clone();
        udp_non_dns.extend([
            "-p".into(),
            "udp".into(),
            "!".into(),
            "--dport".into(),
            "53".into(),
            "-j".into(),
            "ACCEPT".into(),
        ]);

        let udp_ok = self.append_rule_try_skip(family, table, chain, udp_non_dns);

        let mut non_udp = base;
        non_udp.extend([
            "!".into(),
            "-p".into(),
            "udp".into(),
            "-j".into(),
            "ACCEPT".into(),
        ]);
        let non_udp_ok = self.append_rule_try_skip(family, table, chain, non_udp);
        udp_ok && non_udp_ok
    }

    pub(super) fn append_rule_try_skip(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        args: Vec<String>,
    ) -> bool {
        if !is_box_custom_chain(chain) {
            let mut check = vec!["-t".into(), table.into(), "-C".into(), chain.into()];
            check.extend(args.iter().cloned());
            if self.ipt_check_owned(family, &check) {
                return true;
            }
        }

        let mut full = vec!["-t".into(), table.into(), "-A".into(), chain.into()];
        full.extend(args);
        self.ipt_try_owned(family, full)
    }

    pub(super) fn setup_perf_pre_if_chain(
        &self,
        family: Family,
        table: &str,
        chain: &str,
    ) -> Result<()> {
        self.ensure_chain(family, table, chain)?;

        for iface in &self.config.blocked_interfaces {
            self.ensure_rule_append_owned(
                family,
                table,
                chain,
                vec!["-i".into(), iface.clone(), "-j".into(), "ACCEPT".into()],
            )?;
        }

        self.ensure_rule_append(family, table, chain, &["-i", "lo", "-j", "RETURN"])?;

        if !self.config.mac_filter {
            self.ensure_rule_append(family, table, chain, &["-j", "RETURN"])?;
            return Ok(());
        }

        let macs = valid_macs(&self.config.macs_list);
        for iface in &self.config.hotspot_ap_interfaces {
            if self.config.mac_mode == "whitelist" {
                for mac in &macs {
                    self.ensure_rule_append_owned(
                        family,
                        table,
                        chain,
                        vec![
                            "-i".into(),
                            iface.clone(),
                            "-m".into(),
                            "mac".into(),
                            "--mac-source".into(),
                            mac.clone(),
                            "-j".into(),
                            "RETURN".into(),
                        ],
                    )?;
                }
                self.ensure_rule_append(family, table, chain, &["-i", iface, "-j", "ACCEPT"])?;
            } else {
                for mac in &macs {
                    self.ensure_rule_append_owned(
                        family,
                        table,
                        chain,
                        vec![
                            "-i".into(),
                            iface.clone(),
                            "-m".into(),
                            "mac".into(),
                            "--mac-source".into(),
                            mac.clone(),
                            "-j".into(),
                            "ACCEPT".into(),
                        ],
                    )?;
                }
                self.ensure_rule_append(family, table, chain, &["-i", iface, "-j", "RETURN"])?;
            }
        }

        self.ensure_rule_append(family, table, chain, &["-j", "ACCEPT"])
    }

    pub(super) fn setup_perf_out_app_chain(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        context: &RuleContext,
    ) -> Result<()> {
        self.ensure_chain(family, table, chain)?;
        let uid_ebpf = self.app_uid_ebpf_active(family, context);

        match self.config.proxy_mode.as_str() {
            "blacklist" | "black" => {
                if uid_ebpf {
                    let mut args = self.app_uid_match_args(family, Vec::new());
                    args.extend(["-j".into(), "ACCEPT".into()]);
                    self.ensure_rule_append_owned(family, table, chain, args)?;
                } else {
                    for uid in &context.selected_uids {
                        self.ensure_rule_append_owned(
                            family,
                            table,
                            chain,
                            vec![
                                "-m".into(),
                                "owner".into(),
                                "--uid-owner".into(),
                                uid.clone(),
                                "-j".into(),
                                "ACCEPT".into(),
                            ],
                        )?;
                    }
                }
                for gid in &context.selected_gids {
                    self.ensure_rule_append_owned(
                        family,
                        table,
                        chain,
                        vec![
                            "-m".into(),
                            "owner".into(),
                            "--gid-owner".into(),
                            gid.clone(),
                            "-j".into(),
                            "ACCEPT".into(),
                        ],
                    )?;
                }
            }
            "whitelist" | "white" => {
                let mut has_whitelist = false;
                if uid_ebpf {
                    has_whitelist = true;
                    let mut args = self.app_uid_match_args(family, Vec::new());
                    args.extend(["-j".into(), "RETURN".into()]);
                    self.ensure_rule_append_owned(family, table, chain, args)?;
                } else {
                    for uid in &context.selected_uids {
                        has_whitelist = true;
                        self.ensure_rule_append_owned(
                            family,
                            table,
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
                }
                if !context.selected_uids.is_empty() {
                    for uid in ["0", "1052"] {
                        self.ensure_rule_append(
                            family,
                            table,
                            chain,
                            &["-m", "owner", "--uid-owner", uid, "-j", "RETURN"],
                        )?;
                    }
                }
                for gid in &context.selected_gids {
                    has_whitelist = true;
                    self.ensure_rule_append_owned(
                        family,
                        table,
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
                if has_whitelist {
                    self.ensure_rule_append(family, table, chain, &["-j", "ACCEPT"])?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn add_perf_chain_jumps(
        &self,
        family: Family,
        table: &str,
        parent: &str,
        targets: &[&str],
    ) -> Result<()> {
        for target in targets {
            if self.config.proxy_tcp && (table != "mangle" || self.config.network_mode != "enhance")
            {
                self.ensure_rule_append_owned(
                    family,
                    table,
                    parent,
                    vec![
                        "-p".into(),
                        "tcp".into(),
                        "--syn".into(),
                        "-j".into(),
                        (*target).into(),
                    ],
                )?;
            }
            if table == "mangle" && self.config.proxy_udp {
                self.ensure_rule_append_owned(
                    family,
                    table,
                    parent,
                    vec![
                        "-p".into(),
                        "udp".into(),
                        "-m".into(),
                        "conntrack".into(),
                        "--ctstate".into(),
                        "NEW,RELATED".into(),
                        "-j".into(),
                        (*target).into(),
                    ],
                )?;
            }
        }
        Ok(())
    }

    pub(super) fn append_tproxy_perf_connmark_rules(
        &self,
        family: Family,
        chain: &str,
    ) -> Result<()> {
        if self.config.network_mode != "enhance" && self.config.proxy_tcp {
            self.ensure_rule_append(
                family,
                "mangle",
                chain,
                &[
                    "-p",
                    "tcp",
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "NEW,RELATED",
                    "-j",
                    "CONNMARK",
                    "--set-xmark",
                    FWMARK,
                ],
            )?;
        }
        if self.config.proxy_udp {
            self.ensure_rule_append(
                family,
                "mangle",
                chain,
                &[
                    "-p",
                    "udp",
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "NEW,RELATED",
                    "-j",
                    "CONNMARK",
                    "--set-xmark",
                    FWMARK,
                ],
            )?;
        }
        Ok(())
    }
}
