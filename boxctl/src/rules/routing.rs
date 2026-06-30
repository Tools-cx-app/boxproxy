use super::*;

impl<'a> RuleManager<'a> {
    pub(super) fn setup_tproxy_divert_chain(
        &self,
        family: Family,
        capabilities: &Capabilities,
    ) -> Result<()> {
        if self.config.network_mode == "enhance"
            || !capabilities.socket_match
            || !self.tproxy_performance_chain_enabled(capabilities)
        {
            self.cleanup_tproxy_divert_chain(family);
            return Ok(());
        }

        self.ensure_chain(family, "mangle", "DIVERT")?;
        self.ensure_rule_append(
            family,
            "mangle",
            "DIVERT",
            &["-j", "MARK", "--set-xmark", FWMARK],
        )?;
        self.ensure_rule_append(family, "mangle", "DIVERT", &["-j", "ACCEPT"])?;
        self.ensure_rule_insert(
            family,
            "mangle",
            "PREROUTING",
            &["-p", "tcp", "-m", "socket", "--transparent", "-j", "DIVERT"],
        );
        Ok(())
    }

    pub(super) fn cleanup_tproxy_divert_chain(&self, family: Family) {
        self.del_rule(
            family,
            "mangle",
            "PREROUTING",
            &["-p", "tcp", "-m", "socket", "--transparent", "-j", "DIVERT"],
        );
        self.del_rule(
            family,
            "mangle",
            "PREROUTING",
            &["-p", "tcp", "-m", "socket", "-j", "DIVERT"],
        );
        self.cleanup_chain_fast(family, "mangle", "DIVERT");
    }

    pub(super) fn apply_tproxy_ipv6_fakeip_rules(
        &self,
        family: Family,
        chain: &str,
        action: ProxyAction,
    ) -> Result<()> {
        if family != Family::V6
            || self.config.fake_ip6_range.trim().is_empty()
            || self.config.bin_name != "mihomo"
        {
            return Ok(());
        }

        let range = self.config.fake_ip6_range.trim();
        match action {
            ProxyAction::Tproxy => {
                if self.config.network_mode != "enhance" && self.config.proxy_tcp {
                    self.append_tproxy_dispatch_rule(
                        family,
                        chain,
                        vec!["-p".into(), "tcp".into(), "-d".into(), range.into()],
                    )?;
                }
                if self.config.proxy_udp {
                    self.append_tproxy_dispatch_rule(
                        family,
                        chain,
                        vec!["-p".into(), "udp".into(), "-d".into(), range.into()],
                    )?;
                }
            }
            ProxyAction::Mark => {
                if self.config.network_mode != "enhance" && self.config.proxy_tcp {
                    self.ensure_rule_append(
                        family,
                        "mangle",
                        chain,
                        &[
                            "-p",
                            "tcp",
                            "-d",
                            range,
                            "-j",
                            "MARK",
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
                            "-d",
                            range,
                            "-j",
                            "MARK",
                            "--set-xmark",
                            FWMARK,
                        ],
                    )?;
                }
            }
            ProxyAction::Redirect => {}
        }
        Ok(())
    }

    pub(super) fn setup_fake_ip_icmp_rules(&self, family: Family) {
        if family != Family::V4
            || self.config.fake_ip_range.trim().is_empty()
            || !matches!(self.config.bin_name.as_str(), "mihomo" | "sing-box")
        {
            return;
        }
        let range = self.config.fake_ip_range.trim();
        self.ensure_rule_insert(
            family,
            "nat",
            "OUTPUT",
            &[
                "-d",
                range,
                "-p",
                "icmp",
                "-j",
                "DNAT",
                "--to-destination",
                "127.0.0.1",
            ],
        );
        self.ensure_rule_insert(
            family,
            "nat",
            "PREROUTING",
            &[
                "-d",
                range,
                "-p",
                "icmp",
                "-j",
                "DNAT",
                "--to-destination",
                "127.0.0.1",
            ],
        );
    }

    pub(super) fn cleanup_fake_ip_icmp_rules(&self, family: Family) {
        if family != Family::V4 || self.config.fake_ip_range.trim().is_empty() {
            return;
        }
        let range = self.config.fake_ip_range.trim();
        for chain in ["OUTPUT", "PREROUTING"] {
            self.del_rule(
                family,
                "nat",
                chain,
                &[
                    "-p",
                    "icmp",
                    "-d",
                    range,
                    "-j",
                    "DNAT",
                    "--to-destination",
                    "127.0.0.1",
                ],
            );
            self.del_rule(
                family,
                "nat",
                chain,
                &[
                    "-d",
                    range,
                    "-p",
                    "icmp",
                    "-j",
                    "DNAT",
                    "--to-destination",
                    "127.0.0.1",
                ],
            );
        }
    }

    pub(super) fn apply_loopback_reject_rule(
        &self,
        family: Family,
        port: &str,
        context: &RuleContext,
    ) {
        for args in owner_match_variants(context, "-d", loopback_addr(family), port) {
            if self
                .ensure_rule_append_owned(family, "filter", "OUTPUT", args)
                .is_ok()
            {
                return;
            }
        }
    }

    pub(super) fn cleanup_loopback_reject_rule(&self, family: Family, port: &str) {
        let addr = loopback_addr(family);
        let context = self.prepare_context();
        for owned in owner_match_variants(&context, "-d", addr, port) {
            let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
            self.del_rule(family, "filter", "OUTPUT", &refs);
        }

        let fixed = [
            vec![
                "-d",
                addr,
                "-p",
                "tcp",
                "-m",
                "owner",
                "--uid-owner",
                "0:3005",
                "-m",
                "tcp",
                "--dport",
                port,
                "-j",
                "REJECT",
            ],
            vec![
                "-d",
                addr,
                "-p",
                "tcp",
                "-m",
                "owner",
                "--uid-owner",
                "0",
                "--gid-owner",
                "3005",
                "-m",
                "tcp",
                "--dport",
                port,
                "-j",
                "REJECT",
            ],
        ];
        for args in fixed {
            self.del_rule(family, "filter", "OUTPUT", &args);
        }
    }

    pub(super) fn apply_quic_block_rules(&self, family: Family) {
        if self.config.quic != "disable" || !self.config.proxy_udp {
            return;
        }
        let mut failed = Vec::new();
        for port in ["443", "80"] {
            if self
                .ensure_rule_append(
                    family,
                    "filter",
                    "OUTPUT",
                    &["-p", "udp", "--dport", port, "-j", "REJECT"],
                )
                .is_err()
            {
                failed.push(port);
            }
        }
        if !failed.is_empty() {
            logger::warn_key(
                self.config,
                LogKey::QuicBlockRuleFailed,
                &[family_arg(family), arg("ports", failed.join(", "))],
            );
        }
    }

    pub(super) fn cleanup_quic_block_rules(&self, family: Family) {
        self.del_rule(
            family,
            "filter",
            "OUTPUT",
            &[
                "-p",
                "udp",
                "-m",
                "multiport",
                "--dport",
                "443,80",
                "-j",
                "REJECT",
            ],
        );
        self.del_rule(
            family,
            "filter",
            "OUTPUT",
            &["-p", "udp", "--dport", "443", "-j", "REJECT"],
        );
        self.del_rule(
            family,
            "filter",
            "OUTPUT",
            &["-p", "udp", "--dport", "80", "-j", "REJECT"],
        );
    }

    pub(super) fn setup_tproxy_policy_routing(&self, family: Family) -> Result<()> {
        self.ensure_ip_rule(family, FWMARK, TPROXY_TABLE, TPROXY_PREF)?;
        self.ensure_ip_route_local_default(family, TPROXY_TABLE)
    }

    pub(super) fn cleanup_tproxy_policy_routing(&self, family: Family) {
        self.del_ip_rule_if_exists(family, FWMARK, TPROXY_TABLE, TPROXY_PREF);
        self.del_ip_route_local_default_if_exists(family, TPROXY_TABLE);
        self.ip_ignore(family, &["route", "flush", "table", TPROXY_TABLE]);
        self.ip_ignore(family, &["rule", "del", "pref", TPROXY_PREF]);
    }

    pub(super) fn apply_tun_route_rules(&self, family: Family) -> Result<()> {
        self.ensure_ip_rule(family, TUN_BYPASS_MARK, "main", TUN_BYPASS_PREF)?;
        self.ensure_ip_rule(family, TUN_ROUTE_MARK, TUN_ROUTE_TABLE, TUN_ROUTE_PREF)?;
        self.ip_required(
            family,
            &[
                "route",
                "replace",
                "default",
                "dev",
                &self.config.tun_device,
                "table",
                TUN_ROUTE_TABLE,
            ],
        )
    }

    pub(super) fn cleanup_tun_route_rules(&self, family: Family) {
        self.del_ip_rule_if_exists(family, TUN_BYPASS_MARK, "main", TUN_BYPASS_PREF);
        self.del_ip_rule_if_exists(family, TUN_ROUTE_MARK, TUN_ROUTE_TABLE, TUN_ROUTE_PREF);
        self.ip_ignore(family, &["route", "flush", "table", TUN_ROUTE_TABLE]);
    }

    pub(super) fn forward(&self, family: Family, enable: bool) -> Result<()> {
        if enable {
            self.ensure_rule_insert(
                family,
                "filter",
                "FORWARD",
                &["-i", &self.config.tun_device, "-j", "ACCEPT"],
            );
            self.ensure_rule_insert(
                family,
                "filter",
                "FORWARD",
                &["-o", &self.config.tun_device, "-j", "ACCEPT"],
            );
            if family == Family::V4 {
                self.runner
                    .run_ignore("sysctl", &["-w", "net.ipv4.ip_forward=1"]);
                self.runner
                    .run_ignore("sysctl", &["-w", "net.ipv4.conf.default.rp_filter=2"]);
                self.runner
                    .run_ignore("sysctl", &["-w", "net.ipv4.conf.all.rp_filter=2"]);
            }
            Ok(())
        } else {
            self.del_rule(
                family,
                "filter",
                "FORWARD",
                &["-i", &self.config.tun_device, "-j", "ACCEPT"],
            );
            self.del_rule(
                family,
                "filter",
                "FORWARD",
                &["-o", &self.config.tun_device, "-j", "ACCEPT"],
            );
            Ok(())
        }
    }
}
