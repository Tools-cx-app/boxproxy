use super::*;

impl<'a> RuleManager<'a> {
    pub(super) fn apply_external_loopback_rule(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        action: ProxyAction,
    ) -> Result<()> {
        match action {
            ProxyAction::Redirect => {
                self.append_external_protocol_rule(
                    family, table, chain, action, "tcp", "lo", None,
                )?;
            }
            ProxyAction::Tproxy => {
                self.append_external_protocol_rule(
                    family, table, chain, action, "tcp", "lo", None,
                )?;
                self.append_external_protocol_rule(
                    family, table, chain, action, "udp", "lo", None,
                )?;
            }
            ProxyAction::Mark => {}
        }
        Ok(())
    }

    pub(super) fn apply_external_ap_rules(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        action: ProxyAction,
    ) -> Result<()> {
        if !self.config.mac_filter {
            return self.apply_external_all_rules(family, chain, action);
        }

        if self.config.hotspot_ap_interfaces.is_empty() {
            return Ok(());
        }

        let macs = valid_macs(&self.config.macs_list);

        // The whitelist-empty condition is interface-independent, so report it
        // once for all hotspot interfaces instead of one warning per interface.
        if self.config.mac_mode == "whitelist" && macs.is_empty() && family == Family::V4 {
            logger::warn_key(
                self.config,
                LogKey::HotspotWhitelistEmpty,
                &[arg("ifaces", self.config.hotspot_ap_interfaces.join(", "))],
            );
        }

        for iface in &self.config.hotspot_ap_interfaces {
            if self.config.mac_filter {
                if self.config.mac_mode == "whitelist" {
                    for mac in &macs {
                        self.append_external_protocol_rule(
                            family,
                            table,
                            chain,
                            action,
                            "tcp",
                            iface,
                            Some(mac),
                        )?;
                        self.append_external_protocol_rule(
                            family,
                            table,
                            chain,
                            action,
                            "udp",
                            iface,
                            Some(mac),
                        )?;
                    }
                } else {
                    for mac in &macs {
                        match action {
                            ProxyAction::Redirect => {
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
                            ProxyAction::Tproxy => {
                                if self.config.network_mode != "enhance" && self.config.proxy_tcp {
                                    self.ensure_rule_append_owned(
                                        family,
                                        table,
                                        chain,
                                        vec![
                                            "-p".into(),
                                            "tcp".into(),
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
                                if self.config.proxy_udp {
                                    self.ensure_rule_append_owned(
                                        family,
                                        table,
                                        chain,
                                        vec![
                                            "-p".into(),
                                            "udp".into(),
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
                            }
                            ProxyAction::Mark => {}
                        }
                    }
                    self.append_external_protocol_rule(
                        family, table, chain, action, "tcp", iface, None,
                    )?;
                    self.append_external_protocol_rule(
                        family, table, chain, action, "udp", iface, None,
                    )?;
                }
            } else {
                self.append_external_protocol_rule(
                    family, table, chain, action, "tcp", iface, None,
                )?;
                self.append_external_protocol_rule(
                    family, table, chain, action, "udp", iface, None,
                )?;
            }
        }
        Ok(())
    }

    pub(super) fn apply_external_all_rules(
        &self,
        family: Family,
        chain: &str,
        action: ProxyAction,
    ) -> Result<()> {
        match action {
            ProxyAction::Redirect => {
                if self.config.proxy_tcp {
                    self.append_redirect_dispatch_rule(
                        family,
                        chain,
                        vec!["-p".into(), "tcp".into()],
                    )?;
                }
            }
            ProxyAction::Tproxy => {
                if self.config.proxy_tcp && self.config.network_mode != "enhance" {
                    self.append_tproxy_dispatch_rule(
                        family,
                        chain,
                        vec!["-p".into(), "tcp".into()],
                    )?;
                }
                if self.config.proxy_udp {
                    self.append_tproxy_dispatch_rule(
                        family,
                        chain,
                        vec!["-p".into(), "udp".into()],
                    )?;
                }
            }
            ProxyAction::Mark => {}
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn append_external_protocol_rule(
        &self,
        family: Family,
        _table: &str,
        chain: &str,
        action: ProxyAction,
        proto: &str,
        iface: &str,
        mac: Option<&String>,
    ) -> Result<()> {
        let mut args = vec![
            "-p".to_string(),
            proto.to_string(),
            "-i".to_string(),
            iface.to_string(),
        ];
        if let Some(mac) = mac {
            args.extend([
                "-m".into(),
                "mac".into(),
                "--mac-source".into(),
                mac.clone(),
            ]);
        }

        match action {
            ProxyAction::Redirect => {
                if proto != "tcp" || !self.config.proxy_tcp {
                    return Ok(());
                }
                self.append_redirect_dispatch_rule(family, chain, args)
            }
            ProxyAction::Tproxy => {
                if proto == "tcp" {
                    if !self.config.proxy_tcp || self.config.network_mode == "enhance" {
                        return Ok(());
                    }
                } else if !self.config.proxy_udp {
                    return Ok(());
                }
                self.append_tproxy_dispatch_rule(family, chain, args)
            }
            ProxyAction::Mark => Ok(()),
        }
    }

    pub(super) fn apply_ignored_external_interfaces(
        &self,
        family: Family,
        table: &str,
        chain: &str,
    ) -> Result<()> {
        for iface in &self.config.blocked_interfaces {
            self.ensure_rule_append_owned(
                family,
                table,
                chain,
                vec!["-i".into(), iface.clone(), "-j".into(), "RETURN".into()],
            )?;
        }
        Ok(())
    }
}
