use super::*;

impl<'a> RuleManager<'a> {
    pub(super) fn runtime_save(&self) -> Result<()> {
        fs::create_dir_all(&self.config.paths.state)
            .map_err(|err| format!("create state directory failed: {err}"))?;
        let text = format!(
            concat!(
                "network_mode=\"{}\"\n",
                "bin_name=\"{}\"\n",
                "ipv6_mode=\"{}\"\n",
                "dns_hijack_mode=\"{}\"\n",
                "tproxy_port=\"{}\"\n",
                "redir_port=\"{}\"\n",
                "tun_device=\"{}\"\n",
                "performance_mode=\"{}\"\n",
                "proxy_tcp=\"{}\"\n",
                "proxy_udp=\"{}\"\n",
                "dns_hijack_tcp=\"{}\"\n",
                "dns_hijack_udp=\"{}\"\n",
                "bypass_cn_ip=\"{}\"\n"
            ),
            self.config.network_mode,
            self.config.bin_name,
            self.config.ipv6_mode,
            self.config.dns_hijack_mode,
            self.config.tproxy_port,
            self.config.redir_port,
            self.config.tun_device,
            self.config.performance_mode,
            self.config.proxy_tcp,
            self.config.proxy_udp,
            self.config.dns_hijack_tcp,
            self.config.dns_hijack_udp,
            self.config.bypass_cn_ip,
        );
        fs::write(self.config.paths.state.join("runtime.iptables.env"), text)
            .map_err(|err| format!("write runtime snapshot failed: {err}"))
    }

    pub(super) fn runtime_clear(&self) {
        let _ = fs::remove_file(self.config.paths.state.join("runtime.iptables.env"));
    }

    pub(super) fn runtime_env_value(&self, key: &str) -> Option<String> {
        let text = fs::read_to_string(self.config.paths.state.join("runtime.iptables.env")).ok()?;
        for line in text.lines() {
            let Some((name, value)) = line.split_once('=') else {
                continue;
            };
            if name == key {
                return Some(value.trim().trim_matches('"').to_string());
            }
        }
        None
    }
}
