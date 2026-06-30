use super::*;

const COLOROS_CHAINS: &[&str] = &["fw_INPUT", "fw_OUTPUT", "fw_OUTPUT_oplus_dns"];
const ZTE_CHAIN: &str = "zte_fw_gms";

#[derive(Clone, Copy, Debug, Default)]
struct VendorFirewallStats {
    removed: u32,
    failed: u32,
}

impl std::ops::AddAssign for VendorFirewallStats {
    fn add_assign(&mut self, rhs: Self) {
        self.removed += rhs.removed;
        self.failed += rhs.failed;
    }
}

impl<'a> RuleManager<'a> {
    pub(super) fn cleanup_vendor_firewall_if_needed(&self) {
        if !self.config.clean_vendor_firewall {
            return;
        }

        let coloros = self.cleanup_coloros_firewall();
        let zte = self.cleanup_zte_firewall();
        logger::info_key(
            self.config,
            LogKey::VendorFirewallCleanup,
            &[logger::arg_i18n(
                "summary",
                format!(
                    "ColorOS REJECT removed {}, failed {}; ZTE flushed {}, failed {}",
                    coloros.removed, coloros.failed, zte.removed, zte.failed
                ),
                format!(
                    "ColorOS REJECT 清理 {} 条, 失败 {} 条; ZTE flush {} 次, 失败 {} 次",
                    coloros.removed, coloros.failed, zte.removed, zte.failed
                ),
            )],
        );
    }

    fn cleanup_coloros_firewall(&self) -> VendorFirewallStats {
        let mut stats = VendorFirewallStats::default();
        if !self.filter_chain_exists(Family::V4, "fw_INPUT") {
            return stats;
        }

        for chain in COLOROS_CHAINS {
            for family in [Family::V4, Family::V6] {
                stats += self.remove_reject_rules(family, chain);
            }
        }
        stats
    }

    fn cleanup_zte_firewall(&self) -> VendorFirewallStats {
        let mut stats = VendorFirewallStats::default();
        if !self.filter_chain_exists(Family::V4, ZTE_CHAIN) {
            return stats;
        }

        for family in [Family::V4, Family::V6] {
            if !self.filter_chain_exists(family, ZTE_CHAIN) {
                continue;
            }
            if self.ipt_try_owned(family, strings(&["-t", "filter", "-F", ZTE_CHAIN])) {
                stats.removed += 1;
            } else {
                stats.failed += 1;
            }
        }
        stats
    }

    fn remove_reject_rules(&self, family: Family, chain: &str) -> VendorFirewallStats {
        let mut stats = VendorFirewallStats::default();
        for line in self.reject_rule_lines(family, chain) {
            let args = vec![
                "-t".to_string(),
                "filter".to_string(),
                "-D".to_string(),
                chain.to_string(),
                line.to_string(),
            ];
            if self.ipt_try_owned(family, args) {
                stats.removed += 1;
            } else {
                stats.failed += 1;
            }
        }
        stats
    }

    fn reject_rule_lines(&self, family: Family, chain: &str) -> Vec<u32> {
        if !self.filter_chain_exists(family, chain) {
            return Vec::new();
        }

        let args = strings(&["-t", "filter", "-nvL", chain, "--line-numbers"]);
        let Ok(output) = self.runner.run(iptables_cmd(family), &args) else {
            return Vec::new();
        };
        if !output.ok {
            return Vec::new();
        }

        let mut lines = output
            .stdout
            .lines()
            .filter(|line| line.contains("REJECT"))
            .filter_map(|line| line.split_whitespace().next()?.parse::<u32>().ok())
            .collect::<Vec<_>>();
        lines.sort_unstable_by(|a, b| b.cmp(a));
        lines.dedup();
        lines
    }

    fn filter_chain_exists(&self, family: Family, chain: &str) -> bool {
        self.ipt_check_owned(family, &strings(&["-t", "filter", "-nvL", chain]))
    }
}
