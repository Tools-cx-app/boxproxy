use super::*;
use serde_norway::{Mapping, Value};
use std::collections::{HashMap, HashSet};
use yaml_rust2::parser::{Event, EventReceiver, Parser};

pub(super) fn sync_mihomo(config: &Config) -> Result<()> {
    let source = config.source_config_path();
    let source_text = fs::read_to_string(source)
        .map_err(|err| format!("read mihomo config {} failed: {err}", source.display()))?;
    let source_text = if config.auto_sync_config {
        remove_legacy_managed_tun_block(&source_text)
    } else {
        source_text
    };
    let anchor_template_keys = referenced_top_level_anchor_template_keys(&source_text, source)?;
    let mut runtime_value = parse_yaml_runtime_value(&source_text, "mihomo", source)?;
    remove_top_level_anchor_templates(&mut runtime_value, &anchor_template_keys)?;
    if config.auto_sync_config {
        sync_mihomo_value(&mut runtime_value, &MihomoSettings::from(config))?;
    }
    let text = format_yaml_runtime_value(&runtime_value, "mihomo", source)?;
    let runtime = config.runtime_config_path();

    logger::info_key(
        config,
        LogKey::CoreConfigSyncBegin,
        &[
            arg("core", "mihomo"),
            arg("mode", &config.network_mode),
            arg("config", runtime.display()),
        ],
    );

    if write_atomic_runtime_config(source, runtime, &text)? {
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

fn referenced_top_level_anchor_template_keys(
    source_text: &str,
    source: &Path,
) -> Result<Vec<String>> {
    let mut collector = TopLevelAnchorCollector::default();
    let mut parser = Parser::new_from_str(source_text);
    parser.load(&mut collector, true).map_err(|err| {
        format!(
            "scan mihomo anchors in config {} failed: {err}",
            source.display()
        )
    })?;
    Ok(collector.referenced_template_keys())
}

fn remove_top_level_anchor_templates(runtime: &mut Value, keys: &[String]) -> Result<()> {
    if keys.is_empty() {
        return Ok(());
    }

    let root = runtime
        .as_mapping_mut()
        .ok_or_else(|| "YAML config must contain a top-level mapping".to_string())?;
    for key in keys {
        root.shift_remove(key.as_str());
    }
    Ok(())
}

#[derive(Default)]
struct TopLevelAnchorCollector {
    root_started: bool,
    root_is_mapping: bool,
    root_finished: bool,
    expecting_key: bool,
    pending_key: Option<String>,
    value_depth: usize,
    top_level_anchor_keys: HashMap<usize, Vec<String>>,
    referenced_anchors: HashSet<usize>,
}

impl TopLevelAnchorCollector {
    fn referenced_template_keys(self) -> Vec<String> {
        self.top_level_anchor_keys
            .into_iter()
            .filter(|(anchor, _)| self.referenced_anchors.contains(anchor))
            .flat_map(|(_, keys)| keys)
            .collect()
    }

    fn record_top_level_anchor(&mut self, anchor: usize) {
        if anchor == 0 {
            return;
        }
        if let Some(key) = self.pending_key.as_ref() {
            self.top_level_anchor_keys
                .entry(anchor)
                .or_default()
                .push(key.clone());
        }
    }

    fn finish_top_level_value(&mut self) {
        self.pending_key = None;
        self.expecting_key = true;
    }

    fn advance_nested_value(&mut self, event: &Event) {
        match event {
            Event::MappingStart(..) | Event::SequenceStart(..) => self.value_depth += 1,
            Event::MappingEnd | Event::SequenceEnd => {
                self.value_depth -= 1;
                if self.value_depth == 0 {
                    self.finish_top_level_value();
                }
            }
            _ => {}
        }
    }
}

impl EventReceiver for TopLevelAnchorCollector {
    fn on_event(&mut self, event: Event) {
        if self.root_finished {
            return;
        }

        if !self.root_started {
            match event {
                Event::MappingStart(..) => {
                    self.root_started = true;
                    self.root_is_mapping = true;
                    self.expecting_key = true;
                }
                Event::SequenceStart(..) | Event::Scalar(..) | Event::Alias(..) => {
                    self.root_started = true;
                }
                _ => {}
            }
            return;
        }
        if !self.root_is_mapping {
            return;
        }

        if let Event::Alias(anchor) = &event {
            self.referenced_anchors.insert(*anchor);
        }

        if self.value_depth > 0 {
            self.advance_nested_value(&event);
            return;
        }

        if self.expecting_key {
            match event {
                Event::Scalar(key, ..) => {
                    self.pending_key = Some(key);
                    self.expecting_key = false;
                }
                Event::MappingEnd => self.root_finished = true,
                _ => self.root_finished = true,
            }
            return;
        }

        match event {
            Event::Scalar(_, _, anchor, _) => {
                self.record_top_level_anchor(anchor);
                self.finish_top_level_value();
            }
            Event::MappingStart(anchor, _) | Event::SequenceStart(anchor, _) => {
                self.record_top_level_anchor(anchor);
                self.value_depth = 1;
            }
            Event::Alias(_) => self.finish_top_level_value(),
            _ => self.finish_top_level_value(),
        }
    }
}

fn sync_mihomo_value(runtime: &mut Value, settings: &MihomoSettings) -> Result<()> {
    let root = runtime
        .as_mapping_mut()
        .ok_or_else(|| "YAML config must contain a top-level mapping".to_string())?;

    set_value(
        root,
        "redir-port",
        yaml_port_value(&settings.redir_port, "7892"),
    );
    set_value(
        root,
        "tproxy-port",
        yaml_port_value(&settings.tproxy_port, "7893"),
    );
    settings.apply_dns(ensure_mapping(root, "dns")?);

    let current_stack = root
        .get("tun")
        .map(|value| {
            value
                .as_mapping()
                .ok_or_else(|| "YAML key \"tun\" must contain a mapping".to_string())
                .map(|tun| tun.get("stack").and_then(yaml_scalar_text))
        })
        .transpose()?
        .flatten();

    if settings.tun_enabled() {
        let tun_settings = MihomoTunConfig::from(settings, current_stack);
        tun_settings.apply(ensure_mapping(root, "tun")?);
    } else if root.contains_key("tun") {
        set_value(mapping(root, "tun")?, "enable", Value::from(false));
    }

    Ok(())
}

#[derive(Clone)]
struct MihomoSettings {
    network_mode: String,
    proxy_mode: String,
    redir_port: String,
    tproxy_port: String,
    mihomo_dns_port: String,
    tun_device: String,
    fake_ip_range: String,
    fake_ip6_range: String,
    bypass_cn_ip: bool,
    mac_filter: bool,
    selected_uids: Vec<String>,
    blocked_interfaces: Vec<String>,
}

impl From<&Config> for MihomoSettings {
    fn from(config: &Config) -> Self {
        Self {
            network_mode: config.network_mode.clone(),
            proxy_mode: config.proxy_mode.clone(),
            redir_port: config.redir_port.clone(),
            tproxy_port: config.tproxy_port.clone(),
            mihomo_dns_port: config.mihomo_dns_port.clone(),
            tun_device: config.tun_device.clone(),
            fake_ip_range: config.fake_ip_range.clone(),
            fake_ip6_range: config.fake_ip6_range.clone(),
            bypass_cn_ip: config.bypass_cn_ip,
            mac_filter: config.mac_filter,
            selected_uids: config.selected_uids.clone(),
            blocked_interfaces: config.blocked_interfaces.clone(),
        }
    }
}

impl MihomoSettings {
    fn tun_enabled(&self) -> bool {
        matches!(self.network_mode.as_str(), "tun" | "mixed")
    }

    fn app_proxy_filter_enabled(&self) -> bool {
        self.network_mode != "tun"
            && matches!(
                self.proxy_mode.trim().to_ascii_lowercase().as_str(),
                "blacklist" | "black" | "whitelist" | "white"
            )
    }

    fn box_managed_tun_route(&self) -> bool {
        self.network_mode == "tun" && (self.bypass_cn_ip || self.mac_filter)
    }

    fn tun_uid_lists(&self) -> (Vec<String>, Vec<String>) {
        let uids = normalized_text_values(&self.selected_uids);
        match self.proxy_mode.as_str() {
            "whitelist" | "white" => (uids, Vec::new()),
            "blacklist" | "black" => (Vec::new(), uids),
            _ => (Vec::new(), Vec::new()),
        }
    }

    fn apply_dns(&self, dns: &mut Mapping) {
        if self.app_proxy_filter_enabled() {
            set_value(dns, "enhanced-mode", Value::from("redir-host"));
        }
        set_value(
            dns,
            "fake-ip-range",
            Value::from(empty_default(&self.fake_ip_range, "198.18.0.1/16")),
        );
        if !self.fake_ip6_range.trim().is_empty() {
            set_value(
                dns,
                "fake-ip-range6",
                Value::from(self.fake_ip6_range.trim()),
            );
        }
        set_value(
            dns,
            "listen",
            Value::from(format!(
                "0.0.0.0:{}",
                empty_default(&self.mihomo_dns_port, "1053")
            )),
        );
    }
}

struct MihomoTunConfig {
    stack: String,
    device: String,
    auto_route: bool,
    strict_route: Option<bool>,
    auto_redirect: Option<bool>,
    auto_detect_interface: bool,
    include_uid: Vec<String>,
    exclude_uid: Vec<String>,
    exclude_interface: Vec<String>,
}

impl MihomoTunConfig {
    fn from(settings: &MihomoSettings, current_stack: Option<String>) -> Self {
        let box_managed_route = settings.box_managed_tun_route();
        let (include_uid, exclude_uid) = settings.tun_uid_lists();
        Self {
            stack: if settings.bypass_cn_ip {
                "gvisor".to_string()
            } else {
                current_stack
                    .map(|value| {
                        value
                            .split_whitespace()
                            .next()
                            .unwrap_or_default()
                            .to_string()
                    })
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| "gvisor".to_string())
            },
            device: empty_default(&settings.tun_device, "meta").to_string(),
            auto_route: !box_managed_route,
            strict_route: box_managed_route.then_some(false),
            auto_redirect: box_managed_route.then_some(false),
            auto_detect_interface: !box_managed_route,
            include_uid,
            exclude_uid,
            exclude_interface: normalized_text_values(&settings.blocked_interfaces),
        }
    }

    fn apply(&self, tun: &mut Mapping) {
        set_value(tun, "enable", Value::from(true));
        set_value(tun, "mtu", Value::from(1500_u16));
        set_value(tun, "device", Value::from(self.device.as_str()));
        set_value(tun, "stack", Value::from(self.stack.as_str()));
        tun.entry(Value::from("dns-hijack")).or_insert_with(|| {
            Value::Sequence(vec![Value::from("any:53"), Value::from("tcp://any:53")])
        });
        set_value(tun, "auto-route", Value::from(self.auto_route));
        set_value(
            tun,
            "auto-detect-interface",
            Value::from(self.auto_detect_interface),
        );
        tun.shift_remove("include-android-user");
        tun.shift_remove("include-interface");
        if let Some(value) = self.strict_route {
            set_value(tun, "strict-route", Value::from(value));
        }
        if let Some(value) = self.auto_redirect {
            set_value(tun, "auto-redirect", Value::from(value));
        }
        set_optional_string_list(tun, "exclude-interface", &self.exclude_interface);
        set_optional_uid_list(tun, "include-uid", &self.include_uid);
        set_optional_uid_list(tun, "exclude-uid", &self.exclude_uid);
    }
}

fn set_optional_string_list(mapping: &mut Mapping, key: &str, values: &[String]) {
    if values.is_empty() {
        mapping.shift_remove(key);
        return;
    }
    set_value(
        mapping,
        key,
        Value::Sequence(
            values
                .iter()
                .map(|value| Value::from(value.as_str()))
                .collect(),
        ),
    );
}

fn set_optional_uid_list(mapping: &mut Mapping, key: &str, values: &[String]) {
    if values.is_empty() {
        mapping.shift_remove(key);
        return;
    }
    set_value(
        mapping,
        key,
        Value::Sequence(values.iter().map(|value| yaml_uid_value(value)).collect()),
    );
}

fn yaml_port_value(value: &str, default: &str) -> Value {
    let value = empty_default(value, default);
    if value.chars().all(|char| char.is_ascii_digit()) {
        value
            .parse::<u64>()
            .map(Value::from)
            .unwrap_or_else(|_| Value::from(value))
    } else {
        Value::from(value)
    }
}

fn yaml_uid_value(value: &str) -> Value {
    value
        .parse::<u64>()
        .map(Value::from)
        .unwrap_or_else(|_| Value::from(value))
}

fn set_value(mapping: &mut Mapping, key: &str, value: Value) {
    mapping.insert(Value::from(key), value);
}

fn ensure_mapping<'a>(mapping: &'a mut Mapping, key: &str) -> Result<&'a mut Mapping> {
    mapping
        .entry(Value::from(key))
        .or_insert_with(|| Value::Mapping(Mapping::new()))
        .as_mapping_mut()
        .ok_or_else(|| format!("YAML key {key:?} must contain a mapping"))
}

fn mapping<'a>(mapping: &'a mut Mapping, key: &str) -> Result<&'a mut Mapping> {
    mapping
        .get_mut(key)
        .and_then(Value::as_mapping_mut)
        .ok_or_else(|| format!("YAML key {key:?} must contain a mapping"))
}

fn yaml_scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Tagged(value) => yaml_scalar_text(&value.value),
        Value::Null | Value::Sequence(_) | Value::Mapping(_) => None,
    }
}

fn remove_legacy_managed_tun_block(text: &str) -> String {
    let mut output = text.to_string();
    while let Some(begin) = output.find(MANAGED_TUN_BEGIN) {
        let Some(end_relative) = output[begin..].find(MANAGED_TUN_END) else {
            break;
        };
        let start = output[..begin]
            .rfind('\n')
            .map(|index| index + 1)
            .unwrap_or(0);
        let end_marker = begin + end_relative + MANAGED_TUN_END.len();
        let end = output[end_marker..]
            .find('\n')
            .map(|index| end_marker + index + 1)
            .unwrap_or(output.len());
        output.replace_range(start..end, "");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_runtime_overrides_after_expanding_yaml_merges() {
        let mut runtime: Value = serde_norway::from_str(
            "defaults: &defaults\n  type: select\nproxy-groups:\n  - name: first\n    <<: *defaults\n",
        )
        .unwrap();
        runtime.apply_merge().unwrap();

        let settings = MihomoSettings {
            network_mode: "tun".to_string(),
            proxy_mode: "core".to_string(),
            redir_port: "9797".to_string(),
            tproxy_port: "9898".to_string(),
            mihomo_dns_port: "1053".to_string(),
            tun_device: "meta".to_string(),
            fake_ip_range: "198.18.0.1/16".to_string(),
            fake_ip6_range: "fc00::/18".to_string(),
            bypass_cn_ip: false,
            mac_filter: false,
            selected_uids: Vec::new(),
            blocked_interfaces: Vec::new(),
        };

        sync_mihomo_value(&mut runtime, &settings).unwrap();

        assert_eq!(runtime["proxy-groups"][0]["type"], Value::from("select"));
        assert_eq!(runtime["redir-port"], Value::from(9797_u16));
        assert_eq!(runtime["dns"]["listen"], Value::from("0.0.0.0:1053"));
        assert_eq!(runtime["tun"]["device"], Value::from("meta"));
    }

    #[test]
    fn identifies_referenced_anchors_from_yaml_events_not_key_names() {
        let source = r#"
template-key: &not_the_key
  type: select
filter-source: &filter_value "(?i)hk"
keep-me: &unused_anchor
  enable: true
proxy-groups:
  - name: test
    <<: *not_the_key
    filter: *filter_value
"#;

        let keys =
            referenced_top_level_anchor_template_keys(source, Path::new("source.yaml")).unwrap();

        assert!(keys.iter().any(|key| key == "template-key"));
        assert!(keys.iter().any(|key| key == "filter-source"));
        assert!(!keys.iter().any(|key| key == "keep-me"));
    }

    #[test]
    fn removes_only_referenced_top_level_anchor_templates_after_merge() {
        let source = r#"
template-key: &different_anchor_name
  type: select
  include-all: true
keep-me: &unused_anchor
  enable: true
proxy-groups:
  - name: test
    <<: *different_anchor_name
"#;
        let keys =
            referenced_top_level_anchor_template_keys(source, Path::new("source.yaml")).unwrap();
        let mut runtime =
            parse_yaml_runtime_value(source, "mihomo", Path::new("source.yaml")).unwrap();

        remove_top_level_anchor_templates(&mut runtime, &keys).unwrap();

        assert!(runtime.get("template-key").is_none());
        assert_eq!(runtime["proxy-groups"][0]["type"], Value::from("select"));
        assert_eq!(runtime["keep-me"]["enable"], Value::from(true));
    }
}
