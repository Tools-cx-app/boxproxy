use super::*;

pub(super) fn sync_sing_box(config: &Config) -> Result<()> {
    let source = config.source_config_path();
    let source_text = fs::read_to_string(source)
        .map_err(|err| format!("read sing-box config {} failed: {err}", source.display()))?;
    let mut runtime_value = parse_sing_box_runtime_config(&source_text, source)?;
    if config.auto_sync_config {
        sync_sing_box_value(&mut runtime_value, config)?;
    }
    let text = format_sing_box_runtime_config(&runtime_value, source)?;
    let runtime = config.runtime_config_path();

    logger::info_key(
        config,
        LogKey::CoreConfigSyncBegin,
        &[
            arg("core", "sing-box"),
            arg("mode", &config.network_mode),
            arg("config", runtime.display()),
        ],
    );

    if write_atomic_runtime_config(source, runtime, &text)? {
        logger::info_key(
            config,
            LogKey::CoreConfigSyncUpdated,
            &[arg("core", "sing-box")],
        );
    } else {
        logger::debug_key(
            config,
            LogKey::CoreConfigSyncNoChange,
            &[arg("core", "sing-box")],
        );
    }

    Ok(())
}

fn parse_sing_box_runtime_config(text: &str, source: &std::path::Path) -> Result<Value> {
    jsonc_parser::parse_to_serde_value(text, &ParseOptions::default())
        .map_err(|err| format!("parse sing-box config {} failed: {err}", source.display()))
}

fn format_sing_box_runtime_config(value: &Value, source: &std::path::Path) -> Result<String> {
    let formatted = serde_json::to_string_pretty(value)
        .map_err(|err| format!("format sing-box config {} failed: {err}", source.display()))?;
    Ok(format!("{formatted}\n"))
}

fn sync_sing_box_value(value: &mut Value, config: &Config) -> Result<()> {
    let root = value
        .as_object_mut()
        .ok_or_else(|| "sing-box config root must be an object".to_string())?;

    set_value(
        ensure_object(root, "log"),
        "output",
        Value::String(config.bin_log.to_string_lossy().to_string()),
    );
    set_value(
        ensure_object(root, "route"),
        "auto_detect_interface",
        Value::Bool(!sing_box_tun_route_managed_by_box(config)),
    );
    set_sing_box_fakeip_server(ensure_array(ensure_object(root, "dns"), "servers"), config);
    sync_sing_box_inbounds(root, config);
    Ok(())
}

fn sync_sing_box_inbounds(root: &mut Map<String, Value>, config: &Config) {
    let redirect_enabled = matches!(
        config.network_mode.as_str(),
        "redirect" | "mixed" | "enhance"
    );
    let tproxy_enabled = matches!(config.network_mode.as_str(), "tproxy" | "enhance");
    let tun_enabled = matches!(config.network_mode.as_str(), "tun" | "mixed");
    if !root.contains_key("inbounds") && !redirect_enabled && !tproxy_enabled && !tun_enabled {
        return;
    }

    let tun = SingTunConfig::from(config, root);
    let inbounds = ensure_array(root, "inbounds");
    set_sing_box_inbound(
        inbounds,
        "redirect",
        redirect_enabled,
        sing_box_redirect_inbound(config),
        |object| apply_sing_box_redirect(object, config),
    );
    set_sing_box_inbound(
        inbounds,
        "tproxy",
        tproxy_enabled,
        sing_box_tproxy_inbound(config),
        |object| apply_sing_box_tproxy(object, config),
    );
    set_sing_box_inbound(inbounds, "tun", tun_enabled, tun.to_value(), |object| {
        tun.apply(object)
    });
}

fn set_sing_box_inbound<F>(
    inbounds: &mut Vec<Value>,
    inbound_type: &str,
    enabled: bool,
    inbound: Value,
    apply_existing: F,
) where
    F: FnOnce(&mut Map<String, Value>),
{
    let existing = inbounds
        .iter()
        .position(|value| json_field_string(value, "type").as_deref() == Some(inbound_type));
    match (existing, enabled) {
        (Some(index), true) => {
            if let Some(object) = inbounds[index].as_object_mut() {
                apply_existing(object);
            } else {
                inbounds[index] = inbound;
            }
        }
        (Some(index), false) => {
            inbounds.remove(index);
        }
        (None, true) => inbounds.push(inbound),
        (None, false) => {}
    }
}

fn sing_box_redirect_inbound(config: &Config) -> Value {
    Value::Object(Map::from_iter([
        ("type".to_string(), Value::String("redirect".to_string())),
        ("tag".to_string(), Value::String("redirect-in".to_string())),
        ("listen".to_string(), Value::String("::".to_string())),
        (
            "listen_port".to_string(),
            json_port_value(&config.redir_port),
        ),
    ]))
}

fn apply_sing_box_redirect(object: &mut Map<String, Value>, config: &Config) {
    set_value(object, "type", Value::String("redirect".to_string()));
    set_value(object, "tag", Value::String("redirect-in".to_string()));
    set_value(object, "listen", Value::String("::".to_string()));
    set_value(object, "listen_port", json_port_value(&config.redir_port));
}

fn sing_box_tproxy_inbound(config: &Config) -> Value {
    Value::Object(Map::from_iter([
        ("type".to_string(), Value::String("tproxy".to_string())),
        ("tag".to_string(), Value::String("tproxy-in".to_string())),
        ("listen".to_string(), Value::String("::".to_string())),
        (
            "listen_port".to_string(),
            json_port_value(&config.tproxy_port),
        ),
    ]))
}

fn apply_sing_box_tproxy(object: &mut Map<String, Value>, config: &Config) {
    set_value(object, "type", Value::String("tproxy".to_string()));
    set_value(object, "tag", Value::String("tproxy-in".to_string()));
    set_value(object, "listen", Value::String("::".to_string()));
    set_value(object, "listen_port", json_port_value(&config.tproxy_port));
}

fn set_sing_box_fakeip_server(servers: &mut Vec<Value>, config: &Config) {
    let existing = servers
        .iter_mut()
        .find(|value| json_field_string(value, "type").as_deref() == Some("fakeip"));
    match existing {
        Some(value) => {
            if let Some(object) = value.as_object_mut() {
                apply_sing_box_fakeip(object, config);
            } else {
                *value = sing_box_fakeip_server(config);
            }
        }
        None => servers.push(sing_box_fakeip_server(config)),
    }
}

fn sing_box_fakeip_server(config: &Config) -> Value {
    let mut object = Map::from_iter([
        ("type".to_string(), Value::String("fakeip".to_string())),
        ("tag".to_string(), Value::String("fakeip".to_string())),
    ]);
    set_or_remove_json_string(&mut object, "inet4_range", config.fake_ip_range.trim());
    set_or_remove_json_string(&mut object, "inet6_range", config.fake_ip6_range.trim());
    Value::Object(object)
}

fn apply_sing_box_fakeip(object: &mut Map<String, Value>, config: &Config) {
    set_value(object, "type", Value::String("fakeip".to_string()));
    if !object.contains_key("tag") {
        set_value(object, "tag", Value::String("fakeip".to_string()));
    }
    set_or_remove_json_string(object, "inet4_range", config.fake_ip_range.trim());
    set_or_remove_json_string(object, "inet6_range", config.fake_ip6_range.trim());
}

pub(super) fn sing_box_tun_route_managed_by_box(config: &Config) -> bool {
    tun_route_managed_by_box(config)
}

struct SingTunConfig {
    interface_name: String,
    stack: String,
    auto_route: bool,
    strict_route: Option<bool>,
    auto_redirect: Option<bool>,
    include_uid: Vec<String>,
    exclude_uid: Vec<String>,
    exclude_interface: Vec<String>,
}

impl SingTunConfig {
    fn from(config: &Config, root: &Map<String, Value>) -> Self {
        let box_managed_route = sing_box_tun_route_managed_by_box(config);
        let (include_uid, exclude_uid) = tun_uid_lists(config);
        let current_tun = root
            .get("inbounds")
            .and_then(Value::as_array)
            .and_then(|inbounds| find_sing_box_inbound(inbounds, "tun"));
        let stack = tun_stack_value(
            config,
            current_tun.and_then(|value| json_field_string(value, "stack")),
            "mixed",
        );
        let interface_name = empty_default(&config.tun_device, "sing").to_string();
        Self {
            interface_name,
            stack,
            auto_route: !box_managed_route,
            strict_route: if box_managed_route {
                Some(false)
            } else {
                current_tun.and_then(|value| json_field_bool(value, "strict_route"))
            },
            auto_redirect: if box_managed_route {
                Some(false)
            } else {
                current_tun.and_then(|value| json_field_bool(value, "auto_redirect"))
            },
            include_uid,
            exclude_uid,
            exclude_interface: tun_exclude_interfaces(config),
        }
    }

    fn to_value(&self) -> Value {
        let mut object = Map::new();
        self.apply(&mut object);
        Value::Object(object)
    }

    fn apply(&self, object: &mut Map<String, Value>) {
        set_value(object, "type", Value::String("tun".to_string()));
        set_value(object, "tag", Value::String("tun-in".to_string()));
        set_value(
            object,
            "interface_name",
            Value::String(self.interface_name.clone()),
        );
        set_value(
            object,
            "address",
            Value::Array(vec![
                Value::String("172.18.0.1/30".to_string()),
                Value::String("fdfe:dcba:9876::1/126".to_string()),
            ]),
        );
        set_value(object, "mtu", Value::from(1500_u64));
        set_value(object, "stack", Value::String(self.stack.clone()));
        set_value(object, "auto_route", Value::Bool(self.auto_route));
        if let Some(strict_route) = self.strict_route {
            set_value(object, "strict_route", Value::Bool(strict_route));
        }
        if let Some(auto_redirect) = self.auto_redirect {
            set_value(object, "auto_redirect", Value::Bool(auto_redirect));
        }
        set_or_remove_json_uid_array(object, "include_uid", &self.include_uid);
        set_or_remove_json_uid_array(object, "exclude_uid", &self.exclude_uid);
        object.remove("include_interface");
        set_or_remove_json_string_array(object, "exclude_interface", &self.exclude_interface);
    }
}

fn ensure_object<'a>(parent: &'a mut Map<String, Value>, key: &str) -> &'a mut Map<String, Value> {
    if !matches!(parent.get(key), Some(Value::Object(_))) {
        parent.insert(key.to_string(), Value::Object(Map::new()));
    }
    match parent.get_mut(key) {
        Some(Value::Object(object)) => object,
        _ => unreachable!("JSON object insertion did not produce an object"),
    }
}

fn ensure_array<'a>(parent: &'a mut Map<String, Value>, key: &str) -> &'a mut Vec<Value> {
    if !matches!(parent.get(key), Some(Value::Array(_))) {
        parent.insert(key.to_string(), Value::Array(Vec::new()));
    }
    match parent.get_mut(key) {
        Some(Value::Array(array)) => array,
        _ => unreachable!("JSON array insertion did not produce an array"),
    }
}

fn set_or_remove_json_string(object: &mut Map<String, Value>, key: &str, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        object.remove(key);
    } else {
        set_value(object, key, Value::String(value.to_string()));
    }
}

fn set_or_remove_json_uid_array(object: &mut Map<String, Value>, key: &str, values: &[String]) {
    let values = json_uid_values(values);
    if values.is_empty() {
        object.remove(key);
    } else {
        set_value(object, key, Value::Array(values));
    }
}

fn set_or_remove_json_string_array(object: &mut Map<String, Value>, key: &str, values: &[String]) {
    let values = json_string_values(values);
    if values.is_empty() {
        object.remove(key);
    } else {
        set_value(object, key, Value::Array(values));
    }
}

fn json_port_value(value: &str) -> Value {
    let value = value.trim();
    value
        .parse::<u64>()
        .map(Value::from)
        .unwrap_or_else(|_| Value::String(value.to_string()))
}

fn json_uid_values(values: &[String]) -> Vec<Value> {
    values
        .iter()
        .filter_map(|value| {
            let value = value.trim();
            (!value.is_empty()).then(|| {
                value
                    .parse::<u64>()
                    .map(Value::from)
                    .unwrap_or_else(|_| Value::String(value.to_string()))
            })
        })
        .collect()
}

fn json_string_values(values: &[String]) -> Vec<Value> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| Value::String(value.to_string()))
        .collect()
}

fn set_value(object: &mut Map<String, Value>, key: &str, value: Value) {
    object.insert(key.to_string(), value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_jsonc_and_formats_startup_config_without_comments() {
        let source = "{\n  // source comment\n  \"log\": { \"level\": \"info\", },\n}";
        let value =
            parse_sing_box_runtime_config(source, std::path::Path::new("source.jsonc")).unwrap();
        let formatted =
            format_sing_box_runtime_config(&value, std::path::Path::new("source.jsonc")).unwrap();

        assert!(!formatted.contains("source comment"));
        assert!(formatted.ends_with('\n'));
        assert_eq!(
            serde_json::from_str::<Value>(&formatted).unwrap()["log"]["level"],
            "info"
        );
    }

    #[test]
    fn updates_existing_inbound_without_dropping_other_properties() {
        let mut inbounds = vec![serde_json::json!({
            "type": "redirect",
            "custom": true,
        })];

        set_sing_box_inbound(&mut inbounds, "redirect", true, Value::Null, |object| {
            set_value(object, "tag", Value::String("redirect-in".to_string()))
        });

        assert_eq!(inbounds[0]["custom"], true);
        assert_eq!(inbounds[0]["tag"], "redirect-in");
    }
}
