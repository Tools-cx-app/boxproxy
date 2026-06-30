use super::*;

pub(super) fn sync_sing_box(config: &Config) -> Result<()> {
    let path = config.config_path();
    let text = fs::read_to_string(path)
        .map_err(|err| format!("read sing-box config {} failed: {err}", path.display()))?;
    let before = text.clone();

    logger::info_key(
        config,
        LogKey::CoreConfigSyncBegin,
        &[
            arg("core", "sing-box"),
            arg("mode", &config.network_mode),
            arg("config", path.display()),
        ],
    );

    let value: Value = parse_to_serde_value::<Value>(&text, &ParseOptions::default())
        .map_err(|err| format!("parse sing-box config {} failed: {err}", path.display()))?;
    let root = CstRootNode::parse(&text, &ParseOptions::default()).map_err(|err| {
        format!(
            "parse sing-box config structure {} failed: {err}",
            path.display()
        )
    })?;
    sync_sing_box_cst(&root, &value, config);
    let text = root.to_string();

    if text != before {
        fs::write(path, text)
            .map_err(|err| format!("write sing-box config {} failed: {err}", path.display()))?;
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

pub(super) fn sync_sing_box_cst(root: &CstRootNode, value: &Value, config: &Config) {
    let root_obj = root.object_value_or_set();
    let log = root_obj.object_value_or_set("log");
    set_cst_prop(
        &log,
        "output",
        CstInputValue::from(config.bin_log.to_string_lossy().to_string()),
    );

    let route = root_obj.object_value_or_set("route");
    set_cst_prop(
        &route,
        "auto_detect_interface",
        CstInputValue::from(!sing_box_tun_route_managed_by_box(config)),
    );

    let dns = root_obj.object_value_or_set("dns");
    let servers = dns.array_value_or_set("servers");
    set_sing_box_fakeip_server_cst(&servers, config);

    let empty_root = Map::new();
    let root_map = value.as_object().unwrap_or(&empty_root);
    sync_sing_box_inbounds_cst(&root_obj, root_map, config);
}

pub(super) fn sync_sing_box_inbounds_cst(
    root_obj: &CstObject,
    root: &Map<String, Value>,
    config: &Config,
) {
    let redirect_enabled = matches!(
        config.network_mode.as_str(),
        "redirect" | "mixed" | "enhance"
    );
    let tproxy_enabled = matches!(config.network_mode.as_str(), "tproxy" | "enhance");
    let tun_enabled = matches!(config.network_mode.as_str(), "tun" | "mixed");
    let has_inbounds = root.get("inbounds").is_some();

    if !has_inbounds && !redirect_enabled && !tproxy_enabled && !tun_enabled {
        return;
    }

    let tun = SingTunConfig::from(config, root);
    let inbounds = root_obj.array_value_or_set("inbounds");
    set_sing_box_inbound_cst(
        &inbounds,
        "redirect",
        redirect_enabled,
        sing_box_redirect_inbound_cst(config),
        |object| apply_sing_box_redirect_cst(object, config),
    );
    set_sing_box_inbound_cst(
        &inbounds,
        "tproxy",
        tproxy_enabled,
        sing_box_tproxy_inbound_cst(config),
        |object| apply_sing_box_tproxy_cst(object, config),
    );
    set_sing_box_inbound_cst(
        &inbounds,
        "tun",
        tun_enabled,
        tun.to_cst_value(),
        |object| apply_sing_box_tun_cst(object, &tun),
    );
}

pub(super) fn set_sing_box_inbound_cst<F>(
    inbounds: &CstArray,
    inbound_type: &str,
    enabled: bool,
    inbound: CstInputValue,
    apply_existing: F,
) where
    F: FnOnce(&CstObject),
{
    match (find_sing_box_inbound_node(inbounds, inbound_type), enabled) {
        (Some(node), true) => {
            if let Some(object) = node.as_object() {
                apply_existing(&object);
            } else {
                node.remove();
                inbounds.append(inbound);
            }
        }
        (Some(node), false) => node.remove(),
        (None, true) => {
            inbounds.append(inbound);
        }
        (None, false) => {}
    }
}

pub(super) fn find_sing_box_inbound_node(
    inbounds: &CstArray,
    inbound_type: &str,
) -> Option<CstNode> {
    inbounds.elements().into_iter().find(|node| {
        node.to_serde_value()
            .and_then(|value| json_field_string(&value, "type"))
            .as_deref()
            == Some(inbound_type)
    })
}

pub(super) fn sing_box_redirect_inbound_cst(config: &Config) -> CstInputValue {
    cst_object(vec![
        ("type", CstInputValue::from("redirect")),
        ("tag", CstInputValue::from("redirect-in")),
        ("listen", CstInputValue::from("::")),
        ("listen_port", cst_port_value(&config.redir_port)),
    ])
}

pub(super) fn apply_sing_box_redirect_cst(object: &CstObject, config: &Config) {
    set_cst_prop(object, "type", CstInputValue::from("redirect"));
    set_cst_prop(object, "tag", CstInputValue::from("redirect-in"));
    set_cst_prop(object, "listen", CstInputValue::from("::"));
    set_cst_prop(object, "listen_port", cst_port_value(&config.redir_port));
}

pub(super) fn sing_box_tproxy_inbound_cst(config: &Config) -> CstInputValue {
    cst_object(vec![
        ("type", CstInputValue::from("tproxy")),
        ("tag", CstInputValue::from("tproxy-in")),
        ("listen", CstInputValue::from("::")),
        ("listen_port", cst_port_value(&config.tproxy_port)),
    ])
}

pub(super) fn apply_sing_box_tproxy_cst(object: &CstObject, config: &Config) {
    set_cst_prop(object, "type", CstInputValue::from("tproxy"));
    set_cst_prop(object, "tag", CstInputValue::from("tproxy-in"));
    set_cst_prop(object, "listen", CstInputValue::from("::"));
    set_cst_prop(object, "listen_port", cst_port_value(&config.tproxy_port));
}

pub(super) fn sing_box_fakeip_cst_value(config: &Config) -> CstInputValue {
    let mut props = vec![
        ("type".to_string(), CstInputValue::from("fakeip")),
        ("tag".to_string(), CstInputValue::from("fakeip")),
    ];
    if !config.fake_ip_range.trim().is_empty() {
        props.push((
            "inet4_range".to_string(),
            CstInputValue::from(config.fake_ip_range.trim().to_string()),
        ));
    }
    if !config.fake_ip6_range.trim().is_empty() {
        props.push((
            "inet6_range".to_string(),
            CstInputValue::from(config.fake_ip6_range.trim().to_string()),
        ));
    }
    CstInputValue::Object(props)
}

pub(super) fn set_sing_box_fakeip_server_cst(servers: &CstArray, config: &Config) {
    let server = find_sing_box_inbound_node(servers, "fakeip");
    match server {
        Some(node) => {
            if let Some(object) = node.as_object() {
                apply_sing_box_fakeip_cst(&object, config);
            } else {
                node.remove();
                servers.append(sing_box_fakeip_cst_value(config));
            }
        }
        None => {
            servers.append(sing_box_fakeip_cst_value(config));
        }
    }
}

pub(super) fn apply_sing_box_fakeip_cst(object: &CstObject, config: &Config) {
    set_cst_prop(object, "type", CstInputValue::from("fakeip"));
    if object.get("tag").is_none() {
        set_cst_prop(object, "tag", CstInputValue::from("fakeip"));
    }
    set_or_remove_cst_string(object, "inet4_range", config.fake_ip_range.trim());
    set_or_remove_cst_string(object, "inet6_range", config.fake_ip6_range.trim());
}

pub(super) fn sing_box_tun_route_managed_by_box(config: &Config) -> bool {
    tun_route_managed_by_box(config)
}

pub(super) struct SingTunConfig {
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

    fn to_cst_value(&self) -> CstInputValue {
        let mut props = vec![
            ("type".to_string(), CstInputValue::from("tun")),
            ("tag".to_string(), CstInputValue::from("tun-in")),
            (
                "interface_name".to_string(),
                CstInputValue::from(self.interface_name.clone()),
            ),
            (
                "address".to_string(),
                CstInputValue::Array(vec![
                    CstInputValue::from("172.18.0.1/30"),
                    CstInputValue::from("fdfe:dcba:9876::1/126"),
                ]),
            ),
            ("mtu".to_string(), CstInputValue::from(1500_u64)),
            ("stack".to_string(), CstInputValue::from(self.stack.clone())),
            (
                "auto_route".to_string(),
                CstInputValue::from(self.auto_route),
            ),
        ];
        if !self.exclude_interface.is_empty() {
            props.push((
                "exclude_interface".to_string(),
                cst_string_values(&self.exclude_interface),
            ));
        }
        if !self.include_uid.is_empty() {
            props.push(("include_uid".to_string(), cst_uid_values(&self.include_uid)));
        }
        if !self.exclude_uid.is_empty() {
            props.push(("exclude_uid".to_string(), cst_uid_values(&self.exclude_uid)));
        }
        if let Some(strict_route) = self.strict_route {
            props.push((
                "strict_route".to_string(),
                CstInputValue::from(strict_route),
            ));
        }
        if let Some(auto_redirect) = self.auto_redirect {
            props.push((
                "auto_redirect".to_string(),
                CstInputValue::from(auto_redirect),
            ));
        }
        CstInputValue::Object(props)
    }
}

pub(super) fn apply_sing_box_tun_cst(object: &CstObject, tun: &SingTunConfig) {
    set_cst_prop(object, "type", CstInputValue::from("tun"));
    set_cst_prop(object, "tag", CstInputValue::from("tun-in"));
    set_cst_prop(
        object,
        "interface_name",
        CstInputValue::from(tun.interface_name.clone()),
    );
    set_cst_prop(
        object,
        "address",
        CstInputValue::Array(vec![
            CstInputValue::from("172.18.0.1/30"),
            CstInputValue::from("fdfe:dcba:9876::1/126"),
        ]),
    );
    set_cst_prop(object, "mtu", CstInputValue::from(1500_u64));
    set_cst_prop(object, "stack", CstInputValue::from(tun.stack.clone()));
    set_cst_prop(object, "auto_route", CstInputValue::from(tun.auto_route));
    if let Some(strict_route) = tun.strict_route {
        set_cst_prop(object, "strict_route", CstInputValue::from(strict_route));
    }
    if let Some(auto_redirect) = tun.auto_redirect {
        set_cst_prop(object, "auto_redirect", CstInputValue::from(auto_redirect));
    }
    set_or_remove_cst_uid_array(object, "include_uid", &tun.include_uid);
    set_or_remove_cst_uid_array(object, "exclude_uid", &tun.exclude_uid);
    if let Some(prop) = object.get("include_interface") {
        prop.remove();
    }
    set_or_remove_cst_string_array(object, "exclude_interface", &tun.exclude_interface);
}

fn set_or_remove_cst_uid_array(object: &CstObject, key: &str, values: &[String]) {
    if values.is_empty() {
        if let Some(prop) = object.get(key) {
            prop.remove();
        }
    } else {
        set_cst_prop(object, key, cst_uid_values(values));
    }
}

fn set_or_remove_cst_string_array(object: &CstObject, key: &str, values: &[String]) {
    if values.is_empty() {
        if let Some(prop) = object.get(key) {
            prop.remove();
        }
    } else {
        set_cst_prop(object, key, cst_string_values(values));
    }
}
