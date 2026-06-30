use super::*;

pub(super) fn set_cst_prop(object: &CstObject, key: &str, value: CstInputValue) {
    if let Some(prop) = object.get(key) {
        prop.set_value(value);
    } else {
        object.append(key, value);
    }
}

pub(super) fn set_or_remove_cst_string(object: &CstObject, key: &str, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        if let Some(prop) = object.get(key) {
            prop.remove();
        }
    } else {
        set_cst_prop(object, key, CstInputValue::from(value.to_string()));
    }
}

pub(super) fn cst_object(values: Vec<(&str, CstInputValue)>) -> CstInputValue {
    CstInputValue::Object(
        values
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

pub(super) fn find_sing_box_inbound<'a>(
    inbounds: &'a [Value],
    inbound_type: &str,
) -> Option<&'a Value> {
    inbounds
        .iter()
        .find(|value| json_field_string(value, "type").as_deref() == Some(inbound_type))
}

pub(super) fn json_field_string(value: &Value, key: &str) -> Option<String> {
    value.as_object()?.get(key)?.as_str().map(ToOwned::to_owned)
}

pub(super) fn json_field_bool(value: &Value, key: &str) -> Option<bool> {
    value.as_object()?.get(key)?.as_bool()
}

pub(super) fn cst_port_value(value: &str) -> CstInputValue {
    cst_number_value(value).unwrap_or_else(|| CstInputValue::from(value.trim().to_string()))
}

pub(super) fn cst_uid_values(values: &[String]) -> CstInputValue {
    CstInputValue::Array(
        values
            .iter()
            .filter_map(|value| {
                let value = value.trim();
                if value.is_empty() {
                    None
                } else {
                    Some(
                        cst_number_value(value)
                            .unwrap_or_else(|| CstInputValue::from(value.to_string())),
                    )
                }
            })
            .collect(),
    )
}

pub(super) fn cst_string_values(values: &[String]) -> CstInputValue {
    CstInputValue::Array(
        values
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(|value| CstInputValue::from(value.to_string()))
            .collect(),
    )
}

pub(super) fn cst_number_value(value: &str) -> Option<CstInputValue> {
    value.trim().parse::<u64>().ok().map(CstInputValue::from)
}

pub(super) fn normalized_text_values(values: &[String]) -> Vec<String> {
    let mut values: Vec<String> = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    values.sort();
    values.dedup();
    values
}

pub(super) fn yaml_inline_string_list(values: &[String]) -> String {
    values
        .iter()
        .map(|value| yaml_string(value))
        .collect::<Vec<_>>()
        .join(", ")
}

fn yaml_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

pub(super) fn nested_yaml_key(line: &str) -> Option<String> {
    let indent = leading_indent(line);
    if indent == 0 {
        return None;
    }
    let trimmed = line.trim_start();
    if trimmed.starts_with('-') || trimmed.starts_with('#') {
        return None;
    }
    trimmed
        .split_once(':')
        .map(|(key, _)| key.trim().to_string())
        .filter(|key| !key.is_empty())
}

pub(super) fn nested_value_skip_indent(line: &str) -> Option<usize> {
    let (_, value) = line.trim_start().split_once(':')?;
    if value.trim().is_empty() {
        Some(leading_indent(line))
    } else {
        None
    }
}

pub(super) fn leading_indent(line: &str) -> usize {
    line.chars()
        .take_while(|ch| *ch == ' ' || *ch == '\t')
        .count()
}

pub(super) fn has_top_level_key(text: &str, key: &str) -> bool {
    let prefix = format!("{key}:");
    text.lines().any(|line| {
        !line.starts_with(' ') && !line.starts_with('\t') && line.trim_start().starts_with(&prefix)
    })
}

pub(super) fn empty_default<'a>(value: &'a str, default: &'a str) -> &'a str {
    if value.trim().is_empty() {
        default
    } else {
        value.trim()
    }
}

pub(super) fn finish_lines(lines: Vec<String>) -> String {
    let mut output = lines.join("\n");
    while output.contains("\n\n\n") {
        output = output.replace("\n\n\n", "\n\n");
    }
    if !output.ends_with('\n') {
        output.push('\n');
    }
    output
}
