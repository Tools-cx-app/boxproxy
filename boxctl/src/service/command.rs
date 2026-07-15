use super::*;

pub(super) fn core_check_command(config: &Config) -> (String, Vec<String>) {
    let bin = config.bin_path.to_string_lossy().to_string();
    let dir = config.core_dir().to_string_lossy().to_string();
    let file = config.launch_config_path().to_string_lossy().to_string();

    match config.bin_name.as_str() {
        "mihomo" => (bin, vec!["-t".into(), "-d".into(), dir, "-f".into(), file]),
        "sing-box" => (
            bin,
            vec!["check".into(), "-c".into(), file, "-D".into(), dir],
        ),
        "xray" => (bin, vec!["-test".into(), "-confdir".into(), dir]),
        "v2fly" => (bin, vec!["test".into(), "-d".into(), dir]),
        "hysteria" => (String::new(), Vec::new()),
        _ => (String::new(), Vec::new()),
    }
}

pub(super) fn core_run_command(config: &Config) -> (String, Vec<String>) {
    let mut args = Vec::new();
    let dir = config.core_dir().to_string_lossy().to_string();
    let file = config.launch_config_path().to_string_lossy().to_string();
    let bin = config.bin_path.to_string_lossy().to_string();

    match config.bin_name.as_str() {
        "mihomo" => args.extend(["-d".into(), dir, "-f".into(), file]),
        "sing-box" => args.extend(["run".into(), "-c".into(), file, "-D".into(), dir]),
        "xray" => args.extend(["run".into(), "-confdir".into(), dir]),
        "v2fly" => args.extend(["run".into(), "-d".into(), dir]),
        "hysteria" => args.extend(["-c".into(), file]),
        _ => {}
    }

    if config.taskset_cpu {
        match taskset_mask_arg(config) {
            Ok(mask) => {
                let mut taskset_args = vec![mask, bin];
                taskset_args.extend(args);
                return (taskset_program(), taskset_args);
            }
            Err(err) => {
                eprintln!("[core_run_command] taskset fallback: {err}");
            }
        }
    }

    (bin, args)
}

pub(super) fn core_env(config: &Config) -> Vec<(&'static str, String)> {
    let asset_dir = config.core_dir().to_string_lossy().to_string();
    match config.bin_name.as_str() {
        "xray" => vec![("XRAY_LOCATION_ASSET", asset_dir)],
        "v2fly" => vec![("V2RAY_LOCATION_ASSET", asset_dir)],
        _ => Vec::new(),
    }
}

fn taskset_program() -> String {
    for path in [
        "/system/bin/taskset",
        "/vendor/bin/taskset",
        "/system/xbin/taskset",
        "/bin/taskset",
        "/usr/bin/taskset",
    ] {
        if std::path::Path::new(path).is_file() {
            return path.to_string();
        }
    }
    "taskset".to_string()
}

fn taskset_mask_arg(config: &Config) -> Result<String> {
    let cores = if config.allow_cpu.trim().is_empty() {
        detect_cpu_range().ok_or_else(|| "detect CPU cores failed".to_string())?
    } else {
        config.allow_cpu.trim().to_string()
    };
    let requested = cpu_list_to_mask(&cores)?;
    let effective = constrain_to_available_cpus(requested, &cores)?;
    Ok(format!("{effective:x}"))
}

fn detect_cpu_range() -> Option<String> {
    let count = std::thread::available_parallelism().ok()?.get();
    if count == 0 {
        None
    } else {
        Some(format!("0-{}", count - 1))
    }
}

fn cpu_list_to_mask(list: &str) -> Result<u128> {
    let mut mask = 0_u128;
    let mut any = false;

    for item in list.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (start, end) = if let Some((start, end)) = item.split_once('-') {
            let start = parse_cpu_index(start)?;
            let end = parse_cpu_index(end)?;
            if start > end {
                return Err(format!("invalid CPU range: {item}"));
            }
            (start, end)
        } else {
            let cpu = parse_cpu_index(item)?;
            (cpu, cpu)
        };

        for cpu in start..=end {
            let bit = 1_u128
                .checked_shl(cpu)
                .ok_or_else(|| format!("CPU index out of taskset mask range: {cpu}"))?;
            mask |= bit;
            any = true;
        }
    }

    if !any {
        return Err("empty CPU list".to_string());
    }
    Ok(mask)
}

fn parse_cpu_index(value: &str) -> Result<u32> {
    let value = value.trim();
    if value.is_empty() {
        return Err("empty CPU index".to_string());
    }
    value
        .parse::<u32>()
        .map_err(|_| format!("invalid CPU index: {value}"))
}

fn constrain_to_available_cpus(requested: u128, cores: &str) -> Result<u128> {
    let Some(available) = available_cpu_mask() else {
        return Ok(requested);
    };
    let effective = requested & available;
    if effective == 0 {
        return Err(format!(
            "requested CPU cores {cores} are outside available CPU mask {available:x}"
        ));
    }
    if effective != requested {
        eprintln!(
            "[core_run_command] taskset mask adjusted from {requested:x} to {effective:x}, available {available:x}"
        );
    }
    Ok(effective)
}

fn available_cpu_mask() -> Option<u128> {
    [online_cpu_mask(), allowed_cpu_mask()]
        .into_iter()
        .flatten()
        .reduce(|left, right| left & right)
}

fn online_cpu_mask() -> Option<u128> {
    std::fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .and_then(|text| cpu_list_to_mask(text.trim()).ok())
}

fn allowed_cpu_mask() -> Option<u128> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    text.lines().find_map(|line| {
        line.strip_prefix("Cpus_allowed_list:")
            .and_then(|value| cpu_list_to_mask(value.trim()).ok())
    })
}
