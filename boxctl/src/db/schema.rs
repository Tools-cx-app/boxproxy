use super::*;

const SCHEMA_VERSION: i64 = 2;

pub(super) fn ensure_schema(conn: &Connection) -> Result<()> {
    let current: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|err| format!("read database schema version failed: {err}"))?;
    if current >= SCHEMA_VERSION {
        return Ok(());
    }

    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(|err| format!("begin database schema migration failed: {err}"))?;
    let migration = migrate_schema(conn, current).and_then(|()| {
        conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))
            .map_err(|err| format!("update database schema version failed: {err}"))
    });
    match migration {
        Ok(()) => conn
            .execute_batch("COMMIT")
            .map_err(|err| format!("commit database schema migration failed: {err}")),
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(err)
        }
    }
}

fn migrate_schema(conn: &Connection, current: i64) -> Result<()> {
    if current < 1 {
        initialize_schema(conn)?;
    } else {
        migrate_v2(conn)?;
    }
    Ok(())
}

fn initialize_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS runtime_profile (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            core_name TEXT NOT NULL,
            mode TEXT NOT NULL,
            proxy_mode TEXT NOT NULL,
            auto_sync_config INTEGER NOT NULL,
            performance_mode INTEGER NOT NULL,
            clean_vendor_firewall INTEGER NOT NULL DEFAULT 0,
            ipv6_mode TEXT NOT NULL DEFAULT 'enable',
            config_name TEXT NOT NULL,
            tproxy_port TEXT NOT NULL,
            redir_port TEXT NOT NULL,
            quic TEXT NOT NULL,
            mihomo_dns_forward TEXT NOT NULL,
            mihomo_dns_port TEXT NOT NULL,
            proxy_tcp INTEGER NOT NULL,
            proxy_udp INTEGER NOT NULL,
            dns_hijack_tcp INTEGER NOT NULL,
            dns_hijack_udp INTEGER NOT NULL,
            dns_hijack_mode TEXT NOT NULL,
            cgroup_memcg INTEGER NOT NULL,
            memcg_limit TEXT NOT NULL,
            taskset_cpu INTEGER NOT NULL DEFAULT 0,
            allow_cpu TEXT NOT NULL,
            cgroup_blkio INTEGER NOT NULL,
            weight TEXT NOT NULL,
            bypass_cn INTEGER NOT NULL,
            tun_device TEXT NOT NULL,
            fake_ip_range TEXT NOT NULL,
            fake_ip6_range TEXT NOT NULL,
            boot_auto_start INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS app_selection (
            uid INTEGER PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS app_gid_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cnip_force_uids (
            uid INTEGER PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS cnip_settings (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            bypass_cnip INTEGER NOT NULL,
            cnip_mode TEXT NOT NULL DEFAULT 'ipset',
            bypass_ipv4 INTEGER NOT NULL,
            bypass_ipv6 INTEGER NOT NULL,
            ipv4_file TEXT NOT NULL,
            ipv4_url TEXT NOT NULL,
            ipv6_file TEXT NOT NULL,
            ipv6_url TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS wifi_match_settings (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            network_control_enabled INTEGER NOT NULL,
            use_on_wifi_disconnect INTEGER NOT NULL,
            use_on_wifi_connect INTEGER NOT NULL,
            enable_ssid_matching INTEGER NOT NULL,
            enable_network_control_log INTEGER NOT NULL,
            list_mode TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS wifi_match_ssids (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS wifi_match_bssids (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS hotspot_settings (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            mac_filter INTEGER NOT NULL,
            mac_mode TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS hotspot_ap_interfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS blocked_interfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS hotspot_macs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS intranet_bypass_settings (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            initialized INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS intranet_ipv4_cidrs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS intranet_ipv6_cidrs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL
        );
        "#,
    )
    .map_err(|err| format!("initialize database schema failed: {err}"))?;
    Ok(())
}

fn migrate_v2(conn: &Connection) -> Result<()> {
    ensure_columns(
        conn,
        "runtime_profile",
        &[
            ("boot_auto_start", "INTEGER NOT NULL DEFAULT 0"),
            ("clean_vendor_firewall", "INTEGER NOT NULL DEFAULT 0"),
            ("ipv6_mode", "TEXT NOT NULL DEFAULT 'enable'"),
            ("taskset_cpu", "INTEGER NOT NULL DEFAULT 0"),
        ],
    )?;
    ensure_columns(
        conn,
        "cnip_settings",
        &[("cnip_mode", "TEXT NOT NULL DEFAULT 'ipset'")],
    )?;
    Ok(())
}

fn ensure_columns(conn: &Connection, table: &str, columns: &[(&str, &str)]) -> Result<()> {
    let existing = table_columns(conn, table)?;
    for (column, definition) in columns {
        if existing
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(column))
        {
            continue;
        }
        let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {definition}");
        conn.execute(&sql, [])
            .map_err(|err| format!("update {table}.{column} failed: {err}"))?;
    }
    Ok(())
}

fn table_columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
    let pragma = format!("PRAGMA table_info({table})");
    let mut stmt = conn
        .prepare(&pragma)
        .map_err(|err| format!("read {table} schema failed: {err}"))?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|err| format!("read {table} schema failed: {err}"))?;

    columns
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|err| format!("read {table} schema failed: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_version_one_schema_once_and_updates_user_version() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE runtime_profile (id INTEGER PRIMARY KEY);
            CREATE TABLE cnip_settings (id INTEGER PRIMARY KEY);
            PRAGMA user_version = 1;
            ",
        )
        .unwrap();

        ensure_schema(&conn).unwrap();

        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let profile_columns = table_columns(&conn, "runtime_profile").unwrap();
        assert!(profile_columns.iter().any(|column| column == "taskset_cpu"));
        let cnip_columns = table_columns(&conn, "cnip_settings").unwrap();
        assert!(cnip_columns.iter().any(|column| column == "cnip_mode"));
    }
}
