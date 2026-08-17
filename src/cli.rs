use clap::{Arg, Command};

#[cfg(target_os = "linux")]
const INTERFACE_HELP: &str = "Network interface to monitor (use \"any\" to capture all interfaces)";

#[cfg(not(target_os = "linux"))]
const INTERFACE_HELP: &str = "Network interface to monitor";

#[cfg(target_os = "macos")]
const BPF_HELP: &str = "BPF filter expression for packet capture (e.g., \"tcp port 443\"). Note: Using a BPF filter disables PKTAP (process info falls back to lsof)";

#[cfg(not(target_os = "macos"))]
const BPF_HELP: &str =
    "BPF filter expression for packet capture (e.g., \"tcp port 443\", \"dst port 80\")";

pub fn build_cli() -> Command {
    let cmd = Command::new("rustnetec")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Network Monitor")
        .about("Cross-platform network monitoring tool")
        .subcommand(
            // rustnetec: query subcommand (R5/R6)
            Command::new("query")
                .about("Query local SQLite database for connection events")
                .arg(
                    Arg::new("live")
                        .long("live")
                        .help("Poll local HTTP /live endpoint for real-time data (read-only, no SQLite write lock)")
                        .action(clap::ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("db")
                        .long("db")
                        .value_name("PATH")
                        .help("Path to SQLite database file (default: platform-specific data directory)")
                        .required(false),
                )
                .arg(
                    Arg::new("filter")
                        .long("filter")
                        .value_name("EXPR")
                        .help("Filter expression using rustnet filter syntax (e.g., \"proto:TCP process:curl\")")
                        .required(false),
                )
                .arg(
                    Arg::new("sql")
                        .long("sql")
                        .value_name("SQL")
                        .help("Execute raw SQL query (SELECT only)")
                        .required(false),
                ),
        )
        // rustnetec: --install-autostart subcommand (R1 boot autostart, T1.11)
        .subcommand(
            Command::new("install-autostart")
                .about("Register rustnet --daemon (or --tray if autostart_mode=tray in config.yml) as a boot-time autostart entry using the platform's native per-user mechanism (Linux systemd --user, macOS LaunchAgent, Windows HKCU Run). No root/administrator required."),
        )
        // rustnetec: --uninstall-autostart subcommand (R1 boot autostart, T1.11)
        .subcommand(
            Command::new("uninstall-autostart")
                .about("Remove the boot-time autostart entry registered by install-autostart. Idempotent: Ok when no entry exists."),
        );

    // rustnetec: --install-launchdaemon / --uninstall-launchdaemon (T4.2, macOS)
    // 一次性授权安装系统 LaunchDaemon，之后 launchd 以 root 托管 daemon，
    // 无需每次弹授权窗口（永久授权方案）。cfg 属性不能放方法链中间，故
    // 拆成独立 `let cmd = cmd…` 语句。
    #[cfg(target_os = "macos")]
    let cmd = cmd
        .subcommand(
            Command::new("install-launchdaemon")
                .about("Install rustnet --daemon as a system LaunchDaemon (macOS). Requires one-time admin authorization; afterwards launchd runs the daemon as root at boot and restarts it on crash — no repeated password prompts.")
                .arg(
                    Arg::new("http-port")
                        .long("http-port")
                        .value_name("PORT")
                        .help("HTTP listen port for the daemon (default 19811)")
                        .required(false),
                ),
        )
        .subcommand(
            Command::new("uninstall-launchdaemon")
                .about("Remove the system LaunchDaemon installed by install-launchdaemon (macOS). Idempotent: Ok when not installed."),
        );

    let cmd = cmd
        .arg(
            Arg::new("interface")
                .short('i')
                .long("interface")
                .value_name("INTERFACE")
                .help(INTERFACE_HELP)
                .required(false),
        )
        .arg(
            Arg::new("no-localhost")
                .long("no-localhost")
                .help("Filter out localhost connections")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("show-localhost")
                .long("show-localhost")
                .help("Show localhost connections (overrides default filtering)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("refresh-interval")
                .short('r')
                .long("refresh-interval")
                .value_name("MILLISECONDS")
                .help("UI refresh interval in milliseconds")
                .value_parser(clap::value_parser!(u64))
                .default_value("500")
                .required(false),
        )
        .arg(
            Arg::new("no-dpi")
                .long("no-dpi")
                .help("Disable deep packet inspection")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("log-level")
                .short('l')
                .long("log-level")
                .value_name("LEVEL")
                .help("Set the log level (if not provided, no logging will be enabled)")
                .required(false),
        )
        .arg(
            Arg::new("json-log")
                .long("json-log")
                .value_name("FILE")
                .help("Enable JSON logging of connection events to specified file")
                .required(false),
        )
        .arg(
            Arg::new("pcap-export")
                .long("pcap-export")
                .value_name("FILE")
                .help("Export captured packets to PCAP file for Wireshark analysis")
                .required(false),
        )
        .arg(
            Arg::new("pcapng-export")
                .long("pcapng-export")
                .value_name("FILE")
                .help("Export captured packets to annotated PCAPNG file for Wireshark analysis")
                .required(false),
        )
        .arg(
            Arg::new("bpf-filter")
                .short('f')
                .long("bpf-filter")
                .value_name("FILTER")
                .help(BPF_HELP)
                .required(false),
        )
        .arg(
            Arg::new("no-resolve-dns")
                .long("no-resolve-dns")
                .help("Disable reverse DNS resolution for IP addresses (enabled by default; shows hostnames instead of IPs)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("show-ptr-lookups")
                .long("show-ptr-lookups")
                .help("Show PTR lookup connections in UI (hidden by default when DNS resolution is enabled)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-color")
                .long("no-color")
                .help("Disable all colors in the UI (also respects NO_COLOR env var)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("theme")
                .long("theme")
                .value_name("PRESET")
                .help("Color theme preset: \"muted\" (single accent, color reserved for signals) or \"classic\" (original full-color palette)")
                .value_parser(["muted", "classic"])
                .default_value("muted")
                .required(false),
        )
        .arg(
            Arg::new("geoip-country")
                .long("geoip-country")
                .value_name("PATH")
                .help(
                    "Path to GeoLite2-Country.mmdb database. \
                     Auto-discovered from: <config_dir>/GeoIP, $XDG_DATA_HOME/rustnet/geoip, \
                     ~/.local/share/rustnet/geoip, /usr/share/GeoIP, /usr/local/share/GeoIP, \
                     /opt/homebrew/share/GeoIP, /var/lib/GeoIP",
                )
                .required(false),
        )
        .arg(
            Arg::new("geoip-asn")
                .long("geoip-asn")
                .value_name("PATH")
                .help("Path to GeoLite2-ASN.mmdb database (same search paths as --geoip-country)")
                .required(false),
        )
        .arg(
            Arg::new("geoip-city")
                .long("geoip-city")
                .value_name("PATH")
                .help(
                    "Path to GeoLite2-City.mmdb database (same search paths as --geoip-country; \
                     superset of Country — provides city name and postal code in addition to country)",
                )
                .required(false),
        )
        .arg(
            Arg::new("no-geoip")
                .long("no-geoip")
                .help("Disable GeoIP lookups entirely")
                .action(clap::ArgAction::SetTrue),
        )
        // rustnetec: --daemon flag (R1)
        .arg(
            Arg::new("daemon")
                .long("daemon")
                .help("Run in daemon mode (headless, no TUI). Captures and logs network events in the background")
                .action(clap::ArgAction::SetTrue),
        )
        // rustnetec: --autostart flag (R1/T1.11 修复) — 由平台自启机制
        // (HKCU Run / systemd --user / LaunchAgent) 拉起的进程带上此标志:
        // 1) 权限检查走软路径(无抓包权限时降级 process-only 而非退出);
        // 2) Windows 下隐藏控制台黑窗; 3) 启动失败写入 autostart.log。
        // 对用户隐藏(仅 autostart 注册表/unit 条目使用), 避免 --help 干扰。
        .arg(
            Arg::new("autostart")
                .long("autostart")
                .help("Marked by the platform autostart mechanism (internal)")
                .action(clap::ArgAction::SetTrue)
                .hide(true),
        );

    // rustnetec: --tray flag (R1, feature-gated; T3.6.7: independent helper
    // entry — spawns the daemon child, runs the pure GUI tray)
    #[cfg(feature = "tray")]
    let cmd = cmd.arg(
        Arg::new("tray")
            .long("tray")
            .help("Run the system tray helper (spawns the daemon child; pure GUI, no terminal)")
            .action(clap::ArgAction::SetTrue),
    );

    let cmd = cmd
        // rustnetec: --db flag (R2)
        .arg(
            Arg::new("db")
                .long("db")
                .value_name("PATH")
                .help("Path to SQLite database file (default: platform-specific data directory)")
                .required(false),
        )
        // rustnetec: --server-url flag (R3)
        .arg(
            Arg::new("server-url")
                .long("server-url")
                .value_name("URL")
                .help("URL of the rustnet server for data upload (e.g., https://rustnet.example.com)")
                .required(false),
        )
        // rustnetec: --upload-interval flag (R3)
        .arg(
            Arg::new("upload-interval")
                .long("upload-interval")
                .value_name("SECS")
                .help("Interval in seconds between data uploads to server (default: 60)")
                .value_parser(clap::value_parser!(u32))
                .required(false),
        )
        // rustnetec: --http-port flag (R5)
        .arg(
            Arg::new("http-port")
                .long("http-port")
                .value_name("PORT")
                .help("Local loopback HTTP server port (default: 19811)")
                .value_parser(clap::value_parser!(u16))
                .required(false),
        )
        // rustnetec: --sandbox-allow-network flag (R3, macOS)
        .arg(
            Arg::new("sandbox-allow-network")
                .long("sandbox-allow-network")
                .value_name("HOST")
                .help("Allow outbound network to specified host from sandbox (for data upload; DNS on port 53 is also allowed)")
                .required(false),
        )
        // rustnetec: --username flag (R8)
        .arg(
            Arg::new("username")
                .long("username")
                .value_name("NAME")
                .help("Set the username for host identity (default: system username)")
                .required(false),
        )
        // rustnetec: --user-id flag (R8)
        .arg(
            Arg::new("user-id")
                .long("user-id")
                .value_name("ID")
                .help("Set the user ID (snowflake) for host identity (default: auto-generated on first startup)")
                .value_parser(clap::value_parser!(i64))
                .required(false),
        )
        // rustnetec: --machine-id flag (R10)
        .arg(
            Arg::new("machine-id")
                .long("machine-id")
                .value_name("ID")
                .help("Set the machine ID (hardware fingerprint) for host identity (default: auto-detected from hardware)")
                .required(false),
        )
        // rustnetec: --retention-days flag (R9)
        .arg(
            Arg::new("retention-days")
                .long("retention-days")
                .value_name("DAYS")
                .help("Data retention period in days (1-180, default: 90)")
                .value_parser(clap::value_parser!(u32))
                .required(false),
        );

    #[cfg(feature = "kubernetes")]
    let cmd = cmd.arg(
        Arg::new("kubernetes")
            .long("kubernetes")
            .value_name("MODE")
            .help(
                "Kubernetes pod/container attribution: \"auto\" (enable only when running inside a pod), \"on\" (always), or \"off\"",
            )
            .value_parser(["auto", "on", "off"])
            .default_value("auto")
            .required(false),
    );

    #[cfg(any(
        target_os = "linux",
        target_os = "windows",
        all(target_os = "macos", feature = "macos-sandbox")
    ))]
    let cmd = cmd
        .arg(
            Arg::new("no-sandbox")
                .long("no-sandbox")
                .help("Disable sandboxing (on Linux, PR_SET_NO_NEW_PRIVS is still set)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("sandbox-strict")
                .long("sandbox-strict")
                .help("Require full sandbox enforcement or exit")
                .action(clap::ArgAction::SetTrue)
                .conflicts_with("no-sandbox"),
        );

    #[cfg(target_os = "linux")]
    let cmd = cmd.arg(
        Arg::new("no-uid-drop")
            .long("no-uid-drop")
            .help(
                "Keep running as root instead of dropping to SUDO_UID/SUDO_GID (or nobody) \
                 after initialization. Keeping root lets the procfs fallback attribute \
                 other users' processes when eBPF is unavailable",
            )
            .action(clap::ArgAction::SetTrue),
    );

    #[cfg(target_os = "macos")]
    let cmd = cmd.arg(
        Arg::new("no-uid-drop")
            .long("no-uid-drop")
            .help(
                "Keep running as root instead of dropping to SUDO_UID/SUDO_GID (or nobody) \
                 after initialization. Keeping root lets the lsof fallback attribute other \
                 users' processes when PKTAP is unavailable",
            )
            .action(clap::ArgAction::SetTrue),
    );

    #[cfg(target_os = "freebsd")]
    let cmd = cmd.arg(
        Arg::new("no-uid-drop")
            .long("no-uid-drop")
            .help(
                "Keep running as root instead of dropping to SUDO_UID/SUDO_GID (or nobody) \
                 after initialization. Keeping root lets sockstat attribute other users' \
                 processes",
            )
            .action(clap::ArgAction::SetTrue),
    );

    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_interval_defaults_to_500ms() {
        let matches = build_cli()
            .try_get_matches_from(["rustnetec"])
            .expect("default CLI arguments should parse");

        assert_eq!(matches.get_one::<u64>("refresh-interval"), Some(&500));
    }

    // rustnetec: test new flags
    #[test]
    fn daemon_flag_parses() {
        let matches = build_cli()
            .try_get_matches_from(["rustnetec", "--daemon"])
            .expect("--daemon should parse");
        assert!(matches.get_flag("daemon"));
    }

    // rustnetec: T1.11 修复 — 隐藏的 --autostart 标志: 平台自启机制使用,
    // 可解析且对用户隐藏(不出现在 --help)。
    #[test]
    fn autostart_flag_parses() {
        let matches = build_cli()
            .try_get_matches_from(["rustnetec", "--autostart", "--daemon"])
            .expect("--autostart should parse");
        assert!(matches.get_flag("autostart"));
        assert!(matches.get_flag("daemon"));
    }

    #[test]
    fn autostart_flag_hidden_from_help() {
        let help = build_cli().render_long_help();
        let text = help.to_string();
        assert!(
            !text.contains("--autostart"),
            "--autostart is internal and must be hidden from --help"
        );
    }

    #[test]
    fn db_flag_parses() {
        let matches = build_cli()
            .try_get_matches_from(["rustnetec", "--db", "/tmp/test.db"])
            .expect("--db should parse");
        assert_eq!(
            matches.get_one::<String>("db").map(String::as_str),
            Some("/tmp/test.db")
        );
    }

    #[test]
    fn server_url_flag_parses() {
        let matches = build_cli()
            .try_get_matches_from(["rustnetec", "--server-url", "https://example.com"])
            .expect("--server-url should parse");
        assert_eq!(
            matches.get_one::<String>("server-url").map(String::as_str),
            Some("https://example.com")
        );
    }

    #[test]
    fn upload_interval_flag_parses() {
        let matches = build_cli()
            .try_get_matches_from(["rustnetec", "--upload-interval", "30"])
            .expect("--upload-interval should parse");
        assert_eq!(matches.get_one::<u32>("upload-interval"), Some(&30));
    }

    #[test]
    fn http_port_flag_parses() {
        let matches = build_cli()
            .try_get_matches_from(["rustnetec", "--http-port", "8080"])
            .expect("--http-port should parse");
        assert_eq!(matches.get_one::<u16>("http-port"), Some(&8080));
    }

    #[test]
    fn retention_days_flag_parses() {
        let matches = build_cli()
            .try_get_matches_from(["rustnetec", "--retention-days", "30"])
            .expect("--retention-days should parse");
        assert_eq!(matches.get_one::<u32>("retention-days"), Some(&30));
    }

    #[test]
    fn username_flag_parses() {
        let matches = build_cli()
            .try_get_matches_from(["rustnetec", "--username", "alice"])
            .expect("--username should parse");
        assert_eq!(
            matches.get_one::<String>("username").map(String::as_str),
            Some("alice")
        );
    }

    #[test]
    fn user_id_flag_parses() {
        let matches = build_cli()
            .try_get_matches_from(["rustnetec", "--user-id", "12345"])
            .expect("--user-id should parse");
        assert_eq!(matches.get_one::<i64>("user-id"), Some(&12345));
    }

    #[test]
    fn query_subcommand_parses() {
        let matches = build_cli()
            .try_get_matches_from(["rustnetec", "query", "--filter", "proto:TCP"])
            .expect("query subcommand should parse");
        let sub = matches
            .subcommand_matches("query")
            .expect("query subcommand");
        assert_eq!(
            sub.get_one::<String>("filter").map(String::as_str),
            Some("proto:TCP")
        );
    }

    #[test]
    fn query_subcommand_with_sql() {
        let matches = build_cli()
            .try_get_matches_from([
                "rustnetec",
                "query",
                "--sql",
                "SELECT COUNT(*) FROM connection_events",
            ])
            .expect("query --sql should parse");
        let sub = matches
            .subcommand_matches("query")
            .expect("query subcommand");
        assert_eq!(
            sub.get_one::<String>("sql").map(String::as_str),
            Some("SELECT COUNT(*) FROM connection_events")
        );
    }

    #[test]
    fn query_subcommand_with_live() {
        let matches = build_cli()
            .try_get_matches_from(["rustnetec", "query", "--live"])
            .expect("query --live should parse");
        let sub = matches
            .subcommand_matches("query")
            .expect("query subcommand");
        assert!(sub.get_flag("live"));
    }

    // rustnetec: autostart subcommand parsing (R1 boot autostart, T1.11)
    #[test]
    fn install_autostart_subcommand_parses() {
        let matches = build_cli()
            .try_get_matches_from(["rustnetec", "install-autostart"])
            .expect("install-autostart subcommand should parse");
        assert!(
            matches.subcommand_matches("install-autostart").is_some(),
            "install-autostart subcommand should be detected"
        );
    }

    #[test]
    fn uninstall_autostart_subcommand_parses() {
        let matches = build_cli()
            .try_get_matches_from(["rustnetec", "uninstall-autostart"])
            .expect("uninstall-autostart subcommand should parse");
        assert!(
            matches.subcommand_matches("uninstall-autostart").is_some(),
            "uninstall-autostart subcommand should be detected"
        );
    }
}
