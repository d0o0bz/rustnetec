use anyhow::Result;
use log::{LevelFilter, error, info, warn};
use ratatui::prelude::CrosstermBackend;
use rustnet_monitor::{app, cli, network, telemetry, ui};
use simplelog::{ConfigBuilder, WriteLogger};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// rustnetec: 解析 SQLite 数据库路径 — 优先 `--db` 覆盖,否则回退平台默认。
///
/// daemon/tray 分支此前固定用 `telemetry::paths::db_path()`(R2 回归),
/// 忽略了 `--db`;本函数统一该语义,供 SqliteSink、HTTP state 与 uid-drop
/// chown 共用,保证 daemon 落库路径与 `query --live` 一致。
fn resolve_db_path(matches: &clap::ArgMatches) -> PathBuf {
    if let Some(p) = matches.get_one::<String>("db") {
        PathBuf::from(p)
    } else {
        telemetry::paths::db_path().unwrap_or_else(|_| PathBuf::from("data.db"))
    }
}

/// rustnetec: 检测 Windows 下程序是否由「双击」启动（Explorer 新建了控制台）。
///
/// `GetConsoleProcessList` 返回附加到当前控制台的所有进程 PID 数量：
/// - count == 1：独占一个新控制台 → 双击启动（Explorer 为 console 程序新建窗口）
/// - count >= 2：与 shell（cmd/PowerShell）共享控制台 → 从终端运行
/// - count == 0：无控制台（输出被重定向）→ 不是双击
///
/// 仅在判定为双击时返回 true，由调用方据此强制进入托盘模式；
/// 显式 `--tray` / `--daemon` 参数始终优先。
#[cfg(all(feature = "tray", target_os = "windows"))]
fn launched_by_double_click() -> bool {
    use windows::Win32::System::Console::GetConsoleProcessList;
    let mut pids = [0u32; 2];
    let count = unsafe { GetConsoleProcessList(&mut pids) };
    count == 1 && pids[0] != 0
}

/// rustnetec: T1.11 修复 — 程序入口薄包装。
///
/// 带 `--autostart` 时(平台自启机制拉起):
/// 1. Windows 下立即释放控制台, 避免登录黑窗(早于一切输出);
/// 2. 任何启动失败(含依赖检查、权限检查)都会追加写入
///    `<data_dir>/autostart.log`, 让"开机自启失败"可排查。
///
/// 其余情况直接透传 [`run`]。
fn main() -> Result<()> {
    let autostart = std::env::args().any(|a| a == "--autostart");
    #[cfg(target_os = "windows")]
    if autostart {
        unsafe {
            let _ = windows::Win32::System::Console::FreeConsole();
        }
    }

    let result = run();
    if autostart
        && let Err(e) = &result
    {
        append_autostart_error(&format!("autostart run failed: {e:#}"));
    }
    result
}

/// rustnetec: 原 main 主体(见 [`main`] 包装)。
fn run() -> Result<()> {
    // Check for required dependencies on Windows
    #[cfg(target_os = "windows")]
    check_windows_dependencies()?;

    // Parse command line arguments
    let matches = cli::build_cli().get_matches();

    // rustnetec: Handle `query` subcommand early (independent of TUI/daemon mode)
    if let Some(query_matches) = matches.subcommand_matches("query") {
        return run_query_subcommand(query_matches);
    }

    // rustnetec: Handle autostart subcommands (R1 boot autostart, T1.11)
    if matches.subcommand_matches("install-autostart").is_some() {
        return run_install_autostart();
    }
    if matches.subcommand_matches("uninstall-autostart").is_some() {
        return run_uninstall_autostart();
    }
    // rustnetec: Handle LaunchDaemon subcommands (T4.2, macOS 永久授权)
    #[cfg(target_os = "macos")]
    if matches.subcommand_matches("install-launchdaemon").is_some() {
        return run_install_launchdaemon(&matches);
    }
    #[cfg(target_os = "macos")]
    if matches.subcommand_matches("uninstall-launchdaemon").is_some() {
        return run_uninstall_launchdaemon();
    }

    // Set up logging only if log-level was provided
    if let Some(log_level_str) = matches.get_one::<String>("log-level") {
        let log_level = log_level_str
            .parse::<LevelFilter>()
            .map_err(|_| anyhow::anyhow!("Invalid log level: {}", log_level_str))?;
        setup_logging(log_level)?;
    } else if matches.get_flag("autostart") {
        // rustnetec: T1.11 修复 — 自启模式未显式指定 --log-level 时,
        // 默认把日志落盘到 <data_dir>/autostart.log, 使"开机自启失败"
        // 可排查(否则黑窗已隐藏, 错误无迹可寻)。
        if let Err(e) = setup_autostart_log() {
            eprintln!("Warning: failed to initialize autostart log: {}", e);
        }
    }

    // rustnetec: Determine run mode (TUI / daemon / tray)
    let daemon_mode = matches.get_flag("daemon");
    // rustnetec: Windows 双击启动（独占新控制台）且未显式 --daemon 时
    // 强制进入托盘模式（自动开 TUI 见 run_tray_helper）。
    #[cfg(all(feature = "tray", target_os = "windows"))]
    let tray_mode =
        matches.get_flag("tray") || (launched_by_double_click() && !daemon_mode);
    #[cfg(all(feature = "tray", not(target_os = "windows")))]
    let tray_mode = matches.get_flag("tray");
    #[cfg(not(feature = "tray"))]
    let tray_mode = false;

    // rustnetec: Check privileges BEFORE initializing TUI (so error messages
    // are visible). Tray mode uses a soft check (warn, continue) because the
    // tray menu itself (open terminal / local panel / settings / quit) needs
    // no packet capture — unprivileged capture already degrades to
    // process-only mode inside App::start_capture_thread. TUI/daemon keep the
    // hard check so a missing capture permission fails fast with clear
    // guidance instead of a half-working UI.
    // rustnetec: a daemon spawned by the tray helper (marked via the
    // RUSTNETEC_TRAY_DAEMON env var, see run_tray_helper) also uses the soft
    // check: the tray panels (/live, /config) must stay reachable even
    // without capture privileges, with capture degrading to process-only.
    #[cfg(feature = "tray")]
    if tray_mode
        || matches.get_flag("autostart")
        || std::env::var("RUSTNETEC_TRAY_DAEMON").is_ok()
    {
        check_privileges_soft();
    } else {
        check_privileges_early()?;
    }
    #[cfg(not(feature = "tray"))]
    if matches.get_flag("autostart") {
        check_privileges_soft();
    } else {
        check_privileges_early()?;
    }

    // rustnetec: T3.6.7 — tray is now an independent helper process (A
    // topology: tray is the entry point, it spawns the daemon child and runs
    // the pure GUI with a blocking platform event loop). Route to it BEFORE
    // App/capture initialization — the helper must not create an App or open
    // the BPF device itself.
    #[cfg(all(feature = "tray", not(target_os = "freebsd")))]
    if tray_mode && !daemon_mode {
        // rustnetec: Windows 双击启动（Explorer 新建了控制台黑窗）时
        // 释放控制台，避免托盘 GUI 背后残留黑色窗口。从终端显式运行
        // 不触发（共享控制台，count >= 2）。
        #[cfg(all(feature = "tray", target_os = "windows"))]
        if launched_by_double_click() {
            unsafe {
                let _ = windows::Win32::System::Console::FreeConsole();
            }
        }
        return run_tray_helper(&matches);
    }

    // rustnetec: Ensure data and config directories exist, chown before uid drop
    if let Err(e) = telemetry::paths::ensure_dirs() {
        warn!("Failed to create data/config directories: {}", e);
    }

    // rustnetec: 提前生成 http_token（T1.4 修复）
    // Seatbelt (fs_restricted=true) 在本函数稍后应用，会阻止 config.yml 的
    // 写入；若等到 daemon 分支（原 761 行）才生成 token，save 会被 sandbox
    // 静默拒绝，config.yml 的 http_token 保持 null，导致 `query --live`
    // 读取空 token → daemon 鉴权 401。这里在 sandbox 之前生成并随 identity
    // 一起落盘，并缓存到外层变量供 daemon 分支直接使用——sandbox 还会
    // `deny file-read*`，此时再 load config.yml 会失败、重新生成新 token，
    // 造成 daemon 内存 token 与落盘 token 不一致。
    let http_token_early: Option<String>;

    // rustnetec: Initialize host identity (R8+R10, T1.6)
    // Load PersistentConfig, generate missing user_id/machine_id, save back if needed.
    {
        let mut pc = match rustnet_monitor::config::PersistentConfig::load() {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to load config.yml, using defaults: {}", e);
                rustnet_monitor::config::PersistentConfig::default()
            }
        };

        // Apply CLI overrides for identity fields
        if let Some(username) = matches.get_one::<String>("username") {
            pc.username = Some(username.clone());
        }
        // rustnetec: collapse nested `if let` into let-chain (clippy::collapsible_if)
        if let Some(user_id_str) = matches.get_one::<String>("user-id")
            && let Ok(uid) = user_id_str.parse::<i64>()
        {
            pc.user_id = Some(uid);
        }
        if let Some(machine_id) = matches.get_one::<String>("machine-id") {
            pc.machine_id = Some(machine_id.clone());
        }

        let (identity, mut needs_save) = telemetry::identity::HostIdentity::initialize(
            pc.username.as_deref(),
            pc.user_id,
            pc.machine_id.as_deref(),
        );

        // rustnetec: 提前生成 http_token（T1.4 修复）
        // Seatbelt (fs_restricted=true) 在本函数稍后应用，会阻止 config.yml 的
        // 写入；若等到 daemon 分支（原 761 行）才生成 token，save 会被 sandbox
        // 静默拒绝，config.yml 的 http_token 保持 null，导致 `query --live`
        // 读取空 token → daemon 鉴权 401。这里在 sandbox 之前生成并随 identity
        // 一起落盘，保证 daemon/query 读到同一个持久化 token。
        if pc.http_token.is_none() {
            pc.http_token =
                Some(rustnet_monitor::config::PersistentConfig::generate_http_token());
            needs_save = true;
        }
        http_token_early = pc.http_token.clone();

        // Log identity info before potential move
        let mid_prefix = &identity.machine_id[..8.min(identity.machine_id.len())];
        info!(
            "Host identity: machine_id={}..., user_id={}, username={}",
            mid_prefix, identity.user_id, identity.username
        );

        if needs_save {
            // Write back generated fields to config.yml
            pc.user_id = Some(identity.user_id);
            pc.machine_id = Some(identity.machine_id);
            if pc.username.is_none() {
                pc.username = Some(identity.username.clone());
            }
            if let Err(e) = pc.save() {
                warn!("Failed to save config.yml with identity: {}", e);
            } else {
                info!(
                    "Host identity initialized and saved: user_id={}",
                    identity.user_id
                );
            }
        }
    }

    // Build configuration from command line arguments
    let mut config = app::Config::default();

    if let Some(interface) = matches.get_one::<String>("interface") {
        config.interface = Some(interface.to_string());
        info!("Using interface: {}", interface);
    }

    if matches.get_flag("no-localhost") {
        config.filter_localhost = true;
        info!("Filtering localhost connections");
    }

    if matches.get_flag("show-localhost") {
        config.filter_localhost = false;
        info!("Showing localhost connections");
    }

    if let Some(interval) = matches.get_one::<u64>("refresh-interval") {
        config.refresh_interval = *interval;
        info!("Using refresh interval: {}ms", interval);
    }

    if matches.get_flag("no-dpi") {
        config.enable_dpi = false;
        info!("Deep packet inspection disabled");
    }

    if let Some(json_log_path) = matches.get_one::<String>("json-log") {
        config.json_log_file = Some(json_log_path.to_string());
        info!("JSON logging enabled: {}", json_log_path);
    }

    if let Some(pcap_path) = matches.get_one::<String>("pcap-export") {
        config.pcap_export_file = Some(pcap_path.to_string());
        info!("PCAP export enabled: {}", pcap_path);
    }

    if let Some(pcapng_path) = matches.get_one::<String>("pcapng-export") {
        config.pcapng_export_file = Some(pcapng_path.to_string());
        info!("PCAPNG export enabled: {}", pcapng_path);
    }

    if let Some(bpf_filter) = matches.get_one::<String>("bpf-filter") {
        let filter = bpf_filter.trim();
        if !filter.is_empty() {
            config.bpf_filter = Some(filter.to_string());
            info!("Using BPF filter: {}", filter);
        }
    }

    if matches.get_flag("no-resolve-dns") {
        config.resolve_dns = false;
        info!("Reverse DNS resolution disabled");
    }

    if matches.get_flag("show-ptr-lookups") {
        config.show_ptr_lookups = true;
        info!("PTR lookup connections will be shown in UI");
    }

    // Check NO_COLOR environment variable and --no-color flag (https://no-color.org)
    let no_color =
        matches.get_flag("no-color") || std::env::var("NO_COLOR").is_ok_and(|v| !v.is_empty());
    if no_color {
        info!("Colors disabled (NO_COLOR)");
        ui::set_no_color(true);
    }

    // Color theme preset
    let theme_preset = match matches.get_one::<String>("theme").map(String::as_str) {
        Some("classic") => ui::ThemePreset::Classic,
        _ => ui::ThemePreset::Muted,
    };
    info!("Using {theme_preset:?} color theme");
    ui::set_theme_preset(theme_preset);

    // GeoIP configuration
    if matches.get_flag("no-geoip") {
        config.disable_geoip = true;
        info!("GeoIP lookups disabled");
    }

    if let Some(country_path) = matches.get_one::<String>("geoip-country") {
        config.geoip_country_path = Some(country_path.to_string());
        info!("Using GeoIP Country database: {}", country_path);
    }

    if let Some(asn_path) = matches.get_one::<String>("geoip-asn") {
        config.geoip_asn_path = Some(asn_path.to_string());
        info!("Using GeoIP ASN database: {}", asn_path);
    }

    if let Some(city_path) = matches.get_one::<String>("geoip-city") {
        config.geoip_city_path = Some(city_path.to_string());
        info!("Using GeoIP City database: {}", city_path);
    }

    // Kubernetes pod/container attribution mode (values validated by clap)
    #[cfg(feature = "kubernetes")]
    if let Some(mode) = matches.get_one::<String>("kubernetes")
        && let Some(parsed) = network::kubernetes::KubernetesMode::parse(mode)
    {
        config.kubernetes_mode = parsed;
        info!("Kubernetes attribution mode: {}", mode);
    }

    // Resolve the identity to drop root to after privileged init (Linux,
    // macOS, and FreeBSD): the invoking sudo user, or nobody when started as
    // plain root.
    // Resolved before output files are opened so they can be chowned to the
    // target user. Retained descriptors remain usable after the drop, and the
    // resulting files have ownership consistent with the runtime identity.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    let uid_drop_target = if matches.get_flag("no-uid-drop") {
        info!("Root uid drop disabled by --no-uid-drop");
        None
    } else {
        network::platform::privdrop::resolve_drop_target()
    };

    // rustnetec: Chown data/config directories before uid drop (R1)
    // This ensures the runtime user can access data.db and config.yml after
    // privileges are dropped.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    if let Some(ref target) = uid_drop_target {
        if let Ok(dir) = telemetry::paths::data_dir() {
            let _ = telemetry::paths::chown_if_root(&dir, target.uid, target.gid);
        }
        // rustnetec: 用 --db 覆盖路径(若有),保证自定义库文件也被 chown。
        let db_path = resolve_db_path(&matches);
        if db_path.exists() {
            let _ = telemetry::paths::chown_if_root(&db_path, target.uid, target.gid);
        }
        if let Ok(dir) = telemetry::paths::config_dir() {
            let _ = telemetry::paths::chown_if_root(&dir, target.uid, target.gid);
        }
        // rustnetec: collapse nested `if let` into let-chain (clippy::collapsible_if)
        if let Ok(path) = telemetry::paths::config_path()
            && path.exists()
        {
            let _ = telemetry::paths::chown_if_root(&path, target.uid, target.gid);
        }
    }

    let mut output_handles = app::AppOutputHandles::default();

    // Open JSONL outputs before sandboxing and uid drop. The descriptors stay
    // open for the whole run: ownership changes alone are not sufficient for a
    // path under a directory such as /root, which the drop target cannot
    // traverse when trying to reopen the file.
    if let Some(ref json_log_path) = config.json_log_file {
        let file = open_private_append_file(json_log_path).map_err(|e| {
            anyhow::anyhow!("Failed to open JSON log file '{}': {}", json_log_path, e)
        })?;
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
        chown_to_uid_drop_target(&file, uid_drop_target, "JSON log", json_log_path);
        output_handles.json_log = Some(file);
    }

    // Pre-create the PCAP export file and retain its sidecar JSONL descriptor.
    // This must be done BEFORE the sandbox is applied so the files exist when
    // adding rules: Landlock requires an open FD to scope a rule to a file, so
    // a not-yet-existing path falls back to granting write on the whole parent
    // directory. Pre-creating keeps the write rule file-scoped. The PCAP writer
    // later reopens the path with truncation while it still has startup
    // privileges, so a zero-byte file is fine.
    //
    // Done before terminal setup: pre-creation can fail hard (see below), and we
    // want the error to print to a normal terminal rather than into the TUI
    // alt-screen (which would also leave the terminal in raw mode).
    if let Some(ref pcap_path) = config.pcap_export_file {
        let jsonl_path = format!("{}.connections.jsonl", pcap_path);
        for (label, path) in [("PCAP", pcap_path.as_str()), ("sidecar JSONL", &jsonl_path)] {
            // Fail hard rather than continue: if we can't safely create the file
            // (e.g. the path is a symlink, rejected by O_NOFOLLOW), aborting now
            // is the only way the protection is meaningful. The PCAP itself is
            // later written by libpcap's pcap_dump_open, which does NOT honor
            // O_NOFOLLOW, so a warn-and-continue here would let libpcap follow an
            // attacker-controlled symlink and write the capture there anyway.
            let file = precreate_private_file(path).map_err(|e| {
                anyhow::anyhow!("Failed to pre-create {} file '{}': {}", label, path, e)
            })?;
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
            chown_to_uid_drop_target(&file, uid_drop_target, label, path);
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
            let _ = &file;

            if label == "sidecar JSONL" {
                output_handles.pcap_sidecar = Some(file);
            }
        }
    }

    if let Some(ref pcapng_path) = config.pcapng_export_file {
        let file = precreate_private_file(pcapng_path).map_err(|e| {
            anyhow::anyhow!("Failed to pre-create PCAPNG file '{}': {}", pcapng_path, e)
        })?;
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
        chown_to_uid_drop_target(&file, uid_drop_target, "PCAPNG", pcapng_path);
        output_handles.pcapng_export = Some(file);
    }

    // Set up terminal (skip in daemon mode)
    // rustnetec: daemon mode skips TUI setup entirely
    let mut terminal = if !daemon_mode {
        let backend = CrosstermBackend::new(io::stdout());
        Some(ui::setup_terminal(backend)?)
    } else {
        None
    };
    if !daemon_mode {
        info!("Terminal UI initialized");
        // rustnetec: TUI 单实例标记（方案 B）。
        // 写 PID 文件供托盘「打开终端监控」检测：已存在→调到前台，不存在→新开，
        // 保证只打开一个前台 TUI。同时在终端窗口设置固定标题，便于 macOS
        // osascript 按标题定位窗口。退出时在 cleanup 段删除并恢复标题。
        if let Ok(dir) = telemetry::paths::data_dir() {
            let _ = std::fs::write(dir.join("tui.pid"), std::process::id().to_string());
        }
        let _ = crossterm::execute!(
            io::stdout(),
            crossterm::terminal::SetTitle("Rustnetec Monitor")
        );
    } else {
        info!("Running in daemon mode (headless)");
    }

    // Create and start the application
    let mut app = app::App::new_with_output_handles(config.clone(), output_handles)?;
    let (process_ready_rx, capture_ready_rx) = app.start()?;
    info!("Application started");

    // Wait for process detection (including eBPF loading) to complete before
    // applying the sandbox, which drops CAP_BPF and CAP_PERFMON.
    // Without this synchronization, the sandbox could drop these capabilities
    // before the background thread has finished loading eBPF programs.
    match process_ready_rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(()) => info!("Process detection initialized, safe to apply sandbox"),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            warn!("Timed out waiting for process detection init, applying sandbox anyway");
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            warn!("Process detection thread exited early, applying sandbox anyway");
        }
    }

    // Also wait for the capture thread to finish opening the capture device.
    // The open runs on a background thread and needs the startup privileges;
    // without this synchronization the uid drop (Linux/FreeBSD) or sandbox
    // could win the race and the open would fail with EPERM, leaving the UI
    // running with no traffic.
    match capture_ready_rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(()) => info!("Packet capture initialized, safe to apply sandbox"),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            warn!("Timed out waiting for packet capture init, applying sandbox anyway");
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            warn!("Capture thread exited early, applying sandbox anyway");
        }
    }

    // Apply Landlock sandbox (Linux only)
    // This must be done AFTER process detection is initialized because:
    // - eBPF programs need to be loaded first (requires CAP_BPF + CAP_PERFMON)
    // - Packet capture handles need to be opened first (access to /dev)
    // - Log files need to be created first
    #[cfg(target_os = "linux")]
    {
        use network::geoip::GeoIpResolver;
        use network::platform::sandbox::{
            SandboxConfig, SandboxMode, SandboxStatus, apply_sandbox,
        };
        use std::path::PathBuf;

        let sandbox_mode = if matches.get_flag("no-sandbox") {
            SandboxMode::Disabled
        } else if matches.get_flag("sandbox-strict") {
            SandboxMode::Strict
        } else {
            SandboxMode::BestEffort
        };

        // Collect read paths (GeoIP databases). Exclude the bare current-directory
        // entry: a Landlock PathBeneath rule on "." grants recursive read access to
        // the entire CWD subtree (e.g. all of $HOME when rustnet is launched from
        // there), which defeats the point of the read-path whitelist. The concrete
        // GeoIP locations (resources/geoip2, XDG/system dirs) stay covered.
        #[cfg(not(feature = "kubernetes"))]
        let read_paths: Vec<PathBuf> = GeoIpResolver::get_search_paths()
            .into_iter()
            .filter(|p| p.exists() && p.as_os_str() != ".")
            .collect();

        // When Kubernetes attribution is enabled, the resolver also reads pod
        // and container names from the kubelet log directories. /proc is
        // already granted below for process lookup; these need explicit read
        // access or the periodic metadata refresh would be denied once Landlock
        // applies.
        #[cfg(feature = "kubernetes")]
        let read_paths: Vec<PathBuf> = {
            let mut paths: Vec<PathBuf> = GeoIpResolver::get_search_paths()
                .into_iter()
                .filter(|p| p.exists() && p.as_os_str() != ".")
                .collect();
            if config.kubernetes_mode.enabled() {
                for dir in ["/var/log/containers", "/var/log/pods"] {
                    let pb = PathBuf::from(dir);
                    if pb.exists() {
                        paths.push(pb);
                    }
                }
            }
            paths
        };

        let mut write_paths = Vec::new();

        // Add logs directory if logging is enabled
        if matches.get_one::<String>("log-level").is_some() {
            write_paths.push(PathBuf::from("logs"));
        }

        // Add JSON log path if specified
        if let Some(json_log_path) = &config.json_log_file {
            write_paths.push(PathBuf::from(json_log_path));
        }

        // Add PCAP export paths if specified (both .pcap and .pcap.connections.jsonl)
        if let Some(pcap_path) = &config.pcap_export_file {
            write_paths.push(PathBuf::from(pcap_path));
            write_paths.push(PathBuf::from(format!("{}.connections.jsonl", pcap_path)));
        }

        if let Some(pcapng_path) = &config.pcapng_export_file {
            write_paths.push(PathBuf::from(pcapng_path));
        }

        let sandbox_config = SandboxConfig {
            mode: sandbox_mode,
            block_network: true, // RustNet is passive, doesn't need TCP
            read_paths,
            write_paths,
            drop_uid: uid_drop_target,
        };

        match apply_sandbox(&sandbox_config) {
            Ok(result) => {
                // Update UI with sandbox status
                let status_str = match result.status {
                    SandboxStatus::FullyEnforced => "Fully enforced",
                    SandboxStatus::PartiallyEnforced => "Partially enforced",
                    SandboxStatus::NotApplied => "Not applied",
                };

                app.set_sandbox_info(app::SandboxInfo {
                    status: status_str.to_string(),
                    cap_dropped: result.cap_net_raw_dropped,
                    ebpf_caps_dropped: result.ebpf_caps_dropped,
                    uid_dropped: result.uid_dropped,
                    landlock_available: result.landlock_available,
                    fs_restricted: result.landlock_fs_applied,
                    net_restricted: result.landlock_net_applied,
                    scope_restricted: result.landlock_scope_applied,
                    landlock_abi: result.landlock_effective_abi,
                    no_new_privs: result.no_new_privs,
                });
            }
            Err(e) => {
                if sandbox_mode == SandboxMode::Strict {
                    return Err(e.context("Sandbox enforcement required but failed"));
                }
                warn!("Sandbox application error (non-strict mode): {}", e);
                app.set_sandbox_info(app::SandboxInfo {
                    status: "Error".to_string(),
                    cap_dropped: false,
                    ebpf_caps_dropped: false,
                    uid_dropped: false,
                    landlock_available: false,
                    fs_restricted: false,
                    net_restricted: false,
                    scope_restricted: false,
                    landlock_abi: None,
                    no_new_privs: false,
                });
            }
        }
    }

    // Drop root privileges (macOS only). Done after process detection init
    // (capture fds are open, PKTAP is set up) and BEFORE Seatbelt, so the
    // profile does not need to allow the setuid/setgid syscalls. Compiled
    // without the macos-sandbox feature too; only the flag lookups depend on
    // the feature (the flags do not exist in non-sandbox builds).
    #[cfg(target_os = "macos")]
    let uid_dropped = {
        #[cfg(feature = "macos-sandbox")]
        let (skip, strict) = (
            matches.get_flag("no-sandbox"),
            matches.get_flag("sandbox-strict"),
        );
        #[cfg(not(feature = "macos-sandbox"))]
        let (skip, strict) = (false, false);

        match uid_drop_target {
            Some(target) if !skip => match network::platform::privdrop::drop_to(target) {
                Ok(()) => {
                    info!(
                        "Dropped root privileges to uid {} gid {} (verified); lsof-fallback \
                         process attribution is now limited to that user's processes (PKTAP \
                         attribution unaffected)",
                        target.uid, target.gid
                    );
                    true
                }
                Err(e) => {
                    if strict {
                        return Err(e.context("Strict mode requires the root uid drop to succeed"));
                    }
                    warn!("Failed to drop root uid/gid: {}", e);
                    false
                }
            },
            Some(_) => {
                info!("Root uid drop skipped (--no-sandbox)");
                false
            }
            None => false,
        }
    };
    #[cfg(all(target_os = "macos", not(feature = "macos-sandbox")))]
    let _ = uid_dropped;

    // Drop root privileges (FreeBSD only). Done after process detection init,
    // when the BPF capture fds are open and nothing needs root anymore. There
    // is no sandbox on FreeBSD yet (Capsicum is planned), so until then this
    // is the primary containment.
    #[cfg(target_os = "freebsd")]
    if let Some(target) = uid_drop_target {
        match network::platform::privdrop::drop_to(target) {
            Ok(()) => info!(
                "Dropped root privileges to uid {} gid {} (verified); sockstat process \
                 attribution is now limited to that user's processes",
                target.uid, target.gid
            ),
            Err(e) => warn!("Failed to drop root uid/gid: {}", e),
        }
    }

    // Apply Seatbelt sandbox (macOS only)
    // This must be done AFTER app.start() because:
    // - Packet capture handles need to be opened first (BPF/PKTAP fds survive the sandbox)
    // - Log files need to be created first
    #[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
    {
        use network::platform::sandbox::{
            SandboxConfig, SandboxMode, SandboxStatus, apply_sandbox,
        };

        let sandbox_mode = if matches.get_flag("no-sandbox") {
            SandboxMode::Disabled
        } else if matches.get_flag("sandbox-strict") {
            SandboxMode::Strict
        } else {
            SandboxMode::BestEffort
        };

        let log_dir = if matches.get_one::<String>("log-level").is_some() {
            Some("logs".to_string())
        } else {
            None
        };

        // Collect GeoIP paths that may need read access through the sandbox.
        // User-specified paths take priority; otherwise include auto-discovery
        // search paths so the file-read deny on /Users doesn't block them.
        let geoip_paths: Vec<String> = {
            use network::geoip::GeoIpResolver;
            let mut paths = Vec::new();
            if let Some(ref p) = config.geoip_country_path {
                paths.push(p.clone());
            }
            if let Some(ref p) = config.geoip_asn_path {
                paths.push(p.clone());
            }
            if let Some(ref p) = config.geoip_city_path {
                paths.push(p.clone());
            }
            if paths.is_empty() && !config.disable_geoip {
                // Use auto-discovery search paths (directories, not individual files)
                paths.extend(
                    GeoIpResolver::get_search_paths()
                        .into_iter()
                        .filter(|p| p.exists())
                        .map(|p| p.to_string_lossy().into_owned()),
                );
            }
            paths
        };

        // rustnetec: Read --sandbox-allow-network for data upload host (R3, T1.8)
        let allowed_network_host = matches.get_one::<String>("sandbox-allow-network").cloned();

        // rustnetec: W-修复 — SQLite 数据目录需 sandbox 读写放行。
        // Seatbelt 默认 deny /Users 子路径读写,而 SqliteSink(/query、/processes)
        // 在 sandbox 之后打开 data.db → EPERM/CANTOPEN。传入 data_dir 加入白名单。
        let data_dir = telemetry::paths::data_dir().ok().map(|p| p.to_string_lossy().into_owned());

        // rustnetec: 外网可达率探测目标，加入 Seatbelt 出站 TCP 白名单。
        // 从持久化配置读取（与探测线程同源），沙箱在初始化前一次性生成。
        let reachability_targets = rustnet_monitor::config::PersistentConfig::load()
            .unwrap_or_default()
            .reachability_targets;

        let sandbox_config = SandboxConfig {
            mode: sandbox_mode,
            block_network: true,  // RustNet is passive, doesn't need TCP
            allowed_network_host, // rustnetec: specific host allow for data upload
            log_dir,
            json_log_path: config.json_log_file,
            pcap_export_path: config.pcap_export_file,
            pcapng_export_path: config.pcapng_export_file,
            geoip_paths,
            data_dir, // rustnetec: W-修复 — SQLite 数据目录白名单
            reachability_targets, // rustnetec: 可达率探测目标白名单
        };

        match apply_sandbox(&sandbox_config) {
            Ok(result) => {
                let status_str = match result.status {
                    SandboxStatus::FullyEnforced => {
                        info!("Seatbelt sandbox fully enforced: {}", result.message);
                        "Fully enforced"
                    }
                    SandboxStatus::NotApplied => {
                        warn!("Seatbelt sandbox not applied: {}", result.message);
                        "Not applied"
                    }
                };

                app.set_sandbox_info(app::SandboxInfo {
                    status: status_str.to_string(),
                    seatbelt_applied: result.seatbelt_applied,
                    fs_restricted: result.fs_restricted,
                    net_restricted: result.net_blocked,
                    uid_dropped,
                });
            }
            Err(e) => {
                if sandbox_mode == SandboxMode::Strict {
                    return Err(e.context("Seatbelt sandbox enforcement required but failed"));
                }
                info!("Seatbelt sandbox error (non-strict mode): {}", e);
                app.set_sandbox_info(app::SandboxInfo {
                    status: "Error".to_string(),
                    seatbelt_applied: false,
                    fs_restricted: false,
                    net_restricted: false,
                    uid_dropped,
                });
            }
        }
    }

    // Apply restricted token sandbox (Windows only)
    // This must be done AFTER app.start() because:
    // - Npcap handles need to be opened first
    // - Log files need to be created first
    #[cfg(target_os = "windows")]
    {
        use network::platform::sandbox::{
            SandboxConfig, SandboxMode, SandboxStatus, apply_sandbox,
        };

        let sandbox_mode = if matches.get_flag("no-sandbox") {
            SandboxMode::Disabled
        } else if matches.get_flag("sandbox-strict") {
            SandboxMode::Strict
        } else {
            SandboxMode::BestEffort
        };

        let sandbox_config = SandboxConfig { mode: sandbox_mode };

        match apply_sandbox(&sandbox_config) {
            Ok(result) => {
                let status_str = match result.status {
                    SandboxStatus::FullyEnforced => {
                        info!("Windows sandbox fully enforced: {}", result.message);
                        "Fully enforced"
                    }
                    SandboxStatus::PartiallyEnforced => {
                        warn!("Windows sandbox partially enforced: {}", result.message);
                        "Partially enforced"
                    }
                    SandboxStatus::NotApplied => {
                        warn!("Windows sandbox not applied: {}", result.message);
                        "Not applied"
                    }
                };

                app.set_sandbox_info(app::SandboxInfo {
                    status: status_str.to_string(),
                    privileges_removed: result.privileges_removed,
                    privileges_removed_count: result.privileges_removed_count,
                    job_object_applied: result.job_object_applied,
                });
            }
            Err(e) => {
                if sandbox_mode == SandboxMode::Strict {
                    return Err(e.context("Windows sandbox enforcement required but failed"));
                }
                warn!("Windows sandbox error (non-strict mode): {}", e);
                app.set_sandbox_info(app::SandboxInfo {
                    status: "Error".to_string(),
                    privileges_removed: false,
                    privileges_removed_count: 0,
                    job_object_applied: false,
                });
            }
        }
    }

    // rustnetec: W-修复 — SqliteSink 必须在 start_workers 之前挂到 App。
    // start_packet_processor / start_cleanup_thread 在 spawn 时克隆
    // self.sqlite_sink;若在 start_workers 之后才 set_sqlite_sink,线程
    // 持有的是 None → log_connection_event 永不落库 → 连接表(/query)与
    // 进程活动(/processes)始终无数据。此处 daemon/tray 先建 sink 再启线程。
    if daemon_mode || tray_mode {
        let db_path = resolve_db_path(&matches);
        let runtime_config = std::sync::Arc::new(std::sync::RwLock::new(
            rustnet_monitor::config::RuntimeConfig::from_persistent(
                &rustnet_monitor::config::PersistentConfig::load().unwrap_or_default(),
            ),
        ));
        match telemetry::db::SqliteSink::new(Some(db_path), runtime_config) {
            Ok(sink) => {
                app.set_sqlite_sink(std::sync::Arc::new(sink));
                info!("SqliteSink attached — connection events will be persisted to SQLite");
            }
            Err(e) => warn!(
                "Failed to create SqliteSink: {e:#}; connection events will not be persisted to SQLite"
            ),
        }
    }

    // Now that the sandbox has been applied on the main thread, start the worker
    // threads (DPI packet processors, enrichment, snapshot, cleanup, collectors).
    // On Linux these inherit the Landlock domain and the dropped capabilities, so
    // a compromise in a DPI parser is contained even when running as root.
    app.start_workers()?;

    // rustnetec: Branch on run mode
    if daemon_mode || tray_mode {
        // rustnetec: W-fix — write daemon.pid so the tray helper can SIGTERM
        // the daemon as a fallback when POST /admin/shutdown can't reach it
        // (e.g. the single-threaded HTTP server was wedged before this fix,
        // or a request is stuck). Best-effort; failure does not stop startup.
        if let Ok(dir) = telemetry::paths::data_dir() {
            let pid_path = dir.join("daemon.pid");
            if let Err(e) = std::fs::write(&pid_path, std::process::id().to_string()) {
                warn!("Failed to write daemon.pid at {}: {e}", pid_path.display());
            }
        }

        // rustnetec: http_state lives in the outer scope so the tray launcher
        // (T3.3) can call issue_bootstrap_guid on it from run_daemon_loop.
        // Wrapped in Option because daemon mode (no tray) does not need it,
        // and the launcher cfg-gates out on FreeBSD / without the tray feature.
        #[cfg(all(feature = "tray", not(target_os = "freebsd")))]
        let http_state: Option<std::sync::Arc<telemetry::http::HttpState>>;

        // rustnetec: Start HTTP server in daemon/tray mode (R5, T1.4)
        {
            let http_port = matches
                .get_one::<u16>("http-port")
                .copied()
                .unwrap_or(19811);
            let db_path = resolve_db_path(&matches);
            let http_token = {
                // rustnetec: 优先用 sandbox 之前缓存/落盘的 token。Seatbelt
                // `deny file-read*` 使此处的 load() 失败 → default → 重新生成
                // 新 token，导致 daemon 内存 token 与 config.yml 落盘 token
                // 不一致，`query --live` 用落盘 token 请求会 401。
                if let Some(t) = http_token_early {
                    t
                } else {
                    rustnet_monitor::config::PersistentConfig::load()
                        .unwrap_or_default()
                        .http_token
                        .unwrap_or_default()
                }
            };

            // rustnetec: 无状态 session 签名密钥——从持久化 machine_id/
            // http_token 派生（config.yml 不丢则重启后旧 cookie 依然有效），
            // 修复「托盘打开 OK、浏览器刷新报未授权」问题。
            let session_key: [u8; 32] = {
                let pc = rustnet_monitor::config::PersistentConfig::load()
                    .unwrap_or_default();
                let seed = format!(
                    "{}:{}",
                    pc.machine_id.as_deref().unwrap_or(""),
                    pc.http_token.as_deref().unwrap_or("")
                );
                *blake3::hash(seed.as_bytes()).as_bytes()
            };

            let state = std::sync::Arc::new(telemetry::http::HttpState {
                db_path: db_path.clone(),
                http_token,
                should_stop: app.should_stop_handle(),
                // rustnetec: one-time bootstrap code auth (T3.3, R6)
                pending_guids: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                session_key: std::sync::Arc::new(session_key),
                // rustnetec: HTTP listen port for launcher URL (T3.5, R6)
                http_port,
                // rustnetec: daemon→tray live snapshot bridge (T3.6.7, R6)
                live_snapshot: std::sync::Arc::new(std::sync::RwLock::new(serde_json::json!({}))),
                // rustnetec: G2 — 运行时配置共享态(R7 双轨制)。
                // PUT /config 落盘后经 apply_hot_update/apply_restart_items 写入此锁。
                runtime_config: std::sync::Arc::new(std::sync::RwLock::new(
                    rustnet_monitor::config::RuntimeConfig::from_persistent(
                        &rustnet_monitor::config::PersistentConfig::load().unwrap_or_default(),
                    ),
                )),
            });

            if let Err(e) = telemetry::http::start_http_server(http_port, state.clone()) {
                warn!("Failed to start HTTP server: {}", e);
                #[cfg(all(feature = "tray", not(target_os = "freebsd")))]
                {
                    http_state = None;
                }
            } else {
                info!("HTTP server started on 127.0.0.1:{}", http_port);
                #[cfg(all(feature = "tray", not(target_os = "freebsd")))]
                {
                    http_state = Some(state);
                }
            }

            // rustnetec: Start UploadSink in daemon/tray mode (R3, T2.6)
            // 仅当 server_url 已配置时启动上报线程; 否则跳过 (不打告警, 静默)。
            let pc = rustnet_monitor::config::PersistentConfig::load().unwrap_or_default();
            let runtime_config = std::sync::Arc::new(std::sync::RwLock::new(
                rustnet_monitor::config::RuntimeConfig::from_persistent(&pc),
            ));

            // rustnetec: W-修复 — SqliteSink 已在 start_workers 之前创建并挂到 App
            // (见上方 start_workers 前的 sink 创建块);线程 spawn 时克隆的是
            // Some(sink),落库随 log_connection_event 自动进行,此处不再重复创建。

            let server_url = runtime_config.read().unwrap().server_url.clone();
            if server_url.is_some() {
                let identity = {
                    let pc2 = rustnet_monitor::config::PersistentConfig::load().unwrap_or_default();
                    let (id, _) = telemetry::identity::HostIdentity::initialize(
                        pc2.username.as_deref(),
                        pc2.user_id,
                        pc2.machine_id.as_deref(),
                    );
                    id
                };
                let upload_sink =
                    telemetry::upload::UploadSink::new(db_path.clone(), runtime_config, identity);
                match upload_sink.spawn(app.should_stop_handle()) {
                    Ok(handle) => {
                        info!("Upload thread spawned");
                        // Detach: handle 析构不会终止线程, 线程随 should_stop 退出。
                        // 保留句柄到 daemon_loop 退出时由其 join (此处 detach)。
                        std::mem::forget(handle);
                    }
                    Err(e) => warn!("Failed to spawn upload thread: {}", e),
                }
            } else {
                info!("Upload thread skipped (server_url not configured)");
            }

            // rustnetec: 外网可达率探测线程（TCP connect 多目标，每 30s）。
            // 失败只 warn，不影响 daemon 主流程。
            if let Err(e) = telemetry::reachability::start_reachability_probe(
                db_path,
                app.should_stop_handle(),
            ) {
                warn!("Failed to start reachability probe thread: {e}");
            } else {
                info!("Reachability probe thread started");
            }
        }

        // Daemon mode: no TUI, just wait for shutdown signal
        // rustnetec: http_state passed in so tray launcher can issue bootstrap guids (T3.3)
        #[cfg(all(feature = "tray", not(target_os = "freebsd")))]
        run_daemon_loop(&app, tray_mode, http_state);
        #[cfg(not(all(feature = "tray", not(target_os = "freebsd"))))]
        run_daemon_loop(&app, tray_mode, None);
    } else {
        // TUI mode: run the interactive UI loop
        let res = run_ui_loop(terminal.as_mut().unwrap(), &app);

        if let Err(err) = res {
            error!("Application error: {}", err);
            println!("Error: {}", err);
        }
    }

    // Cleanup
    app.stop();
    if let Some(ref mut term) = terminal {
        ui::restore_terminal(term)?;
    }
    // rustnetec: 删除 TUI 单实例 PID 文件（方案 B）并恢复终端标题。
    if !daemon_mode {
        if let Ok(dir) = telemetry::paths::data_dir() {
            let _ = std::fs::remove_file(dir.join("tui.pid"));
        }
    }
    // rustnetec: W-fix — 删除 daemon.pid，避免托盘 helper 误向已退出的 PID
    // 发信号。daemon/tray 模式下写过；TUI 模式下文件不存在，remove 静默失败。
    if let Ok(dir) = telemetry::paths::data_dir() {
        let _ = std::fs::remove_file(dir.join("daemon.pid"));
    }

    info!("RustNet Monitor shutting down");
    Ok(())
}

fn setup_logging(level: LevelFilter) -> Result<()> {
    // The log directory is resolved relative to the current working directory.
    // rustnet typically runs as root, so a pre-planted symlink at `logs/` (e.g.
    // `logs -> /etc`) would let an attacker who controls the launch directory
    // redirect root-owned writes to an arbitrary location. Refuse to use it if
    // it is a symlink (symlink_metadata does not follow the link).
    let log_dir = Path::new("logs");
    #[cfg(unix)]
    if let Ok(meta) = fs::symlink_metadata(log_dir)
        && meta.file_type().is_symlink()
    {
        anyhow::bail!("refusing to use log directory 'logs': it is a symlink");
    }

    if !log_dir.exists() {
        fs::create_dir_all(log_dir)?;
        // Restrict the directory to the owner: the diagnostic log can contain
        // connection metadata and (at debug/trace) DNS/SNI hostnames, and rustnet
        // typically runs as root, so it must not be world-readable. Mirrors the
        // 0o600 treatment of the JSON/PCAP outputs.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = fs::set_permissions(log_dir, fs::Permissions::from_mode(0o700)) {
                warn!("Failed to set logs directory permissions: {}", e);
            }
        }
    }

    // Create timestamped log file name
    let timestamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S");
    let log_file_path = log_dir.join(format!("rustnet_{}.log", timestamp));

    // On Unix, open with O_NOFOLLOW so a symlink pre-planted at the (predictable,
    // timestamped) path cannot redirect the write, and set the 0o600 mode at
    // creation time to avoid a create-then-chmod window where the file is briefly
    // world-readable.
    #[cfg(unix)]
    let log_file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&log_file_path)?
    };
    #[cfg(not(unix))]
    let log_file = fs::File::create(&log_file_path)?;

    // Enable the `target` field on every log line so each entry carries
    // the originating module (e.g. `network::dpi::dns`). Combined with
    // the startup-banner lines below, this addresses #310 — users now
    // see both the program identity (name/version/pid) at the top of
    // the file and which subsystem emitted each subsequent line.
    let config = ConfigBuilder::new()
        .set_target_level(LevelFilter::Error)
        .build();

    WriteLogger::init(level, config, log_file)?;

    // Startup banner — one identifying header so a user grepping a
    // long-lived log file can immediately see which binary, which
    // version, and which pid produced these lines. The `pkg_name` is
    // the cargo package name (`rustnet-monitor`), not `argv[0]`, so it
    // stays correct when the binary is renamed or symlinked.
    info!(
        "{} v{} starting (pid {})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        std::process::id()
    );

    Ok(())
}

/// rustnetec: T1.11 修复 — 自启模式默认日志: 追加写入
/// `<data_dir>/autostart.log`(Info 级)。带 `--autostart` 且未显式指定
/// `--log-level` 时由 [`run`] 调用, 使开机自启的启动/运行轨迹可查。
///
/// 与 `setup_logging` 的差异: 固定路径、追加模式(保留多次自启历史)、
/// 失败不致命(自启日志只是诊断辅助, 不影响主流程)。
fn setup_autostart_log() -> Result<()> {
    let dir = telemetry::paths::data_dir()?;
    fs::create_dir_all(&dir)?;
    let log_path = dir.join("autostart.log");

    // On Unix, open with O_NOFOLLOW + 0o600 (mirrors setup_logging) so a
    // pre-planted symlink at the predictable path cannot redirect writes and
    // the file is not world-readable (it may contain connection metadata).
    #[cfg(unix)]
    let log_file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&log_path)?
    };
    #[cfg(not(unix))]
    let log_file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(&log_path)?;

    let config = ConfigBuilder::new()
        .set_target_level(LevelFilter::Error)
        .build();
    WriteLogger::init(LevelFilter::Info, config, log_file)?;

    info!(
        "{} v{} autostart (pid {})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        std::process::id()
    );
    Ok(())
}

/// rustnetec: T1.11 修复 — 追加一行错误诊断到 `<data_dir>/autostart.log`。
///
/// 由 [`main`] 包装在自启进程整体失败(返回 Err)时兜底调用, 保证即使
/// 日志系统尚未初始化(如依赖检查失败在 `setup_autostart_log` 之前)也能
/// 留下可排查记录。失败时静默放弃(自启日志只是诊断辅助)。
fn append_autostart_error(message: &str) {
    use std::io::Write;
    let log_path = match telemetry::paths::data_dir() {
        Ok(dir) => dir.join("autostart.log"),
        Err(e) => {
            eprintln!("autostart error logging skipped (no data dir): {e}");
            return;
        }
    };
    if let Some(parent) = log_path.parent()
        && let Err(e) = fs::create_dir_all(parent)
    {
        eprintln!("autostart error logging skipped (create dir): {e}");
        return;
    }

    #[cfg(unix)]
    let open_result = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&log_path)
    };
    #[cfg(not(unix))]
    let open_result = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(&log_path);

    let mut file = match open_result {
        Ok(f) => f,
        Err(e) => {
            eprintln!("autostart error logging skipped (open): {e}");
            return;
        }
    };
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let _ = writeln!(file, "[{timestamp}] {message}");
}

/// Hand an output file over to the uid-drop target.
///
/// Retained descriptors remain usable regardless of path traversal, but the
/// resulting file should still belong to the runtime identity. Best-effort:
/// failure does not prevent the privilege drop.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn chown_to_uid_drop_target(
    file: &fs::File,
    target: Option<network::platform::privdrop::DropTarget>,
    label: &str,
    path: &str,
) {
    if let Some(target) = target
        && let Err(e) = network::platform::privdrop::chown_to_target(file, target)
    {
        warn!(
            "Failed to chown {} file '{}' to uid {}: {} (the file may not be writable after the root uid drop)",
            label, path, target.uid, e
        );
    }
}

fn precreate_private_file(path: &str) -> io::Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(path)
    }

    #[cfg(not(unix))]
    {
        fs::File::create(path)
    }
}

/// Open an append-only private output before privileges are reduced.
///
/// Unlike [`precreate_private_file`], this preserves existing contents because
/// `--json-log` has append semantics.
fn open_private_append_file(path: &str) -> io::Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(path)
    }

    #[cfg(not(unix))]
    {
        fs::OpenOptions::new().create(true).append(true).open(path)
    }
}

#[cfg(all(test, unix))]
mod output_file_tests {
    use super::open_private_append_file;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rustnet-output-test-{}-{}",
                std::process::id(),
                tag
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            ScratchDir(dir)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn creates_file_with_0600_permissions() {
        let dir = ScratchDir::new("perms");
        let path = dir.path("events.log");

        let file =
            open_private_append_file(path.to_str().unwrap()).expect("fresh open should succeed");
        let mode = file.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "new output must be created mode 0o600");
    }

    #[test]
    fn appends_rather_than_truncates() {
        let dir = ScratchDir::new("append");
        let path = dir.path("events.log");
        let path = path.to_str().unwrap();

        writeln!(open_private_append_file(path).unwrap(), "line1").unwrap();
        writeln!(open_private_append_file(path).unwrap(), "line2").unwrap();

        assert_eq!(std::fs::read_to_string(path).unwrap(), "line1\nline2\n");
    }

    #[test]
    fn retained_descriptor_survives_inaccessible_parent() {
        let dir = ScratchDir::new("retained");
        let path = dir.path("events.log");
        let mut file = open_private_append_file(path.to_str().unwrap()).unwrap();

        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o000)).unwrap();
        writeln!(file, "still writable").unwrap();
        file.sync_all().unwrap();
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(std::fs::read_to_string(path).unwrap(), "still writable\n");
    }

    #[test]
    fn refuses_symlinked_path() {
        let dir = ScratchDir::new("symlink");
        let target = dir.path("real_target.log");
        let link = dir.path("evil.log");
        std::fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = open_private_append_file(link.to_str().unwrap())
            .expect_err("O_NOFOLLOW must refuse a symlinked path");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "expected ELOOP from O_NOFOLLOW, got: {err}"
        );
        assert!(std::fs::read(&target).unwrap().is_empty());
    }
}

/// Sort connections based on the specified column and direction
use ui::{clear_all_with_confirmation, copy_to_clipboard, sort_connections};

/// rustnetec: 安装 LaunchDaemon 成功后重启托盘应用（T4.2 永久授权配套）。
///
/// 用**完整 argv**（`std::env::args().skip(1)`）重新 spawn 当前可执行文件，
/// 保证任何启动方式（双击 app / 终端命令）重启后参数一致；然后提示并
/// 退出当前进程。重启后 `run_tray_helper` 检测到 LaunchDaemon 已装，
/// 不再弹窗，直接连接 launchd 托管的 daemon。
/// `-> !`：spawn 后必然退出，不会返回。
#[cfg(all(feature = "tray", not(target_os = "freebsd")))]
fn restart_tray_helper() -> ! {
    let exe = std::env::current_exe().expect("failed to resolve current executable");
    let args: Vec<String> = std::env::args().skip(1).collect(); // 完整 argv（跳过 argv[0]）
    info!("Restarting tray helper after LaunchDaemon install: {exe:?} {args:?}");
    println!("永久授权安装成功，正在重启应用…");
    let _ = std::process::Command::new(&exe).args(&args).spawn();
    std::process::exit(0);
}

/// rustnetec: T3.6.7 — tray helper entry point (A topology: tray spawns the
/// daemon child and runs the pure GUI). Executes as `rustnet --tray` without
/// `--daemon`: probes/spawns the daemon, performs the HTTP handshake, builds
/// the tray controller, then drives the platform event loop on the main
/// thread while a consumer thread translates menu clicks into actions.
/// On exit the daemon child (if we spawned it) is reaped.
#[cfg(all(feature = "tray", not(target_os = "freebsd")))]
fn run_tray_helper(matches: &clap::ArgMatches) -> Result<()> {
    let http_port = matches
        .get_one::<u16>("http-port")
        .copied()
        .unwrap_or(19811);
    let daemon_base = format!("http://127.0.0.1:{http_port}");

    // rustnetec: 启动引导（T4.2 永久授权配套）——macOS 下若未安装
    // LaunchDaemon，弹窗询问用户是否现在安装永久授权；用户确认后执行
    // 一次性系统授权安装，成功后重启应用（重启后检测到已装，不再弹窗）。
    // 用户选「暂不」或安装失败 → 继续原流程（每启动一次弹授权窗口）。
    #[cfg(target_os = "macos")]
    if !telemetry::launchdaemon::is_installed() && ui::prompt_launchdaemon_install() {
        match telemetry::launchdaemon::install(http_port) {
            Ok(()) => restart_tray_helper(), // 安装成功 → 重启应用
            Err(e) => {
                warn!("LaunchDaemon install failed, continuing with per-launch auth: {e}");
                eprintln!("LaunchDaemon install failed: {e}");
            }
        }
    }

    // --- HTTP handshake: is a daemon already listening? ---
    let daemon_up = daemon_port_open(http_port);

    // --- Spawn the daemon child if it is not running ---
    // rustnetec: T3.6.11 — shared handle so the macOS command thread can reap
    // the daemon BEFORE NSApp.terminate kills the helper process (terminate
    // would otherwise skip the end-of-function reaping, leaking the daemon).
    let daemon_child = std::sync::Arc::new(std::sync::Mutex::new(None::<std::process::Child>));
    // rustnetec: T4.2 — 已安装 LaunchDaemon 时，daemon 由 launchd 以 root
    // 托管（RunAtLoad 开机自启 + KeepAlive 崩溃重启），托盘无需 spawn 也
    // 拿不到 child 句柄；直接等 HTTP 就绪即可。未安装时才走下面的
    // spawn / osascript 弹窗路径。
    #[cfg(target_os = "macos")]
    let launchdaemon_managed = telemetry::launchdaemon::is_installed();
    #[cfg(not(target_os = "macos"))]
    let launchdaemon_managed = false;

    if !daemon_up && !launchdaemon_managed {
        let exe = std::env::current_exe()?;
        info!(
            "Tray helper: daemon not running — spawning child {:?} --daemon --http-port {http_port}",
            exe
        );
        // rustnetec: T4.2 — macOS 下若无 BPF 抓包权限，通过系统授权窗口
        // （osascript `do shell script ... with administrator privileges`）
        // 以 root 启动 daemon，让抓包真正可用，而不是降级 process-only。
        // 有权限时保持普通 spawn。
        #[cfg(target_os = "macos")]
        let _spawned_privately = {
            let has_bpf = network::privileges::check_packet_capture_privileges()
                .map(|s| s.has_privileges)
                .unwrap_or(false);
            if has_bpf {
                let child = std::process::Command::new(&exe)
                    .arg("--daemon")
                    .arg("--http-port")
                    .arg(http_port.to_string())
                    .env("RUSTNETEC_TRAY_DAEMON", "1")
                    .spawn()
                    .map_err(|e| anyhow::anyhow!("failed to spawn daemon child: {e}"))?;
                *daemon_child.lock().unwrap() = Some(child);
                true
            } else {
                // 弹系统授权窗口提权启动 daemon。约束：
                // 1. 命令被 AppleScript 的 do shell script "..." 包裹，内部
                //    不能出现 `"`（会提前终止字符串 → -2740），路径一律单引号。
                // 2. osascript 提权不设 SUDO_UID/SUDO_GID/HOME，而 daemon 的
                //    resolve_drop_target() 依赖 SUDO_UID/GID 才能正确降权回
                //    原用户（否则降为 nobody 并 chown 用户目录），HOME 决定
                //    config.yml/token 路径——三者必须显式传入。
                // 3. 绝不能加 `nohup`：osascript 授权会话无控制终端，macOS 的
                //    nohup 会报 "can't detach from console: Inappropriate ioctl
                //    for device" 并**直接退出**，env/daemon 根本不会执行（实测
                //    日志只有两行 nohup 报错、无 daemon 输出）。用 `&` 后台化
                //    + `</dev/null` 断开 stdin + 输出重定向即可——非交互 sh
                //    退出时不会向后台作业发 SIGHUP，daemon 保持存活。
                let uid = unsafe { libc::getuid() };
                let gid = unsafe { libc::getgid() };
                let home = std::env::var("HOME").unwrap_or_default();
                let exe_q = exe.display().to_string().replace('\'', "'\\''");
                let home_q = home.replace('\'', "'\\''");
                let log = format!("/tmp/rustnetec-daemon-{http_port}.log");
                let script = format!(
                    "do shell script \"env SUDO_UID={uid} SUDO_GID={gid} \
                     HOME='{home_q}' RUSTNETEC_TRAY_DAEMON=1 '{exe_q}' --daemon \
                     --http-port {http_port} < /dev/null >> '{log}' 2>&1 &\" \
                     with administrator privileges"
                );
                info!("Tray helper: no BPF access — launching daemon via system auth dialog");
                let _ = std::process::Command::new("osascript")
                    .arg("-e")
                    .arg(&script)
                    .spawn()
                    .map_err(|e| anyhow::anyhow!("failed to spawn auth dialog: {e}"))?;
                // 提权路径拿不到 daemon 子进程句柄（osascript 立即返回，
                // daemon 是 nohup 后台孙进程）；daemon_child 保持 None，
                // 退出时靠 POST /admin/shutdown 优雅回收（见 Quit 分支）。
                false
            }
        };
        // rustnetec: T4.2 — 非 macOS 保持原路径。
        #[cfg(not(target_os = "macos"))]
        let _spawned_privately = {
            let mut daemon_cmd = std::process::Command::new(&exe);
            daemon_cmd
                .arg("--daemon")
                .arg("--http-port")
                .arg(http_port.to_string())
                .env("RUSTNETEC_TRAY_DAEMON", "1");
            // rustnetec: 修复 — 不再用 CREATE_NO_WINDOW: --autostart 的托盘
            // helper 已 FreeConsole, 父进程无控制台时带 CREATE_NO_WINDOW spawn
            // 会返回 ERROR_NOT_SUPPORTED (os error 50), 导致 daemon 子进程
            // 启动失败(autostart.log 中 "failed to spawn daemon child")。
            // 改为 Windows 下给 daemon 追加 --autostart: daemon 自身 FreeConsole
            // 隐藏黑窗(父进程无控制台时子进程本就无控制台), 并自动获得软权限
            // 检查与 autostart.log 记录, 与 HKCU Run 自启注册行为一致。
            #[cfg(target_os = "windows")]
            daemon_cmd.arg("--autostart");
            let child = daemon_cmd
                .spawn()
                .map_err(|e| anyhow::anyhow!("failed to spawn daemon child: {e}"))?;
            *daemon_child.lock().unwrap() = Some(child);
            false
        };
        // Wait for the daemon HTTP server to come up (up to ~30s; the auth
        // dialog path needs the user to type the password first).
        let mut ready = false;
        for _ in 0..300 {
            if daemon_port_open(http_port) {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if !ready {
            warn!("Tray helper: daemon child did not become HTTP-ready in time");
        }
    } else if !daemon_up {
        // rustnetec: T4.2 — LaunchDaemon 已安装但端口未起。注意 RunAtLoad
        // 只在系统加载服务时触发一次，托盘退出停掉 daemon 后 launchd 不会
        // 自动再拉起（KeepAlive=false 也不复活）——所以这里必须主动
        // `launchctl kickstart` 拉起 launchd 托管的 daemon，再等待 HTTP 就绪。
        // kickstart 对已加载的 system 服务无需 root（实测普通用户可行）。
        info!("Tray helper: LaunchDaemon installed — kickstarting launchd daemon");
        let _ = std::process::Command::new("launchctl")
            .args(["kickstart", "system/com.rustnetec.daemon"])
            .status();
        let mut ready = false;
        for _ in 0..300 {
            if daemon_port_open(http_port) {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if !ready {
            warn!("Tray helper: launchd-managed daemon did not become HTTP-ready in time");
        }
    } else {
        info!("Tray helper: connecting to existing daemon at {daemon_base}");
    }

    // --- Build the pure-GUI tray controller (no App, no capture) ---
    let mut tray_controller = match ui::TrayController::new(
        include_bytes!("../resources/packaging/linux/graphics/rustnetec.png"),
        256,
        256,
        "Rustnetec",
    ) {
        Ok(ctrl) => ctrl,
        Err(e) => {
            warn!("Failed to create system tray icon: {e}; continuing headless");
            eprintln!("Warning: failed to create system tray icon: {e}; continuing headless");
            // Headless fallback: keep running so the daemon we spawned stays up.
            // rustnetec: T3.6.11 — daemon_child is a shared Arc<Mutex<Option<Child>>>.
            if let Some(mut child) = daemon_child.lock().unwrap().take() {
                let _ = child.wait();
            }
            return Ok(());
        }
    };
    let pc = rustnet_monitor::config::PersistentConfig::load().unwrap_or_default();
    tray_controller.set_remote_enabled(pc.server_url.is_some());

    // rustnetec: Windows 双击启动时自动打开 TUI 终端（单实例，
    // open_terminal_monitor 会复用已有 TUI 窗口）。TUI 是独立进程，
    // 用户关闭 TUI 窗口不影响托盘与 daemon 继续运行；托盘菜单
    // 「打开终端监控」随时可再次拉起。
    #[cfg(all(feature = "tray", target_os = "windows"))]
    if launched_by_double_click() {
        ui::open_terminal_monitor();
    }

    // --- macOS: initialize NSApplication and run the blocking Cocoa event
    //     loop (T3.6.8). AppKit only dispatches menu clicks/tracking events
    //     while the main thread is inside NSApp.run() — the old 50ms
    //     CFRunLoopRunInMode polling left the menu dead (T3.6.3-T3.6.6). Translated
    //     commands are drained on a worker thread (the mpsc receiver is Send;
    //     TrayController itself is not), and a CFRunLoopTimer refreshes the
    //     status line on the main thread. Non-macOS keeps the simple loop.
    #[cfg(target_os = "macos")]
    {
        use objc2::MainThreadMarker;
        use objc2_app_kit::NSApp;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let mtm = MainThreadMarker::new().expect("tray helper runs on the main thread");
        let ns_app = NSApp(mtm);
        // Keep a raw pointer for the timer callback / quit path; the Retained
        // handle below keeps the instance alive for the whole helper.
        let ns_app_ptr: *const _ = &*ns_app;

        // --- Take the command receiver out of the controller (Send) and run
        //     a worker thread that executes menu actions. ---
        let cmd_rx = tray_controller
            .take_cmd_rx()
            .expect("tray command receiver must exist after construction");
        let quit_flag = Arc::new(AtomicBool::new(false));
        let qf = Arc::clone(&quit_flag);
        let daemon_base_cmd = daemon_base.clone();
        // rustnetec: T3.6.11 — clone the shared daemon handle so this worker
        // can reap the daemon child BEFORE NSApp.terminate ends the process.
        let daemon_child_cmd = std::sync::Arc::clone(&daemon_child);
        std::thread::Builder::new()
            .name("tray-command".to_string())
            .spawn(move || {
                use ui::TrayCommand as Cmd;
                loop {
                    if qf.load(Ordering::Relaxed) {
                        break;
                    }
                    match cmd_rx.try_recv() {
                        Ok(Cmd::Quit) => {
                            info!("Tray menu: Quit selected — shutting down");
                            // rustnetec: 退出托盘前检测前台 TUI，询问是否一起关闭
                            // （用户确认后关闭其 Terminal 窗口，TUI 进程随之退出）。
                            ui::close_tui_if_confirmed();
                            // rustnetec: T3.6.11 — reap the daemon child here,
                            // BEFORE setting qf (the timer callback then calls
                            // NSApp.terminate, which would otherwise skip the
                            // end-of-function reaping and leak the daemon).
                            if let Some(mut child) = daemon_child_cmd.lock().unwrap().take() {
                                info!("Tray helper: stopping daemon child");
                                let _ = child.kill();
                                let _ = child.wait();
                            } else if daemon_port_open(http_port) {
                                // rustnetec: 托盘退出时，无论 daemon 是弹窗
                                // 启动还是 LaunchDaemon 托管，都随托盘一起退出
                                // （HTTP shutdown）。KeepAlive=false，daemon
                                // 退出后 launchd 不会复活它。
                                info!(
                                    "Tray helper: stopping daemon via HTTP (tray quit)"
                                );
                                stop_daemon_via_http(&daemon_base_cmd);
                            }
                            qf.store(true, Ordering::Relaxed);
                            break;
                        }
                        Ok(Cmd::TogglePause) => {
                            info!(
                                "Tray menu: TogglePause selected (pause/resume not yet implemented)"
                            );
                        }
                        Ok(Cmd::OpenTerminal) => {
                            ui::open_terminal_monitor();
                        }
                        Ok(Cmd::OpenLocalPanel) => {
                            // rustnetec: T3.6.9 — bootstrap-handshake URL so the
                            // browser gets a session cookie (avoids 401 on /config).
                            ui::open_browser(&bootstrap_guid_url(&daemon_base_cmd));
                        }
                        Ok(Cmd::OpenRemotePanel) => {
                            let server_url = rustnet_monitor::config::PersistentConfig::load()
                                .ok()
                                .and_then(|c| c.server_url);
                            match server_url {
                                Some(u) => ui::open_browser(&u),
                                None => warn!("OpenRemotePanel but server_url not configured"),
                            }
                        }
                        Ok(Cmd::OpenSettings) => {
                            // rustnetec: T3.6.9 — handshake first (session cookie),
                            // then the /config link in the index page is reachable.
                            // rustnetec: W6 — 追加 #settings 直达设置页(WebUI hash 路由)。
                            ui::open_browser(&format!(
                                "{}#settings",
                                bootstrap_guid_url(&daemon_base_cmd)
                            ));
                        }
                        Ok(Cmd::None) | Err(_) => {}
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            })?;

        // --- CFRunLoopTimer: refresh the status line on the main thread. ---
        struct RefreshCtx {
            controller: *mut ui::TrayController,
            quit: *const AtomicBool,
            ns_app: *const std::ffi::c_void,
            daemon_base: String,
            status_fields: Vec<rustnet_monitor::config::TrayStatusField>,
        }
        // SAFETY: `controller` and `quit` point to values owned by this
        // function's scope; the timer callback runs on the main run loop,
        // which only executes while we are inside ns_app.run() below — the
        // pointers stay valid for the whole blocking run.
        extern "C" fn refresh_cb(
            _timer: core_foundation::runloop::CFRunLoopTimerRef,
            info: *mut std::ffi::c_void,
        ) {
            let ctx = unsafe { &mut *(info as *mut RefreshCtx) };
            if unsafe { (*ctx.quit).load(Ordering::Relaxed) } {
                // Quit requested: ask NSApplication to terminate so
                // ns_app.run() below returns and the helper can reap the
                // daemon child.
                let app = unsafe { &*(ctx.ns_app as *const objc2_app_kit::NSApplication) };
                app.terminate(None);
                return;
            }
            let live_url = format!("{}/live", ctx.daemon_base);
            // rustnetec: T4.3 — /live 端点需要 Bearer 鉴权（check_auth，仅
            // `/` 与 `/bootstrap-guid` 免鉴权）；http_token 落盘非空后不带
            // token 会 401，refresh_status_from_live 从不执行，托盘动态状态
            // 停在初始文案不更新。与 bootstrap_guid_url / stop_daemon_via_http
            // 同款模式：读 PersistentConfig.http_token，非空时附加 Bearer。
            let mut req = ureq::get(&live_url).timeout(Duration::from_millis(800));
            if let Some(token) = rustnet_monitor::config::PersistentConfig::load()
                .ok()
                .and_then(|c| c.http_token)
                .filter(|t| !t.is_empty())
            {
                req = req.set("Authorization", &format!("Bearer {token}"));
            }
            if let Ok(resp) = req.call()
                && let Ok(live) = resp.into_json::<serde_json::Value>()
            {
                let ctrl = unsafe { &mut *ctx.controller };
                ctrl.refresh_status_from_live(&live, &ctx.status_fields);
            }
        }

        let pc0 = rustnet_monitor::config::PersistentConfig::load().unwrap_or_default();
        let refresh_interval = pc0.tray_refresh_interval_secs.max(1) as f64;
        let mut refresh_ctx = Box::new(RefreshCtx {
            controller: &mut tray_controller,
            quit: Arc::as_ptr(&quit_flag),
            ns_app: ns_app_ptr.cast(),
            daemon_base: daemon_base.clone(),
            status_fields: pc0.tray_status_fields.clone(),
        });
        let mut timer_ctx = core_foundation::runloop::CFRunLoopTimerContext {
            version: 0,
            info: (&mut *refresh_ctx as *mut RefreshCtx).cast(),
            retain: None,
            release: None,
            copyDescription: None,
        };
        let fire_date = core_foundation::date::CFDate::now().abs_time() + refresh_interval;
        let timer = core_foundation::runloop::CFRunLoopTimer::new(
            fire_date,
            refresh_interval,
            0,
            0,
            refresh_cb,
            &mut timer_ctx,
        );
        // rustnetec: 注册到 kCFRunLoopCommonModes（default + tracking + modal
        // 的集合），而不是 kCFRunLoopDefaultMode——macOS 菜单打开期间主 run
        // loop 进入 NSEventTrackingRunLoopMode，default mode 的 timer 不触发，
        // 状态行在菜单常驻打开时会冻结。common modes 下菜单打开时刷新 timer
        // 照常触发，status_item 实时更新。
        //
        // 与 T3.6.6 注释的区分：T3.6.6 说的是 CFRunLoopRunInMode 拒绝 common modes
        // （common modes 是集合、不能作为 run mode 传入 run_in_mode）；而
        // CFRunLoopAddTimer(common modes) 是标准用法，不受 T11 影响。
        unsafe {
            core_foundation::runloop::CFRunLoop::get_main()
                .add_timer(&timer, core_foundation::runloop::kCFRunLoopCommonModes);
        }
        // Keep the refresh context alive for the duration of the blocking run.
        std::mem::forget(refresh_ctx);

        info!("Tray helper: entering NSApp.run() (blocking Cocoa event loop)");
        ns_app.run();
        info!("Tray helper: NSApp.run() returned");
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Non-macOS backends (ksni/Win32) manage their own event pumps. Poll
        // translated commands directly; no AppKit run loop needed.
        let quit_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let pc0 = rustnet_monitor::config::PersistentConfig::load().unwrap_or_default();
        let status_fields = pc0.tray_status_fields.clone();
        // rustnetec: throttle /live polling to tray_refresh_interval_secs
        // (start with the interval already elapsed so the first refresh is
        // immediate instead of waiting one full cadence).
        let mut last_live_refresh = std::time::Instant::now()
            - std::time::Duration::from_secs(pc0.tray_refresh_interval_secs.max(1));
        while !quit_flag.load(std::sync::atomic::Ordering::Relaxed) {
            // rustnetec: Windows 需要 Win32 消息泵才能把托盘图标/菜单的
            // 窗口消息（WM_APP/WM_COMMAND）分发到 tray_proc——没有它
            // 右键菜单和点击事件永远到不了 MenuEvent channel（实测
            // 托盘无菜单）。非阻塞 PeekMessageW 与 50ms 轮询共存。
            #[cfg(target_os = "windows")]
            {
                use windows::Win32::UI::WindowsAndMessaging::{
                    DispatchMessageW, MSG, PeekMessageW, TranslateMessage, PM_REMOVE,
                };
                let mut msg: MSG = unsafe { std::mem::zeroed() };
                while unsafe { PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE) }.as_bool() {
                    unsafe {
                        let _ = TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                }
            }
            use ui::TrayCommand as Cmd;
            match tray_controller.poll_command() {
                Cmd::Quit => {
                    info!("Tray menu: Quit selected — shutting down");
                    // rustnetec: 退出托盘前检测前台 TUI，询问是否一起关闭。
                    ui::close_tui_if_confirmed();
                    quit_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
                Cmd::TogglePause => {
                    info!("Tray menu: TogglePause selected (pause/resume not yet implemented)");
                }
                Cmd::OpenTerminal => ui::open_terminal_monitor(),
                Cmd::OpenLocalPanel => {
                    // rustnetec: T3.6.9 — bootstrap-handshake URL (session cookie)
                    ui::open_browser(&bootstrap_guid_url(&daemon_base));
                }
                Cmd::OpenRemotePanel => {
                    let server_url = rustnet_monitor::config::PersistentConfig::load()
                        .ok()
                        .and_then(|c| c.server_url);
                    match server_url {
                        Some(u) => ui::open_browser(&u),
                        None => warn!("OpenRemotePanel but server_url not configured"),
                    }
                }
                Cmd::OpenSettings => {
                    // rustnetec: T3.6.9 — handshake first; W6 — #settings 直达设置页
                    ui::open_browser(&format!(
                        "{}#settings",
                        bootstrap_guid_url(&daemon_base)
                    ));
                }
                Cmd::None => {}
            }
            // Poll /live for the status line on the configured cadence.
            // rustnetec: T4.3 — 与 macOS refresh_cb 同款修复：/live 需要
            // Bearer 鉴权，http_token 非空时不带 token 会 401，动态状态不刷新。
            // rustnetec: 按 tray_refresh_interval_secs 节流（原来每 50ms 都
            // 请求一次 /live），失败时打 warn 日志便于诊断状态不更新。
            if last_live_refresh.elapsed().as_secs() >= pc0.tray_refresh_interval_secs.max(1) {
                last_live_refresh = std::time::Instant::now();
                if let Ok(pc) = rustnet_monitor::config::PersistentConfig::load() {
                    let mut req = ureq::get(&format!("{daemon_base}/live"))
                        .timeout(Duration::from_millis(800));
                    if let Some(token) = pc.http_token.as_deref().filter(|t| !t.is_empty()) {
                        req = req.set("Authorization", &format!("Bearer {token}"));
                    }
                    match req.call() {
                        Ok(resp) => match resp.into_json::<serde_json::Value>() {
                            Ok(live) => {
                                tray_controller.refresh_status_from_live(&live, &status_fields);
                            }
                            Err(e) => warn!("Tray helper: /live JSON decode failed: {e}"),
                        },
                        Err(e) => warn!("Tray helper: GET /live failed: {e}"),
                    }
                } else {
                    warn!("Tray helper: PersistentConfig::load failed — skipping status refresh");
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // --- Reap the daemon child (only if we spawned it) on exit ---
    // rustnetec: T3.6.11 — daemon_child is now a shared Arc<Mutex<...>>; the
    // macOS command thread already reaped it before NSApp.terminate, so this
    // take() is normally None (idempotent). Kept as a safety net for the
    // non-macOS branch / abnormal exits.
    if let Some(mut child) = daemon_child.lock().unwrap().take() {
        info!("Tray helper: stopping daemon child");
        let _ = child.kill();
        let _ = child.wait();
    }
    Ok(())
}

/// rustnetec: T3.6.7 — probe whether the daemon HTTP server is listening on
/// `port`. A TCP connect is sufficient for the handshake: the daemon binds
/// 127.0.0.1 before serving, so connectable == daemon up.
#[cfg(all(feature = "tray", not(target_os = "freebsd")))]
fn daemon_port_open(port: u16) -> bool {
    use std::net::{Ipv4Addr, SocketAddr, TcpStream};
    use std::time::Duration;
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok()
}

/// rustnetec: T4.2 — stop the daemon, first over HTTP (`/admin/shutdown`),
/// then via a direct signal from `daemon.pid` as a fallback.
///
/// Used when the daemon was launched via the auth dialog (osascript): the
/// helper has no `Child` handle for it (it is a nohup'd grandchild), so the
/// normal `child.kill()` reap cannot reach it. `handle_admin_shutdown` sets
/// `should_stop`, which the daemon's main loop observes and exits cleanly.
///
/// rustnetec: W-fix — the original HTTP-only path could leave the daemon
/// running when the (previously single-threaded) HTTP server was wedged on a
/// stuck request, making `/admin/shutdown` time out. After a brief grace
/// period we read `daemon.pid` and send SIGTERM directly so the daemon is
/// reliably reaped. Best-effort: no-op / warn when the daemon is already gone.
#[cfg(all(feature = "tray", not(target_os = "freebsd")))]
fn stop_daemon_via_http(daemon_base: &str) {
    use std::time::Duration;
    let token = rustnet_monitor::config::PersistentConfig::load()
        .ok()
        .and_then(|c| c.http_token)
        .unwrap_or_default();
    let url = format!("{daemon_base}/admin/shutdown");
    let mut req = ureq::post(&url).timeout(Duration::from_millis(800));
    if !token.is_empty() {
        req = req.set("Authorization", &format!("Bearer {token}"));
    }
    match req.call() {
        Ok(_) => info!("Tray helper: sent /admin/shutdown to daemon"),
        Err(e) => warn!("Tray helper: /admin/shutdown failed: {e}"),
    }

    // Give the daemon a brief moment to exit gracefully after the HTTP
    // request before escalating to a signal.
    std::thread::sleep(Duration::from_millis(600));

    // Fallback: if the daemon is still alive, signal it directly via the PID
    // file. This covers the wedged-HTTP-server case and any race where the
    // shutdown request was not processed. kill(pid, 0) on Unix / a zero exit
    // status tells us whether the process still exists.
    if let Some(pid) = read_daemon_pid() {
        if pid_is_alive(pid) {
            warn!(
                "Tray helper: daemon (pid {pid}) still running after HTTP shutdown; sending signal"
            );
            terminate_pid(pid);
        } else {
            info!("Tray helper: daemon (pid {pid}) exited cleanly after HTTP shutdown");
        }
    }
}

/// rustnetec: W-fix — read the daemon's PID from `<data_dir>/daemon.pid`.
#[cfg(all(feature = "tray", not(target_os = "freebsd")))]
fn read_daemon_pid() -> Option<u32> {
    let dir = telemetry::paths::data_dir().ok()?;
    let raw = std::fs::read_to_string(dir.join("daemon.pid")).ok()?;
    raw.trim().parse::<u32>().ok()
}

/// rustnetec: W-fix — whether a process with `pid` is still alive.
#[cfg(all(unix, feature = "tray", not(target_os = "freebsd")))]
fn pid_is_alive(pid: u32) -> bool {
    // kill(pid, 0) performs no signal but checks existence/permissions.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// rustnetec: W-fix — send SIGTERM to `pid` (Unix).
#[cfg(all(unix, feature = "tray", not(target_os = "freebsd")))]
fn terminate_pid(pid: u32) {
    unsafe {
        let _ = libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
}

/// rustnetec: W-fix — whether a process with `pid` is still alive (Windows).
#[cfg(all(windows, feature = "tray", not(target_os = "freebsd")))]
fn pid_is_alive(pid: u32) -> bool {
    // taskkill with no /F just probes; a zero status means it exists.
    std::process::Command::new("taskkill")
        .args(["/PID", &pid.to_string()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// rustnetec: W-fix — force-kill `pid` and its child tree (Windows).
#[cfg(all(windows, feature = "tray", not(target_os = "freebsd")))]
fn terminate_pid(pid: u32) {
    let _ = std::process::Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F", "/T"])
        .output();
}

/// rustnetec: T3.6.9 — build the bootstrap-handshake panel URL for the tray
/// helper.
///
/// The helper is a separate process from the daemon, so it cannot call
/// `HttpState::issue_bootstrap_guid()` directly. It POSTs `/bootstrap-guid`
/// (Bearer token from config, like all non-/ endpoints), receives
/// `{"guid":"<hex>"}`, and returns `http://127.0.0.1:<port>/?code=<guid>` —
/// the daemon's `/` handler redeems the guid and issues a session cookie so
/// the browser can then reach `/config`, `/live`, etc. On failure falls back
/// to the bare base URL (login page) so the user still sees a page.
#[cfg(all(feature = "tray", not(target_os = "freebsd")))]
fn bootstrap_guid_url(daemon_base: &str) -> String {
    let token = rustnet_monitor::config::PersistentConfig::load()
        .ok()
        .and_then(|c| c.http_token)
        .unwrap_or_default();
    let url = format!("{daemon_base}/bootstrap-guid");
    match ureq::post(&url)
        .set("Authorization", &format!("Bearer {token}"))
        .timeout(Duration::from_millis(800))
        .call()
    {
        Ok(resp) => {
            if let Ok(json) = resp.into_json::<serde_json::Value>()
                && let Some(guid) = json.get("guid").and_then(|g| g.as_str())
            {
                return format!("{daemon_base}/?code={guid}");
            }
            warn!("Tray helper: /bootstrap-guid response missing guid");
            format!("{daemon_base}/")
        }
        Err(e) => {
            warn!("Tray helper: POST /bootstrap-guid failed: {e}");
            format!("{daemon_base}/")
        }
    }
}

// rustnetec: Daemon mode main loop (R1)
/// Run the daemon loop: wait for SIGTERM/SIGINT, then exit gracefully.
/// The capture pipeline runs in background threads started by App;
/// this function just keeps the main thread alive until a shutdown signal.
///
/// `tray_mode`: when true, the loop also drives a system tray controller
/// (`TrayController`). The tray branch uses a 50ms-granularity non-blocking
/// poll so menu clicks respond within ≤50ms, independent of the configurable
/// 1-15s status-line refresh cadence. The non-tray daemon branch keeps the
/// original coarse `sleep(1s)` wait.
fn run_daemon_loop(
    app: &app::App,
    tray_mode: bool,
    #[cfg(all(feature = "tray", not(target_os = "freebsd")))] http_state: Option<
        std::sync::Arc<telemetry::http::HttpState>,
    >,
    #[cfg(not(all(feature = "tray", not(target_os = "freebsd"))))] _http_state: Option<()>,
) {
    // rustnetec: 偏差2 修复 — 注册 SIGTERM/SIGINT handler 触发优雅退出
    //
    // 之前 run_daemon_loop 注释「rely on ctrlc」是错误假设：全项目无 ctrlc
    // handler 注册，SIGTERM 会直接终止进程，SQLite WAL 可能未 checkpoint。
    //
    // 使用 signal-hook 注册 SIGINT/SIGTERM/HUP/QUIT，收到信号后调用 app.stop()
    // 设置 should_stop，capture thread 检测后优雅退出，run_daemon_loop 随后 break。
    use signal_hook::consts::signal::{SIGINT, SIGTERM};
    #[cfg(not(windows))]
    use signal_hook::consts::signal::{SIGHUP, SIGQUIT};
    use signal_hook::flag;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let shutdown_flag = Arc::new(AtomicBool::new(false));
    // best-effort registration; failure here only means we can't catch
    // that particular signal, not that the daemon is broken.
    // SIGHUP/SIGQUIT are Unix-only (signal-hook gates them with
    // #[cfg(not(windows))]); Windows gets SIGINT/SIGTERM only.
    for sig in [SIGINT, SIGTERM] {
        let _ = flag::register(sig, Arc::clone(&shutdown_flag));
    }
    #[cfg(not(windows))]
    for sig in [SIGHUP, SIGQUIT] {
        let _ = flag::register(sig, Arc::clone(&shutdown_flag));
    }

    info!(
        "Daemon loop started, waiting for shutdown signal (Ctrl+C or SIGTERM) — signal-hook registered"
    );
    // rustnetec: T11 diagnostics — stderr directly, independent of --log-level
    eprintln!("[tray-diag] run_daemon_loop entered, tray_mode={tray_mode}");

    // rustnetec: macOS requires the main-thread Cocoa event loop to be
    // running before the tray icon is created (tray-icon platform note:
    // "make sure the event loop is already running and not just created
    // before creating a TrayIcon"). Drive it once with a short run_in_mode
    // so NSStatusItem creation and display work; the main loop below keeps
    // driving it with CFRunLoopRunInMode instead of plain sleep (T3.6.3).
    //
    // T3.6.4: also initialize the NSApplication singleton FIRST — the tray-icon
    // native example starts with `NSApp()`. Without it the status item may
    // show but AppKit never dispatches click/menu events (menu items appear
    // dead), because NSApplication is the hub of the Cocoa event system.
    // `std::mem::forget` keeps the singleton alive for the process lifetime.
    //
    // T3.6.6: T3.6.5's kCFRunLoopCommonModes was WRONG — CFRunLoopRunInMode rejects
    // kCFRunLoopCommonModes as a run mode ("invalid mode 'kCFRunLoopCommonModes'
    // provided to CFRunLoopRunSpecific"), aborting the warmup and leaving no
    // icon. Reverted to kCFRunLoopDefaultMode; the real menu-dispatch fix is
    // the polling structure in the main loop below.
    #[cfg(all(feature = "tray", target_os = "macos"))]
    if tray_mode {
        use objc2::MainThreadMarker;
        use objc2_app_kit::NSApp;
        let mtm = MainThreadMarker::new().expect("run_daemon_loop runs on the main thread");
        let ns_app = NSApp(mtm);
        std::mem::forget(ns_app); // keep NSApplication alive for the whole daemon loop

        use core_foundation::runloop::{CFRunLoop, kCFRunLoopDefaultMode};
        CFRunLoop::run_in_mode(
            unsafe { kCFRunLoopDefaultMode },
            Duration::from_millis(50),
            false,
        );
    }

    // rustnetec: tray controller (T3.2). Only constructed when tray_mode is
    // true AND the tray feature is compiled in AND we are not on FreeBSD
    // (no tray backend there). On FreeBSD the tray feature is cfg-gated out,
    // so the branch collapses to a plain daemon loop.
    #[cfg(all(feature = "tray", not(target_os = "freebsd")))]
    let mut tray_controller: Option<ui::TrayController> = if tray_mode {
        eprintln!("[tray-diag] creating TrayController…");
        match ui::TrayController::new(
            include_bytes!("../resources/packaging/linux/graphics/rustnetec.png"),
            256,
            256,
            "Rustnetec",
        ) {
            Ok(ctrl) => {
                eprintln!("[tray-diag] TrayController created OK");
                Some(ctrl)
            }
            Err(e) => {
                // rustnetec: T7 — also print to stderr so the failure is
                // visible even when the user didn't pass --log-level (which
                // is the only condition under which setup_logging runs and
                // warn! becomes visible; otherwise the terminal stays blank).
                warn!("Failed to create system tray icon: {e}; continuing headless");
                eprintln!("Warning: failed to create system tray icon: {e}; continuing headless");
                None
            }
        }
    } else {
        None
    };

    // rustnetec: initial remote-panel enable/disable + first status refresh (T3.2)
    #[cfg(all(feature = "tray", not(target_os = "freebsd")))]
    if let Some(ref mut ctrl) = tray_controller {
        let pc = rustnet_monitor::config::PersistentConfig::load().unwrap_or_default();
        ctrl.set_remote_enabled(pc.server_url.is_some());
        let rc = rustnet_monitor::config::RuntimeConfig::from_persistent(&pc);
        ctrl.refresh_status(app, &rc);
    }

    // rustnetec: status refresh bookkeeping (tray branch only)
    #[cfg(all(feature = "tray", not(target_os = "freebsd")))]
    let mut last_refresh = std::time::Instant::now();
    #[cfg(all(feature = "tray", not(target_os = "freebsd")))]
    let mut current_interval_secs: u64 = {
        let pc = rustnet_monitor::config::PersistentConfig::load().unwrap_or_default();
        pc.tray_refresh_interval_secs
    };

    loop {
        if tray_mode {
            // rustnetec: T11 diagnostics — alive tick every ~2s (40 × 50ms)
            #[cfg(all(feature = "tray", not(target_os = "freebsd")))]
            {
                static mut TICK: u64 = 0;
                // SAFETY: single-threaded main loop, only here touches TICK
                unsafe {
                    TICK += 1;
                }
                if unsafe { TICK.is_multiple_of(40) } {
                    eprintln!("[tray-diag] main loop alive (tick {})", unsafe { TICK });
                }
            }

            // rustnetec: tray branch — 50ms non-blocking poll for snappy menus (T3.2)
            #[cfg(all(feature = "tray", not(target_os = "freebsd")))]
            {
                if let Some(ref mut ctrl) = tray_controller {
                    use ui::TrayCommand as Cmd;
                    match ctrl.poll_command() {
                        Cmd::Quit => {
                            eprintln!("[tray-diag] got Quit command");
                            info!("Tray menu: Quit selected, stopping app");
                            app.stop();
                            break;
                        }
                        Cmd::TogglePause => {
                            eprintln!("[tray-diag] got TogglePause command");
                            // rustnetec: TODO — App has no pause/resume API yet;
                            // log placeholder so the menu item visibly does something.
                            info!(
                                "Tray menu: TogglePause selected (pause/resume not yet implemented)"
                            );
                        }
                        Cmd::OpenTerminal => {
                            eprintln!("[tray-diag] got OpenTerminal command");
                            // rustnetec: launcher T3.3 — open a terminal running rustnet query --live
                            ui::open_terminal("rustnet query --live");
                        }
                        Cmd::OpenLocalPanel => {
                            eprintln!("[tray-diag] got OpenLocalPanel command");
                            // rustnetec: launcher T3.3 — one-time bootstrap guid handshake
                            if let Some(ref state) = http_state {
                                ui::open_local_panel(state);
                            } else {
                                warn!(
                                    "Tray: OpenLocalPanel but HTTP server not running; falling back to bare URL"
                                );
                                ui::open_browser("http://127.0.0.1:19811/");
                            }
                        }
                        Cmd::OpenRemotePanel => {
                            // rustnetec: launcher T3.3 — remote panel uses the configured server_url
                            let server_url = rustnet_monitor::config::PersistentConfig::load()
                                .ok()
                                .and_then(|pc| pc.server_url);
                            match server_url {
                                Some(url) => ui::open_browser(&url),
                                None => warn!(
                                    "Tray: OpenRemotePanel but server_url not configured (item should have been disabled)"
                                ),
                            }
                        }
                        Cmd::OpenSettings => {
                            // rustnetec: W6 — 与 helper 分支一致:先 bootstrap 握手
                            // 拿 session cookie,再带 #settings 直达设置页。裸打开
                            // /config 返回 JSON 而非页面,且未握手时 401。
                            let port = http_state.as_ref().map(|s| s.http_port).unwrap_or(19811);
                            let url = match &http_state {
                                Some(state) => format!(
                                    "http://127.0.0.1:{port}/?code={}#settings",
                                    state.issue_bootstrap_guid()
                                ),
                                None => format!("http://127.0.0.1:{port}/#settings"),
                            };
                            ui::open_browser(&url);
                        }
                        Cmd::None => {}
                    }
                }
            }

            // rustnetec: status refresh on configurable 1-15s cadence (T3.2)
            #[cfg(all(feature = "tray", not(target_os = "freebsd")))]
            if last_refresh.elapsed().as_secs() >= current_interval_secs {
                eprintln!("[tray-diag] status refresh starting");
                if let Some(ref mut ctrl) = tray_controller {
                    let pc = rustnet_monitor::config::PersistentConfig::load().unwrap_or_default();
                    let rc = rustnet_monitor::config::RuntimeConfig::from_persistent(&pc);
                    ctrl.refresh_status(app, &rc);
                    // hot-update: pick up new interval each cycle
                    current_interval_secs = pc.tray_refresh_interval_secs;
                }
                eprintln!("[tray-diag] status refresh done");
                last_refresh = std::time::Instant::now();
            }

            // rustnetec: T8 — macOS tray needs the main-thread Cocoa event
            // loop running continuously to display the icon and dispatch menu
            // events. CFRunLoopRunInMode with a 50ms timeout drives it while
            // keeping the poll cadence; other platforms keep plain sleep.
            //
            // T3.6.6: T3.6.5's kCFRunLoopCommonModes was WRONG — CFRunLoopRunInMode
            // rejects it as a run mode. Reverted to kCFRunLoopDefaultMode.
            #[cfg(all(feature = "tray", target_os = "macos"))]
            {
                use core_foundation::runloop::{CFRunLoop, kCFRunLoopDefaultMode};
                CFRunLoop::run_in_mode(
                    unsafe { kCFRunLoopDefaultMode },
                    Duration::from_millis(50),
                    false,
                );
            }
            #[cfg(not(all(feature = "tray", target_os = "macos")))]
            std::thread::sleep(Duration::from_millis(50));
        } else {
            // rustnetec: T3.6.7 — plain daemon branch also publishes the live
            // snapshot so the tray helper can poll GET /live over HTTP (the
            // helper is a separate process and has no App handle).
            #[cfg(all(feature = "tray", not(target_os = "freebsd")))]
            if let Some(ref state) = http_state {
                state.update_live_snapshot(app);
            }
            // rustnetec: plain daemon branch — coarse 1s wait (original behavior)
            std::thread::sleep(Duration::from_secs(1));
        }

        if shutdown_flag.load(std::sync::atomic::Ordering::Relaxed) {
            info!("Shutdown signal received via signal-hook, stopping app");
            app.stop();
            break;
        }

        // 兼容路径：若 should_stop 已被其他机制置位（如 HTTP restart-capture），
        // 也应退出 daemon loop。
        if app.is_stopping() {
            info!("Shutdown signaled via app.is_stopping(), exiting daemon loop");
            break;
        }
    }
}

// rustnetec: Handle `rustnet query` subcommand (R5, T1.3)
fn run_query_subcommand(matches: &clap::ArgMatches) -> Result<()> {
    // rustnetec: simplify redundant closures (clippy::redundant_closure)
    let db_path = matches
        .get_one::<String>("db")
        .map(std::path::PathBuf::from)
        .unwrap_or_default(); // rustnetec: clippy unwrap_or_default
    let filter = matches.get_one::<String>("filter").map(|s| s.as_str());
    let sql = matches.get_one::<String>("sql").map(|s| s.as_str());
    let live = matches.get_flag("live");

    // rustnetec: G1 改造 — `run_query` 现返回 `Vec<Value>`,
    // CLI 侧负责序列化为 pretty JSON 输出到 stdout。
    let rows = telemetry::query::run_query(&db_path, filter, sql, live)?;
    let output = serde_json::to_string_pretty(&serde_json::Value::Array(rows))
        .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e));
    println!("{output}");
    Ok(())
}

// rustnetec: Handle `rustnet install-autostart` subcommand (R1 boot autostart, T1.11)
fn run_install_autostart() -> Result<()> {
    // Load PersistentConfig to honor autostart_mode: tray (requires the tray feature).
    let mut pc = rustnet_monitor::config::PersistentConfig::load()?;
    let mode = pc.autostart_mode;
    telemetry::autostart::install(mode)?;
    // Persist the autostart intent so config.yml reflects reality.
    pc.autostart_enabled = true;
    pc.autostart_mode = mode;
    if let Err(e) = pc.save() {
        warn!("autostart installed but failed to persist config: {}", e);
    } else {
        info!(
            "registered rustnet {} as a boot-time autostart entry",
            mode.cli_flag()
        );
    }
    Ok(())
}

// rustnetec: Handle `rustnet uninstall-autostart` subcommand (R1 boot autostart, T1.11)
fn run_uninstall_autostart() -> Result<()> {
    telemetry::autostart::uninstall()?;
    // Persist autostart_enabled=false but keep autostart_mode so reinstall is reversible.
    let mut pc = rustnet_monitor::config::PersistentConfig::load().unwrap_or_default();
    pc.autostart_enabled = false;
    if let Err(e) = pc.save() {
        warn!("autostart uninstalled but failed to persist config: {}", e);
    } else {
        info!("removed the rustnet boot-time autostart entry");
    }
    Ok(())
}

// rustnetec: Handle `rustnet install-launchdaemon` subcommand (T4.2, macOS)
// 一次性授权安装系统 LaunchDaemon，之后 launchd 以 root 托管 daemon，
// 开机自启、崩溃重启、无需重复授权（永久授权方案）。
#[cfg(target_os = "macos")]
fn run_install_launchdaemon(matches: &clap::ArgMatches) -> Result<()> {
    let http_port = matches
        .get_one::<u16>("http-port")
        .copied()
        .unwrap_or(19811);
    telemetry::launchdaemon::install(http_port)?;
    println!("LaunchDaemon installed — daemon will run as root via launchd (no more password prompts).");
    Ok(())
}

// rustnetec: Handle `rustnet uninstall-launchdaemon` subcommand (T4.2, macOS)
#[cfg(target_os = "macos")]
fn run_uninstall_launchdaemon() -> Result<()> {
    telemetry::launchdaemon::uninstall()?;
    println!("LaunchDaemon removed.");
    Ok(())
}

fn run_ui_loop<B: ratatui::prelude::Backend>(
    terminal: &mut ui::Terminal<B>,
    app: &app::App,
) -> Result<()>
where
    <B as ratatui::prelude::Backend>::Error: Send + Sync + 'static,
{
    let tick_rate = Duration::from_millis(200);
    // Idle redraw ceiling. Terminal emulators repaint whenever output
    // arrives (iTerm2's renderer repaints the window on any content
    // change), so the draw cadence directly sets the terminal's CPU
    // cost. Input and data changes redraw immediately; graph animation
    // and the live sidebar counters advance at this heartbeat.
    let redraw_interval = Duration::from_millis(500);
    // Full-size traffic waves scroll between 500ms samples in smaller
    // increments. The one-row Overview waves keep the lower idle repaint rate
    // because their four-dot vertical resolution makes faster motion flicker.
    let wave_redraw_interval = Duration::from_millis(200);
    let mut last_tick = std::time::Instant::now();
    let mut last_draw = std::time::Instant::now();
    let mut needs_redraw = true; // first frame
    let mut ui_state = ui::UIState::default();
    // rustnetec: 修复 show_historic 复选框 — TUI 启动时读持久化配置
    // (PersistentConfig.show_historic,设置页「显示 → 历史」)作为 t 键
    // 切换的默认状态。之前该值写入 RuntimeConfig 后无人消费,复选框形同虚设。
    let show_historic = rustnet_monitor::config::PersistentConfig::load()
        .map(|pc| pc.show_historic)
        .unwrap_or(false);
    ui_state.show_historic = show_historic;
    app.set_show_historic(show_historic);
    let (has_country_db, _, _) = app.get_geoip_status();
    ui_state.has_geoip = has_country_db;
    let mut click_regions = ui::ClickableRegions::default();

    // Data state persists across loop iterations — only refreshed on timer tick
    // or when an event changes the underlying data (filter, sort, historic toggle, etc.)
    let mut connections: Vec<network::types::Connection> = Vec::new();
    let mut grouped_rows: Vec<ui::GroupedRow<'_>> = Vec::new();
    let mut stats = app.get_stats();
    let mut needs_data_refresh = true;
    let mut needs_regroup = false;
    let mut last_seen_generation = u64::MAX; // force the first refresh

    'main: loop {
        // Refresh connection data only when needed:
        // - On timer tick (every 200ms), but only if the snapshot actually
        //   changed since we last consumed it (it rebuilds every
        //   refresh-interval ms, so most ticks would re-clone and re-sort
        //   identical data)
        // - When an event changes filter, sort, or data source
        let tick_elapsed = last_tick.elapsed() >= tick_rate;
        let snapshot_generation = app.snapshot_generation();
        if tick_elapsed {
            // Keep counters (packets processed/dropped, etc.) live on every
            // tick even when the connection list is unchanged.
            stats = app.get_stats();
            last_tick = std::time::Instant::now();
        }
        if needs_data_refresh || (tick_elapsed && snapshot_generation != last_seen_generation) {
            connections = if !ui_state.has_active_filter() && !ui_state.filter_mode {
                app.get_connections()
            } else {
                app.get_filtered_connections(&ui_state.filter_query)
            };
            sort_connections(
                &mut connections,
                ui_state.sort_column,
                ui_state.sort_ascending,
            );
            grouped_rows = if ui_state.grouping_enabled {
                ui::compute_grouped_rows(&connections, &ui_state.expanded_groups)
            } else {
                Vec::new()
            };
            last_seen_generation = snapshot_generation;
            needs_data_refresh = false;
            needs_regroup = false;
            needs_redraw = true;
        } else if needs_regroup {
            // Only rebuild grouped rows from existing connections
            // (e.g., after expand/collapse or grouping toggle)
            grouped_rows = if ui_state.grouping_enabled {
                ui::compute_grouped_rows(&connections, &ui_state.expanded_groups)
            } else {
                Vec::new()
            };
            needs_regroup = false;
            needs_redraw = true;
        }

        // Ensure we have a valid selection (handles connection removals)
        if ui_state.grouping_enabled {
            let selected_idx = ui_state
                .ensure_valid_grouped_selection(&grouped_rows)
                .unwrap_or(0);
            ui_state.grouped_scroll_offset = ui::compute_scroll_offset(
                selected_idx,
                ui_state.grouped_scroll_offset,
                ui_state.visible_rows,
                grouped_rows.len(),
            );
        } else {
            let selected_idx = ui_state.ensure_valid_selection(&connections).unwrap_or(0);
            ui_state.scroll_offset = ui::compute_scroll_offset(
                selected_idx,
                ui_state.scroll_offset,
                ui_state.visible_rows,
                connections.len(),
            );
        }

        // Draw the UI, but only when something warrants it: immediately
        // after input or a data change, otherwise at the idle heartbeat.
        // The sidebar counters are live atomics read at render time, so
        // an unconditional draw here would emit fresh cells (and force a
        // terminal repaint) on every 200ms tick even with nothing going on.
        // The startup splash animates faster than the idle heartbeat, so
        // it gets a shorter redraw interval for its ~1s lifetime.
        let idle_redraw = if app.is_loading() {
            Duration::from_millis(100)
        } else if matches!(ui_state.selected_tab, 1 | 3) {
            wave_redraw_interval
        } else {
            redraw_interval
        };
        if needs_redraw || last_draw.elapsed() >= idle_redraw {
            terminal.draw(|f| {
                let grouped = if ui_state.grouping_enabled {
                    Some(grouped_rows.as_slice())
                } else {
                    None
                };
                if let Err(err) = ui::draw(
                    f,
                    app,
                    &ui_state,
                    &connections,
                    grouped,
                    &stats,
                    &mut click_regions,
                ) {
                    error!("UI draw error: {}", err);
                }
            })?;
            last_draw = std::time::Instant::now();
            needs_redraw = false;
        }

        // Update visible rows for page navigation based on terminal height.
        // Chrome rows: tab bar (2) + section title (1) + table header incl.
        // margin (2) + status bar (1) = 6, plus the filter line (1) when a
        // filter is being edited or active.
        if let Ok(size) = terminal.size() {
            let chrome = if ui_state.filter_mode || ui_state.has_active_filter() {
                7
            } else {
                6
            };
            ui_state.visible_rows = (size.height as usize).saturating_sub(chrome);
        }

        // Sleep until the next data tick or redraw heartbeat, whichever
        // comes first, unless an event arrives earlier.
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::from_secs(0))
            .min(idle_redraw.saturating_sub(last_draw.elapsed()));

        // Clear clipboard message after timeout
        if let Some((_, time)) = &ui_state.clipboard_message
            && time.elapsed().as_secs() >= 3
        {
            ui_state.clipboard_message = None;
            needs_redraw = true;
        }

        // Handle input events, draining any queued burst (mouse motion,
        // key auto-repeat) before the next iteration so a flood of
        // events costs one redraw instead of one redraw per event.
        let mut poll_timeout = timeout;
        'events: while crossterm::event::poll(poll_timeout)? {
            poll_timeout = Duration::ZERO;
            let event = crossterm::event::read()?;
            match event {
                crossterm::event::Event::Mouse(mouse) => {
                    use crossterm::event::{MouseButton, MouseEventKind};

                    // Active tab's Component gets first crack — currently
                    // only OverviewTab claims (scroll wheel inside the
                    // scroll area). Click events fall through to the
                    // global ClickableRegions dispatch below.
                    let grouped_opt = if ui_state.grouping_enabled {
                        Some(grouped_rows.as_slice())
                    } else {
                        None
                    };
                    let mut hctx = ui::HandlerContext {
                        app,
                        ui_state: &mut ui_state,
                        connections: &connections,
                        grouped_rows: grouped_opt,
                        click_regions: &click_regions,
                    };
                    if let Some(effects) =
                        ui::dispatch_mouse(hctx.ui_state.selected_tab, mouse, &mut hctx)
                    {
                        let outcome = ui::apply_effects(effects, &mut ui_state, app);
                        if outcome.needs_data_refresh {
                            needs_data_refresh = true;
                        }
                        if outcome.needs_regroup {
                            needs_regroup = true;
                        }
                        needs_redraw = true;
                        continue 'events;
                    }

                    if let MouseEventKind::Down(MouseButton::Left) = mouse.kind {
                        {
                            needs_redraw = true;
                            ui_state.quit_confirmation = false;
                            ui_state.clear_confirmation = false;

                            // Detect double-click (two clicks within 400ms at the same row)
                            let is_double_click =
                                if let Some((_, prev_row, prev_time)) = ui_state.last_click {
                                    prev_row == mouse.row && prev_time.elapsed().as_millis() < 400
                                } else {
                                    false
                                };
                            ui_state.last_click =
                                Some((mouse.column, mouse.row, std::time::Instant::now()));

                            if let Some(action) = click_regions.hit_test(mouse.column, mouse.row) {
                                match action.clone() {
                                    ui::ClickAction::SwitchTab(tab_idx) => {
                                        ui_state.selected_tab = tab_idx;
                                    }
                                    ui::ClickAction::SelectConnection(conn_idx) => {
                                        if ui_state.grouping_enabled {
                                            ui_state.set_selected_grouped_by_index(
                                                &grouped_rows,
                                                conn_idx,
                                            );
                                            if is_double_click
                                                && let Some(row) = grouped_rows.get(conn_idx)
                                            {
                                                match row {
                                                    ui::GroupedRow::Group { .. } => {
                                                        // Double-click group header: toggle expand/collapse
                                                        ui_state.toggle_group_expansion();
                                                        needs_regroup = true;
                                                    }
                                                    ui::GroupedRow::Connection { .. } => {
                                                        // Double-click connection: open Details tab
                                                        ui_state.selected_tab = 1;
                                                    }
                                                }
                                            }
                                        } else {
                                            ui_state.set_selected_by_index(&connections, conn_idx);
                                            if is_double_click {
                                                // Double-click connection in flat view: open Details tab
                                                ui_state.selected_tab = 1;
                                            }
                                        }
                                    }
                                    ui::ClickAction::SelectConnectionKey(key) => {
                                        // Keep the grouped selection coherent: adopt the
                                        // clicked connection's group when grouping is on.
                                        if ui_state.grouping_enabled {
                                            for row in &grouped_rows {
                                                if let ui::GroupedRow::Connection {
                                                    process_name,
                                                    connection,
                                                    ..
                                                } = row
                                                    && connection.key() == key
                                                {
                                                    ui_state.selected_group =
                                                        Some(process_name.clone());
                                                    break;
                                                }
                                            }
                                        }
                                        ui_state.set_connection_key(Some(key));
                                    }
                                    ui::ClickAction::CopyField { label, value } => {
                                        copy_to_clipboard(
                                            &value,
                                            &format!("{}: {}", label, value),
                                            &mut ui_state,
                                            app,
                                        );
                                    }
                                }
                            }
                        }
                    }
                    // Scroll events are handled by OverviewTab::handle_mouse above.
                }
                crossterm::event::Event::Key(key) => {
                    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};

                    // On Windows, crossterm reports both Press and Release events
                    // On Linux/macOS, only Press events are reported
                    // Filter to only handle Press events for consistent cross-platform behavior
                    if key.kind != KeyEventKind::Press {
                        continue 'events;
                    }
                    needs_redraw = true;

                    // Give the active tab's Component first crack
                    // at the key (including filter-mode input — OverviewTab
                    // owns that). If it claims (returns Some), the loop
                    // skips its fallback match. The per-key confirmation
                    // reset happens here for both branches so q / x can
                    // still set their own confirmations without the
                    // catch-all clobbering them.
                    match key.code {
                        KeyCode::Char('q') => ui_state.clear_confirmation = false,
                        KeyCode::Char('x') => ui_state.quit_confirmation = false,
                        _ => {
                            ui_state.quit_confirmation = false;
                            ui_state.clear_confirmation = false;
                        }
                    }

                    let grouped_opt = if ui_state.grouping_enabled {
                        Some(grouped_rows.as_slice())
                    } else {
                        None
                    };
                    let mut hctx = ui::HandlerContext {
                        app,
                        ui_state: &mut ui_state,
                        connections: &connections,
                        grouped_rows: grouped_opt,
                        click_regions: &click_regions,
                    };
                    let claimed = if let Some(effects) =
                        ui::dispatch_key(hctx.ui_state.selected_tab, key, &mut hctx)
                    {
                        let outcome = ui::apply_effects(effects, &mut ui_state, app);
                        if outcome.needs_data_refresh {
                            needs_data_refresh = true;
                        }
                        if outcome.needs_regroup {
                            needs_regroup = true;
                        }
                        true
                    } else {
                        false
                    };

                    if claimed {
                        // Component handled the key end-to-end.
                    } else {
                        // Normal-mode fallback: keys that weren't claimed
                        // by the active tab's Component. Global navigation
                        // and quit/help/interface-toggle live here, plus
                        // cross-tab fallbacks for x (clear) and Esc which
                        // would otherwise stop working on non-Overview
                        // tabs. Per-arm confirmation clearing is no longer
                        // needed — the dispatcher above already applied
                        // the per-key reset rule.
                        match (key.code, key.modifiers) {
                            // Quit with confirmation
                            (KeyCode::Char('q'), _) => {
                                if ui_state.quit_confirmation {
                                    info!("User confirmed application exit");
                                    break 'main;
                                } else {
                                    info!("User requested quit - showing confirmation");
                                    ui_state.quit_confirmation = true;
                                }
                            }

                            // Ctrl+C always quits immediately
                            (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                                info!("User requested immediate exit with Ctrl+C");
                                break 'main;
                            }

                            // Tab navigation (forward)
                            (KeyCode::Tab, KeyModifiers::NONE)
                            | (KeyCode::Char(']'), KeyModifiers::NONE) => {
                                ui_state.next_tab();
                            }

                            // Shift+Tab navigation (backward)
                            (KeyCode::BackTab, _)
                            | (KeyCode::Tab, KeyModifiers::SHIFT)
                            | (KeyCode::Char('['), KeyModifiers::NONE) => {
                                ui_state.prev_tab();
                            }

                            // Direct-jump shortcuts to each tab (mirrors the
                            // numeric-jump convention used by htop, tmux, etc.).
                            // Tab indices match `TAB_TITLES` in
                            // `ui::widgets::tabs_bar`: Overview, Details,
                            // Activity, Graph, Help.
                            (KeyCode::Char('1'), KeyModifiers::NONE) => ui_state.jump_to_tab(0),
                            (KeyCode::Char('2'), KeyModifiers::NONE) => ui_state.jump_to_tab(1),
                            (KeyCode::Char('3'), KeyModifiers::NONE) => ui_state.jump_to_tab(2),
                            (KeyCode::Char('4'), KeyModifiers::NONE) => ui_state.jump_to_tab(3),
                            (KeyCode::Char('5'), KeyModifiers::NONE) => ui_state.jump_to_tab(4),

                            // Help toggle — kept because `h` is the universal
                            // mnemonic for help across less / man / vim / tmux.
                            (KeyCode::Char('h'), _) => {
                                ui_state.show_help = !ui_state.show_help;
                                if ui_state.show_help {
                                    ui_state.selected_tab = 4; // Switch to help tab
                                } else {
                                    ui_state.selected_tab = 0; // Back to overview
                                }
                            }

                            // x and Esc keep cross-tab fallbacks here so
                            // clear / filter-clear / tab-back still work
                            // from Details / Activity / Graph / Help
                            // (OverviewTab only claims them on Overview).
                            (KeyCode::Char('x'), _)
                                if clear_all_with_confirmation(&mut ui_state, app) =>
                            {
                                needs_data_refresh = true;
                            }

                            (KeyCode::Esc, _) => {
                                if !ui_state.filter_query.is_empty() {
                                    ui_state.clear_filter();
                                    needs_data_refresh = true;
                                } else if ui_state.selected_tab != 0 {
                                    ui_state.selected_tab = 0;
                                }
                            }

                            _ => {}
                        }
                    }
                } // end Event::Key
                crossterm::event::Event::Resize(..) => {
                    needs_redraw = true;
                }
                _ => {} // ignore focus, paste, etc.
            } // end match event
        } // end event drain
    } // end loop

    Ok(())
}

/// Check if we have privileges for packet capture before starting the TUI
fn check_privileges_early() -> Result<()> {
    match network::privileges::check_packet_capture_privileges() {
        Ok(status) if !status.has_privileges => {
            // Print error to stderr before TUI starts
            eprintln!(
                "\n╔═══════════════════════════════════════════════════════════════════════════╗"
            );
            eprintln!(
                "║                   INSUFFICIENT PRIVILEGES                                 ║"
            );
            eprintln!(
                "╚═══════════════════════════════════════════════════════════════════════════╝"
            );
            eprintln!();
            eprintln!("{}", status.error_message());

            return Err(anyhow::anyhow!(
                "Insufficient privileges for packet capture"
            ));
        }
        Err(e) => {
            // Privilege check failed - warn but continue
            eprintln!("Warning: Failed to check privileges: {}", e);
            eprintln!("Continuing anyway, but packet capture may fail...\n");
        }
        _ => {
            // Privileges OK
        }
    }

    Ok(())
}

/// rustnetec: Soft privilege check (tray mode T3.6.1, autostart mode T1.11).
///
/// The tray menu (open terminal / local panel / settings / quit) does not
/// need packet capture, and neither does an autostart-registered daemon
/// (marked with `--autostart`, e.g. HKCU Run on Windows): both must keep
/// running for an unprivileged user. Capture degrades to process-only mode
/// inside `App::start_capture_thread` (it sets `CaptureStatus::Failed` and
/// logs "Application will run in process-only mode" instead of aborting),
/// so the tray/daemon keeps working with an empty/zero status line.
///
/// Unlike [`check_privileges_early`], this prints a warning and continues —
/// it never aborts the process.
fn check_privileges_soft() {
    match network::privileges::check_packet_capture_privileges() {
        Ok(status) if !status.has_privileges => {
            warn!(
                "Started without packet capture privileges — running in process-only mode. {}",
                status.error_message()
            );
            eprintln!(
                "Warning: insufficient privileges for packet capture — running in process-only mode.\n{}",
                status.error_message()
            );
        }
        Err(e) => {
            // Privilege check failed - warn but continue
            warn!("Failed to check privileges (soft mode): {}", e);
        }
        _ => {
            // Privileges OK
        }
    }
}

#[cfg(target_os = "windows")]
fn check_windows_dependencies() -> Result<()> {
    use anyhow::anyhow;

    // Check if Npcap/WinPcap DLLs are available
    // Try to load the DLLs to see if they're in the system path
    let wpcap_available = check_dll_available("wpcap.dll");
    let packet_available = check_dll_available("Packet.dll");

    if !wpcap_available || !packet_available {
        eprintln!(
            "\n╔═══════════════════════════════════════════════════════════════════════════╗"
        );
        eprintln!("║                          MISSING DEPENDENCY                               ║");
        eprintln!("╚═══════════════════════════════════════════════════════════════════════════╝");
        eprintln!();
        eprintln!("RustNet requires Npcap for packet capture on Windows.");
        eprintln!();

        if !wpcap_available {
            eprintln!("  ✗ wpcap.dll not found");
        }
        if !packet_available {
            eprintln!("  ✗ Packet.dll not found");
        }

        eprintln!();
        eprintln!("To fix this:");
        eprintln!();
        eprintln!("  1. Download Npcap from: https://npcap.com/dist/");
        eprintln!("  2. Run the installer");
        eprintln!("  3. IMPORTANT: Check \"Install Npcap in WinPcap API-compatible Mode\"");
        eprintln!("  4. Complete the installation");
        eprintln!();
        eprintln!("After installation, restart your terminal and try again.");
        eprintln!();

        return Err(anyhow!(
            "Npcap is not installed or not in WinPcap compatible mode"
        ));
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn check_dll_available(dll_name: &str) -> bool {
    use std::ffi::CString;
    use windows::Win32::Foundation::{FreeLibrary, HMODULE};
    use windows::Win32::System::LibraryLoader::LoadLibraryA;
    use windows::core::PCSTR;

    // Try to load the DLL
    let dll_cstring = match CString::new(dll_name) {
        Ok(s) => s,
        Err(_) => return false,
    };

    unsafe {
        // Use LoadLibraryA to check if the DLL can be loaded
        let handle = LoadLibraryA(PCSTR(dll_cstring.as_ptr() as *const u8));

        if let Ok(h) = handle
            && h != HMODULE(std::ptr::null_mut())
        {
            // Free the library if it was loaded
            let _ = FreeLibrary(h);
            true
        } else {
            false
        }
    }
}
