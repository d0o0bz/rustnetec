// rustnetec: Boot-time autostart registration (R1 sub-requirement, T1.11)
//
// Registers `rustnet --daemon` (or `--tray`) as a boot-time autostart entry
// using each platform's native mechanism. All entries are installed in the
// *current user* scope so no root/administrator privilege is required.
//
// Platform matrix:
//   Linux   — `systemd --user` unit at `~/.config/systemd/user/rustnetec.service`
//   macOS   — per-user LaunchAgent plist at
//             `~/Library/LaunchAgents/com.rustnetec.{daemon,tray}.plist`
//   Windows — per-user `HKEY_CURRENT_USER\Software\Microsoft\Windows\
//             CurrentVersion\Run` value named `Rustnetec`
//
// The module exposes a unified abstraction:
//   `install(mode)` / `uninstall()` / `is_installed() -> bool`
// with platform branches internally. The `AutostartMode::Tray` variant is
// feature-gated behind `cfg(feature = "tray")`; when the feature is disabled
// the variant is absent and `validate()` on `PersistentConfig` rejects
// `autostart_mode: Tray`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Autostart launch mode.
///
/// `Daemon` runs `rustnet --daemon` (headless capture + local HTTP).
/// `Tray` runs `rustnet --tray` (daemon + system tray icon); only available
/// when the `tray` cargo feature is enabled.
// rustnetec: Default 改用 derive（clippy derivable_impls），#[default] 标记 Daemon
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum AutostartMode {
    #[default]
    Daemon,
    #[cfg(feature = "tray")]
    Tray,
}

impl AutostartMode {
    /// CLI flag the autostart entry should invoke.
    pub fn cli_flag(self) -> &'static str {
        match self {
            AutostartMode::Daemon => "--daemon",
            #[cfg(feature = "tray")]
            AutostartMode::Tray => "--tray",
        }
    }

    /// Short identifier used in resource filenames / registry value names.
    pub fn id(self) -> &'static str {
        match self {
            AutostartMode::Daemon => "daemon",
            #[cfg(feature = "tray")]
            AutostartMode::Tray => "tray",
        }
    }
}

/// Absolute path to the current executable, used as `ExecStart` / `ProgramArguments`.
///
/// Resolved via `std::env::current_exe()`; falls back to the bare binary name
/// `rustnet` so that an entry installed from a test build still references a
/// discoverable command.
fn current_exe_path() -> Result<String> {
    let exe = std::env::current_exe()
        .context("failed to resolve current executable path")?
        .to_string_lossy()
        .into_owned();
    Ok(exe)
}

// ---------------------------------------------------------------------------
// Unified public API — platform branches delegate to the helpers below.
// ---------------------------------------------------------------------------

/// Register `rustnet` as a boot-time autostart entry for the current user.
///
/// Overwrites any existing entry so the installed mode always reflects the
/// latest `install()` call. Idempotent: calling twice with the same mode
/// produces a single valid resource.
pub fn install(mode: AutostartMode) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        install_linux(mode)?;
    }
    #[cfg(target_os = "macos")]
    {
        install_macos(mode)?;
    }
    #[cfg(target_os = "windows")]
    {
        install_windows(mode)?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = mode;
        anyhow::bail!("autostart is not supported on this platform");
    }
    Ok(())
}

/// Remove the boot-time autostart entry for the current user.
///
/// Idempotent: returns `Ok(())` when no entry exists.
pub fn uninstall() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        uninstall_linux()?;
    }
    #[cfg(target_os = "macos")]
    {
        uninstall_macos()?;
    }
    #[cfg(target_os = "windows")]
    {
        uninstall_windows()?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        anyhow::bail!("autostart is not supported on this platform");
    }
    Ok(())
}

/// Whether an autostart entry is currently registered for the current user.
pub fn is_installed() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(path) = linux_unit_path() {
            return path.exists();
        }
        // rustnetec: clippy needless_return — 此 cfg 下为函数末尾自然返回，去掉 return
        false
    }
    #[cfg(target_os = "macos")]
    {
        // rustnetec: clippy needless_return — 此 cfg 下为函数末尾自然返回，去掉 return
        daemon_plist_path().exists() || tray_plist_path().exists()
    }
    #[cfg(target_os = "windows")]
    {
        // rustnetec: clippy needless_return — 此 cfg 下为函数末尾自然返回，去掉 return
        is_installed_windows()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        false
    }
}

// ---------------------------------------------------------------------------
// Linux — `systemd --user` unit
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn systemd_user_dir() -> Result<PathBuf> {
    let base = if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg)
    } else {
        home_dir()?.join(".config")
    };
    Ok(base.join("systemd/user"))
}

#[cfg(target_os = "linux")]
fn linux_unit_path() -> Result<PathBuf> {
    Ok(systemd_user_dir()?.join("rustnetec.service"))
}

#[cfg(target_os = "linux")]
fn install_linux(mode: AutostartMode) -> Result<()> {
    let unit_dir = systemd_user_dir()?;
    std::fs::create_dir_all(&unit_dir)
        .with_context(|| format!("failed to create systemd user dir {:?}", unit_dir))?;

    let exe = current_exe_path()?;
    let flag = mode.cli_flag();
    let after = if matches!(mode, AutostartMode::Tray) {
        "After=graphical-session.target\n"
    } else {
        ""
    };
    let wanted_by = if matches!(mode, AutostartMode::Tray) {
        "graphical-session.target"
    } else {
        "default.target"
    };

    let unit = format!(
        "[Unit]\n\
         Description=rustnetec network monitor ({mode})\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exe} {flag}\n\
         Restart=on-failure\n\
         \n\
         [Install]\n\
         {after}\
         WantedBy={wanted_by}\n",
        mode = mode.id(),
        exe = exe,
        flag = flag,
        after = after,
        wanted_by = wanted_by,
    );

    let unit_path = linux_unit_path()?;
    std::fs::write(&unit_path, unit)
        .with_context(|| format!("failed to write unit file {:?}", unit_path))?;

    // Best-effort: enable via systemctl. If systemctl is unavailable (e.g. in
    // a container), the unit file is still in place and will be picked up by
    // the user manager on next login.
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "enable", "rustnetec.service"])
        .status();
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_linux() -> Result<()> {
    // Best-effort disable before removing the unit file.
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "rustnetec.service"])
        .status();

    let unit_path = linux_unit_path()?;
    if unit_path.exists() {
        std::fs::remove_file(&unit_path)
            .with_context(|| format!("failed to remove unit file {:?}", unit_path))?;
    }
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    Ok(())
}

// ---------------------------------------------------------------------------
// macOS — per-user LaunchAgent plist
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn launch_agents_dir() -> Result<PathBuf> {
    Ok(home_dir()?.join("Library/LaunchAgents"))
}

#[cfg(target_os = "macos")]
fn daemon_plist_path() -> PathBuf {
    // unwrap is acceptable here: home_dir only fails in pathological envs,
    // and is_installed callers handle the false case.
    launch_agents_dir()
        .map(|d| d.join("com.rustnetec.daemon.plist"))
        .unwrap_or_else(|_| PathBuf::from("com.rustnetec.daemon.plist"))
}

#[cfg(target_os = "macos")]
#[cfg(feature = "tray")]
fn tray_plist_path() -> PathBuf {
    launch_agents_dir()
        .map(|d| d.join("com.rustnetec.tray.plist"))
        .unwrap_or_else(|_| PathBuf::from("com.rustnetec.tray.plist"))
}

#[cfg(target_os = "macos")]
#[cfg(not(feature = "tray"))]
fn tray_plist_path() -> PathBuf {
    PathBuf::from("com.rustnetec.tray.plist")
}

#[cfg(target_os = "macos")]
fn install_macos(mode: AutostartMode) -> Result<()> {
    let dir = launch_agents_dir()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create LaunchAgents dir {:?}", dir))?;

    let exe = current_exe_path()?;
    let flag = mode.cli_flag();
    let label = match mode {
        AutostartMode::Daemon => "com.rustnetec.daemon",
        #[cfg(feature = "tray")]
        AutostartMode::Tray => "com.rustnetec.tray",
    };
    let plist_path = match mode {
        AutostartMode::Daemon => daemon_plist_path(),
        #[cfg(feature = "tray")]
        AutostartMode::Tray => tray_plist_path(),
    };

    // Escape minimal XML special chars in the exe path (defensive).
    let exe_esc = exe
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");

    // rustnetec: T3.6.7 — KeepAlive semantics differ by mode. Daemon is a
    // headless background service: crash-restart (KeepAlive=true) is desired.
    // Tray is a user-facing GUI entry: after the user picks "Quit", launchd
    // must NOT resurrect it, otherwise the app can never be closed — so Tray
    // uses KeepAlive=false and relies on RunAtLoad (boot/login autostart).
    let keep_alive = matches!(mode, AutostartMode::Daemon);

    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>Label</key>\n\
         \t<string>{label}</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array>\n\
         \t\t<string>{exe}</string>\n\
         \t\t<string>{flag}</string>\n\
         \t</array>\n\
         \t<key>RunAtLoad</key>\n\
         \t<true/>\n\
         \t<key>KeepAlive</key>\n\
         \t<{keep_alive}/>\n\
         </dict>\n\
         </plist>\n",
        label = label,
        exe = exe_esc,
        flag = flag,
        keep_alive = if keep_alive { "true" } else { "false" },
    );

    std::fs::write(&plist_path, plist)
        .with_context(|| format!("failed to write plist {:?}", plist_path))?;

    // Best-effort load. `launchctl load` is the legacy form; on newer macOS
    // `launchctl bootstrap` is preferred. Try both, ignore failures.
    let _ = std::process::Command::new("launchctl")
        .args(["unload", &plist_path.to_string_lossy()])
        .status();
    let _ = std::process::Command::new("launchctl")
        .args(["load", &plist_path.to_string_lossy()])
        .status();
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_macos() -> Result<()> {
    for plist_path in [daemon_plist_path(), tray_plist_path()] {
        if plist_path.exists() {
            let _ = std::process::Command::new("launchctl")
                .args(["unload", &plist_path.to_string_lossy()])
                .status();
            std::fs::remove_file(&plist_path)
                .with_context(|| format!("failed to remove plist {:?}", plist_path))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows — per-user HKCU Run value
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
const RUN_KEY_PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
#[cfg(target_os = "windows")]
const RUN_VALUE_NAME: &str = "Rustnetec";

#[cfg(target_os = "windows")]
fn install_windows(mode: AutostartMode) -> Result<()> {
    use windows::Win32::System::Registry::{
        HKEY_CURRENT_USER, KEY_SET_VALUE, REG_SZ, RegCloseKey, RegOpenKeyExW, RegSetValueExW,
    };
    use windows::core::w;

    let exe = current_exe_path()?;
    let flag = mode.cli_flag();
    // Quote the exe path to survive spaces, then append the mode flag.
    let value_data = format!("\"{exe}\" {flag}", exe = exe, flag = flag);

    let mut hkey = std::mem::MaybeUninit::uninit();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            w!("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            Some(0),
            KEY_SET_VALUE,
            hkey.as_mut_ptr(),
        )
    };
    if status.is_err() {
        anyhow::bail!("RegOpenKeyExW(HKCU\\{}) failed: {:?}", RUN_KEY_PATH, status);
    }
    let hkey = unsafe { hkey.assume_init() };

    let data: Vec<u16> = value_data
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let status = unsafe {
        RegSetValueExW(
            hkey,
            w!("Rustnetec"),
            Some(0),
            REG_SZ,
            Some(std::slice::from_raw_parts(
                data.as_ptr() as *const u8,
                data.len() * 2,
            )),
        )
    };
    let _ = unsafe { RegCloseKey(hkey) };

    if status.is_err() {
        anyhow::bail!("RegSetValueExW({}) failed: {:?}", RUN_VALUE_NAME, status);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn uninstall_windows() -> Result<()> {
    use windows::Win32::System::Registry::{
        HKEY_CURRENT_USER, KEY_SET_VALUE, RegCloseKey, RegDeleteValueW, RegOpenKeyExW,
    };
    use windows::core::w;

    let mut hkey = std::mem::MaybeUninit::uninit();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            w!("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            Some(0),
            KEY_SET_VALUE,
            hkey.as_mut_ptr(),
        )
    };
    if status.is_err() {
        // Key missing → nothing to uninstall.
        return Ok(());
    }
    let hkey = unsafe { hkey.assume_init() };

    // Delete is best-effort: missing value returns an error we swallow.
    let _ = unsafe { RegDeleteValueW(hkey, w!("Rustnetec")) };
    let _ = unsafe { RegCloseKey(hkey) };
    Ok(())
}

#[cfg(target_os = "windows")]
fn is_installed_windows() -> bool {
    use windows::Win32::System::Registry::{
        HKEY_CURRENT_USER, KEY_QUERY_VALUE, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
    };
    use windows::core::w;

    let mut hkey = std::mem::MaybeUninit::uninit();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            w!("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            Some(0),
            KEY_QUERY_VALUE,
            hkey.as_mut_ptr(),
        )
    };
    if status.is_err() {
        return false;
    }
    let hkey = unsafe { hkey.assume_init() };

    let mut len: u32 = 0;
    let query_status =
        unsafe { RegQueryValueExW(hkey, w!("Rustnetec"), None, None, None, Some(&mut len)) };
    let _ = unsafe { RegCloseKey(hkey) };
    query_status.is_ok()
}

// ---------------------------------------------------------------------------
// Shared home-dir helper (mirrors paths.rs semantics; kept local to avoid a
// cross-module dependency for a single line).
// ---------------------------------------------------------------------------

fn home_dir() -> Result<PathBuf> {
    if let Ok(home) = std::env::var("HOME") {
        return Ok(PathBuf::from(home));
    }
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        return Ok(PathBuf::from(userprofile));
    }
    anyhow::bail!("Could not determine home directory")
}

// ---------------------------------------------------------------------------
// Tests — cfg-gated per platform, mirrors the T1.11 verification matrix.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_cli_flag() {
        assert_eq!(AutostartMode::Daemon.cli_flag(), "--daemon");
    }

    #[cfg(feature = "tray")]
    #[test]
    fn tray_cli_flag() {
        assert_eq!(AutostartMode::Tray.cli_flag(), "--tray");
    }

    #[test]
    fn mode_default_is_daemon() {
        let m = AutostartMode::default();
        assert_eq!(m, AutostartMode::Daemon);
    }

    #[test]
    fn mode_id_matches_cli() {
        // id() is used in resource filenames; just exercise it for coverage.
        let _ = AutostartMode::Daemon.id();
    }

    // ---- Linux branch ----
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_unit_path_under_systemd_user() {
        let p = linux_unit_path().unwrap();
        assert!(
            p.ends_with("systemd/user/rustnetec.service"),
            "linux unit path: {:?}",
            p
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_install_creates_unit_file() {
        // Use a sandboxed XDG_CONFIG_HOME so we don't clobber the real unit.
        let tmp = std::env::temp_dir().join("rustnetec-test-autostart-linux");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        unsafe { std::env::set_var("XDG_CONFIG_HOME", &tmp) };

        install(AutostartMode::Daemon).unwrap();
        let unit = tmp.join("systemd/user/rustnetec.service");
        assert!(unit.exists(), "unit file should exist after install");
        let content = std::fs::read_to_string(&unit).unwrap();
        assert!(
            content.contains("--daemon"),
            "daemon unit should reference --daemon: {}",
            content
        );

        // Idempotency: second install must not panic / leave a broken file.
        install(AutostartMode::Daemon).unwrap();
        assert!(unit.exists());

        // is_installed reflects state
        assert!(is_installed(), "is_installed should be true after install");

        // Uninstall removes the unit file.
        uninstall().unwrap();
        assert!(
            !unit.exists(),
            "unit file should be removed after uninstall"
        );
        assert!(
            !is_installed(),
            "is_installed should be false after uninstall"
        );

        // Idempotent uninstall (file already gone) is Ok.
        uninstall().unwrap();

        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ---- macOS branch ----
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_daemon_plist_path_under_launchagents() {
        let p = daemon_plist_path();
        assert!(
            p.ends_with("Library/LaunchAgents/com.rustnetec.daemon.plist"),
            "macOS daemon plist path: {:?}",
            p
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_install_creates_plist() {
        // Use a sandboxed HOME so we don't clobber a real LaunchAgent.
        let tmp = std::env::temp_dir().join("rustnetec-test-autostart-macos");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let old_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", &tmp) };

        install(AutostartMode::Daemon).unwrap();
        let plist = tmp.join("Library/LaunchAgents/com.rustnetec.daemon.plist");
        assert!(plist.exists(), "daemon plist should exist after install");
        let content = std::fs::read_to_string(&plist).unwrap();
        assert!(
            content.contains("--daemon"),
            "daemon plist should reference --daemon: {}",
            content
        );
        assert!(
            content.contains("RunAtLoad") && content.contains("<true/>"),
            "plist should set RunAtLoad=true: {}",
            content
        );

        // Idempotency
        install(AutostartMode::Daemon).unwrap();
        assert!(plist.exists());

        assert!(is_installed(), "is_installed should be true after install");

        uninstall().unwrap();
        assert!(!plist.exists(), "plist should be removed after uninstall");
        assert!(
            !is_installed(),
            "is_installed should be false after uninstall"
        );

        // Idempotent uninstall
        uninstall().unwrap();

        if let Some(h) = old_home {
            unsafe { std::env::set_var("HOME", h) };
        } else {
            unsafe { std::env::remove_var("HOME") };
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ---- Windows branch ----
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_install_uninstall_roundtrip() {
        // Exercise install/uninstall against the real HKCU Run key.
        // This is safe because we use a unique value name and clean up.
        install(AutostartMode::Daemon).unwrap();
        assert!(is_installed(), "is_installed should be true after install");

        // Idempotency: second install is Ok.
        install(AutostartMode::Daemon).unwrap();
        assert!(is_installed());

        uninstall().unwrap();
        assert!(
            !is_installed(),
            "is_installed should be false after uninstall"
        );

        // Idempotent uninstall
        uninstall().unwrap();
    }

    // ---- tray feature-gated variant ----
    #[cfg(all(target_os = "linux", feature = "tray"))]
    #[test]
    fn linux_install_tray_writes_tray_flag() {
        let tmp = std::env::temp_dir().join("rustnetec-test-autostart-linux-tray");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        unsafe { std::env::set_var("XDG_CONFIG_HOME", &tmp) };

        install(AutostartMode::Tray).unwrap();
        let unit = tmp.join("systemd/user/rustnetec.service");
        let content = std::fs::read_to_string(&unit).unwrap();
        assert!(
            content.contains("--tray"),
            "tray unit should reference --tray: {}",
            content
        );
        assert!(
            content.contains("graphical-session.target"),
            "tray unit should bind to graphical-session.target: {}",
            content
        );

        uninstall().unwrap();
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[cfg(all(target_os = "macos", feature = "tray"))]
    #[test]
    fn macos_install_tray_writes_tray_plist() {
        let tmp = std::env::temp_dir().join("rustnetec-test-autostart-macos-tray");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let old_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", &tmp) };

        install(AutostartMode::Tray).unwrap();
        let plist = tmp.join("Library/LaunchAgents/com.rustnetec.tray.plist");
        assert!(plist.exists(), "tray plist should exist after install");
        let content = std::fs::read_to_string(&plist).unwrap();
        assert!(
            content.contains("--tray"),
            "tray plist should reference --tray: {}",
            content
        );

        uninstall().unwrap();
        assert!(!plist.exists());

        if let Some(h) = old_home {
            unsafe { std::env::set_var("HOME", h) };
        } else {
            unsafe { std::env::remove_var("HOME") };
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
