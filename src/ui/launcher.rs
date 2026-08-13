// rustnetec: Cross-platform launcher for the tray menu (R6, T3.3)
//
// Feature-gated under `#[cfg(feature = "tray")]` because the launcher is only
// called from tray menu handlers. Provides:
// - `open_terminal(command)`: open a new terminal window and run a command
// - `open_browser(url)`: open a URL in the default browser
// - `open_local_panel(state)`: bootstrap-handshake path — issues a one-time
//   guid via `HttpState::issue_bootstrap_guid`, builds
//   `http://127.0.0.1:<port>/?code=<guid>`, and opens the browser so the
//   server redeems the guid and issues a session cookie (no token in URL
//   history, no manual paste).
//
// All platform spawns fall back to copying the command/URL to the clipboard
// (via `arboard` directly — the existing `clipboard.rs::copy_to_clipboard`
// needs a `UIState`, which daemon/tray mode does not have) so the user can
// paste it manually when no terminal/browser is available (headless boxes,
// missing xdg-open, etc.).

#![cfg(feature = "tray")]

use std::process::Command;

use log::{info, warn};

use crate::telemetry::http::HttpState;

/// Open a new terminal window and execute `command` in it.
///
/// Platform behavior:
/// - macOS: `osascript` tells Terminal.app to run the command in a new window.
///   `open -a Terminal` alone only opens an empty window; the AppleScript path
///   actually injects the command.
/// - Linux: `x-terminal-emulator -e "<command>"` (Debian alternatives); falls
///   back to `gnome-terminal --`, `konsole -e`, `xterm -e` if the launcher is
///   absent.
/// - Windows: `cmd /C start cmd /k "<command>"` opens a new cmd window that
///   stays open (`/k`) so the user can read the output.
///
/// On spawn failure, copies `command` to the clipboard so the user can paste
/// it into a terminal they open themselves.
pub fn open_terminal(command: &str) {
    let spawned = dispatch_terminal(command);
    if spawned {
        info!("Launched terminal for command: {command}");
    } else {
        warn!("Failed to launch terminal for command: {command}; copying to clipboard as fallback");
        copy_to_clipboard_fallback(command);
    }
}

/// rustnetec: Open the full front-end TUI monitor (方案 B, single-instance).
///
/// TUI mode (plain `rustnet`, no flags) writes its PID to
/// `<data_dir>/tui.pid` at startup and removes it on exit (see main.rs).
/// Here we: if a TUI instance is already alive, focus its terminal window
/// (macOS: activate the Terminal window whose title matches "Rustnetec");
/// otherwise open a new terminal running this binary in TUI mode. Either
/// way only ONE front-end TUI window ever runs.
pub fn open_terminal_monitor() {
    if let Some(pid) = tui_pid_alive() {
        info!("TUI already running (pid {pid}) — focusing its terminal window");
        if activate_tui_terminal() {
            return;
        }
        warn!("Failed to focus existing TUI window; opening a new one");
    }
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "rustnet".to_string());
    #[cfg(unix)]
    let quoted = format!("'{}'", exe.replace('\'', "'\\''"));
    // rustnetec: 前台 TUI 抓包需要 root（BPF 设备），unix 下用 sudo 启动；
    // 密码由用户在打开的 Terminal 窗口输入（sudo 会提示）。Windows 无 sudo：
    // Npcap 以 admin_only=no（安装向导里取消勾选 "Restrict Npcap driver's
    // access to Administrators only"）安装后，普通用户即可直接抓包，无需提权，
    // 保持原样。
    // 注意：
    // 1. macOS sudo 默认 env_reset 会把 HOME 重置为 /var/root，导致 TUI 的
    //    data_dir()/config.yml 错位到 root 的 HOME（tui.pid 写进 /var/root，
    //    launcher 读不到 → 单实例失效；config.yml/token 也不一致），故显式
    //    保留用户 HOME。
    // 2. 命令会被 osascript 以 `do script "..."` 包裹（AppleScript 字符串），
    //    命令中的任何 `"` 都会提前终止字符串 → syntax error (-2740)。所以
    //    HOME 必须内联为实际值并用单引号包裹，绝不能写 `HOME="$HOME"`。
    #[cfg(unix)]
    let cmd = {
        let home = std::env::var("HOME").unwrap_or_default();
        let home_quoted = format!("'{}'", home.replace('\'', "'\\''"));
        format!("sudo env HOME={home_quoted} {quoted}")
    };
    #[cfg(windows)]
    let cmd = format!("\"{}\"", exe);
    open_terminal(&cmd);
}

/// rustnetec: Read `<data_dir>/tui.pid` and return the PID if that process
/// is still alive. `None` when no TUI is running (file missing / stale pid /
/// dead process).
fn tui_pid_alive() -> Option<u32> {
    let dir = crate::telemetry::paths::data_dir().ok()?;
    let pid: u32 = std::fs::read_to_string(dir.join("tui.pid")).ok()?.trim().parse().ok()?;
    process_alive(pid).then_some(pid)
}

/// rustnetec: Return `true` if the process with `pid` is running.
#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    // kill(pid, 0) performs a zero-signal existence check, no signal sent.
    // The TUI runs under sudo (root): a non-root launcher gets EPERM from
    // kill(pid, 0) on a root process — that still means the process EXISTS,
    // so EPERM must be treated as alive, not as "not running".
    let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if ret == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(windows)]
fn process_alive(pid: u32) -> bool {
    // Minimal: check the process still exists via OpenProcess with a zero
    // access query. Windows crate is already a dependency of the bin.
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    let handle = unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()
    };
    match handle {
        Some(h) => {
            unsafe { let _ = CloseHandle(h); }
            true
        }
        None => false,
    }
}

/// rustnetec: 启动时询问是否安装 LaunchDaemon 永久授权（T4.2 配套）。
///
/// 托盘启动时若检测到未安装 LaunchDaemon（daemon 每次都要弹授权窗口），
/// 弹原生对话框引导用户选择是否现在安装。返回 `true` = 用户选择
/// 「现在授权」（调用方随后执行 `telemetry::launchdaemon::install`）；
/// `false` = 用户选择「暂不」（调用方继续原流程：osascript 弹窗提权启动
/// daemon，保持现状）。非 macOS 无 LaunchDaemon，恒返回 `false`。
pub fn prompt_launchdaemon_install() -> bool {
    #[cfg(target_os = "macos")]
    {
        // 命令经 osascript `-e` 直接执行（非 do script 字符串），无引号冲突；
        // 对话框按钮返回值是 "button returned:现在授权"。
        let script = "display dialog \"未检测到永久授权（LaunchDaemon）。是否现在通过系统授权安装？安装后 daemon 将由系统托管，无需重复授权。\" buttons {\"暂不\", \"现在授权\"} default button \"现在授权\" with icon caution";
        let confirmed = Command::new("osascript")
            .args(["-e", script])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("现在授权"))
            .unwrap_or(false);
        if confirmed {
            info!("User chose to install the LaunchDaemon (permanent authorization)");
        } else {
            info!("User chose to skip LaunchDaemon install — continuing with per-launch auth");
        }
        confirmed
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// rustnetec: 退出托盘前询问是否一起关闭前台 TUI（方案 B 配套）。
///
/// 若前台 TUI 正在运行（`tui.pid` 存活），macOS 弹原生对话框询问；
/// 用户确认后关闭标题含 "Rustnetec" 的 Terminal 窗口——窗口关闭会终止
/// 其中以 sudo 运行的 TUI 进程（shell 收到 SIGHUP），无需额外 kill
/// （托盘是普通用户，直接 kill root 的 TUI 进程也会 EPERM）。
///
/// 返回 `true` 表示 TUI 已关闭或本就不存在（无需询问）；
/// `false` 表示用户选择保留 TUI，仅退出托盘。
pub fn close_tui_if_confirmed() -> bool {
    if tui_pid_alive().is_none() {
        return true; // 没有前台 TUI，无需询问
    }
    #[cfg(target_os = "macos")]
    {
        // rustnetec: 命令会被 osascript 以 `-e` 参数直接执行（非 do script
        // 字符串），无 AppleScript 引号冲突；对话框按钮返回值是
        // "button returned:一起关闭"。
        let script = "display dialog \"检测到前台 TUI 正在运行，是否一起关闭？\" buttons {\"取消\", \"一起关闭\"} default button \"一起关闭\" with icon caution";
        let confirmed = Command::new("osascript")
            .args(["-e", script])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("一起关闭"))
            .unwrap_or(false);
        if !confirmed {
            info!("User chose to keep the TUI running; quitting tray only");
            return false;
        }
        info!("User confirmed — closing the TUI window together");
        close_tui_window()
    }
    #[cfg(not(target_os = "macos"))]
    {
        // 非 macOS：无可靠的原生窗口关闭/对话框，保守保留 TUI。
        warn!("close_tui_if_confirmed: dialog not implemented on this platform");
        false
    }
}

/// rustnetec: Close the Terminal window running the TUI (macOS).
///
/// Closing the window terminates the sudo'd TUI process inside it (the
/// shell receives SIGHUP), and the TUI's cleanup removes `tui.pid` on exit.
#[cfg(target_os = "macos")]
fn close_tui_window() -> bool {
    let script =
        "tell application \"Terminal\" to close (first window whose name contains \"Rustnetec\")";
    Command::new("osascript")
        .arg("-e")
        .arg(script)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// rustnetec: Focus the terminal window running the TUI (macOS).
///
/// The TUI sets its window title to "Rustnetec Monitor" (crossterm SetTitle),
/// so we ask Terminal.app to activate and bring the matching window to the
/// front. Returns `false` when no matching window is found (e.g. the TUI is
/// running in iTerm or a remote session) so the caller can fall back.
#[cfg(target_os = "macos")]
fn activate_tui_terminal() -> bool {
    let script = "tell application \"Terminal\"\n\
                  \tactivate\n\
                  \tset tuiWin to first window whose name contains \"Rustnetec\"\n\
                  \tset index of tuiWin to 1\n\
                  end tell";
    Command::new("osascript")
        .arg("-e")
        .arg(script)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// rustnetec: Focus the TUI terminal window (non-macOS). Best-effort: no
/// reliable per-window activation is available, so report "already running"
/// without opening a duplicate.
#[cfg(not(target_os = "macos"))]
fn activate_tui_terminal() -> bool {
    false
}

/// Open `url` in the default web browser.
///
/// Platform behavior:
/// - macOS: `open <url>`
/// - Linux: `xdg-open <url>`
/// - Windows: `cmd /C start "" "<url>"` (the empty title arg stops `start`
///   from interpreting a URL starting with `/` as a flag).
///
/// On spawn failure, copies `url` to the clipboard.
pub fn open_browser(url: &str) {
    let spawned = dispatch_browser(url);
    if spawned {
        info!("Launched browser for URL: {url}");
    } else {
        warn!("Failed to launch browser for URL: {url}; copying to clipboard as fallback");
        copy_to_clipboard_fallback(url);
    }
}

/// Open the local HTTP panel with a one-time bootstrap guid.
///
/// The guid is redeemed by the HTTP server on first hit, which issues a
/// session cookie — so the Bearer token never lands in browser URL history.
/// The port is read from the running HTTP state if available; falls back to
/// the default 19811 if the state was not wired in.
pub fn open_local_panel(state: &HttpState) {
    let guid = state.issue_bootstrap_guid();
    // rustnetec: read the live listen port from HttpState (T3.5) so the
    // launcher honours a user-supplied `--http-port` override instead of
    // always hitting 19811. The port is populated at HttpState construction
    // in main.rs and is the same port the server was bound to.
    let url = format!("http://127.0.0.1:{}/?code={guid}", state.http_port);
    open_browser(&url);
}

// ---- platform dispatch ----

/// Return `true` if a terminal was successfully spawned.
#[cfg(target_os = "macos")]
fn dispatch_terminal(command: &str) -> bool {
    // osascript: tell Terminal to run the command in a new window.
    // `do script` opens a new window and executes; the escaped quotes let the
    // command contain spaces/special chars.
    let script = format!("tell application \"Terminal\" to do script \"{command}\"");
    Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .spawn()
        .is_ok()
}

#[cfg(target_os = "linux")]
fn dispatch_terminal(command: &str) -> bool {
    // Try x-terminal-emulator (Debian alternatives) first, then common names.
    for (program, args) in [
        ("x-terminal-emulator", vec!["-e", command]),
        ("gnome-terminal", vec!["--", command]),
        ("konsole", vec!["-e", command]),
        ("xterm", vec!["-e", command]),
    ] {
        let mut cmd = Command::new(program);
        cmd.args(&args);
        if cmd.spawn().is_ok() {
            return true;
        }
    }
    false
}

#[cfg(target_os = "windows")]
fn dispatch_terminal(command: &str) -> bool {
    // `start cmd /k` opens a new cmd window that stays open after the command.
    // rustnetec: tray helper 已 FreeConsole, 显式 null stdio 避免继承失效句柄
    // (os error 6/50), 见 main.rs run_tray_helper 同类修复。
    use std::process::Stdio;
    Command::new("cmd")
        .args(["/C", "start", "cmd", "/k", command])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .is_ok()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn dispatch_terminal(_command: &str) -> bool {
    false
}

/// Return `true` if a browser was successfully spawned.
#[cfg(target_os = "macos")]
fn dispatch_browser(url: &str) -> bool {
    Command::new("open").arg(url).spawn().is_ok()
}

#[cfg(target_os = "linux")]
fn dispatch_browser(url: &str) -> bool {
    Command::new("xdg-open").arg(url).spawn().is_ok()
}

#[cfg(target_os = "windows")]
fn dispatch_browser(url: &str) -> bool {
    // Empty title arg stops `start` from treating a URL starting with `/` as
    // a flag.
    // rustnetec: tray helper 已 FreeConsole, 显式 null stdio 避免继承失效句柄
    // (os error 6/50), 见 main.rs run_tray_helper 同类修复。
    use std::process::Stdio;
    Command::new("cmd")
        .args(["/C", "start", "", url])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .is_ok()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn dispatch_browser(_url: &str) -> bool {
    false
}

// ---- clipboard fallback ----

/// Copy `text` to the clipboard as a manual-launch fallback.
///
/// Uses `arboard` directly (the existing `clipboard.rs::copy_to_clipboard`
/// needs a `UIState` which daemon/tray mode does not have). Failure is
/// best-effort: we log a warning and return — there is nothing more the
/// launcher can do if both the platform spawn AND the clipboard failed.
fn copy_to_clipboard_fallback(text: &str) {
    match arboard::Clipboard::new().and_then(|mut cb| cb.set_text(text)) {
        Ok(()) => info!("Copied to clipboard as launcher fallback: {text}"),
        Err(e) => warn!("Clipboard fallback also failed: {e}"),
    }
}
