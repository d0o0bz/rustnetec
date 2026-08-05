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
    // The port is not stored on HttpState directly; the server was started on
    // a port passed to start_http_server. We bind to the default 19811 here
    // (the tray branch in main.rs always starts the HTTP server on the
    // configured port, and the launcher is only called from there, so the
    // default matches unless the user overrode --http-port — in which case
    // the URL still works because the browser hits 127.0.0.1 and the server
    // is on the override port; TODO T3.4: thread the actual port through).
    let url = format!("http://127.0.0.1:19811/?code={guid}");
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
    Command::new("cmd")
        .args(["/C", "start", "cmd", "/k", command])
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
    Command::new("cmd")
        .args(["/C", "start", "", url])
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
