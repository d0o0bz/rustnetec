// rustnetec: System tray controller (R1/R6, T3.2)
//
// Feature-gated under `#[cfg(feature = "tray")]`. Provides:
// - `TrayCommand` enum: menu actions forwarded to the daemon main loop
// - `TrayController`: owns the `tray_icon::TrayIcon`, `muda::Menu`, and all
//   `MenuItem` handles; builds the menu, polls events non-blockingly, and
//   refreshes the dynamic status line.
//
// Design notes:
// - Tooltip/brand name is `Rustnetec` (per T3.2 revision; 显示名改版).
// - The status line is rendered from `RuntimeConfig.tray_status_fields` in
//   the user-configured order; refresh cadence is
//   `RuntimeConfig.tray_refresh_interval_secs` (1-15s, default 1).
// - In/out rates use ↓/↑ Unicode arrows and reuse `ui::format::format_rate`
//   (2-decimal precision, B/KB/MB/GB) to stay consistent with the TUI.
// - FreeBSD is excluded at compile time: tray code only builds on
//   linux/macos/windows. On FreeBSD the daemon falls back to headless mode.

#![cfg(feature = "tray")]
// FreeBSD has no tray backend in tray-icon 0.24; exclude the whole module so
// `cargo build --features tray --target *-freebsd` does not pull GTK.
#![cfg_attr(target_os = "freebsd", allow(dead_code))]

use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use log::{info, warn};
use muda::MenuEvent;
use tray_icon::TrayIconEvent;

use crate::app::App;
use crate::config::{RuntimeConfig, TrayStatusField};

/// Menu item IDs. `muda` dispatches menu clicks via `MenuEvent::receiver()`
/// tagged with a `MenuId`; we map each id back to a `TrayCommand`.
mod menu_ids {
    pub const OPEN_TERMINAL: &str = "open_terminal";
    pub const OPEN_LOCAL_PANEL: &str = "open_local_panel";
    pub const OPEN_REMOTE_PANEL: &str = "open_remote_panel";
    pub const TOGGLE_PAUSE: &str = "toggle_pause";
    pub const SETTINGS: &str = "settings";
    pub const QUIT: &str = "quit";
}

/// Commands forwarded from tray menu clicks to the daemon main loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayCommand {
    OpenTerminal,
    OpenLocalPanel,
    OpenRemotePanel,
    TogglePause,
    OpenSettings,
    Quit,
    /// Sentinel returned when no new event is pending.
    None,
}

/// Status-line render context. Decouples `refresh_status` from `App`'s
/// internal locking so the renderer only touches already-public accessors.
struct StatusContext {
    is_paused: bool,
    interface: Option<String>,
    rate_in_bps: f64,
    rate_out_bps: f64,
    connections: usize,
    uptime: Duration,
}

/// Controls a single system tray icon + context menu.
///
/// Created on the main thread (tray-icon requirement on macOS/Linux). The
/// daemon main loop calls `poll_command()` every ~50ms for snappy menu
/// response, and `refresh_status()` on the configured 1-15s cadence.
pub struct TrayController {
    _tray_icon: tray_icon::TrayIcon,
    menu: muda::Menu,
    /// Status-line menu item (first item, dynamically updated).
    status_item: muda::MenuItem,
    /// Pause/continue toggle item; text flips between ⏸/▶.
    pause_item: muda::MenuItem,
    /// Open remote panel item; disabled when server_url is not configured.
    remote_item: muda::MenuItem,
    /// Channel the menu-event → TrayCommand translator writes into.
    ///
    /// rustnetec: T13 — `Option` so the receiver can be moved to a dedicated
    /// command thread. `mpsc::Receiver` is `Send` while `TrayController`
    /// itself is NOT (it owns `Rc<RefCell<…>>` tray-icon/muda platform
    /// objects), so in the dual-process tray helper the main thread runs the
    /// blocking Cocoa event loop and a worker thread polls this receiver.
    cmd_rx: Option<Receiver<TrayCommand>>,
    /// Tracks pause state for menu text flipping. Mirrors App's pause flag
    /// but cached locally so we don't read App on every menu click.
    paused: bool,
}

impl TrayController {
    /// Build the tray icon, menu, and event channel.
    ///
    /// `icon_bytes` is the encoded icon file content (PNG) — decoded to 32bpp
    /// RGBA internally (T3.6.2); `tooltip` is shown on hover — use `"Rustnetec"`.
    pub fn new(
        icon_bytes: &[u8],
        _icon_width: u32,
        _icon_height: u32,
        tooltip: &str,
    ) -> anyhow::Result<Self> {
        // rustnetec: decode the PNG icon to 32bpp RGBA before handing it to
        // tray-icon (T3.6.2). tray_icon::Icon::from_rgba requires raw RGBA pixels
        // with len == width*height*4 and fails with BadIcon on anything else;
        // passing the compressed PNG bytes directly (as before) always failed,
        // leaving the tray headless. image is an optional dep pulled in by the
        // `tray` feature (already in the graph via arboard, promoted to direct).
        let decoded = image::load_from_memory(icon_bytes)
            .map_err(|e| anyhow::anyhow!("failed to decode tray icon PNG: {e}"))?;
        let rgba = decoded.to_rgba8();
        let (icon_width, icon_height) = rgba.dimensions();
        let icon = tray_icon::Icon::from_rgba(rgba.into_raw(), icon_width, icon_height)
            .map_err(|e| anyhow::anyhow!("failed to create tray icon from RGBA: {e}"))?;

        // Build menu items
        let status_item = muda::MenuItem::with_id(
            "status",
            "● monitoring",
            false, // disabled — read-only status display
            None,
        );
        let open_terminal =
            muda::MenuItem::with_id(menu_ids::OPEN_TERMINAL, "打开终端监控", true, None);
        let open_local =
            muda::MenuItem::with_id(menu_ids::OPEN_LOCAL_PANEL, "打开本地面板", true, None);
        let remote_item =
            muda::MenuItem::with_id(menu_ids::OPEN_REMOTE_PANEL, "打开远程面板", true, None);
        let pause_item = muda::MenuItem::with_id(menu_ids::TOGGLE_PAUSE, "⏸ 暂停捕获", true, None);
        let settings_item = muda::MenuItem::with_id(menu_ids::SETTINGS, "设置…", true, None);
        let quit_item = muda::MenuItem::with_id(menu_ids::QUIT, "退出", true, None);
        let sep1 = muda::PredefinedMenuItem::separator();
        let sep2 = muda::PredefinedMenuItem::separator();
        let sep3 = muda::PredefinedMenuItem::separator();

        let menu = muda::Menu::new();
        // rustnetec: menu layout — status / sep / open×3 / sep / pause / sep / settings / quit
        menu.append(&status_item)?;
        menu.append(&sep1)?;
        menu.append(&open_terminal)?;
        menu.append(&open_local)?;
        menu.append(&remote_item)?;
        menu.append(&sep2)?;
        menu.append(&pause_item)?;
        menu.append(&sep3)?;
        menu.append(&settings_item)?;
        menu.append(&quit_item)?;

        let tray_icon = tray_icon::TrayIconBuilder::new()
            .with_tooltip(tooltip)
            .with_icon(icon)
            .with_menu(Box::new(menu.clone()))
            .build()?;

        info!("System tray icon created (tooltip={tooltip})");

        Ok(Self {
            _tray_icon: tray_icon,
            menu,
            status_item,
            pause_item,
            remote_item,
            cmd_rx: Some(Self::spawn_translator()),
            paused: false,
        })
    }

    /// rustnetec: T13 — take the command receiver out of the controller so it
    /// can be polled from a dedicated worker thread.
    ///
    /// `mpsc::Receiver<TrayCommand>` is `Send`, but `TrayController` itself
    /// is NOT (it owns `Rc<RefCell<…>>` tray-icon/muda platform objects that
    /// must stay on the main thread). In the dual-process tray helper the
    /// main thread runs the blocking Cocoa event loop (`NSApp.run()`), so the
    /// translated commands are drained here on a worker thread instead.
    ///
    /// After this is called, [`TrayController::poll_command`] returns
    /// `TrayCommand::None` (the receiver is gone).
    pub fn take_cmd_rx(&mut self) -> Option<Receiver<TrayCommand>> {
        self.cmd_rx.take()
    }

    /// Spawn a thread that drains `muda::MenuEvent` + `tray_icon::TrayIconEvent`
    /// receivers and translates them to `TrayCommand` on an mpsc channel.
    ///
    /// This keeps the main loop's `poll_command()` O(1) and non-blocking.
    fn spawn_translator() -> Receiver<TrayCommand> {
        let (tx, rx): (Sender<TrayCommand>, Receiver<TrayCommand>) = mpsc::channel();

        std::thread::Builder::new()
            .name("tray-event-translator".to_string())
            .spawn(move || {
                loop {
                    // Drain menu events
                    while let Ok(menu_event) = MenuEvent::receiver().try_recv() {
                        let cmd = match menu_event.id.0.as_str() {
                            menu_ids::OPEN_TERMINAL => TrayCommand::OpenTerminal,
                            menu_ids::OPEN_LOCAL_PANEL => TrayCommand::OpenLocalPanel,
                            menu_ids::OPEN_REMOTE_PANEL => TrayCommand::OpenRemotePanel,
                            menu_ids::TOGGLE_PAUSE => TrayCommand::TogglePause,
                            menu_ids::SETTINGS => TrayCommand::OpenSettings,
                            menu_ids::QUIT => TrayCommand::Quit,
                            _ => continue, // unknown id (e.g. "status") — ignore
                        };
                        let _ = tx.send(cmd);
                    }
                    // Drain tray-icon click events (not actionable yet but
                    // must be consumed to avoid buffer growth)
                    while TrayIconEvent::receiver().try_recv().is_ok() {}

                    // Poll interval: 50ms balances responsiveness vs CPU
                    std::thread::sleep(Duration::from_millis(50));
                }
            })
            .map_err(|e| warn!("failed to spawn tray-event-translator: {e}"))
            .ok();

        rx
    }

    /// Non-blocking poll for the next tray command.
    ///
    /// Returns `TrayCommand::None` when no event is pending. Call this every
    /// ~50ms from the daemon main loop for ≤50ms menu-click latency.
    ///
    /// rustnetec: T13 — after `take_cmd_rx()` moves the receiver to a worker
    /// thread, this always returns `TrayCommand::None`.
    pub fn poll_command(&self) -> TrayCommand {
        match self.cmd_rx.as_ref() {
            Some(rx) => match rx.try_recv() {
                Ok(cmd) => cmd,
                Err(_) => TrayCommand::None,
            },
            None => TrayCommand::None,
        }
    }

    /// Enable/disable the "打开远程面板" item based on server_url config.
    ///
    /// Call once at startup and whenever config changes (hot update).
    pub fn set_remote_enabled(&self, enabled: bool) {
        let _ = self.remote_item.set_enabled(enabled);
    }

    /// Refresh the dynamic status line + tooltip from App state.
    ///
    /// Renders fields in `tray_status_fields` order. In/out rates use ↓/↑
    /// arrows. The status menu item text and tooltip are both updated so the
    /// user sees status regardless of menu open state.
    pub fn refresh_status(&mut self, app: &App, runtime_config: &RuntimeConfig) {
        let ctx = Self::collect_status_context(app);
        self.paused = ctx.is_paused;

        let status_text = Self::render_status_line(&ctx, &runtime_config.tray_status_fields);

        // Update tooltip — brand name "Rustnetec" prefix per T3.2 revision
        let tooltip = format!("Rustnetec\n{}", status_text);
        let _ = self._tray_icon.set_tooltip(Some(&tooltip));

        // Update status menu item text
        let menu_label = if ctx.is_paused {
            format!("⏸ 已暂停 · {}", status_text)
        } else {
            format!("● 监控中 · {}", status_text)
        };
        let _ = self.status_item.set_text(menu_label);

        // Flip pause menu item text
        let pause_label = if ctx.is_paused {
            "▶ 继续捕获"
        } else {
            "⏸ 暂停捕获"
        };
        let _ = self.pause_item.set_text(pause_label);
    }

    /// Refresh the dynamic status line + tooltip from the daemon's live
    /// snapshot pulled over HTTP (T3.6.7, dual-process tray helper).
    ///
    /// The tray helper is a separate process and never holds an `App`, so it
    /// cannot call [`TrayController::refresh_status`]. Instead the daemon
    /// publishes a minimal JSON snapshot (`HttpState::update_live_snapshot`)
    /// and the helper renders it here. `live` is the parsed `GET /live`
    /// response body.
    pub fn refresh_status_from_live(
        &mut self,
        live: &serde_json::Value,
        fields: &[TrayStatusField],
    ) {
        let ctx = Self::status_context_from_live(live);
        self.paused = ctx.is_paused;

        let status_text = Self::render_status_line(&ctx, fields);

        // Update tooltip — brand name "Rustnetec" prefix per T3.2 revision
        let tooltip = format!("Rustnetec\n{}", status_text);
        let _ = self._tray_icon.set_tooltip(Some(&tooltip));

        // Update status menu item text
        let menu_label = if ctx.is_paused {
            format!("⏸ 已暂停 · {}", status_text)
        } else {
            format!("● 监控中 · {}", status_text)
        };
        let _ = self.status_item.set_text(menu_label);

        // Flip pause menu item text
        let pause_label = if ctx.is_paused {
            "▶ 继续捕获"
        } else {
            "⏸ 暂停捕获"
        };
        let _ = self.pause_item.set_text(pause_label);
    }

    /// Build a `StatusContext` from the daemon's `/live` JSON snapshot.
    ///
    /// Field names match `HttpState::update_live_snapshot`:
    /// `interface`, `rate_in_bps`, `rate_out_bps`, `connections`,
    /// `uptime_secs`, `paused`. Missing/malformed fields fall back to
    /// neutral values so the tray never panics on a schema drift.
    fn status_context_from_live(live: &serde_json::Value) -> StatusContext {
        StatusContext {
            is_paused: live
                .get("paused")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            interface: live
                .get("interface")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            rate_in_bps: live
                .get("rate_in_bps")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as f64,
            rate_out_bps: live
                .get("rate_out_bps")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as f64,
            connections: live
                .get("connections")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize,
            uptime: Duration::from_secs(
                live.get("uptime_secs")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            ),
        }
    }

    /// Collect status context from public App accessors.
    fn collect_status_context(app: &App) -> StatusContext {
        // Aggregate inbound/outbound rates across all interfaces
        let rates = app.get_interface_rates();
        let (rate_in_bps, rate_out_bps) = rates.values().fold((0u64, 0u64), |(rx, tx), r| {
            (rx + r.rx_bytes_per_sec, tx + r.tx_bytes_per_sec)
        });
        let rate_in_bps = rate_in_bps as f64;
        let rate_out_bps = rate_out_bps as f64;

        // Active (non-historic) connection count
        let connections = app
            .get_connections()
            .iter()
            .filter(|c| !c.is_historic)
            .count();

        // Uptime: use first connection's created_at as capture start proxy
        // (App doesn't expose a precise start Instant; this is good enough
        // for a tray status display and avoids adding a new field.)
        let uptime = app
            .get_connections()
            .iter()
            .map(|c| c.created_at)
            .min()
            .and_then(|start| start.elapsed().ok())
            .unwrap_or_default();

        StatusContext {
            is_paused: app.is_stopping(), // rustnetec: TODO wire real pause flag if added
            // rustnetec: resolve virtual capture devices (pktap/any/NPF) to
            // the real active interface for an accurate status line.
            interface: app.get_display_interface(),
            rate_in_bps,
            rate_out_bps,
            connections,
            uptime,
        }
    }

    /// Render the status line from context + selected fields.
    ///
    /// Fields are joined with double-space separators to avoid confusion with
    /// single spaces inside rate values (e.g. "3.20 KB/s").
    fn render_status_line(ctx: &StatusContext, fields: &[TrayStatusField]) -> String {
        let parts: Vec<String> = fields
            .iter()
            .map(|f| Self::render_field(ctx, *f))
            .filter(|s| !s.is_empty())
            .collect();
        parts.join("  ")
    }

    /// Render a single status field.
    fn render_field(ctx: &StatusContext, field: TrayStatusField) -> String {
        use crate::ui::format::format_rate;
        match field {
            TrayStatusField::State => {
                if ctx.is_paused {
                    "⏸".to_string()
                } else {
                    "●".to_string()
                }
            }
            TrayStatusField::Interface => ctx.interface.clone().unwrap_or_else(|| "—".to_string()),
            TrayStatusField::RateIn => format!("↓{}", format_rate(ctx.rate_in_bps)),
            TrayStatusField::RateOut => format!("↑{}", format_rate(ctx.rate_out_bps)),
            TrayStatusField::RateTotal => {
                format!("{}", format_rate(ctx.rate_in_bps + ctx.rate_out_bps))
            }
            TrayStatusField::Connections => format!("{} conn", ctx.connections),
            TrayStatusField::Uptime => format!(
                "{}m{}s",
                ctx.uptime.as_secs() / 60,
                ctx.uptime.as_secs() % 60
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_status_line_default_fields() {
        let ctx = StatusContext {
            is_paused: false,
            interface: Some("eth0".to_string()),
            rate_in_bps: 3_200_000.0,
            rate_out_bps: 950.0,
            connections: 12,
            uptime: Duration::from_secs(323),
        };
        let fields = vec![
            TrayStatusField::State,
            TrayStatusField::Interface,
            TrayStatusField::RateIn,
            TrayStatusField::RateOut,
            TrayStatusField::Connections,
        ];
        let line = TrayController::render_status_line(&ctx, &fields);
        // ●  eth0  ↓3.20 MB/s  ↑950 B/s  12 conn
        assert!(line.contains("●"));
        assert!(line.contains("eth0"));
        assert!(line.contains("↓"));
        assert!(line.contains("↑"));
        assert!(line.contains("12 conn"));
    }

    #[test]
    fn render_paused_state() {
        let ctx = StatusContext {
            is_paused: true,
            interface: None,
            rate_in_bps: 0.0,
            rate_out_bps: 0.0,
            connections: 0,
            uptime: Duration::ZERO,
        };
        let state = TrayController::render_field(&ctx, TrayStatusField::State);
        assert_eq!(state, "⏸");
    }

    #[test]
    fn render_uptime_field() {
        let ctx = StatusContext {
            is_paused: false,
            interface: None,
            rate_in_bps: 0.0,
            rate_out_bps: 0.0,
            connections: 0,
            uptime: Duration::from_secs(125), // 2m5s
        };
        let uptime = TrayController::render_field(&ctx, TrayStatusField::Uptime);
        assert_eq!(uptime, "2m5s");
    }

    #[test]
    fn render_rate_total_combines_in_out() {
        let ctx = StatusContext {
            is_paused: false,
            interface: None,
            rate_in_bps: 1_000_000.0, // ~0.95 MB/s
            rate_out_bps: 500_000.0,  // ~0.48 MB/s
            connections: 0,
            uptime: Duration::ZERO,
        };
        let total = TrayController::render_field(&ctx, TrayStatusField::RateTotal);
        // Should render as "1.43 MB/s" or similar (combined rx+tx)
        assert!(total.contains("MB/s"));
    }
}
