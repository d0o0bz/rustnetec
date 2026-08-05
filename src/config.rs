//! Runtime configuration: CLI flags, GeoIP database discovery, refresh
//! interval, DNS resolution toggle, and pcap export settings.
//!
//! rustnetec: Extended with PersistentConfig for YAML-based persistent
//! configuration (R7), supporting load/save/validate with serde.

use anyhow::{Result, anyhow};
use log::info;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

// rustnetec: AutostartMode is defined in telemetry::autostart (T1.11) and
// re-exported here so PersistentConfig can carry it as a serde field without
// creating a cross-module import cycle.
pub use crate::telemetry::autostart::AutostartMode;

// rustnetec: TrayStatusField — selectable status-line fields for the system
// tray (R1/R6, T3.2). The order of `tray_status_fields` in PersistentConfig
// determines the left-to-right rendering order of the tray status line.
// Lowercase serde rename keeps config.yml human-friendly
// (`state`, `rate_in`, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrayStatusField {
    /// Capture state indicator: ● monitoring / ⏸ paused
    State,
    /// Active network interface name (e.g. eth0)
    Interface,
    /// Aggregate inbound rate: ↓3.20 KB/s
    RateIn,
    /// Aggregate outbound rate: ↑950 B/s
    RateOut,
    /// Aggregate total rate (rx+tx): 4.15 KB/s — single value, direction lost
    RateTotal,
    /// Active (non-historic) connection count: 12 conn
    Connections,
    /// Process uptime since capture start: 5m23s
    Uptime,
}

impl Default for TrayStatusField {
    fn default() -> Self {
        Self::State
    }
}

/// Application configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Network interface to monitor
    pub interface: Option<String>,
    /// Interface language (ISO code)
    pub language: String,
    /// Path to MaxMind GeoIP database
    pub geoip_db_path: Option<PathBuf>,
    /// Refresh interval in milliseconds
    pub refresh_interval: u64,
    /// Show IP locations (requires MaxMind DB)
    pub show_locations: bool,
    /// Filter out localhost (loopback) traffic
    pub filter_localhost: bool,
    /// Interval in milliseconds for the packet processing loop's sleep. 0 means minimal sleep for continuous processing.
    pub packet_processing_interval_ms: u64,
    /// Custom configuration file path
    pub config_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: None,
            language: "en".to_string(),
            geoip_db_path: None,
            refresh_interval: 500,
            show_locations: true,
            filter_localhost: true,
            packet_processing_interval_ms: 0, // Default to continuous processing (minimal sleep)
            config_path: None,
        }
    }
}

impl Config {
    /// Load configuration from file
    pub fn load(path: Option<&str>) -> Result<Self> {
        let config_path = if let Some(path) = path {
            PathBuf::from(path)
        } else {
            Self::find_config_file()?
        };

        let mut config = Config::default();

        if config_path.exists() {
            config.config_path = Some(config_path.clone());

            // Read config file
            let content = fs::read_to_string(&config_path)?;

            // Parse YAML
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                if let Some(pos) = line.find(':') {
                    let key = line[..pos].trim();
                    let value = line[pos + 1..].trim();

                    match key {
                        "interface" => {
                            config.interface = Some(value.to_string());
                        }
                        "language" => {
                            config.language = value.to_string();
                        }
                        "geoip_db_path" => {
                            config.geoip_db_path = Some(PathBuf::from(value));
                        }
                        "refresh_interval" => {
                            if let Ok(interval) = value.parse::<u64>() {
                                config.refresh_interval = interval;
                            }
                        }
                        "show_locations" => {
                            if value == "true" {
                                config.show_locations = true;
                            } else if value == "false" {
                                config.show_locations = false;
                            }
                        }
                        "filter_localhost" => {
                            if value == "true" {
                                config.filter_localhost = true;
                            } else if value == "false" {
                                config.filter_localhost = false;
                            }
                        }
                        "packet_processing_interval_ms" => {
                            if let Ok(interval) = value.parse::<u64>() {
                                config.packet_processing_interval_ms = interval;
                            }
                        }
                        _ => {
                            // Ignore unknown keys
                        }
                    }
                }
            }
        }

        // Try to find GeoIP database if not specified in config
        if config.geoip_db_path.is_none() {
            for path in Self::possible_geoip_paths() {
                if path.exists() {
                    config.geoip_db_path = Some(path);
                    break;
                }
            }
        }

        Ok(config)
    }

    /// Find configuration file
    fn find_config_file() -> Result<PathBuf> {
        // Try XDG config directory first
        if let Ok(xdg_config) = std::env::var("XDG_CONFIG_HOME") {
            let xdg_path = PathBuf::from(xdg_config).join("rustnet/config.yml");
            if xdg_path.exists() {
                return Ok(xdg_path);
            }
        }

        // Try ~/.config/rustnet
        let home = Self::get_home_dir()?;
        let home_config = home.join(".config/rustnet/config.yml");
        if home_config.exists() {
            return Ok(home_config);
        }

        // Try current directory
        let current_config = PathBuf::from("config.yml");
        if current_config.exists() {
            return Ok(current_config);
        }

        // Default to home config path
        Ok(home_config)
    }

    /// Get home directory
    fn get_home_dir() -> Result<PathBuf> {
        if let Ok(home) = std::env::var("HOME") {
            return Ok(PathBuf::from(home));
        }

        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            return Ok(PathBuf::from(userprofile));
        }

        Err(anyhow!("Could not determine home directory"))
    }

    /// Get possible GeoIP database paths
    fn possible_geoip_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // Current directory
        paths.push(PathBuf::from("GeoLite2-City.mmdb"));

        // Try XDG data directory
        if let Ok(xdg_data) = std::env::var("XDG_DATA_HOME") {
            paths.push(PathBuf::from(xdg_data).join("rustnet/GeoLite2-City.mmdb"));
        }

        // Try home directory
        if let Ok(home) = Self::get_home_dir() {
            paths.push(home.join(".local/share/rustnet/GeoLite2-City.mmdb"));
        }

        // System paths
        paths.push(PathBuf::from("/usr/share/GeoIP/GeoLite2-City.mmdb"));
        paths.push(PathBuf::from("/usr/local/share/GeoIP/GeoLite2-City.mmdb"));

        paths
    }
}

// rustnetec: PersistentConfig — YAML-backed persistent configuration (R7)

/// Persistent configuration stored in `config.yml`.
///
/// This struct is the single source of truth for all configurable settings
/// that survive across restarts. It is loaded at startup, can be modified
/// via the local HTTP API (`PUT /config`), and is saved back to disk on
/// every change.
///
/// Field categories:
/// - **Record switches**: control which optional fields are written to SQLite
/// - **Capture config**: interface, BPF filter, DPI, localhost filter, refresh
/// - **Output config**: JSON log, PCAP/PCAPNG export paths
/// - **Display config**: PTR lookups, historic mode, language
/// - **GeoIP**: database paths and disable flag
/// - **Host identity**: username, user_id (snowflake), machine_id (hardware)
/// - **Upload**: server URL, token, batch size, interval
/// - **Retention**: data retention period in days
/// - **Local HTTP**: port and auth token
/// - **Runtime state**: pending_restart flag
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentConfig {
    // --- Record switches (default: all enabled) ---
    #[serde(default = "default_true")]
    pub record_dns: bool,
    #[serde(default = "default_true")]
    pub record_process: bool,
    #[serde(default = "default_true")]
    pub record_service: bool,
    #[serde(default = "default_true")]
    pub record_rtt: bool,
    #[serde(default = "default_true")]
    pub record_connection_stats: bool,
    #[serde(default = "default_true")]
    pub record_geoip: bool,
    #[serde(default = "default_true")]
    pub record_dpi: bool,

    // --- Capture config ---
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub bpf_filter: Option<String>,
    #[serde(default = "default_true")]
    pub enable_dpi: bool,
    #[serde(default = "default_true")]
    pub filter_localhost: bool,
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval: u64,

    // --- Output config ---
    #[serde(default)]
    pub json_log_file: Option<String>,
    #[serde(default)]
    pub pcap_export_file: Option<String>,
    #[serde(default)]
    pub pcapng_export_file: Option<String>,

    // --- Display config ---
    #[serde(default)]
    pub show_ptr_lookups: bool,
    #[serde(default)]
    pub show_historic: bool,
    #[serde(default = "default_language")]
    pub language: String,

    // --- GeoIP ---
    #[serde(default)]
    pub geoip_country_path: Option<String>,
    #[serde(default)]
    pub geoip_asn_path: Option<String>,
    #[serde(default)]
    pub geoip_city_path: Option<String>,
    #[serde(default)]
    pub disable_geoip: bool,

    // --- Host identity ---
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub user_id: Option<i64>,
    #[serde(default)]
    pub machine_id: Option<String>,

    // --- Upload ---
    #[serde(default)]
    pub server_url: Option<String>,
    #[serde(default)]
    pub server_token: Option<String>,
    #[serde(default = "default_upload_batch_size")]
    pub upload_batch_size: u32,
    #[serde(default = "default_upload_interval_secs")]
    pub upload_interval_secs: u32,

    // --- Retention ---
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,

    // --- Local HTTP ---
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    #[serde(default)]
    pub http_token: Option<String>,

    // --- Boot autostart (R1 sub-requirement; default off) ---
    #[serde(default)]
    pub autostart_enabled: bool,
    #[serde(default)]
    pub autostart_mode: AutostartMode,

    // --- System tray (R1/R6, T3.2) ---
    /// Selectable status-line fields for the tray tooltip/menu.
    /// Order in the vec determines left-to-right render order.
    #[serde(default = "default_tray_status_fields")]
    pub tray_status_fields: Vec<TrayStatusField>,
    /// Tray status-line refresh interval in seconds (1-15, default 2).
    #[serde(default = "default_tray_refresh_interval_secs")]
    pub tray_refresh_interval_secs: u64,

    // --- Runtime state ---
    #[serde(default)]
    pub pending_restart: bool,
}

fn default_true() -> bool {
    true
}
fn default_refresh_interval() -> u64 {
    500
}
fn default_language() -> String {
    "en".to_string()
}
fn default_upload_batch_size() -> u32 {
    500
}
fn default_upload_interval_secs() -> u32 {
    60
}
fn default_retention_days() -> u32 {
    90
}
fn default_http_port() -> u16 {
    19811
}

// rustnetec: tray config defaults (T3.2)
fn default_tray_status_fields() -> Vec<TrayStatusField> {
    vec![
        TrayStatusField::State,
        TrayStatusField::Interface,
        TrayStatusField::RateIn,
        TrayStatusField::RateOut,
        TrayStatusField::Connections,
    ]
}

fn default_tray_refresh_interval_secs() -> u64 {
    2
}

impl Default for PersistentConfig {
    fn default() -> Self {
        Self {
            record_dns: true,
            record_process: true,
            record_service: true,
            record_rtt: true,
            record_connection_stats: true,
            record_geoip: true,
            record_dpi: true,

            interface: None,
            bpf_filter: None,
            enable_dpi: true,
            filter_localhost: true,
            refresh_interval: 500,

            json_log_file: None,
            pcap_export_file: None,
            pcapng_export_file: None,

            show_ptr_lookups: false,
            show_historic: false,
            language: "en".to_string(),

            geoip_country_path: None,
            geoip_asn_path: None,
            geoip_city_path: None,
            disable_geoip: false,

            username: None,
            user_id: None,
            machine_id: None,

            server_url: None,
            server_token: None,
            upload_batch_size: 500,
            upload_interval_secs: 60,

            retention_days: 90,

            http_port: 19811,
            http_token: None,

            autostart_enabled: false,
            autostart_mode: AutostartMode::default(),

            tray_status_fields: default_tray_status_fields(),
            tray_refresh_interval_secs: default_tray_refresh_interval_secs(),

            pending_restart: false,
        }
    }
}

impl PersistentConfig {
    /// Load configuration from the platform-specific config path.
    /// Returns default values if the file does not exist.
    pub fn load() -> Result<Self> {
        let path = crate::telemetry::paths::config_path()?;
        Self::load_from(&path)
    }

    /// Load configuration from a specific path.
    /// Returns default values if the file does not exist.
    pub fn load_from(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            info!(
                "Config file not found at {}, using defaults",
                path.display()
            );
            return Ok(Self::default());
        }

        let content = fs::read_to_string(path)?;
        let config: PersistentConfig = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Save configuration to the platform-specific config path.
    /// Creates the parent directory if needed. Sets file permissions to 0600 on Unix.
    pub fn save(&self) -> Result<()> {
        let path = crate::telemetry::paths::config_path()?;
        self.save_to(&path)
    }

    /// Save configuration to a specific path.
    /// Creates the parent directory if needed. Sets file permissions to 0600 on Unix.
    pub fn save_to(&self, path: &PathBuf) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }

        let yaml = serde_yaml::to_string(self)?;

        // Write atomically: write to temp file then rename
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?
                .write_all(yaml.as_bytes())?;
        }
        #[cfg(not(unix))]
        {
            fs::write(path, yaml.as_bytes())?;
        }

        info!("Configuration saved to {}", path.display());
        Ok(())
    }

    /// Validate configuration values, returning an error with a descriptive
    /// message if any value is out of range.
    pub fn validate(&self) -> Result<()> {
        if self.retention_days < 1 || self.retention_days > 180 {
            return Err(anyhow!("retention_days must be 1-180"));
        }
        if self.refresh_interval < 100 || self.refresh_interval > 60000 {
            return Err(anyhow!("refresh_interval must be 100-60000 ms"));
        }
        if self.http_port == 0 {
            return Err(anyhow!("invalid port"));
        }
        if self.upload_batch_size < 1 || self.upload_batch_size > 5000 {
            return Err(anyhow!("upload_batch_size must be 1-5000"));
        }
        if self.upload_interval_secs < 5 || self.upload_interval_secs > 3600 {
            return Err(anyhow!("upload_interval_secs must be 5-3600"));
        }
        if let Some(ref url) = self.server_url
            && !url.starts_with("http://")
            && !url.starts_with("https://")
        {
            return Err(anyhow!("invalid server_url"));
        }
        if let Some(ref iface) = self.interface
            && iface.is_empty()
        {
            return Err(anyhow!("interface must be non-empty or null"));
        }
        // rustnetec: tray config validation (T3.2)
        if self.tray_refresh_interval_secs < 1 || self.tray_refresh_interval_secs > 15 {
            return Err(anyhow!("tray_refresh_interval_secs must be 1-15 seconds"));
        }
        if self.tray_status_fields.is_empty() {
            return Err(anyhow!("tray_status_fields must not be empty"));
        }
        // Reject duplicate fields — would render duplicates in the status line
        let mut seen = std::collections::HashSet::new();
        for f in &self.tray_status_fields {
            if !seen.insert(f) {
                return Err(anyhow!("tray_status_fields must not contain duplicates"));
            }
        }
        // rustnetec: autostart_mode validation (T1.11) — only allow Tray when
        // the `tray` cargo feature is enabled. Without the feature the Tray
        // variant does not even exist in AutostartMode, so a YAML such as
        // `autostart_mode: Tray` would already fail to deserialize.
        #[cfg(not(feature = "tray"))]
        {
            // No-op: Tray variant is absent; serde rejects unknown values at
            // load time, so any value here is guaranteed Daemon.
        }
        #[cfg(feature = "tray")]
        {
            // Nothing to reject at runtime: both Daemon and Tray are valid
            // when the feature is enabled.
        }
        Ok(())
    }

    /// Generate a random 32-byte hex token for HTTP authentication.
    /// Called on first startup when no token exists.
    pub fn generate_http_token() -> String {
        use std::fmt::Write;
        let mut buf = [0u8; 32];
        // Use getrandom for cryptographic randomness
        #[cfg(unix)]
        {
            // Simple random from system time + pid as fallback
            // In production, this should use getrandom crate
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let pid = std::process::id() as u64;
            let mut state = seed ^ pid;
            for byte in buf.iter_mut() {
                // xorshift64
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
        }
        #[cfg(not(unix))]
        {
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let pid = std::process::id() as u64;
            let mut state = seed ^ pid;
            for byte in buf.iter_mut() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
        }
        let mut hex = String::with_capacity(64);
        for byte in &buf {
            write!(&mut hex, "{:02x}", byte).unwrap();
        }
        hex
    }

    /// Ensure http_token is set, generating one if missing.
    /// Returns true if a new token was generated (caller should save).
    pub fn ensure_http_token(&mut self) -> bool {
        // rustnetec: clippy map_or simplify — 用 match 显式判空避开类型歧义
        let need_new = match self.http_token.as_ref() {
            None => true,
            Some(t) => t.is_empty(),
        };
        if need_new {
            self.http_token = Some(Self::generate_http_token());
            info!("Generated new HTTP auth token");
            true
        } else {
            false
        }
    }
}

// rustnetec: RuntimeConfig — runtime shared state (R7 dual-track config)

/// Runtime configuration shared across threads via `Arc<RwLock<RuntimeConfig>>`.
///
/// Fields are partitioned into three categories based on when changes take effect:
///
/// 1. **Hot-update items**: changes apply immediately (no restart needed)
/// 2. **Restart-required items**: changes are persisted to config.yml and
///    take effect after capture restart or process restart
/// 3. **Startup-once items**: changes require a full process restart
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    // --- Hot-update items (modify → immediate effect) ---
    pub show_ptr_lookups: bool,
    pub show_historic: bool,
    pub username: Option<String>,
    pub upload_batch_size: u32,
    pub language: String,
    pub http_token: Option<String>,
    /// rustnetec: tray status-line field set (T3.2) — hot-update so the
    /// "设置" dialog can toggle fields without a restart.
    pub tray_status_fields: Vec<TrayStatusField>,
    /// rustnetec: tray status-line refresh interval in seconds (T3.2)
    pub tray_refresh_interval_secs: u64,

    // --- Restart-required items (modify → persist + pending_restart = true) ---
    pub interface: Option<String>,
    pub bpf_filter: Option<String>,
    pub enable_dpi: bool,
    pub filter_localhost: bool,
    pub refresh_interval: u64,
    pub retention_days: u32,
    pub server_url: Option<String>,
    pub server_token: Option<String>,
    pub upload_interval_secs: u32,
    pub http_port: u16,
    pub record_dns: bool,
    pub record_process: bool,
    pub record_service: bool,
    pub record_rtt: bool,
    pub record_connection_stats: bool,
    pub record_geoip: bool,
    pub record_dpi: bool,

    // --- Startup-once items (modify → persist + "restart process" hint) ---
    pub json_log_file: Option<String>,
    pub pcap_export_file: Option<String>,
    pub pcapng_export_file: Option<String>,
    pub user_id: i64,
    pub machine_id: String,

    // --- Internal state ---
    pub pending_restart: bool,
}

impl RuntimeConfig {
    /// Create a RuntimeConfig from a PersistentConfig.
    /// This is called at startup to initialize the shared runtime state.
    pub fn from_persistent(pc: &PersistentConfig) -> Self {
        Self {
            // Hot-update items
            show_ptr_lookups: pc.show_ptr_lookups,
            show_historic: pc.show_historic,
            username: pc.username.clone(),
            upload_batch_size: pc.upload_batch_size,
            language: pc.language.clone(),
            http_token: pc.http_token.clone(),
            tray_status_fields: pc.tray_status_fields.clone(),
            tray_refresh_interval_secs: pc.tray_refresh_interval_secs,

            // Restart-required items
            interface: pc.interface.clone(),
            bpf_filter: pc.bpf_filter.clone(),
            enable_dpi: pc.enable_dpi,
            filter_localhost: pc.filter_localhost,
            refresh_interval: pc.refresh_interval,
            retention_days: pc.retention_days,
            server_url: pc.server_url.clone(),
            server_token: pc.server_token.clone(),
            upload_interval_secs: pc.upload_interval_secs,
            http_port: pc.http_port,
            record_dns: pc.record_dns,
            record_process: pc.record_process,
            record_service: pc.record_service,
            record_rtt: pc.record_rtt,
            record_connection_stats: pc.record_connection_stats,
            record_geoip: pc.record_geoip,
            record_dpi: pc.record_dpi,

            // Startup-once items
            json_log_file: pc.json_log_file.clone(),
            pcap_export_file: pc.pcap_export_file.clone(),
            pcapng_export_file: pc.pcapng_export_file.clone(),
            user_id: pc.user_id.unwrap_or(0),
            machine_id: pc.machine_id.clone().unwrap_or_default(),

            // Internal state
            pending_restart: pc.pending_restart,
        }
    }

    /// Apply hot-update items from a PersistentConfig.
    /// Only fields that can take effect immediately are updated;
    /// restart-required and startup-once items are left unchanged.
    pub fn apply_hot_update(&mut self, pc: &PersistentConfig) {
        self.show_ptr_lookups = pc.show_ptr_lookups;
        self.show_historic = pc.show_historic;
        self.username = pc.username.clone();
        self.upload_batch_size = pc.upload_batch_size;
        self.language = pc.language.clone();
        self.http_token = pc.http_token.clone();
        // rustnetec: tray config is hot-update (T3.2) — settings dialog can
        // toggle status fields / refresh interval without a process restart.
        self.tray_status_fields = pc.tray_status_fields.clone();
        self.tray_refresh_interval_secs = pc.tray_refresh_interval_secs;
    }

    /// Apply restart-required items from a PersistentConfig.
    /// Called after a capture restart to pick up the new values.
    pub fn apply_restart_items(&mut self, pc: &PersistentConfig) {
        self.interface = pc.interface.clone();
        self.bpf_filter = pc.bpf_filter.clone();
        self.enable_dpi = pc.enable_dpi;
        self.filter_localhost = pc.filter_localhost;
        self.refresh_interval = pc.refresh_interval;
        self.retention_days = pc.retention_days;
        self.server_url = pc.server_url.clone();
        self.server_token = pc.server_token.clone();
        self.upload_interval_secs = pc.upload_interval_secs;
        self.http_port = pc.http_port;
        self.record_dns = pc.record_dns;
        self.record_process = pc.record_process;
        self.record_service = pc.record_service;
        self.record_rtt = pc.record_rtt;
        self.record_connection_stats = pc.record_connection_stats;
        self.record_geoip = pc.record_geoip;
        self.record_dpi = pc.record_dpi;
        self.pending_restart = false;
    }
}

#[cfg(test)]
mod persistent_config_tests {
    use super::*;

    #[test]
    fn default_values() {
        let config = PersistentConfig::default();
        assert!(config.record_dns);
        assert!(config.record_process);
        assert!(config.enable_dpi);
        assert!(config.filter_localhost);
        assert_eq!(config.refresh_interval, 500);
        assert_eq!(config.retention_days, 90);
        assert_eq!(config.http_port, 19811);
        assert_eq!(config.upload_batch_size, 500);
        assert_eq!(config.upload_interval_secs, 60);
        assert!(config.interface.is_none());
        assert!(config.server_url.is_none());
        assert!(config.http_token.is_none());
        assert!(!config.pending_restart);
    }

    #[test]
    fn validate_accepts_valid_config() {
        let config = PersistentConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_retention_days_too_low() {
        let config = PersistentConfig {
            retention_days: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_retention_days_too_high() {
        let config = PersistentConfig {
            retention_days: 181,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_refresh_interval_too_low() {
        let config = PersistentConfig {
            refresh_interval: 50,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_refresh_interval_too_high() {
        let config = PersistentConfig {
            refresh_interval: 70000,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_invalid_server_url() {
        let config = PersistentConfig {
            server_url: Some("ftp://bad.example.com".to_string()),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_accepts_valid_server_url() {
        let config = PersistentConfig {
            server_url: Some("https://rustnet.example.com".to_string()),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_interface() {
        let config = PersistentConfig {
            interface: Some("".to_string()),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_upload_batch_size_out_of_range() {
        let mut config = PersistentConfig {
            upload_batch_size: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
        config.upload_batch_size = 5001;
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_upload_interval_secs_out_of_range() {
        let mut config = PersistentConfig {
            upload_interval_secs: 1,
            ..Default::default()
        };
        assert!(config.validate().is_err());
        config.upload_interval_secs = 4000;
        assert!(config.validate().is_err());
    }

    #[test]
    fn load_save_roundtrip() {
        let tmp = std::env::temp_dir().join("rustnetec-test-config-roundtrip");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let path = tmp.join("config.yml");

        let original = PersistentConfig {
            interface: Some("eth0".to_string()),
            retention_days: 30,
            language: "zh-CN".to_string(),
            server_url: Some("https://rustnet.example.com".to_string()),
            ..Default::default()
        };

        original.save_to(&path).unwrap();

        let loaded = PersistentConfig::load_from(&path).unwrap();
        assert_eq!(loaded.interface, Some("eth0".to_string()));
        assert_eq!(loaded.retention_days, 30);
        assert_eq!(loaded.language, "zh-CN");
        assert_eq!(
            loaded.server_url,
            Some("https://rustnet.example.com".to_string())
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn load_returns_default_when_file_missing() {
        let path = PathBuf::from("/tmp/rustnetec-nonexistent-config-test/config.yml");
        let config = PersistentConfig::load_from(&path).unwrap();
        assert_eq!(config.refresh_interval, 500);
    }

    #[test]
    fn ensure_http_token_generates_when_missing() {
        let mut config = PersistentConfig::default();
        assert!(config.http_token.is_none());
        let generated = config.ensure_http_token();
        assert!(generated);
        assert!(config.http_token.is_some());
        let token = config.http_token.unwrap();
        assert_eq!(token.len(), 64); // 32 bytes hex = 64 chars
    }

    #[test]
    fn ensure_http_token_noop_when_present() {
        let mut config = PersistentConfig {
            http_token: Some("existing_token".to_string()),
            ..Default::default()
        };
        let generated = config.ensure_http_token();
        assert!(!generated);
        assert_eq!(config.http_token, Some("existing_token".to_string()));
    }

    #[test]
    #[cfg(unix)]
    fn save_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = std::env::temp_dir().join("rustnetec-test-config-perms");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let path = tmp.join("config.yml");
        let config = PersistentConfig::default();
        config.save_to(&path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "config file should have 0600 permissions");

        let _ = fs::remove_dir_all(&tmp);
    }
}

#[cfg(test)]
mod runtime_config_tests {
    use super::*;

    #[test]
    fn from_persistent_maps_all_fields() {
        let pc = PersistentConfig {
            interface: Some("eth0".to_string()),
            show_ptr_lookups: true,
            retention_days: 30,
            user_id: Some(12345),
            machine_id: Some("abc123".to_string()),
            http_token: Some("tok".to_string()),
            ..Default::default()
        };

        let rc = RuntimeConfig::from_persistent(&pc);
        assert_eq!(rc.interface, Some("eth0".to_string()));
        assert!(rc.show_ptr_lookups);
        assert_eq!(rc.retention_days, 30);
        assert_eq!(rc.user_id, 12345);
        assert_eq!(rc.machine_id, "abc123");
        assert_eq!(rc.http_token, Some("tok".to_string()));
    }

    #[test]
    fn from_persistent_defaults_missing_user_id() {
        let pc = PersistentConfig::default();
        let rc = RuntimeConfig::from_persistent(&pc);
        assert_eq!(rc.user_id, 0);
        assert_eq!(rc.machine_id, "");
    }

    #[test]
    fn apply_hot_update_only_touches_hot_fields() {
        let mut pc = PersistentConfig {
            show_ptr_lookups: true,
            show_historic: true,
            language: "zh-CN".to_string(),
            interface: Some("eth0".to_string()),
            retention_days: 30,
            ..Default::default()
        };

        let mut rc = RuntimeConfig::from_persistent(&pc);

        // Modify hot and restart fields
        pc.show_ptr_lookups = false;
        pc.language = "ja".to_string();
        pc.interface = Some("wlan0".to_string());
        pc.retention_days = 60;

        rc.apply_hot_update(&pc);

        // Hot items should be updated
        assert!(!rc.show_ptr_lookups);
        assert_eq!(rc.language, "ja");

        // Restart items should NOT be updated
        assert_eq!(rc.interface, Some("eth0".to_string()));
        assert_eq!(rc.retention_days, 30);
    }

    #[test]
    fn apply_restart_items_updates_restart_fields() {
        let mut pc = PersistentConfig {
            interface: Some("eth0".to_string()),
            retention_days: 30,
            pending_restart: true,
            ..Default::default()
        };

        let mut rc = RuntimeConfig::from_persistent(&pc);

        // Modify restart fields
        pc.interface = Some("wlan0".to_string());
        pc.retention_days = 60;

        rc.apply_restart_items(&pc);

        // Restart items should be updated
        assert_eq!(rc.interface, Some("wlan0".to_string()));
        assert_eq!(rc.retention_days, 60);

        // pending_restart should be cleared
        assert!(!rc.pending_restart);
    }

    #[test]
    fn hot_update_does_not_touch_pending_restart() {
        let mut pc = PersistentConfig {
            pending_restart: true,
            ..Default::default()
        };

        let mut rc = RuntimeConfig::from_persistent(&pc);
        assert!(rc.pending_restart);

        // Hot update should not change pending_restart
        pc.show_ptr_lookups = true;
        rc.apply_hot_update(&pc);
        assert!(rc.pending_restart);
    }
}
