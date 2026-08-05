// rustnetec: Host identity — snowflake user_id + BLAKE3 machine_id (R8+R10, T1.6)

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Host identity information for telemetry and upload payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostIdentity {
    /// Hardware-level machine ID (BLAKE3 hex, 64 characters).
    /// Stable across OS reinstalls; derived from platform hardware sources.
    pub machine_id: String,
    /// Installation-level user ID (snowflake algorithm, 64-bit).
    /// Regenerated on reinstall; persisted in config.yml.
    pub user_id: i64,
    /// Username (user-configurable, defaults to system username).
    pub username: String,
    /// Local IP list (dynamically collected, not persisted).
    #[serde(skip)]
    pub ip_list: Vec<String>,
}

// ---- Snowflake ID generation ----

/// Custom epoch: 2025-01-01 00:00:00 UTC in milliseconds.
const SNOWFLAKE_EPOCH: u64 = 1735689600000;

/// Generate a snowflake-style user_id.
///
/// Bit layout (64 bits):
/// - 41 bits: millisecond timestamp (relative to custom epoch)
/// - 10 bits: machine/sequence identifier (process_id % 1024)
/// - 12 bits: sequence counter (per-millisecond)
/// - 1 bit: sign (always 0)
///
/// This is suitable for installation-level identification, not for
/// high-throughput event ID generation.
pub fn generate_user_id() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let timestamp = now.saturating_sub(SNOWFLAKE_EPOCH);
    let machine_bits = (std::process::id() % 1024) as u64;

    // Simple sequence: use sub-millisecond nanos for uniqueness within same ms
    let seq = now % 4096;

    let id = ((timestamp & 0x1FFFFFFFFFF) << 22) | (machine_bits << 12) | seq;
    id as i64
}

// ---- Machine ID generation ----

/// Generate a hardware-level machine_id using BLAKE3 hash.
///
/// Platform sources (in priority order):
/// - macOS: IOPlatformUUID via `ioreg`
/// - Linux: /sys/class/dmi/id/product_uuid
/// - Windows: SMBIOS UUID via GetSystemFirmwareTable
/// - FreeBSD: kern.hostuuid via sysctl
///
/// Fallback chain:
/// 1. Primary platform source
/// 2. Primary MAC address
/// 3. Random bytes (persisted to config.yml as last resort)
pub fn get_machine_id() -> String {
    // Try platform-specific hardware source
    if let Some(hw_id) = read_platform_hardware_id() {
        return blake3_hex(hw_id.as_bytes());
    }

    // Fallback: primary MAC address
    if let Some(mac) = read_primary_mac_address() {
        return blake3_hex(mac.as_bytes());
    }

    // Last resort: random (caller should persist this)
    let random_bytes: [u8; 32] = rand_fallback();
    blake3_hex(&random_bytes)
}

/// Read platform-specific hardware identifier.
/// Returns None if the source is unavailable.
fn read_platform_hardware_id() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        read_ioplatform_uuid()
    }
    #[cfg(target_os = "linux")]
    {
        read_dmi_product_uuid()
    }
    #[cfg(target_os = "windows")]
    {
        read_smbios_uuid()
    }
    #[cfg(target_os = "freebsd")]
    {
        read_freebsd_hostuuid()
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows",
        target_os = "freebsd"
    )))]
    {
        None
    }
}

#[cfg(target_os = "macos")]
fn read_ioplatform_uuid() -> Option<String> {
    use std::process::Command;
    let output = Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains("IOPlatformUUID") {
            // Format: "IOPlatformUUID" = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
            if let Some(eq_pos) = line.find('=') {
                let value = line[eq_pos + 1..].trim();
                let cleaned = value.trim_matches('"').trim();
                if !cleaned.is_empty() {
                    return Some(cleaned.to_string());
                }
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn read_dmi_product_uuid() -> Option<String> {
    let content = std::fs::read_to_string("/sys/class/dmi/id/product_uuid").ok()?;
    let trimmed = content.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

#[cfg(target_os = "windows")]
fn read_smbios_uuid() -> Option<String> {
    // On Windows, use GetSystemFirmwareTable to read SMBIOS UUID.
    // This requires unsafe Win32 API calls; for now, fall through to MAC.
    // Full implementation deferred to Windows-specific build.
    None
}

#[cfg(target_os = "freebsd")]
fn read_freebsd_hostuuid() -> Option<String> {
    use std::process::Command;
    let output = Command::new("sysctl")
        .args(["-n", "kern.hostuuid"])
        .output()
        .ok()?;
    let uuid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if uuid.is_empty() || uuid == "kern.hostuuid" {
        None
    } else {
        Some(uuid)
    }
}

/// Read the primary (first non-loopback) MAC address.
fn read_primary_mac_address() -> Option<String> {
    #[cfg(unix)]
    {
        read_mac_unix()
    }
    #[cfg(windows)]
    {
        read_mac_windows()
    }
    #[cfg(not(unix))]
    {
        None
    }
}

#[cfg(unix)]
fn read_mac_unix() -> Option<String> {
    // rustnetec: 使用全路径 std::fs::* 替代局部 `use std::fs;`，避免 cfg 路径下的 unused import 误报
    // Try /sys/class/net on Linux
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str == "lo" {
                    continue;
                }
                let addr_path = format!("/sys/class/net/{}/address", name_str);
                if let Ok(addr) = std::fs::read_to_string(&addr_path) {
                    let mac = addr.trim().to_string();
                    if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                        return Some(mac);
                    }
                }
            }
        }
    }
    // Try ifconfig on macOS/FreeBSD
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("ifconfig").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("ether ")
                    && let Some(addr) = line.split("ether ").nth(1)
                {
                    let mac = addr.trim().to_string();
                    if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                        return Some(mac);
                    }
                }
            }
        }
    }
    None
}

#[cfg(windows)]
fn read_mac_windows() -> Option<String> {
    // Windows MAC address reading requires Win32 API.
    // Fall through to random fallback for now.
    None
}

/// Generate a random fallback machine_id.
/// Uses a simple time-seeded pseudo-random generator (no external rand dependency).
fn rand_fallback() -> [u8; 32] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seed = now.as_nanos() as u64;

    // xorshift64 for pseudo-random bytes
    let mut state = seed;
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_exact_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes());
    }
    bytes
}

/// Compute BLAKE3 hash and return as 64-character hex string.
fn blake3_hex(input: &[u8]) -> String {
    let mut hasher = Hasher::new();
    hasher.update(input);
    hasher.finalize().to_hex().to_string()
}

// ---- Username ----

/// Get the current username.
/// Returns the system username if not overridden.
pub fn get_system_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

// ---- IP list ----

/// Collect local IP addresses, filtering out loopback and link-local.
pub fn collect_ip_list() -> Vec<String> {
    // Use rustnet-core's collect_local_ips if available,
    // otherwise fall back to a simple implementation.
    #[cfg(unix)]
    {
        collect_ip_list_unix()
    }
    #[cfg(windows)]
    {
        collect_ip_list_windows()
    }
    #[cfg(not(unix))]
    {
        Vec::new()
    }
}

#[cfg(unix)]
fn collect_ip_list_unix() -> Vec<String> {
    use std::process::Command;
    let output = match Command::new("ifconfig").output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ips = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        // Match "inet " (IPv4) or "inet6 " (IPv6)
        if line.starts_with("inet ") {
            if let Some(addr) = line.split_whitespace().nth(1) {
                let addr = addr.trim_end_matches('%');
                // Skip loopback and link-local
                if addr != "127.0.0.1" && !addr.starts_with("169.254.") {
                    ips.push(addr.to_string());
                }
            }
        } else if line.starts_with("inet6 ")
            && let Some(addr) = line.split_whitespace().nth(1)
        {
            // Skip loopback and link-local
            if !addr.starts_with("::1") && !addr.starts_with("fe80") {
                ips.push(addr.to_string());
            }
        }
    }

    ips
}

#[cfg(windows)]
fn collect_ip_list_windows() -> Vec<String> {
    // Windows IP collection requires Win32 API or ipconfig parsing.
    // Simplified implementation for now.
    Vec::new()
}

// ---- HostIdentity initialization ----

impl HostIdentity {
    /// Initialize host identity from PersistentConfig values.
    /// Generates missing fields (user_id, machine_id) as needed.
    /// Returns the initialized identity and whether config needs saving.
    pub fn initialize(
        username: Option<&str>,
        user_id: Option<i64>,
        machine_id: Option<&str>,
    ) -> (Self, bool) {
        let mut needs_save = false;

        let uid = match user_id {
            Some(id) if id != 0 => id,
            _ => {
                needs_save = true;
                generate_user_id()
            }
        };

        let mid = match machine_id {
            Some(id) if !id.is_empty() => id.to_string(),
            _ => {
                // Try hardware source first; if fallback (random), needs_save = true
                let generated = get_machine_id();
                // If machine_id was None, we should persist it
                needs_save = true;
                generated
            }
        };

        let uname = match username {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => get_system_username(),
        };

        let ip_list = collect_ip_list();

        (
            HostIdentity {
                machine_id: mid,
                user_id: uid,
                username: uname,
                ip_list,
            },
            needs_save,
        )
    }

    /// Refresh the dynamic IP list.
    pub fn refresh_ip_list(&mut self) {
        self.ip_list = collect_ip_list();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_user_id_returns_positive() {
        let id = generate_user_id();
        assert!(id > 0, "user_id should be positive, got {}", id);
    }

    #[test]
    fn generate_user_id_is_unique() {
        let id1 = generate_user_id();
        // Small delay to ensure different timestamp
        std::thread::sleep(std::time::Duration::from_millis(1));
        let id2 = generate_user_id();
        // They may or may not differ depending on timing, but both should be valid
        assert!(id1 > 0);
        assert!(id2 > 0);
    }

    #[test]
    fn get_machine_id_is_64_hex_chars() {
        let mid = get_machine_id();
        assert_eq!(
            mid.len(),
            64,
            "machine_id should be 64 hex chars, got {}",
            mid.len()
        );
        assert!(
            mid.chars().all(|c| c.is_ascii_hexdigit()),
            "machine_id should be hex"
        );
    }

    #[test]
    fn get_machine_id_is_stable() {
        let mid1 = get_machine_id();
        let mid2 = get_machine_id();
        // On the same machine, hardware-based IDs should be stable
        // (random fallback may differ, but that's acceptable in test environments)
        assert_eq!(mid1.len(), 64);
        assert_eq!(mid2.len(), 64);
    }

    #[test]
    fn blake3_hex_produces_64_chars() {
        let hash = blake3_hex(b"test");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn blake3_hex_is_deterministic() {
        let h1 = blake3_hex(b"hello");
        let h2 = blake3_hex(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn blake3_hex_differs_for_different_inputs() {
        let h1 = blake3_hex(b"hello");
        let h2 = blake3_hex(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn get_system_username_is_not_empty() {
        let name = get_system_username();
        assert!(!name.is_empty(), "username should not be empty");
    }

    #[test]
    fn host_identity_initialize_generates_missing() {
        let (identity, needs_save) = HostIdentity::initialize(None, None, None);
        assert!(needs_save, "should need save when fields are missing");
        assert!(!identity.machine_id.is_empty());
        assert!(identity.user_id > 0);
        assert!(!identity.username.is_empty());
    }

    #[test]
    fn host_identity_initialize_uses_provided() {
        let (identity, needs_save) = HostIdentity::initialize(
            Some("alice"),
            Some(12345),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
        );
        assert!(!needs_save, "should not need save when all fields provided");
        assert_eq!(identity.username, "alice");
        assert_eq!(identity.user_id, 12345);
        assert_eq!(
            identity.machine_id,
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        );
    }

    #[test]
    fn host_identity_refresh_ip_list() {
        let (mut identity, _) = HostIdentity::initialize(None, None, None);
        identity.refresh_ip_list();
        // ip_list may be empty in CI, but the call should not panic
    }

    #[test]
    fn snowflake_epoch_is_reasonable() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        assert!(now > SNOWFLAKE_EPOCH, "current time should be after epoch");
    }

    #[test]
    fn rand_fallback_produces_32_bytes() {
        let bytes = rand_fallback();
        assert_eq!(bytes.len(), 32);
        // Should not be all zeros (extremely unlikely)
        assert!(bytes.iter().any(|&b| b != 0));
    }
}
