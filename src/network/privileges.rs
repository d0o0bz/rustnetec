//! Network privilege detection for packet capture
//!
//! This module checks if the application has sufficient privileges to capture
//! network packets on different platforms (Linux, macOS, Windows).

use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::anyhow;
#[cfg(any(
    not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd"
    )),
    target_os = "windows"
))]
use log::warn;
use log::{debug, info};

/// Privilege check result with detailed information
#[derive(Debug, Clone)]
pub struct PrivilegeStatus {
    /// Whether sufficient privileges are available
    pub has_privileges: bool,
    /// Missing capabilities or permissions
    pub missing: Vec<String>,
    /// Platform-specific instructions to gain privileges
    pub instructions: Vec<String>,
}

impl PrivilegeStatus {
    /// Create a status indicating sufficient privileges
    pub fn sufficient() -> Self {
        Self {
            has_privileges: true,
            missing: Vec::new(),
            instructions: Vec::new(),
        }
    }

    /// Create a status indicating insufficient privileges
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd",
        test
    ))]
    pub fn insufficient(missing: Vec<String>, instructions: Vec<String>) -> Self {
        Self {
            has_privileges: false,
            missing,
            instructions,
        }
    }

    /// Get a human-readable error message
    pub fn error_message(&self) -> String {
        if self.has_privileges {
            return String::new();
        }

        let mut msg = String::from("Insufficient privileges for network packet capture.\n\n");

        if !self.missing.is_empty() {
            msg.push_str("Missing:\n");
            for item in &self.missing {
                msg.push_str(&format!("  • {}\n", item));
            }
            msg.push('\n');
        }

        if !self.instructions.is_empty() {
            msg.push_str("How to fix:\n");
            for (i, instruction) in self.instructions.iter().enumerate() {
                msg.push_str(&format!("  {}. {}\n", i + 1, instruction));
            }
        }

        msg
    }
}

/// rustnetec: Windows 抓包问题的分类结果（方案 C 运行时引导）。
///
/// 由 [`classify_windows_npcap_error`] 从 pcap 错误串得出，供两处复用：
/// - `check_windows_privileges` 生成启动横幅里的 instructions；
/// - overview 页在抓包线程失败后显示对应提示（覆盖托盘场景）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsNpcapIssue {
    /// Npcap 未安装（或未以 WinPcap API 兼容模式安装）。
    NotInstalled,
    /// Npcap 已安装，但限制为仅管理员可打开抓包设备（admin_only）。
    AdminOnly,
}

/// rustnetec: 按关键字把 pcap 错误串分类为可引导的 Windows 抓包问题；
/// 无法归类的返回 `None`。纯字符串函数，不依赖平台 API，可在任意平台单测。
pub fn classify_windows_npcap_error(error: &str) -> Option<WindowsNpcapIssue> {
    let lower = error.to_lowercase();
    if lower.contains("wpcap")
        || lower.contains("npcap")
        || lower.contains("not installed")
        || lower.contains("cannot load")
        || lower.contains("no such file")
        || lower.contains(".dll")
    {
        Some(WindowsNpcapIssue::NotInstalled)
    } else if lower.contains("access")
        || lower.contains("denied")
        || lower.contains("permission")
        || lower.contains("not allowed")
        || lower.contains("insufficient")
    {
        Some(WindowsNpcapIssue::AdminOnly)
    } else {
        None
    }
}

/// Check if the current process has sufficient privileges for packet capture
pub fn check_packet_capture_privileges() -> Result<PrivilegeStatus> {
    #[cfg(target_os = "linux")]
    {
        check_linux_privileges()
    }

    #[cfg(target_os = "macos")]
    {
        check_macos_privileges()
    }

    #[cfg(target_os = "windows")]
    {
        check_windows_privileges()
    }

    #[cfg(target_os = "freebsd")]
    {
        check_freebsd_privileges()
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd"
    )))]
    {
        // Unknown platform - return optimistic result
        warn!("Privilege check not implemented for this platform");
        Ok(PrivilegeStatus::sufficient())
    }
}

#[cfg(target_os = "linux")]
fn check_linux_privileges() -> Result<PrivilegeStatus> {
    use std::fs;

    // Check if running as root by reading /proc/self/status
    let is_root = is_root_user();

    if is_root {
        info!("Running as root - all privileges available");
        return Ok(PrivilegeStatus::sufficient());
    }

    debug!("Not running as root, checking capabilities");

    // Check for required capabilities via /proc/self/status
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|e| anyhow!("Failed to read /proc/self/status: {}", e))?;

    // Parse CapEff (effective capabilities) line
    let cap_value = status
        .lines()
        .find(|line| line.starts_with("CapEff:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|cap_hex| u64::from_str_radix(cap_hex, 16).ok())
        .ok_or_else(|| anyhow!("Failed to parse effective capabilities"))?;

    debug!("Current effective capabilities: 0x{:x}", cap_value);

    // Required capability for read-only packet capture (no promiscuous mode)
    const CAP_NET_RAW: u64 = 13; // For packet capture

    let mut missing = Vec::new();

    // Check CAP_NET_RAW
    if (cap_value & (1u64 << CAP_NET_RAW)) != 0 {
        debug!("CAP_NET_RAW: present");
        return Ok(PrivilegeStatus::sufficient());
    } else {
        debug!("CAP_NET_RAW: missing");
        missing.push("CAP_NET_RAW capability (required for packet capture)".to_string());
    }

    // Build instructions for gaining privileges
    let mut instructions = vec![
        "Run with sudo: sudo rustnet".to_string(),
        "Set capabilities (modern Linux 5.8+, with eBPF): sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' $(which rustnet)".to_string(),
        "Set capabilities (packet capture only, no eBPF): sudo setcap 'cap_net_raw+eip' $(which rustnet)".to_string(),
    ];

    // Add Docker-specific instructions if it looks like we're in a container
    if is_running_in_container() {
        instructions.push(
            "If running in Docker, add these flags:\n  \
             --cap-add=NET_RAW --cap-add=BPF --cap-add=PERFMON \
             --net=host --pid=host"
                .to_string(),
        );
    }

    Ok(PrivilegeStatus::insufficient(missing, instructions))
}

/// Detect if running inside a container
#[cfg(target_os = "linux")]
fn is_running_in_container() -> bool {
    use std::fs;

    // Check for .dockerenv file
    if fs::metadata("/.dockerenv").is_ok() {
        return true;
    }

    // Check cgroup
    if let Ok(cgroup) = fs::read_to_string("/proc/self/cgroup")
        && (cgroup.contains("docker") || cgroup.contains("kubepods") || cgroup.contains("lxc"))
    {
        return true;
    }

    false
}

#[cfg(target_os = "macos")]
fn check_macos_privileges() -> Result<PrivilegeStatus> {
    use std::fs;

    // Check if running as root by reading effective UID from process
    let is_root = is_root_user();

    if is_root {
        info!("Running as root - all privileges available");
        return Ok(PrivilegeStatus::sufficient());
    }

    debug!("Not running as root, checking BPF device permissions");

    // On macOS, packet capture requires access to BPF devices
    // Try to open a BPF device to check permissions
    let bpf_devices = (0..10)
        .map(|i| format!("/dev/bpf{}", i))
        .collect::<Vec<_>>();

    let mut can_access_bpf = false;
    for bpf_device in &bpf_devices {
        if fs::metadata(bpf_device).is_ok() {
            debug!("Checking BPF device: {}", bpf_device);

            // Try to actually open it (this is the real test)
            if std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(bpf_device)
                .is_ok()
            {
                can_access_bpf = true;
                debug!("Successfully opened BPF device: {}", bpf_device);
                break;
            }
        }
    }

    if can_access_bpf {
        return Ok(PrivilegeStatus::sufficient());
    }

    // No BPF access - build error message
    let missing = vec!["Access to BPF devices (/dev/bpf*)".to_string()];

    let instructions = vec![
        "Run with sudo: sudo rustnet".to_string(),
        "Change BPF device permissions (temporary):\n  \
         sudo chmod o+rw /dev/bpf*"
            .to_string(),
        "Install BPF permission helper (persistent):\n  \
         brew install wireshark && sudo /usr/local/bin/install-bpf"
            .to_string(),
    ];

    Ok(PrivilegeStatus::insufficient(missing, instructions))
}

#[cfg(target_os = "windows")]
fn check_windows_privileges() -> Result<PrivilegeStatus> {
    use pcap::Device;

    debug!("Checking Windows privileges by attempting to list network interfaces");

    // Try to list network devices - this will fail if we don't have sufficient privileges
    match Device::list() {
        Ok(devices) => {
            info!(
                "Successfully listed {} network devices - privileges sufficient",
                devices.len()
            );
            Ok(PrivilegeStatus::sufficient())
        }
        Err(e) => {
            debug!("Failed to list network devices: {}", e);

            // rustnetec: 方案 C — 按 Npcap 状态分类错误，给出可操作的引导
            // （下载页 + 取消勾选 admin_only，使普通用户也能抓包）。
            match classify_windows_npcap_error(&e.to_string()) {
                Some(WindowsNpcapIssue::NotInstalled) => {
                    let missing = vec!["Npcap runtime (packet capture driver)".to_string()];

                    let instructions = vec![
                        "Download and install Npcap from: https://npcap.com/dist/".to_string(),
                        "Check \"Install Npcap in WinPcap API-compatible Mode\"".to_string(),
                        "Uncheck \"Restrict Npcap driver's access to Administrators only\" so standard users can capture".to_string(),
                    ];

                    Ok(PrivilegeStatus::insufficient(missing, instructions))
                }
                Some(WindowsNpcapIssue::AdminOnly) => {
                    let missing = vec!["Packet capture device access".to_string()];

                    let instructions = vec![
                        "Run as Administrator: Right-click the terminal and select 'Run as Administrator'".to_string(),
                        "Or reinstall Npcap and uncheck \"Restrict Npcap driver's access to Administrators only\" (equivalent to /admin_only=no) so standard users can capture".to_string(),
                    ];

                    Ok(PrivilegeStatus::insufficient(missing, instructions))
                }
                None => {
                    // Some other error - assume it's not a privilege issue
                    warn!(
                        "Network device enumeration failed but error doesn't indicate privilege issue: {}",
                        e
                    );
                    Ok(PrivilegeStatus::sufficient())
                }
            }
        }
    }
}

#[cfg(target_os = "freebsd")]
fn check_freebsd_privileges() -> Result<PrivilegeStatus> {
    use std::fs;

    // Check if running as root by reading effective UID from process
    let is_root = is_root_user();

    if is_root {
        info!("Running as root - all privileges available");
        return Ok(PrivilegeStatus::sufficient());
    }

    debug!("Not running as root, checking BPF device permissions");

    // On FreeBSD, packet capture requires access to BPF devices
    // Try to open a BPF device to check permissions
    let bpf_devices = (0..10)
        .map(|i| format!("/dev/bpf{}", i))
        .collect::<Vec<_>>();

    let mut can_access_bpf = false;
    for bpf_device in &bpf_devices {
        if fs::metadata(bpf_device).is_ok() {
            debug!("Checking BPF device: {}", bpf_device);

            // Try to actually open it (this is the real test)
            if std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(bpf_device)
                .is_ok()
            {
                can_access_bpf = true;
                debug!("Successfully opened BPF device: {}", bpf_device);
                break;
            }
        }
    }

    if can_access_bpf {
        return Ok(PrivilegeStatus::sufficient());
    }

    // No BPF access - build error message
    let missing = vec!["Access to BPF devices (/dev/bpf*)".to_string()];

    let instructions = vec![
        "Run with sudo: sudo rustnet".to_string(),
        "Add your user to the bpf group:\n  \
         sudo pw groupmod bpf -m $(whoami)\n  \
         Then logout and login again"
            .to_string(),
        "Change BPF device permissions (temporary):\n  \
         sudo chmod o+rw /dev/bpf*"
            .to_string(),
    ];

    Ok(PrivilegeStatus::insufficient(missing, instructions))
}

/// Check if running as root user on Unix systems
#[cfg(unix)]
fn is_root_user() -> bool {
    effective_uid() == 0
}

/// Return the effective UID of the current process on Unix systems
#[cfg(unix)]
pub fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privilege_status_error_message() {
        let status = PrivilegeStatus::insufficient(
            vec!["CAP_NET_RAW".to_string()],
            vec!["Run with sudo".to_string()],
        );

        let msg = status.error_message();
        assert!(msg.contains("Insufficient privileges"));
        assert!(msg.contains("CAP_NET_RAW"));
        assert!(msg.contains("Run with sudo"));
    }

    #[test]
    fn test_sufficient_privileges() {
        let status = PrivilegeStatus::sufficient();
        assert!(status.has_privileges);
        assert!(status.error_message().is_empty());
    }

    #[test]
    fn test_classify_windows_npcap_error_not_installed() {
        assert_eq!(
            classify_windows_npcap_error(
                "failed to load wpcap.dll: The specified module could not be found"
            ),
            Some(WindowsNpcapIssue::NotInstalled)
        );
        assert_eq!(
            classify_windows_npcap_error("npcap is not installed"),
            Some(WindowsNpcapIssue::NotInstalled)
        );
        assert_eq!(
            classify_windows_npcap_error("cannot load Packet.dll"),
            Some(WindowsNpcapIssue::NotInstalled)
        );
    }

    #[test]
    fn test_classify_windows_npcap_error_admin_only() {
        assert_eq!(
            classify_windows_npcap_error("Error opening adapter: Access is denied"),
            Some(WindowsNpcapIssue::AdminOnly)
        );
        assert_eq!(
            classify_windows_npcap_error(
                "you don't have permission to capture on that device"
            ),
            Some(WindowsNpcapIssue::AdminOnly)
        );
        assert_eq!(
            classify_windows_npcap_error("insufficient privileges for packet capture"),
            Some(WindowsNpcapIssue::AdminOnly)
        );
    }

    #[test]
    fn test_classify_windows_npcap_error_unknown() {
        assert_eq!(classify_windows_npcap_error("the interface disappeared"), None);
        assert_eq!(classify_windows_npcap_error(""), None);
        // 大小写不敏感
        assert_eq!(
            classify_windows_npcap_error("ACCESS DENIED"),
            Some(WindowsNpcapIssue::AdminOnly)
        );
    }
}
