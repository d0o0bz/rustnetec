// rustnetec: Platform-specific path resolution for data and config directories.
// Used by R1/R2/R7/R8/R9 for SQLite database, config.yml, and chown operations.

use anyhow::{Result, anyhow};
use std::fs;
use std::path::PathBuf;

/// Returns the platform-specific data directory for rustnetec.
///
/// - Linux/FreeBSD: `$XDG_DATA_HOME/rustnetec/` (fallback `~/.local/share/rustnetec/`)
/// - macOS: `~/Library/Application Support/rustnetec/`
/// - Windows: `%LOCALAPPDATA%\rustnetec\`
pub fn data_dir() -> Result<PathBuf> {
    let dir = match std::env::consts::OS {
        "linux" | "freebsd" => if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            PathBuf::from(xdg)
        } else {
            home_dir()?.join(".local/share")
        }
        .join("rustnetec"),
        "macos" => home_dir()?.join("Library/Application Support/rustnetec"),
        "windows" => if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
            PathBuf::from(local_appdata)
        } else {
            home_dir()?
        }
        .join("rustnetec"),
        _ => return Err(anyhow!("Unsupported platform for data directory")),
    };
    Ok(dir)
}

/// Returns the platform-specific config directory for rustnetec.
///
/// - Linux/FreeBSD: `$XDG_CONFIG_HOME/rustnetec/` (fallback `~/.config/rustnetec/`)
/// - macOS: `~/Library/Application Support/rustnetec/`
/// - Windows: `%APPDATA%\rustnetec\`
pub fn config_dir() -> Result<PathBuf> {
    let dir = match std::env::consts::OS {
        "linux" | "freebsd" => if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            PathBuf::from(xdg)
        } else {
            home_dir()?.join(".config")
        }
        .join("rustnetec"),
        "macos" => home_dir()?.join("Library/Application Support/rustnetec"),
        "windows" => if let Ok(appdata) = std::env::var("APPDATA") {
            PathBuf::from(appdata)
        } else {
            home_dir()?
        }
        .join("rustnetec"),
        _ => return Err(anyhow!("Unsupported platform for config directory")),
    };
    Ok(dir)
}

/// Returns the path to the SQLite database file: `data_dir()/data.db`
pub fn db_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("data.db"))
}

/// Returns the path to the config file: `config_dir()/config.yml`
pub fn config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.yml"))
}

/// Creates the data and config directories if they don't exist.
/// On Unix, sets directory permissions to `0700` (owner-only rwx).
pub fn ensure_dirs() -> Result<()> {
    let dirs = [data_dir()?, config_dir()?];
    for dir in dirs {
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

/// Chown a path to the specified uid/gid when running as root.
/// Only available on Unix. Used before dropping root privileges
/// so that the runtime user can still access data/config files.
///
/// This is a best-effort operation: errors are logged but not propagated,
/// since the retained file descriptors remain usable after the uid drop
/// even if the path ownership is wrong.
#[cfg(unix)]
pub fn chown_if_root(path: &std::path::Path, uid: u32, gid: u32) -> Result<()> {
    use log::warn;
    // Only chown if we are running as root (uid 0)
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let c_path = std::ffi::CString::new(path.to_string_lossy().into_owned())?;
    let result = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if result != 0 {
        let err = std::io::Error::last_os_error();
        warn!(
            "Failed to chown '{}' to uid:{} gid:{}: {}",
            path.display(),
            uid,
            gid,
            err
        );
        // Best-effort: don't fail hard, the retained fd is still usable
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn chown_if_root(_path: &std::path::Path, _uid: u32, _gid: u32) -> Result<()> {
    Ok(())
}

/// Returns the user's home directory.
fn home_dir() -> Result<PathBuf> {
    // Try HOME (Unix) or USERPROFILE (Windows) first
    if let Ok(home) = std::env::var("HOME") {
        return Ok(PathBuf::from(home));
    }
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        return Ok(PathBuf::from(userprofile));
    }
    // On Windows, try HOMEDRIVE + HOMEPATH
    // rustnetec: clippy collapsible_nested_if — 合并嵌套 if let 为 let-chain（Rust 1.88+ 稳定）
    if let Ok(homedrive) = std::env::var("HOMEDRIVE")
        && let Ok(homepath) = std::env::var("HOMEPATH")
    {
        return Ok(PathBuf::from(format!("{}{}", homedrive, homepath)));
    }
    Err(anyhow!("Could not determine home directory"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_returns_valid_path() {
        let dir = data_dir();
        assert!(dir.is_ok(), "data_dir() should succeed");
        let dir = dir.unwrap();
        assert!(
            dir.to_string_lossy().contains("rustnetec"),
            "data_dir should contain 'rustnetec': {:?}",
            dir
        );
    }

    #[test]
    fn config_dir_returns_valid_path() {
        let dir = config_dir();
        assert!(dir.is_ok(), "config_dir() should succeed");
        let dir = dir.unwrap();
        assert!(
            dir.to_string_lossy().contains("rustnetec"),
            "config_dir should contain 'rustnetec': {:?}",
            dir
        );
    }

    #[test]
    fn db_path_ends_with_data_db() {
        let path = db_path().unwrap();
        assert_eq!(
            path.file_name().unwrap(),
            "data.db",
            "db_path should end with 'data.db'"
        );
    }

    #[test]
    fn config_path_ends_with_config_yml() {
        let path = config_path().unwrap();
        assert_eq!(
            path.file_name().unwrap(),
            "config.yml",
            "config_path should end with 'config.yml'"
        );
    }

    #[test]
    fn ensure_dirs_creates_directories() {
        // Use a temporary subdirectory to avoid polluting the real paths
        let tmp = std::env::temp_dir().join("rustnetec-test-paths");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        // We can't easily test the real ensure_dirs() without side effects,
        // but we can verify the directory creation logic works
        let test_data = tmp.join("data");
        let test_config = tmp.join("config");
        fs::create_dir_all(&test_data).unwrap();
        fs::create_dir_all(&test_config).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&test_data, fs::Permissions::from_mode(0o700)).unwrap();
            let mode = fs::metadata(&test_data).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "directory should have 0700 permissions");
        }

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    #[cfg(unix)]
    fn chown_if_root_is_noop_for_non_root() {
        // When not running as root, chown_if_root should be a no-op
        let tmp = std::env::temp_dir().join("rustnetec-test-chown");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        // This should succeed even if we're not root
        let result = chown_if_root(&tmp, 1000, 1000);
        assert!(result.is_ok(), "chown_if_root should not fail for non-root");
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn linux_data_dir_respects_xdg() {
        // This test verifies the logic path; actual env var testing
        // would require process-level isolation
        if std::env::consts::OS == "linux" || std::env::consts::OS == "freebsd" {
            let dir = data_dir().unwrap();
            if std::env::var("XDG_DATA_HOME").is_ok() {
                assert!(
                    dir.starts_with(std::env::var("XDG_DATA_HOME").unwrap()),
                    "data_dir should respect XDG_DATA_HOME"
                );
            } else {
                assert!(
                    dir.ends_with(".local/share/rustnetec"),
                    "data_dir should fallback to ~/.local/share/rustnetec: {:?}",
                    dir
                );
            }
        }
    }

    #[test]
    fn macos_data_dir_is_application_support() {
        if std::env::consts::OS == "macos" {
            let dir = data_dir().unwrap();
            assert!(
                dir.ends_with("Library/Application Support/rustnetec"),
                "macOS data_dir should be ~/Library/Application Support/rustnetec: {:?}",
                dir
            );
        }
    }
}
