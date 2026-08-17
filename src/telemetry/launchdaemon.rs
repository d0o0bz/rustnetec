// rustnetec: macOS LaunchDaemon 永久授权安装（T4.2 / 用户需求）
//
// 目标：daemon（抓包子进程）不再每次通过 osascript 弹授权窗口启动，而是
// 一次性安装为系统 LaunchDaemon：
//   - 写 `/Library/LaunchDaemons/com.rustnetec.daemon.plist`
//   - `launchctl bootstrap system` 加载
// 之后由 launchd 以 root 托管 daemon：开机自启、崩溃自动重启、运行期间
// 无需任何授权。仅「安装/卸载」本身需要一次系统授权（osascript 弹窗）。
//
// 关键点：
// 1. launchd 以 root 启动 daemon，但环境是 launchd 的（无用户 HOME、无
//    SUDO_UID/GID）。daemon 的 resolve_drop_target() 依赖 SUDO_UID/GID
//    才能正确降权回原用户（否则降为 nobody 并 chown 用户目录），HOME
//    决定 config.yml/token 路径——三者必须写进 plist 的
//    EnvironmentVariables。
// 2. 命令被 AppleScript `do shell script "..."` 包裹，内部不能出现 `"`
//    （-2740）；安装分两步：Rust 先写临时 plist（用户可写），osascript
//    提权只执行 `cp` + `launchctl bootstrap`（路径单引号，无双引号）。
// 3. 非 macOS 平台该模块无操作（模块整体 cfg 门控在调用侧）。

use anyhow::{Context, Result, bail};
use log::info;
use std::path::PathBuf;

/// launchd 服务标签（也用作 plist 文件名前缀）。
const LABEL: &str = "com.rustnetec.daemon";
const PLIST_FILENAME: &str = "com.rustnetec.daemon.plist";

/// 系统 LaunchDaemon plist 的固定路径（root 所有，需授权写入）。
fn daemon_plist_path() -> PathBuf {
    PathBuf::from("/Library/LaunchDaemons").join(PLIST_FILENAME)
}

/// 当前可执行文件绝对路径。
fn current_exe_path() -> Result<String> {
    let exe = std::env::current_exe()
        .context("failed to resolve current executable path")?
        .to_string_lossy()
        .into_owned();
    Ok(exe)
}

/// 从 LaunchDaemon plist 文本中提取 ProgramArguments 数组的第一个条目
/// （即 daemon 可执行文件路径）。解析失败（结构异常）返回 None。
///
/// 仅做轻量文本解析，不依赖外部 plist crate：本模块生成的 plist 格式固定
/// （ProgramArguments 数组首元素即 exe 路径），足以覆盖安装/校验场景。
fn plist_program_exe(content: &str) -> Option<String> {
    let key = "<key>ProgramArguments</key>";
    let key_pos = content.find(key)? + key.len();
    let rest = &content[key_pos..];
    let open = rest.find("<string>")? + "<string>".len();
    let close = rest[open..].find("</string>")?;
    Some(rest[open..open + close].to_string())
}

/// 校验 plist 内容：ProgramArguments 指向的可执行文件真实存在。
/// 与文件系统解耦，便于单元测试。
fn plist_executable_exists(content: &str) -> bool {
    match plist_program_exe(content) {
        Some(exe) => PathBuf::from(exe).is_file(),
        None => false,
    }
}

/// 是否已安装且有效的 LaunchDaemon：
/// plist 存在，且其 ProgramArguments 指向的可执行文件真实存在。
///
/// 二进制改名/移动后（如 rustnet → rustnetec），旧 plist 会因 exe 不存在
/// 而被判为未安装，避免托盘误判"已安装"后走 kickstart 失败路径
/// （`Could not find service`，daemon 永远起不来）。
pub fn is_installed() -> bool {
    let path = daemon_plist_path();
    if !path.exists() {
        return false;
    }
    match std::fs::read_to_string(&path) {
        Ok(content) => plist_executable_exists(&content),
        Err(_) => false,
    }
}

/// 是否存在 plist 文件（无论内容是否有效）。供 uninstall 清理损坏/过期
/// plist 使用——若用严格版 is_installed() 判断，损坏 plist 会永远卸不掉。
pub fn plist_exists() -> bool {
    daemon_plist_path().exists()
}

/// 生成 LaunchDaemon plist 内容。
///
/// ProgramArguments 指向当前二进制 `--daemon --http-port <port>`；
/// EnvironmentVariables 保留用户 HOME / SUDO_UID / SUDO_GID（降权回原用户
/// 与 config.yml 路径正确性所必需）以及 RUSTNETEC_TRAY_DAEMON 标记。
/// RunAtLoad=true（加载即启动）；KeepAlive=false（用户可随时 pkill 停止
/// daemon，launchd 不会自动复活——否则 pkill 后 daemon 永远杀不死）。
fn plist_content(exe: &str, http_port: u16, home: &str, uid: u32, gid: u32) -> String {
    // Escape minimal XML special chars in the exe path (defensive).
    let exe_esc = exe
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    format!(
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
         \t\t<string>--daemon</string>\n\
         \t\t<string>--http-port</string>\n\
         \t\t<string>{port}</string>\n\
         \t</array>\n\
         \t<key>EnvironmentVariables</key>\n\
         \t<dict>\n\
         \t\t<key>HOME</key>\n\
         \t\t<string>{home}</string>\n\
         \t\t<key>SUDO_UID</key>\n\
         \t\t<string>{uid}</string>\n\
         \t\t<key>SUDO_GID</key>\n\
         \t\t<string>{gid}</string>\n\
         \t\t<key>RUSTNETEC_TRAY_DAEMON</key>\n\
         \t\t<string>1</string>\n\
         \t</dict>\n\
         \t<key>RunAtLoad</key>\n\
         \t<true/>\n\
         \t<key>KeepAlive</key>\n\
         \t<false/>\n\
         </dict>\n\
         </plist>\n",
        label = LABEL,
        exe = exe_esc,
        port = http_port,
        home = home,
        uid = uid,
        gid = gid,
    )
}

/// 一次性授权安装 LaunchDaemon。
///
/// 流程：Rust 把 plist 写到临时目录（用户可写）→ osascript `do shell
/// script ... with administrator privileges`（弹一次系统授权）执行
/// `cp` 到 /Library/LaunchDaemons/ + `launchctl bootstrap system`。
/// 之后 daemon 由 launchd 托管，不再需要授权。
pub fn install(http_port: u16) -> Result<()> {
    if is_installed() {
        info!("LaunchDaemon already installed: {}", daemon_plist_path().display());
        return Ok(());
    }

    let exe = current_exe_path()?;
    let home = std::env::var("HOME").unwrap_or_default();
    // SAFETY: getuid/getgid 无失败模式、无指针。
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let plist = plist_content(&exe, http_port, &home, uid, gid);

    // 写临时 plist（用户可写，避免提权命令里内联 XML 的引号地狱）。
    let tmp = std::env::temp_dir().join(PLIST_FILENAME);
    std::fs::write(&tmp, plist).with_context(|| format!("failed to write temp plist {:?}", tmp))?;

    // 提权命令：cp 临时 plist 到系统目录 + bootstrap。命令内只有单引号
    // 路径，无 `"`，不会被 AppleScript 字符串截断。先 bootout 兜底
    // （旧 plist 的 exe 失效导致 is_installed()=false 但服务可能仍加载），
    // 保证重装幂等。
    let target = daemon_plist_path();
    let cmd = format!(
        "do shell script \"launchctl bootout system/{label} 2>/dev/null; \
         cp '{}' '/Library/LaunchDaemons/' && \
         launchctl bootstrap system '{}'\" with administrator privileges",
        tmp.display(),
        target.display(),
        label = LABEL
    );
    let out = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&cmd)
        .output()
        .context("failed to run osascript for LaunchDaemon install")?;

    let _ = std::fs::remove_file(&tmp); // 清理临时文件
    if !out.status.success() {
        bail!(
            "LaunchDaemon install failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    info!("LaunchDaemon installed and bootstrapped: {}", target.display());
    Ok(())
}

/// 卸载 LaunchDaemon：bootout + 删除 plist（同样需一次授权）。
/// 用 plist_exists() 而非 is_installed() 判断：exe 已失效的过期 plist
/// 也必须能卸载，否则旧文件永远残留。
pub fn uninstall() -> Result<()> {
    if !plist_exists() {
        info!("LaunchDaemon not installed — nothing to do");
        return Ok(());
    }
    let target = daemon_plist_path();
    let cmd = format!(
        "do shell script \"launchctl bootout system/{} 2>/dev/null; \
         rm -f '{}'\" with administrator privileges",
        LABEL,
        target.display()
    );
    let out = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&cmd)
        .output()
        .context("failed to run osascript for LaunchDaemon uninstall")?;
    if !out.status.success() {
        bail!(
            "LaunchDaemon uninstall failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    info!("LaunchDaemon removed: {}", target.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_contains_required_keys() {
        let p = plist_content("/usr/local/bin/rustnet", 19811, "/Users/alice", 501, 20);
        assert!(p.contains("<key>Label</key>"));
        assert!(p.contains("com.rustnetec.daemon"));
        assert!(p.contains("--daemon"));
        assert!(p.contains("--http-port"));
        assert!(p.contains("19811"));
        assert!(p.contains("<key>HOME</key>"));
        assert!(p.contains("/Users/alice"));
        assert!(p.contains("<key>SUDO_UID</key>"));
        assert!(p.contains("501"));
        assert!(p.contains("<key>SUDO_GID</key>"));
        assert!(p.contains("20"));
        assert!(p.contains("<key>RUSTNETEC_TRAY_DAEMON</key>"));
        assert!(p.contains("<key>RunAtLoad</key>"));
        assert!(p.contains("<key>KeepAlive</key>"));
        assert!(p.contains("<key>KeepAlive</key>\n\t<false/>"));
    }
    #[test]
    fn plist_escapes_exe_xml() {
        let p = plist_content("/tmp/a&b<c>d", 19811, "/Users/alice", 501, 20);
        assert!(p.contains("a&amp;b&lt;c&gt;d"));
        assert!(!p.contains("/tmp/a&b<c>d"));
    }
    #[test]
    fn plist_program_exe_extracts_first_argument() {
        let p = plist_content("/usr/local/bin/rustnetec", 19811, "/Users/alice", 501, 20);
        assert_eq!(plist_program_exe(&p), Some("/usr/local/bin/rustnetec".to_string()));
    }
    #[test]
    fn plist_program_exe_malformed_returns_none() {
        assert_eq!(plist_program_exe("not a plist"), None);
        // ProgramArguments 存在但数组为空
        let p = "<dict><key>ProgramArguments</key><array></array></dict>";
        assert_eq!(plist_program_exe(p), None);
    }
    #[test]
    fn plist_executable_exists_checks_real_file() {
        // 当前可执行文件真实存在（测试进程自身）
        let p = plist_content(&current_exe_path().unwrap(), 19811, "/Users/alice", 501, 20);
        assert!(plist_executable_exists(&p));
        // 指向不存在路径的 plist 必须判为未安装
        let p2 = plist_content("/nonexistent/rustnetec", 19811, "/Users/alice", 501, 20);
        assert!(!plist_executable_exists(&p2));
    }
}
