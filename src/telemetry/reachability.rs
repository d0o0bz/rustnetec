//! rustnetec: 外网可达率探测线程。
//!
//! 每轮对配置的一组 DNS 服务器（`ip:port`，默认 53）发起 UDP DNS 查询，
//! 查询固定域名（`ntp.ntsc.ac.cn` 与 `ntp.sjtu.edu.cn`）。
//! 策略：随机起点 + 环形顺序 + **快速优先**——命中 ≤150ms 的「快」目标
//! （国内 DNS 通常 <50ms）立即早退；慢目标（如国外 8.8.8.8 ~180ms）记作
//! 候选但继续探测，以优先返回国内结果；全部失败才判定不可达。
//! 结果写入 `reachability_probes` 表，供仪表盘「外网可达率」图表查询。
//!
//! 设计：
//! - 用 DNS（UDP/53）而非 NTP/TCP connect：DNS 是上网的基础依赖，
//!   响应快（国内 ~10ms）、流量小（请求 ~40B、响应 ~60B）、连通率高；
//!   测的是「DNS 真的能解析」而非「端口开着」。
//! - 多目标冗余：单个 DNS 服务器故障/被屏蔽不影响整体可达性判断。
//! - 独立 SQLite 连接 + WAL，与 SqliteSink writer 并发安全。
//! - 每轮重新读取 PersistentConfig，改 config.yml 后下一轮生效，无需重启。

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use log::{info, warn};
use rusqlite::{params, Connection, OpenFlags};

use crate::config::PersistentConfig;

/// 单个目标的 UDP 收发超时。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// 探测目标解析失败/关闭时的兜底间隔。
const DEFAULT_INTERVAL_SECS: u64 = 12;
/// 「快」目标延迟阈值（毫秒）：命中即早退。
/// 国内 DNS 通常 <50ms，国外（如 8.8.8.8）~180ms；设为 150ms 可优先国内。
const FAST_THRESHOLD_MS: f64 = 150.0;
/// 探测时查询的固定域名列表（同时查询，任一返回即成功）。
/// 选用稳定存在的国内域名，避免被污染/拦截。
const PROBE_DOMAINS: &[&str] = &["ntp.ntsc.ac.cn", "ntp.sjtu.edu.cn"];
/// DNS 报文最小长度（12 字节 header）。
const DNS_HEADER_LEN: usize = 12;

/// 一轮探测的聚合结果。
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeResult {
    /// 本轮是否探测到至少一个可达目标。
    pub reachable: bool,
    /// 本轮**第一个成功目标**的往返耗时（毫秒）；早退策略下不再取全量最小值，
    /// 全部失败为 None。
    pub latency_ms: Option<f64>,
    /// 早退策略下简化为 1（可达）/ 0（不可达），不再统计可达目标总数。
    pub targets_ok: u32,
    /// 本轮探测的目标总数。
    pub targets_total: u32,
}

/// 解析 `host:port` 为 socket 地址；无端口时默认 53（DNS）。
///
/// 支持域名（由系统 resolver 解析）和裸 IP。返回第一个解析到的地址。
fn parse_target(target: &str) -> Option<SocketAddr> {
    // 已经带端口。
    if let Ok(mut addrs) = target.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return Some(addr);
        }
    }
    // 裸 host：补 DNS 端口 53。
    let with_port = format!("{target}:53");
    if let Ok(mut addrs) = with_port.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return Some(addr);
        }
    }
    None
}

/// 编码 DNS QNAME：`example.com` → `\x07example\x03com\x00`。
fn encode_qname(domain: &str) -> Vec<u8> {
    let mut qname = Vec::new();
    for label in domain.split('.') {
        if label.is_empty() {
            continue;
        }
        let len = label.len().min(63) as u8;
        qname.push(len);
        qname.extend_from_slice(label.as_bytes());
    }
    qname.push(0);
    qname
}

/// 构造 DNS 查询报文：查询给定域名的 A 记录（QTYPE=1, QCLASS=1 IN）。
///
/// Header：ID=0（用不到响应匹配）、flags=0x0100（RD=1 递归查询）、qdcount=1。
fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut pkt = Vec::new();
    // ID=0x0000, flags=0x0100, qdcount=1, ancount=0, nscount=0, arcount=0
    pkt.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&encode_qname(domain));
    // QTYPE=A (1), QCLASS=IN (1)
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    pkt
}

/// 判断 DNS 响应是否合法：至少 12 字节、QR=1（响应）、RCODE=0（无错误）。
fn is_valid_dns_response(data: &[u8]) -> bool {
    if data.len() < DNS_HEADER_LEN {
        return false;
    }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qr = (flags >> 15) & 1;
    let rcode = flags & 0xF;
    qr == 1 && rcode == 0
}

/// 对单个 DNS 目标发起一次探测，返回往返耗时（毫秒）。
///
/// 依次查询 `PROBE_DOMAINS` 中的域名，任一返回有效 DNS 响应即成功，
/// 取该次往返耗时。
fn probe_one(target: &str) -> Option<f64> {
    let addr = parse_target(target)?;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect(addr).ok()?;
    socket.set_read_timeout(Some(CONNECT_TIMEOUT)).ok()?;
    socket.set_write_timeout(Some(CONNECT_TIMEOUT)).ok()?;

    for domain in PROBE_DOMAINS {
        let req = build_dns_query(domain);
        let start = Instant::now();
        if socket.send(&req).is_err() {
            continue;
        }
        let mut buf = [0u8; 512];
        match socket.recv(&mut buf) {
            Ok(n) if is_valid_dns_response(&buf[..n]) => {
                return Some(start.elapsed().as_secs_f64() * 1000.0);
            }
            _ => continue,
        }
    }
    None
}

/// splitmix64 终态混合（用于把种子打散，替代会退化的 LCG）。
fn mix64(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

/// 基于种子的确定性随机起点（纯函数，便于测试）。
///
/// 用 splitmix64 混合种子后取模 `n`，对任意常见 `n`（2、5 等）都有良好分布。
/// 之前用 LCG（乘数 1664525 被 5 整除）导致 `random_start(5)` 恒为 3——
/// 每轮都从 8.8.8.8（国外 DNS）开始探测，早退后延迟恒为 ~180ms。
fn random_start_from(seed: u64, n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    (mix64(seed) as usize) % n
}

/// 基于时间种子的随机起点，委托给纯函数 `random_start_from`。
fn random_start(n: usize) -> usize {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    random_start_from(seed, n)
}

/// 本轮探测顺序：从 `start` 起环形遍历 `0..n`（不重复、全覆盖）。
fn probe_order(n: usize, start: usize) -> Vec<usize> {
    (0..n).map(|i| (start + i) % n).collect()
}

/// 从随机起点按环形顺序探测，**快速优先 + 成功早退**。
///
/// - 命中延迟 ≤ `FAST_THRESHOLD_MS`（快目标，如国内 DNS）→ 立即返回；
/// - 慢目标（如国外 8.8.8.8 ~180ms）记作候选但**继续探测**，期望找到更快的目标；
/// - 全部探测完仍无快目标 → 回退到第一个慢目标候选（若有）；否则不可达。
///
/// `probe` 为单目标探测闭包（生产用 `probe_one`，测试可注入假实现验证早退）。
fn probe_with_order<F>(targets: &[String], start: usize, mut probe: F) -> ProbeResult
where
    F: FnMut(&str) -> Option<f64>,
{
    let n = targets.len();
    let mut slow_candidate: Option<f64> = None;
    for idx in probe_order(n, start) {
        if let Some(ms) = probe(targets[idx].trim()) {
            if ms <= FAST_THRESHOLD_MS {
                return ProbeResult {
                    reachable: true,
                    latency_ms: Some(ms),
                    targets_ok: 1,
                    targets_total: n as u32,
                };
            }
            // 慢目标：记录首个候选，继续探测期望命中更快的国内目标。
            if slow_candidate.is_none() {
                slow_candidate = Some(ms);
            }
        }
    }
    if let Some(ms) = slow_candidate {
        return ProbeResult {
            reachable: true,
            latency_ms: Some(ms),
            targets_ok: 1,
            targets_total: n as u32,
        };
    }
    ProbeResult {
        reachable: false,
        latency_ms: None,
        targets_ok: 0,
        targets_total: n as u32,
    }
}

/// 对一组目标执行一轮探测并聚合结果。
///
/// 策略：随机起点 + 环形顺序 + 快速优先——优先返回 ≤150ms 的国内 DNS 结果，
/// 慢目标（国外）仅作候选回退；全部失败才算不可达。
pub fn run_probe_round(targets: &[String]) -> ProbeResult {
    let start = random_start(targets.len());
    probe_with_order(targets, start, probe_one)
}

/// 把一轮探测结果写入 `reachability_probes` 表（INSERT OR REPLACE，按 ts 去重）。
fn persist_probe(conn: &Connection, result: &ProbeResult) -> rusqlite::Result<()> {
    let ts = chrono::Local::now().to_rfc3339();
    conn.execute(
        "INSERT OR REPLACE INTO reachability_probes \
         (ts, reachable, latency_ms, targets_ok, targets_total) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            ts,
            result.reachable as i64,
            result.latency_ms,
            result.targets_ok as i64,
            result.targets_total as i64,
        ],
    )?;
    Ok(())
}

/// 启动可达率探测后台线程，立即返回。线程随 `should_stop` 置位退出。
///
/// 每轮从 `PersistentConfig::load()` 重新读取开关、目标列表与间隔，
/// 因此修改 config.yml 后下一轮生效，无需重启 daemon。
pub fn start_reachability_probe(
    db_path: PathBuf,
    should_stop: Arc<AtomicBool>,
) -> Result<(), std::io::Error> {
    // 启动前建表，确保表存在（与 SqliteSink 共用同一 DB 文件）。
    let conn = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS reachability_probes (\
            ts TEXT PRIMARY KEY, reachable INTEGER NOT NULL, latency_ms REAL,\
            targets_ok INTEGER NOT NULL, targets_total INTEGER NOT NULL);\
         CREATE INDEX IF NOT EXISTS idx_reach_ts ON reachability_probes (ts);",
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    drop(conn);

    thread::Builder::new()
        .name("reachability-probe".to_string())
        .spawn(move || {
            info!("Reachability probe thread started");
            while !should_stop.load(Ordering::Relaxed) {
                let cfg = PersistentConfig::load().unwrap_or_default();
                if !cfg.reachability_enabled || cfg.reachability_targets.is_empty() {
                    // 关闭或无目标：按默认间隔空转等待，避免忙轮询。
                    thread::sleep(Duration::from_secs(DEFAULT_INTERVAL_SECS));
                    continue;
                }

                let result = run_probe_round(&cfg.reachability_targets);
                match Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_WRITE) {
                    Ok(c) => {
                        if let Err(e) = persist_probe(&c, &result) {
                            warn!("reachability persist failed: {e}");
                        }
                    }
                    Err(e) => warn!("reachability open db failed: {e}"),
                }

                let secs = cfg.reachability_interval_secs.max(5) as u64;
                // 分段 sleep，以便 should_stop 在 1s 粒度内响应。
                let started = Instant::now();
                while started.elapsed() < Duration::from_secs(secs)
                    && !should_stop.load(Ordering::Relaxed)
                {
                    thread::sleep(Duration::from_secs(1));
                }
            }
            info!("Reachability probe thread exiting");
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_probe_round_empty_targets_is_unreachable() {
        let r = run_probe_round(&[]);
        assert!(!r.reachable);
        assert!(r.latency_ms.is_none());
        assert_eq!(r.targets_ok, 0);
        assert_eq!(r.targets_total, 0);
    }

    #[test]
    fn parse_target_defaults_to_dns_port() {
        // 裸 IP 补 53
        let addr = parse_target("8.8.8.8").expect("should resolve");
        assert_eq!(addr.port(), 53);
        // 显式端口保留
        let addr = parse_target("8.8.8.8:5353").expect("should resolve");
        assert_eq!(addr.port(), 5353);
        // 非法
        assert!(parse_target("not a host!!").is_none());
    }

    #[test]
    fn dns_query_is_well_formed() {
        let pkt = build_dns_query("ntp.ntsc.ac.cn");
        // header
        assert_eq!(&pkt[..DNS_HEADER_LEN], &[0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // 结尾 QTYPE=A(1) + QCLASS=IN(1)
        assert_eq!(&pkt[pkt.len()-4..], &[0x00, 0x01, 0x00, 0x01]);
        // QNAME 应以 \x00 结尾，且 label 长度正确
        assert_eq!(pkt[DNS_HEADER_LEN], 3); // "ntp"
    }

    #[test]
    fn qname_encoding() {
        let q = encode_qname("example.com");
        assert_eq!(q, vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
    }

    #[test]
    fn validates_dns_response() {
        // 过短
        assert!(!is_valid_dns_response(&[0u8; 10]));
        // 长度够但 QR=0（查询而非响应）
        let query = [0u8; 12];
        assert!(!is_valid_dns_response(&query));
        // 合法响应：QR=1, RCODE=0
        let mut resp = [0u8; 12];
        resp[2] = 0x81; // flags high byte: QR=1, RD=1
        resp[3] = 0x80; // flags low byte: RA=1, RCODE=0
        assert!(is_valid_dns_response(&resp));
        // RCODE=3（NXDOMAIN）应判为无效
        resp[3] = 0x83;
        assert!(!is_valid_dns_response(&resp));
    }

    #[test]
    fn random_start_from_stays_in_range_and_varies() {
        // n<=1 恒为 0
        assert_eq!(random_start_from(0, 0), 0);
        assert_eq!(random_start_from(0, 1), 0);
        // 多组 n、多组种子：结果必须落在 [0, n)，且 n>=2 时至少出现 2 个不同值。
        // 防退化回归：LCG 曾因乘数被 5 整除导致 random_start(5) 恒为 3。
        for n in [2usize, 3, 5, 7, 16] {
            let mut seen = std::collections::HashSet::new();
            for seed in 0..10_000u64 {
                let s = random_start_from(seed, n);
                assert!(s < n, "random_start_from({seed}, {n}) = {s} out of range");
                seen.insert(s);
            }
            if n >= 2 {
                assert!(
                    seen.len() >= 2,
                    "random_start_from for n={n} did not vary: {seen:?}"
                );
            }
        }
    }

    #[test]
    fn probe_order_is_cyclic_and_covers_all() {
        // 环形顺序：起点之后环绕，且每个索引恰好出现一次
        for n in [1usize, 2, 3, 5, 8] {
            for start in 0..n {
                let order = probe_order(n, start);
                assert_eq!(order.len(), n, "order length mismatch for n={n}");
                assert_eq!(order[0], start, "must start at {start}");
                let mut seen = vec![false; n];
                for &i in &order {
                    assert!(!seen[i], "duplicate index {i} in order for n={n}");
                    seen[i] = true;
                }
                // 相邻步进为 +1（环形）
                for w in order.windows(2) {
                    assert_eq!((w[1] + n - w[0]) % n, 1);
                }
            }
        }
    }

    #[test]
    fn probe_with_order_stops_at_first_success() {
        // 注入假探测：只有 b 成功；从 start=0 开始（顺序 a,b,c,d），
        // 应探测 a（失败）→ b（成功）即早退，不再探测 c/d。
        let targets = vec![
            "a:53".to_string(),
            "b:53".to_string(),
            "c:53".to_string(),
            "d:53".to_string(),
        ];
        let mut probed: Vec<String> = Vec::new();
        let r = probe_with_order(&targets, 0, |t| {
            probed.push(t.to_string());
            if t.starts_with('b') {
                Some(12.5)
            } else {
                None
            }
        });
        assert!(r.reachable);
        assert_eq!(r.latency_ms, Some(12.5));
        assert_eq!(r.targets_ok, 1);
        assert_eq!(r.targets_total, 4);
        // 早退：探测了 a、b 后即停，未探测 c/d
        assert_eq!(probed, vec!["a:53".to_string(), "b:53".to_string()]);
    }

    #[test]
    fn probe_with_order_all_fail_is_unreachable() {
        let targets = vec!["a:53".to_string(), "b:53".to_string()];
        let r = probe_with_order(&targets, 0, |_| None);
        assert!(!r.reachable);
        assert!(r.latency_ms.is_none());
        assert_eq!(r.targets_ok, 0);
        assert_eq!(r.targets_total, 2);
    }

    #[test]
    fn probe_with_order_prefers_fast_over_slow() {
        // a 是慢目标（>150ms，模拟国外），b 是快目标（≤150ms，模拟国内）。
        // 应记录 a 为候选但继续探测，命中 b 后返回快目标延迟。
        let targets = vec![
            "a:53".to_string(),
            "b:53".to_string(),
            "c:53".to_string(),
            "d:53".to_string(),
        ];
        let mut probed: Vec<String> = Vec::new();
        let r = probe_with_order(&targets, 0, |t| {
            probed.push(t.to_string());
            if t.starts_with('a') {
                Some(180.0) // 慢（国外）
            } else if t.starts_with('b') {
                Some(12.0) // 快（国内）
            } else {
                None
            }
        });
        assert!(r.reachable);
        // 命中快目标 b 的延迟，而非慢候选 a
        assert_eq!(r.latency_ms, Some(12.0));
        assert_eq!(r.targets_ok, 1);
        assert_eq!(r.targets_total, 4);
        // 探测了 a（慢，候选）、b（快，早退），未探测 c/d
        assert_eq!(probed, vec!["a:53".to_string(), "b:53".to_string()]);
    }

    #[test]
    fn probe_with_order_falls_back_to_slow_candidate() {
        // 全部目标都慢（>150ms）：无快目标时回退到第一个慢候选
        let targets = vec![
            "a:53".to_string(),
            "b:53".to_string(),
            "c:53".to_string(),
        ];
        let r = probe_with_order(&targets, 0, |t| {
            if t.starts_with('a') {
                Some(180.0)
            } else if t.starts_with('b') {
                Some(190.0)
            } else {
                None
            }
        });
        assert!(r.reachable);
        assert_eq!(r.latency_ms, Some(180.0)); // 回退到首个慢候选
        assert_eq!(r.targets_ok, 1);
        assert_eq!(r.targets_total, 3);
    }

    #[test]
    fn probe_with_order_empty_is_unreachable() {
        let r = probe_with_order(&[], 0, |_| None);
        assert!(!r.reachable);
        assert!(r.latency_ms.is_none());
        assert_eq!(r.targets_ok, 0);
        assert_eq!(r.targets_total, 0);
    }
}
