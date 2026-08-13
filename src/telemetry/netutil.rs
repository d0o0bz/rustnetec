// rustnetec: T-C1 — 外网/局域网/本机回路识别辅助函数。
//
// 本模块提供 IP 地址分类的纯函数，供 `/stats/*` 端点查询时过滤
// 「外部网络连接」「局域网连接」「本机回路连接」三类流量。
//
// 判定逻辑（依据 RFC 1918 / RFC 6598 / RFC 3927 / RFC 4291）：
// - `classify_dest(ip)` 返回 `DestClass` 四分类枚举：
//   * `External`   —— 公网（含文档用例段 203.0.113/24、198.51.100/24、192.0.2/24，
//                     真实流量不会命中，保留为外网）
//   * `Lan`        —— 局域网（RFC1918 私网段 + CGNAT 100.64.0.0/10）
//   * `Loopback`   —— 本机回路（127.0.0.0/8、::1）
//   * `LinkLocal`  —— 链路本地（169.254.0.0/16、fe80::/10）
// - `is_external_ip(ip)` ≡ `classify_dest(ip) == External`
// - `is_lan_ip(ip)`      ≡ `classify_dest(ip) == Lan`
//
// 注：`Loopback` 与 `LinkLocal` 既不算外网也不算局域网，属「本机/邻居发现」
// 流量，前端图表可据此三分类（外网/局域网/本机回路）展示。

/// IP 地址分类枚举（四分类）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DestClass {
    /// 公网（含文档用例段，排除私网/loopback/link-local/CGNAT）
    External,
    /// 局域网（RFC1918 私网段 + CGNAT 100.64.0.0/10）
    Lan,
    /// 本机回路（127.0.0.0/8、::1）
    Loopback,
    /// 链路本地（169.254.0.0/16、fe80::/10）
    LinkLocal,
}

impl DestClass {
    /// 分类的稳定字符串标识，用于持久化到 SQLite。
    /// 与 `/stats/range` 的 `scope` 参数取值（external/lan）对齐。
    pub fn as_str(self) -> &'static str {
        match self {
            DestClass::External => "external",
            DestClass::Lan => "lan",
            DestClass::Loopback => "loopback",
            DestClass::LinkLocal => "linklocal",
        }
    }
}

/// 判定目标 IP 是否为「外部网络」（公网）。
///
/// 排除：RFC1918 私网段、loopback、link-local、CGNAT（100.64.0.0/10）。
/// 包含：文档用例段（203.0.113/24、198.51.100/24、192.0.2/24）——真实流量不命中，
/// 保留为外网。
///
/// # 示例
///
/// ```
/// use rustnet_monitor::telemetry::netutil::is_external_ip;
/// assert!(is_external_ip("8.8.8.8"));
/// assert!(!is_external_ip("10.0.0.1"));
/// assert!(!is_external_ip("127.0.0.1"));
/// ```
pub fn is_external_ip(ip: &str) -> bool {
    classify_dest(ip) == DestClass::External
}

/// 判定目标 IP 是否为「局域网」。
///
/// 包含：RFC1918 私网段、CGNAT（100.64.0.0/10）。
/// 排除：loopback、link-local（属「本机/邻居发现」，非局域网）。
///
/// # 示例
///
/// ```
/// use rustnet_monitor::telemetry::netutil::is_lan_ip;
/// assert!(is_lan_ip("192.168.1.1"));
/// assert!(is_lan_ip("100.64.0.1"));
/// assert!(!is_lan_ip("127.0.0.1"));
/// ```
pub fn is_lan_ip(ip: &str) -> bool {
    classify_dest(ip) == DestClass::Lan
}

/// 分类目标 IP 地址。
///
/// 返回 `DestClass` 四分类枚举，供 `/stats/*` 端点按 `scope=external/lan`
/// 过滤时使用。调用方拉取 `connection_events` 行后，用此函数过滤 `dest_ip`。
///
/// # 错误处理
///
/// 解析失败的 IP（格式非法）归类为 `External`——保守策略，避免把异常地址
/// 误判为局域网后从外网图表中漏掉。
pub fn classify_dest(ip: &str) -> DestClass {
    // 先尝试 IPv4 解析（点分十进制），失败则尝试 IPv6。
    // `std::net::IpAddr` 解析失败时保守归类为 External。
    use std::net::IpAddr;
    let parsed: Option<IpAddr> = ip.parse().ok();
    match parsed {
        Some(IpAddr::V4(v4)) => classify_ipv4(v4),
        Some(IpAddr::V6(v6)) => classify_ipv6(v6),
        None => DestClass::External, // 格式非法，保守归类为外网
    }
}

/// IPv4 分类辅助函数。
fn classify_ipv4(ip: std::net::Ipv4Addr) -> DestClass {
    let octets = ip.octets();
    let [a, b, _c, _d] = octets;

    // Loopback: 127.0.0.0/8
    if a == 127 {
        return DestClass::Loopback;
    }

    // Link-local: 169.254.0.0/16
    if a == 169 && b == 254 {
        return DestClass::LinkLocal;
    }

    // RFC1918 私网段
    // 10.0.0.0/8
    if a == 10 {
        return DestClass::Lan;
    }
    // 172.16.0.0/12：a==172 且 b ∈ [16, 31]
    if a == 172 && (16..=31).contains(&b) {
        return DestClass::Lan;
    }
    // 192.168.0.0/16
    if a == 192 && b == 168 {
        return DestClass::Lan;
    }

    // CGNAT: 100.64.0.0/10 (RFC 6598)
    if a == 100 && (64..=127).contains(&b) {
        return DestClass::Lan;
    }

    // 其余视为外网（含文档用例段 203.0.113/24、198.51.100/24、192.0.2/24）
    DestClass::External
}

/// IPv6 分类辅助函数。
fn classify_ipv6(ip: std::net::Ipv6Addr) -> DestClass {
    let segments = ip.segments();

    // Loopback: ::1
    if ip == std::net::Ipv6Addr::LOCALHOST {
        return DestClass::Loopback;
    }

    // Link-local: fe80::/10
    // fe80::/10 范围：前 10 位为 1111111010，即 segments[0] 在 0xfe80..=0xfebf
    if segments[0] >= 0xfe80 && segments[0] <= 0xfebf {
        return DestClass::LinkLocal;
    }

    // IPv4-mapped IPv6 地址（::ffff:a.b.c.d）：透传到 IPv4 分类
    if segments[0] == 0 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0
        && segments[4] == 0 && segments[5] == 0xffff
    {
        let v4 = std::net::Ipv4Addr::new(
            ((segments[6] >> 8) & 0xff) as u8,
            (segments[6] & 0xff) as u8,
            ((segments[7] >> 8) & 0xff) as u8,
            (segments[7] & 0xff) as u8,
        );
        return classify_ipv4(v4);
    }

    // Unique Local Address fc00::/7（RFC 4193）：视为局域网
    if (segments[0] & 0xfe00) == 0xfc00 {
        return DestClass::Lan;
    }

    // 其余视为外网
    DestClass::External
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- IPv4 分类测试 ----

    #[test]
    fn ipv4_public_is_external() {
        assert!(is_external_ip("8.8.8.8"));
        assert!(is_external_ip("1.1.1.1"));
        assert!(is_external_ip("203.0.113.1")); // 文档用例段，保留为外网
        assert!(is_external_ip("198.51.100.1"));
        assert!(is_external_ip("192.0.2.1"));
    }

    #[test]
    fn ipv4_private_rfc1918_is_lan() {
        assert!(is_lan_ip("10.0.0.1"));
        assert!(is_lan_ip("10.255.255.255"));
        assert!(is_lan_ip("172.16.0.1"));
        assert!(is_lan_ip("172.31.255.255"));
        assert!(is_lan_ip("192.168.0.1"));
        assert!(is_lan_ip("192.168.1.1"));
    }

    #[test]
    fn ipv4_cgnat_is_lan() {
        assert!(is_lan_ip("100.64.0.1"));
        assert!(is_lan_ip("100.127.255.255"));
    }

    #[test]
    fn ipv4_loopback_is_not_lan_not_external() {
        assert!(!is_lan_ip("127.0.0.1"));
        assert!(!is_external_ip("127.0.0.1"));
        assert_eq!(classify_dest("127.0.0.1"), DestClass::Loopback);
    }

    #[test]
    fn ipv4_link_local_is_not_lan_not_external() {
        assert!(!is_lan_ip("169.254.1.1"));
        assert!(!is_external_ip("169.254.1.1"));
        assert_eq!(classify_dest("169.254.1.1"), DestClass::LinkLocal);
    }

    #[test]
    fn ipv4_private_is_not_external() {
        assert!(!is_external_ip("10.0.0.1"));
        assert!(!is_external_ip("172.16.0.1"));
        assert!(!is_external_ip("192.168.1.1"));
        assert!(!is_external_ip("100.64.0.1")); // CGNAT
    }

    #[test]
    fn ipv4_public_is_not_lan() {
        assert!(!is_lan_ip("8.8.8.8"));
        assert!(!is_lan_ip("1.1.1.1"));
    }

    // ---- IPv6 分类测试 ----

    #[test]
    fn ipv6_loopback_is_loopback_class() {
        assert_eq!(classify_dest("::1"), DestClass::Loopback);
        assert!(!is_external_ip("::1"));
        assert!(!is_lan_ip("::1"));
    }

    #[test]
    fn ipv6_link_local_is_linklocal_class() {
        assert_eq!(classify_dest("fe80::1"), DestClass::LinkLocal);
        assert_eq!(classify_dest("febf::1"), DestClass::LinkLocal);
        // fe7f::/10 不在 fe80::/10 范围内
        assert_ne!(classify_dest("fec0::1"), DestClass::LinkLocal);
    }

    #[test]
    fn ipv6_unique_local_is_lan() {
        assert!(is_lan_ip("fc00::1"));
        assert!(is_lan_ip("fd00::1"));
        assert!(is_lan_ip("fd12:3456:789a::1"));
    }

    #[test]
    fn ipv6_global_is_external() {
        assert!(is_external_ip("2001:4860:4860::8888")); // Google DNS
        assert!(is_external_ip("2606:4700:4700::1111")); // Cloudflare DNS
    }

    #[test]
    fn ipv4_mapped_ipv6_classifies_via_ipv4() {
        // ::ffff:10.0.0.1 应归类为 Lan
        assert_eq!(classify_dest("::ffff:10.0.0.1"), DestClass::Lan);
        // ::ffff:8.8.8.8 应归类为 External
        assert_eq!(classify_dest("::ffff:8.8.8.8"), DestClass::External);
        // ::ffff:127.0.0.1 应归类为 Loopback
        assert_eq!(classify_dest("::ffff:127.0.0.1"), DestClass::Loopback);
    }

    // ---- 异常输入测试 ----

    #[test]
    fn invalid_ip_classifies_as_external() {
        assert_eq!(classify_dest("not-an-ip"), DestClass::External);
        assert_eq!(classify_dest(""), DestClass::External);
        assert_eq!(classify_dest("999.999.999.999"), DestClass::External);
    }

    // ---- 边界值测试 ----

    #[test]
    fn ipv4_boundary_addresses() {
        // 172.16.0.0 是 172.16/12 的起点
        assert_eq!(classify_dest("172.16.0.0"), DestClass::Lan);
        // 172.31.255.255 是 172.16/12 的终点
        assert_eq!(classify_dest("172.31.255.255"), DestClass::Lan);
        // 172.15.255.255 在 172.16/12 之外，应为 External
        assert_eq!(classify_dest("172.15.255.255"), DestClass::External);
        // 172.32.0.0 在 172.16/12 之外，应为 External
        assert_eq!(classify_dest("172.32.0.0"), DestClass::External);

        // CGNAT 边界：100.64.0.0 起点、100.127.255.255 终点
        assert_eq!(classify_dest("100.64.0.0"), DestClass::Lan);
        assert_eq!(classify_dest("100.127.255.255"), DestClass::Lan);
        // 100.63.255.255 在 CGNAT 之外
        assert_eq!(classify_dest("100.63.255.255"), DestClass::External);
        // 100.128.0.0 在 CGNAT 之外
        assert_eq!(classify_dest("100.128.0.0"), DestClass::External);
    }
}
