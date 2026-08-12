//! rustnetec: WebUI 设置页 PUT /config 的 YAML 形态回归测试。
//!
//! 背景：设置页保存曾报 HTTP 400，根因有三：
//! 1. 托盘状态行字段枚举名用了 `rate_in` 等带下划线写法，而后端
//!    `TrayStatusField` 为 `#[serde(rename_all = "lowercase")]`（`ratein`），
//!    导致 `tray_status_fields` 反序列化失败；
//! 2. 空数字/`language`(String 非 Option) 字段生成 `key:`(null)，
//!    使 serde 反序列化 u64/String 失败；
//! 3. `tray_status_fields: []` 会被 `PersistentConfig::validate()` 拒绝。
//! 前端修复为：正确枚举名 + 空值键跳过(走 serde default) + 空数组删除键。
//! 以下用例锁定"修复后的 YAML 形态必须可解析且通过校验"。

use rustnet_monitor::config::PersistentConfig;

#[test]
fn fixed_frontend_yaml_parses_and_validates() {
    // 修复后完整形态：枚举名 lowercase、数字/数组有值
    let y = "record_dns: true\n\
             refresh_interval: 500\n\
             retention_days: 90\n\
             tray_status_fields: [\"state\", \"interface\", \"ratein\", \"rateout\", \"connections\"]\n\
             reachability_targets: [\"8.8.8.8:53\", \"223.5.5.5:53\"]\n\
             autostart_mode: \"Daemon\"\n\
             language: \"zh-CN\"\n\
             upload_interval_secs: 60\n\
             http_port: 19811\n";
    let cfg: PersistentConfig = serde_yaml::from_str(y).expect("fixed YAML must parse");
    cfg.validate().expect("fixed YAML must validate");
}

#[test]
fn underscored_enum_name_is_rejected() {
    // 旧错误形态（rate_in）必须被拒绝——防止前端回退到带下划线枚举名
    let y = "tray_status_fields: [\"state\", \"rate_in\"]\n";
    assert!(
        serde_yaml::from_str::<PersistentConfig>(y).is_err(),
        "underscored enum variant must fail to deserialize"
    );
}

#[test]
fn null_number_is_rejected() {
    // null 数字必须被拒绝——前端应跳过空数字键而非生成 `key:`
    let y = "refresh_interval:\n";
    assert!(
        serde_yaml::from_str::<PersistentConfig>(y).is_err(),
        "null u64 must fail to deserialize"
    );
}

#[test]
fn sparse_config_uses_serde_defaults() {
    // 前端跳过空键后：缺失字段走 serde default，可解析且校验通过
    let y = "record_dns: true\n";
    let cfg: PersistentConfig = serde_yaml::from_str(y).expect("sparse YAML must parse");
    cfg.validate().expect("sparse YAML must validate");
    assert_eq!(cfg.tray_status_fields.len(), 5); // default: State/Interface/RateIn/RateOut/Connections
}
