// rustnetec: Telemetry module for data persistence, event sinks, and identity.

pub mod db; // rustnetec: SqliteSink for local data persistence (R2)
pub mod http; // rustnetec: Local loopback HTTP service (R5, T1.4)
pub mod identity; // rustnetec: Host identity — snowflake user_id + BLAKE3 machine_id (R8+R10, T1.6)
pub mod paths;
pub mod query; // rustnetec: query subcommand with filter-to-SQL translation (R5, T1.3)

use serde::Serialize;
use std::sync::Arc;

/// Connection event data extracted from a Connection for sink consumption.
///
/// Field set aligns with `log_connection_event()` json!() output in app.rs.
/// This struct decouples the event pipeline from the Connection type, allowing
/// sinks (JsonLineSink, SqliteSink, UploadSink) to consume events without
/// depending on the full Connection struct (which does not derive Serialize).
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionEventData {
    // Event metadata
    pub timestamp: String,
    pub event: String,

    // Five-tuple
    pub protocol: String,
    pub source_ip: String,
    pub source_port: u16,
    pub destination_ip: String,
    pub destination_port: u16,

    // DNS resolution (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_hostname: Option<String>,

    // Process attribution (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_ppid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_gid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution_match: Option<String>,

    // RTT (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,

    // Kubernetes (optional, feature-gated)
    #[cfg(feature = "kubernetes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kubernetes: Option<serde_json::Map<String, serde_json::Value>>,

    // Service (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,

    // Direction (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,

    // DPI (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpi_protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpi_domain: Option<String>,

    // GeoIP (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip_country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip_country_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip_asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip_as_org: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip_city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip_postal_code: Option<String>,

    // Connection statistics (for closed events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_sent: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_received: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u64>,
}

/// Trait for consuming connection events.
///
/// Implementations include JsonLineSink (existing JSONL output),
/// SqliteSink (P1), and UploadSink (P2). The trait is Send + Sync
/// so it can be shared across threads.
pub trait ConnectionEventSink: Send + Sync {
    /// Accept a connection event for processing.
    /// Implementations should not block the calling thread;
    /// use internal buffering or async dispatch if needed.
    fn accept(&self, event: &ConnectionEventData);
}

// ---- JsonLineSink implementation ----

/// A ConnectionEventSink that writes events as JSONL to a file.
/// Wraps the existing JsonLineWriter from app.rs.
pub struct JsonLineSink {
    writer: Arc<crate::app::JsonLineWriter>,
}

impl JsonLineSink {
    pub fn new(writer: Arc<crate::app::JsonLineWriter>) -> Self {
        Self { writer }
    }
}

impl ConnectionEventSink for JsonLineSink {
    fn accept(&self, event: &ConnectionEventData) {
        let json = serde_json::to_value(event).unwrap_or_else(|e| {
            log::warn!("Failed to serialize ConnectionEventData: {}", e);
            serde_json::json!({})
        });
        self.writer.write(&json);
    }
}

/// A no-op sink that discards all events. Useful as a default
/// when no sinks are configured.
pub struct NullSink;

impl ConnectionEventSink for NullSink {
    fn accept(&self, _event: &ConnectionEventData) {}
}

/// A multi-sink that fans out events to multiple sinks.
pub struct FanoutSink {
    pub sinks: Vec<Box<dyn ConnectionEventSink>>,
}

impl ConnectionEventSink for FanoutSink {
    fn accept(&self, event: &ConnectionEventData) {
        for sink in &self.sinks {
            sink.accept(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_event_data_serializes() {
        let event = ConnectionEventData {
            timestamp: "2026-08-04T20:00:00.123+08:00".to_string(),
            event: "new_connection".to_string(),
            protocol: "TCP".to_string(),
            source_ip: "192.168.1.1".to_string(),
            source_port: 12345,
            destination_ip: "10.0.0.1".to_string(),
            destination_port: 443,
            destination_hostname: Some("example.com".to_string()),
            source_hostname: None,
            pid: Some(1234),
            process_ppid: None,
            process_name: Some("curl".to_string()),
            process_executable: None,
            process_uid: None,
            process_gid: None,
            attribution_match: None,
            rtt_ms: Some(12.3),
            #[cfg(feature = "kubernetes")]
            kubernetes: None,
            service_name: Some("https".to_string()),
            direction: Some("outgoing".to_string()),
            dpi_protocol: Some("HTTPS".to_string()),
            dpi_domain: Some("example.com".to_string()),
            geoip_country_code: Some("US".to_string()),
            geoip_country_name: None,
            geoip_asn: None,
            geoip_as_org: None,
            geoip_city: None,
            geoip_postal_code: None,
            bytes_sent: None,
            bytes_received: None,
            duration_secs: None,
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["protocol"], "TCP");
        assert_eq!(json["source_port"], 12345);
        assert_eq!(json["destination_hostname"], "example.com");
        // None fields should be skipped
        assert!(json.get("source_hostname").is_none());
        assert!(json.get("bytes_sent").is_none());
    }

    #[test]
    fn null_sink_accepts_without_error() {
        let sink = NullSink;
        let event = ConnectionEventData {
            timestamp: "2026-08-04T20:00:00.123+08:00".to_string(),
            event: "new_connection".to_string(),
            protocol: "TCP".to_string(),
            source_ip: "1.2.3.4".to_string(),
            source_port: 80,
            destination_ip: "5.6.7.8".to_string(),
            destination_port: 443,
            destination_hostname: None,
            source_hostname: None,
            pid: None,
            process_ppid: None,
            process_name: None,
            process_executable: None,
            process_uid: None,
            process_gid: None,
            attribution_match: None,
            rtt_ms: None,
            #[cfg(feature = "kubernetes")]
            kubernetes: None,
            service_name: None,
            direction: None,
            dpi_protocol: None,
            dpi_domain: None,
            geoip_country_code: None,
            geoip_country_name: None,
            geoip_asn: None,
            geoip_as_org: None,
            geoip_city: None,
            geoip_postal_code: None,
            bytes_sent: None,
            bytes_received: None,
            duration_secs: None,
        };
        sink.accept(&event); // should not panic
    }
}
