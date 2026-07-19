//! Email notifier — sends alerts via SMTP.
//!
//! Uses the `lettre` crate for SMTP delivery (no local MTA required).
//! Each alert is sent as a plain-text email with a human-readable
//! subject and body.

use edgeshield_common::Alert;
use edgeshield_config::config::EmailConfig;
use lettre::message::header::ContentType;
use lettre::message::Message;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::{AsyncTransport, Tokio1Executor};
use tracing::info;

use crate::fanout::{Notifier, NotifierError};

/// An email-backed notifier. Sends each alert as a plain-text email
/// via SMTP using async transport.
pub struct EmailNotifier {
    config: EmailConfig,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl EmailNotifier {
    /// Create a new email notifier.
    pub fn new(config: EmailConfig) -> Result<Self, NotifierError> {
        let creds = Credentials::new(
            config.username.clone(),
            config.password.clone(),
        );

        // Use `starttls_relay` for STARTTLS (port 587, default) or
        // `relay` for implicit TLS (port 465). The `starttls` config
        // flag selects between them. Both constructors set up TLS
        // parameters automatically.
        let transport_builder = if config.starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
        }
        .map_err(|e| NotifierError::Config(format!("SMTP relay build failed: {e}")))?
        .port(config.port)
        .credentials(creds);

        Ok(Self {
            config,
            transport: transport_builder.build(),
        })
    }

    /// Build the email body for an alert.
    fn build_email(&self, alert: &Alert) -> Result<Message, NotifierError> {
        let subject = format!(
            "{} {} — {}",
            self.config.subject_prefix, alert.severity, alert.message
        );

        let body = format_alert_body(alert);

        Message::builder()
            .from(self.config.from.parse().map_err(|e| {
                NotifierError::Config(format!("invalid from address: {e}"))
            })?)
            .to(self.config.to.parse().map_err(|e| {
                NotifierError::Config(format!("invalid to address: {e}"))
            })?)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body)
            .map_err(|e| NotifierError::Delivery(format!("email build failed: {e}")))
    }
}

/// Render an alert as a human-readable plain-text email body.
fn format_alert_body(alert: &Alert) -> String {
    let device = &alert.device_snapshot;
    let mut body = format!(
        "EdgeShield Alert\n\
         ================\n\n\
         Rule: {rule_name}\n\
         Severity: {severity}\n\
         Event: {event_type}\n\
         Time: {timestamp}\n\n\
         Device:\n\
         MAC: {mac}\n\
         Hostname: {hostname}\n\
         Vendor: {vendor}\n\
         IPs: {ips}\n\
         Protocols: {protocols}\n\n\
         Message: {message}\n",
        rule_name = alert.rule_name,
        severity = alert.severity,
        event_type = alert.event_type,
        timestamp = alert.timestamp,
        mac = device.mac,
        hostname = device.hostname.as_deref().unwrap_or("(unknown)"),
        vendor = device.vendor.as_deref().unwrap_or("(unknown)"),
        ips = if device.ips.is_empty() {
            "(none)".to_string()
        } else {
            device
                .ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        },
        protocols = if device.protocols.is_empty() {
            "(none)".to_string()
        } else {
            device
                .protocols
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        },
        message = alert.message,
    );

    if alert.acknowledged {
        body.push_str("\n(Alert acknowledged)\n");
    }

    body
}

#[async_trait::async_trait]
impl Notifier for EmailNotifier {
    async fn deliver(&self, alert: &Alert) -> Result<(), NotifierError> {
        let email = self.build_email(alert)?;

        self.transport
            .send(email)
            .await
            .map_err(|e| NotifierError::Delivery(format!("SMTP send failed: {e}")))?;

        info!(mac = %alert.mac, to = %self.config.to, "alert sent via email");
        Ok(())
    }

    fn name(&self) -> &str {
        "email"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edgeshield_common::{AlertEventType, Device, Severity};
    use mac_address::MacAddress;
    use std::str::FromStr;

    fn sample_alert() -> Alert {
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let mut device = Device::new(mac);
        device.vendor = Some("TP-Link".to_string());
        device.hostname = Some("living-room-plug".to_string());
        Alert::new(
            "new-device".to_string(),
            Severity::Warning,
            AlertEventType::NewDevice,
            device,
            "New device discovered".to_string(),
        )
    }

    #[test]
    fn test_format_alert_body_includes_fields() {
        let alert = sample_alert();
        let body = format_alert_body(&alert);
        assert!(body.contains("Rule: new-device"));
        assert!(body.contains("Severity: warning"));
        assert!(body.contains("MAC: 00:11:22:33:44:55"));
        assert!(body.contains("Hostname: living-room-plug"));
        assert!(body.contains("Vendor: TP-Link"));
        assert!(body.contains("Message: New device discovered"));
    }

    #[test]
    fn test_format_alert_body_handles_unknown_fields() {
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let device = Device::new(mac);
        let alert = Alert::new(
            "test".to_string(),
            Severity::Info,
            AlertEventType::NewDevice,
            device,
            "test".to_string(),
        );
        let body = format_alert_body(&alert);
        assert!(body.contains("Hostname: (unknown)"));
        assert!(body.contains("Vendor: (unknown)"));
        assert!(body.contains("IPs: (none)"));
    }
}