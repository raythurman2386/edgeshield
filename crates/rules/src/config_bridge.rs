//! Conversion from config types to rule engine types.
//!
//! This module bridges `edgeshield_config::RuleConfig` (the TOML
//! representation) to `edgeshield_rules::Rule` (the runtime
//! representation). Keeping this conversion in the `rules` crate
//! means `edgeshield_config` doesn't depend on `edgeshield_rules`.

use edgeshield_common::Severity;
use std::str::FromStr;

use crate::engine::{Rule, RuleCondition};
use edgeshield_config::config::{RuleConditionConfig, RuleConfig};

/// Convert a `RuleConfig` from the TOML config into a runtime `Rule`.
///
/// Returns an error if the condition or severity is invalid (severity
/// is validated at config parse time, but the condition string is
/// validated here since `RuleConditionConfig` is an untagged enum that
/// accepts any string).
impl TryFrom<RuleConfig> for Rule {
    type Error = String;

    fn try_from(config: RuleConfig) -> Result<Self, Self::Error> {
        let severity = Severity::from_str(&config.severity)?;
        let condition = convert_condition(&config.condition)?;
        Ok(Rule::new(
            config.name,
            config.enabled,
            condition,
            severity,
            config.cooldown_seconds,
        ))
    }
}

/// Convert a `RuleConditionConfig` into a `RuleCondition`.
fn convert_condition(config: &RuleConditionConfig) -> Result<RuleCondition, String> {
    match config {
        RuleConditionConfig::Simple(s) => match s.as_str() {
            "new_device" => Ok(RuleCondition::NewDevice),
            "protocol_change" => Ok(RuleCondition::ProtocolChange),
            other => Err(format!(
                "unknown simple condition '{other}': expected new_device or protocol_change"
            )),
        },
        RuleConditionConfig::NewDeviceByVendor { new_device_by_vendor } => {
            Ok(RuleCondition::NewDeviceByVendor(new_device_by_vendor.clone()))
        }
        RuleConditionConfig::NewDeviceByMacPrefix { new_device_by_mac_prefix } => {
            Ok(RuleCondition::NewDeviceByMacPrefix(new_device_by_mac_prefix.clone()))
        }
        RuleConditionConfig::DeviceOffline { device_offline } => Ok(
            RuleCondition::DeviceOffline {
                after_seconds: device_offline.after_seconds,
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edgeshield_config::config::{DeviceOfflineCondition, RuleConfig};

    #[test]
    fn test_convert_new_device_rule() {
        let config = RuleConfig {
            name: "new-device".to_string(),
            enabled: true,
            condition: RuleConditionConfig::Simple("new_device".to_string()),
            severity: "info".to_string(),
            cooldown_seconds: 300,
        };
        let rule: Rule = config.try_into().unwrap();
        assert_eq!(rule.name, "new-device");
        assert!(rule.enabled);
        assert_eq!(rule.severity, Severity::Info);
        assert_eq!(rule.cooldown_seconds, 300);
        assert!(matches!(rule.condition, RuleCondition::NewDevice));
    }

    #[test]
    fn test_convert_device_offline_rule() {
        let config = RuleConfig {
            name: "offline".to_string(),
            enabled: true,
            condition: RuleConditionConfig::DeviceOffline {
                device_offline: DeviceOfflineCondition { after_seconds: 1800 },
            },
            severity: "warning".to_string(),
            cooldown_seconds: 0,
        };
        let rule: Rule = config.try_into().unwrap();
        assert!(matches!(
            rule.condition,
            RuleCondition::DeviceOffline { after_seconds: 1800 }
        ));
    }

    #[test]
    fn test_convert_invalid_simple_condition() {
        let config = RuleConfig {
            name: "bad".to_string(),
            enabled: true,
            condition: RuleConditionConfig::Simple("unknown_condition".to_string()),
            severity: "info".to_string(),
            cooldown_seconds: 0,
        };
        let result: Result<Rule, _> = config.try_into();
        assert!(result.is_err());
    }
}