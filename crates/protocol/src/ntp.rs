//! NTP (Network Time Protocol) header validation for EdgeShield.
//!
//! NTP uses UDP port 123. The header is 48 bytes for the basic fields
//! (up to 64 bytes with optional authenticator). We validate the
//! version and mode fields to confirm a packet is really NTP — this
//! reduces false positives where port 123 is used by something else.
//!
//! # NTP header format (first 4 bytes)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |LI | VN  |Mode |    Stratum     |     Poll      |  Precision   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! - **Leap Indicator (LI)**: 2 bits (0-3)
//! - **Version Number (VN)**: 3 bits (3 = NTPv3, 4 = NTPv4)
//! - **Mode**: 3 bits (1-6 are the useful values; 0 and 7 are reserved)
//!
//! We accept VN 3 or 4 and Mode 1-6 (client, server, symmetric, broadcast,
//! control). This is permissive enough for real traffic but rejects
//! random UDP payloads that happen to hit port 123.

use tracing::trace;

/// Information extracted from an NTP packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpInfo {
    /// NTP version number (3 or 4 for valid packets).
    pub version: u8,
    /// NTP mode (1=client, 2=server, 3=symmetric-active, 4=symmetric-passive,
    /// 5=broadcast, 6=control).
    pub mode: u8,
    /// Leap indicator (0=no warning, 1=last minute 61s, 2=last minute 59s,
    /// 3=alarm/unsynchronized).
    pub leap_indicator: u8,
}

/// Parse and validate an NTP packet payload.
///
/// Returns `None` if the payload is too short or the version/mode
/// fields are outside the expected ranges.
pub fn parse_ntp(payload: &[u8]) -> Option<NtpInfo> {
    // The basic NTP header is 48 bytes.
    if payload.len() < 48 {
        trace!(len = payload.len(), "NTP payload too short");
        return None;
    }

    let first_byte = payload[0];
    let leap_indicator = (first_byte >> 6) & 0x03;
    let version = (first_byte >> 3) & 0x07;
    let mode = first_byte & 0x07;

    // Accept NTPv3 and NTPv4. Earlier versions are obsolete; later
    // versions don't exist in the wild.
    if version != 3 && version != 4 {
        trace!(version, "NTP version not 3 or 4");
        return None;
    }

    // Mode 0 is reserved; mode 7 is reserved for private use. Modes
    // 1-6 cover client, server, symmetric, broadcast, and control.
    if !(1..=6).contains(&mode) {
        trace!(mode, "NTP mode outside 1-6");
        return None;
    }

    Some(NtpInfo {
        version,
        mode,
        leap_indicator,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal NTPv4 client request (mode 3).
    fn build_ntp_request(version: u8, mode: u8, leap: u8) -> Vec<u8> {
        let mut buf = vec![0u8; 48];
        let first_byte = (leap << 6) | (version << 3) | mode;
        buf[0] = first_byte;
        buf[1] = 1; // stratum
        buf
    }

    #[test]
    fn test_parse_ntp_v4_client_request() {
        let payload = build_ntp_request(4, 3, 0);
        let info = parse_ntp(&payload).unwrap();
        assert_eq!(info.version, 4);
        assert_eq!(info.mode, 3);
        assert_eq!(info.leap_indicator, 0);
    }

    #[test]
    fn test_parse_ntp_v3_server_response() {
        let payload = build_ntp_request(3, 4, 0);
        let info = parse_ntp(&payload).unwrap();
        assert_eq!(info.version, 3);
        assert_eq!(info.mode, 4);
    }

    #[test]
    fn test_parse_ntp_leap_indicator_extracted() {
        let payload = build_ntp_request(4, 3, 3);
        let info = parse_ntp(&payload).unwrap();
        assert_eq!(info.leap_indicator, 3);
    }

    #[test]
    fn test_parse_ntp_too_short() {
        assert!(parse_ntp(&[0u8; 47]).is_none());
    }

    #[test]
    fn test_parse_ntp_invalid_version() {
        // Version 2 is obsolete — should be rejected.
        let payload = build_ntp_request(2, 3, 0);
        assert!(parse_ntp(&payload).is_none());
        // Version 5 doesn't exist.
        let payload = build_ntp_request(5, 3, 0);
        assert!(parse_ntp(&payload).is_none());
    }

    #[test]
    fn test_parse_ntp_invalid_mode() {
        // Mode 0 is reserved.
        let payload = build_ntp_request(4, 0, 0);
        assert!(parse_ntp(&payload).is_none());
        // Mode 7 is reserved for private use.
        let payload = build_ntp_request(4, 7, 0);
        assert!(parse_ntp(&payload).is_none());
    }

    #[test]
    fn test_parse_ntp_all_valid_modes() {
        for mode in 1..=6 {
            let payload = build_ntp_request(4, mode, 0);
            let info = parse_ntp(&payload).unwrap();
            assert_eq!(info.mode, mode);
        }
    }
}