//! DHCP protocol parsing for EdgeShield.
//!
//! Extracts hostname (option 12) and vendor class (option 60) from
//! DHCP packets. DHCP uses UDP ports 67 (server) and 68 (client).
//!
//! # DHCP Message Format
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)   |
//! +---------------+---------------+---------------+---------------+
//! |                            xid (4)                            |
//! +-------------------------------+-------------------------------+
//! |           secs (2)            |           flags (2)           |
//! +-------------------------------+-------------------------------+
//! |                          ciaddr (4)                           |
//! +---------------------------------------------------------------+
//! |                          yiaddr (4)                           |
//! +---------------------------------------------------------------+
//! |                          siaddr (4)                           |
//! +---------------------------------------------------------------+
//! |                          giaddr (4)                           |
//! +---------------------------------------------------------------+
//! |                                                               |
//! |                          chaddr (16)                          |
//! |                                                               |
//! +---------------------------------------------------------------+
//! |                                                               |
//! |                          sname (64)                           |
//! +---------------------------------------------------------------+
//! |                                                               |
//! |                          file (128)                           |
//! +---------------------------------------------------------------+
//! |                        options (variable)                     |
//! +---------------------------------------------------------------+
//! ```
//!
//! Options are TLV-encoded: tag (1 byte), length (1 byte), value (length bytes).
//! Common tags:
//! - 12: Hostname
//! - 60: Vendor class identifier
//! - 53: DHCP message type (1=Discover, 2=Offer, 3=Request, 4=Decline, 5=ACK, 6=NAK, 7=Release, 8=Inform)

use tracing::trace;

/// Information extracted from a DHCP packet.
#[derive(Debug, Clone, Default)]
pub struct DhcpInfo {
    /// Hostname from option 12.
    pub hostname: Option<String>,
    /// Vendor class identifier from option 60.
    pub vendor_class: Option<String>,
    /// DHCP message type from option 53.
    pub message_type: Option<u8>,
}

/// Parse a DHCP packet payload and extract options.
///
/// The payload should start at the DHCP header (after the UDP header).
/// Returns `None` if the payload is too short to be a valid DHCP message.
pub fn parse_dhcp(payload: &[u8]) -> Option<DhcpInfo> {
    if payload.len() < 240 {
        trace!(len = payload.len(), "DHCP payload too short");
        return None;
    }

    // The DHCP options start at byte 240 (after the fixed header).
    // The first 4 bytes of the options field are the magic cookie (0x63825363).
    if payload.len() < 244 {
        return None;
    }

    // Verify magic cookie
    if payload[240] != 0x63 || payload[241] != 0x82
        || payload[242] != 0x53 || payload[243] != 0x63
    {
        trace!("DHCP magic cookie not found");
        return None;
    }

    let mut info = DhcpInfo::default();
    let mut offset = 244;

    // Parse TLV options
    while offset + 1 < payload.len() {
        let tag = payload[offset];

        // End option (255) terminates the options list
        if tag == 255 {
            break;
        }

        // Pad option (0) is a no-op
        if tag == 0 {
            offset += 1;
            continue;
        }

        if offset + 1 >= payload.len() {
            break;
        }

        let len = payload[offset + 1] as usize;

        if offset + 2 + len > payload.len() {
            break;
        }

        let value = &payload[offset + 2..offset + 2 + len];

        match tag {
            12 => {
                // Hostname
                if let Ok(hostname) = std::str::from_utf8(value) {
                    let hostname = hostname.trim_end_matches('\0').to_string();
                    if !hostname.is_empty() {
                        trace!(hostname = %hostname, "DHCP hostname extracted");
                        info.hostname = Some(hostname);
                    }
                }
            }
            60 => {
                // Vendor class identifier
                if let Ok(vendor) = std::str::from_utf8(value) {
                    let vendor = vendor.trim_end_matches('\0').to_string();
                    if !vendor.is_empty() {
                        trace!(vendor = %vendor, "DHCP vendor class extracted");
                        info.vendor_class = Some(vendor);
                    }
                }
            }
            53 => {
                // DHCP message type — len is guaranteed >= 1 by the bounds check above
                info.message_type = Some(value[0]);
            }
            _ => {}
        }

        offset += 2 + len;
    }

    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DHCP packet with a hostname option.
    fn build_dhcp_payload(hostname: &str) -> Vec<u8> {
        let mut buf = vec![0u8; 240];

        // Magic cookie
        buf.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);

        // DHCP message type option (53)
        buf.push(53);
        buf.push(1);
        buf.push(3); // Request

        // Hostname option (12)
        buf.push(12);
        buf.push(hostname.len() as u8);
        buf.extend_from_slice(hostname.as_bytes());

        // End option
        buf.push(255);

        buf
    }

    #[test]
    fn test_dhcp_parse_hostname() {
        let payload = build_dhcp_payload("raspberrypi");
        let info = parse_dhcp(&payload).unwrap();
        assert_eq!(info.hostname.as_deref(), Some("raspberrypi"));
        assert_eq!(info.message_type, Some(3));
    }

    #[test]
    fn test_dhcp_parse_empty_hostname() {
        let payload = build_dhcp_payload("");
        let info = parse_dhcp(&payload).unwrap();
        assert!(info.hostname.is_none());
    }

    #[test]
    fn test_dhcp_parse_too_short() {
        let result = parse_dhcp(&[0u8; 10]);
        assert!(result.is_none());
    }

    #[test]
    fn test_dhcp_parse_no_magic_cookie() {
        let mut payload = vec![0u8; 244];
        // Wrong magic cookie
        payload[240] = 0x00;
        payload[241] = 0x00;
        payload[242] = 0x00;
        payload[243] = 0x00;
        let result = parse_dhcp(&payload);
        assert!(result.is_none());
    }

    #[test]
    fn test_dhcp_parse_vendor_class() {
        let mut buf = vec![0u8; 240];
        buf.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);

        // Vendor class option (60)
        buf.push(60);
        buf.push(9);
        buf.extend_from_slice(b"udhcp 1.0");

        // End option
        buf.push(255);

        let info = parse_dhcp(&buf).unwrap();
        assert_eq!(info.vendor_class.as_deref(), Some("udhcp 1.0"));
    }

    #[test]
    fn test_dhcp_parse_multiple_options() {
        let mut buf = vec![0u8; 240];
        buf.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);

        // Message type: Offer
        buf.push(53);
        buf.push(1);
        buf.push(2);

        // Hostname
        buf.push(12);
        buf.push(5);
        buf.extend_from_slice(b"my-pc");

        // Vendor class
        buf.push(60);
        buf.push(6);
        buf.extend_from_slice(b"dhcpcd");

        // End
        buf.push(255);

        let info = parse_dhcp(&buf).unwrap();
        assert_eq!(info.hostname.as_deref(), Some("my-pc"));
        assert_eq!(info.vendor_class.as_deref(), Some("dhcpcd"));
        assert_eq!(info.message_type, Some(2));
    }
}
