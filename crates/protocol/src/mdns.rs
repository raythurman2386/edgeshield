//! mDNS (Multicast DNS) protocol parsing for EdgeShield.
//!
//! Extracts service instance names, service types, and hostnames from
//! mDNS packets. mDNS reuses the DNS wire format on UDP port 5353,
//! typically multicast to 224.0.0.251.
//!
//! # What we extract
//!
//! mDNS packets carry DNS records. The most useful for device
//! identification are:
//!
//! - **PTR records** — map a service type (`_airplay._tcp.local`) to
//!   an instance name (`Living Room Apple TV._airplay._tcp.local`).
//! - **SRV records** — map an instance to a hostname + port.
//! - **A/AAAA records** — map a hostname to an IP.
//! - **TXT records** — carry device metadata (model, deviceid, etc.).
//!
//! We extract the first usable hostname from SRV records (the
//! `target` field) and the instance name from PTR records. The
//! hostname is the most actionable field — it's what turns a bare MAC
//! into "living-room-apple-tv.local" in a new-device alert.
//!
//! # DNS wire format
//!
//! Names are encoded as a sequence of labels, each prefixed by a
//! length byte, terminated by a zero byte. Names can be compressed
//! using pointers (a 2-byte value where the top two bits are set)
//! that reference an earlier offset in the packet. We support
//! compression — without it, most real mDNS packets would fail to
//! parse.
//!
//! # Why not use a DNS crate
//!
//! The DNS wire format is simple enough for our needs (extract a
//! hostname and instance name) that pulling in a full DNS parser
//! would be overkill. This keeps the `edgeshield-protocol` crate
//! dependency-light.

use tracing::trace;

/// Information extracted from an mDNS packet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MdnsInfo {
    /// Hostname from the first SRV record's target field
    /// (e.g., "living-room-apple-tv.local"). This is the most
    /// actionable field for device identification.
    pub hostname: Option<String>,
    /// Service instance name from the first PTR record
    /// (e.g., "Living Room Apple TV._airplay._tcp.local").
    pub instance: Option<String>,
    /// Service type from the first PTR record's name
    /// (e.g., "_airplay._tcp.local").
    pub service_type: Option<String>,
}

/// DNS record types we care about.
const RECORD_TYPE_PTR: u16 = 12;
const RECORD_TYPE_SRV: u16 = 33;

/// Parse an mDNS packet payload and extract identifying information.
///
/// The payload should start at the DNS header (after the UDP header).
/// Returns `None` if the payload is too short or malformed.
pub fn parse_mdns(payload: &[u8]) -> Option<MdnsInfo> {
    // DNS header is 12 bytes: ID (2), flags (2), QDCOUNT (2), ANCOUNT (2),
    // NSCOUNT (2), ARCOUNT (2).
    if payload.len() < 12 {
        trace!(len = payload.len(), "mDNS payload too short for header");
        return None;
    }

    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    let nscount = u16::from_be_bytes([payload[8], payload[9]]);
    let arcount = u16::from_be_bytes([payload[10], payload[11]]);

    let mut info = MdnsInfo::default();
    let mut offset = 12usize;

    // Skip the question section (QDCOUNT entries). Each question is a
    // name + 4 bytes (type + class). We need to skip names because they
    // may use compression.
    for _ in 0..qdcount {
        let (name_end, _) = skip_name(payload, offset)?;
        if name_end + 4 > payload.len() {
            return None;
        }
        offset = name_end + 4;
    }

    // Walk the answer/authority/additional sections. We collect the
    // first usable hostname and instance name across all sections —
    // order within a section is not guaranteed to be useful, but the
    // first SRV target and first PTR instance are good enough for
    // device identification.
    for section_count in [ancount, nscount, arcount] {
        for _ in 0..section_count {
            let record = match parse_record(payload, offset) {
                Some(r) => r,
                None => {
                    return if info.hostname.is_some() || info.instance.is_some() {
                        Some(info)
                    } else {
                        None
                    };
                }
            };
            offset = record.next_offset;

            // Extract hostname from the first SRV record.
            if info.hostname.is_none()
                && record.record_type == RECORD_TYPE_SRV
                && let Some(target) = record.srv_target
            {
                info.hostname = Some(target);
            }

            // Extract instance name and service type from the first PTR record.
            if info.instance.is_none() && record.record_type == RECORD_TYPE_PTR {
                info.instance = record.ptr_rdata;
                info.service_type = record.name;
            }
        }
    }

    if info.hostname.is_none() && info.instance.is_none() && info.service_type.is_none() {
        None
    } else {
        Some(info)
    }
}

/// A parsed DNS resource record.
struct ParsedRecord {
    /// The owner name of the record (e.g., "_airplay._tcp.local" for a
    /// PTR record, "Living Room._airplay._tcp.local" for an SRV).
    name: Option<String>,
    /// The record type (PTR, SRV, TXT, etc.).
    record_type: u16,
    /// Offset of the next record in the packet.
    next_offset: usize,
    /// For SRV records: the target hostname.
    srv_target: Option<String>,
    /// For PTR records: the rdata (an instance name).
    ptr_rdata: Option<String>,
}

/// Parse a single resource record starting at `offset`.
fn parse_record(payload: &[u8], offset: usize) -> Option<ParsedRecord> {
    let (name_end, name) = read_name(payload, offset)?;
    // name + type(2) + class(2) + ttl(4) + rdlength(2) = 10 bytes
    if name_end + 10 > payload.len() {
        return None;
    }
    let record_type = u16::from_be_bytes([payload[name_end], payload[name_end + 1]]);
    let rdlength = u16::from_be_bytes([payload[name_end + 8], payload[name_end + 9]]) as usize;
    let rdata_start = name_end + 10;
    if rdata_start + rdlength > payload.len() {
        return None;
    }
    let next_offset = rdata_start + rdlength;

    let mut record = ParsedRecord {
        name,
        record_type,
        next_offset,
        srv_target: None,
        ptr_rdata: None,
    };

    let rdata = &payload[rdata_start..rdata_start + rdlength];

    match record_type {
        RECORD_TYPE_PTR => {
            // PTR rdata is a domain name.
            let (_, rdata_name) = read_name(payload, rdata_start)?;
            record.ptr_rdata = rdata_name;
        }
        // SRV rdata: priority(2) + weight(2) + port(2) + target(name).
        RECORD_TYPE_SRV if rdata.len() >= 7 => {
            let target_offset = rdata_start + 6;
            let (_, target) = read_name(payload, target_offset)?;
            record.srv_target = target;
        }
        _ => {}
    }

    Some(record)
}

/// Skip over a domain name, returning the offset just past the name
/// and the name string (if parseable). Handles compression pointers.
fn skip_name(payload: &[u8], offset: usize) -> Option<(usize, Option<String>)> {
    read_name_internal(payload, offset, false)
}

/// Read a domain name, returning the offset just past the name and
/// the decoded name string. Handles compression pointers.
fn read_name(payload: &[u8], offset: usize) -> Option<(usize, Option<String>)> {
    read_name_internal(payload, offset, true)
}

/// Core name-reading logic. `collect` controls whether we build the
/// name string (we always need to walk it to find the end).
fn read_name_internal(
    payload: &[u8],
    mut offset: usize,
    collect: bool,
) -> Option<(usize, Option<String>)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end_offset: Option<usize> = None;
    let mut jumps = 0u8;
    let original_offset = offset;

    loop {
        if offset >= payload.len() {
            return None;
        }
        let len = payload[offset];

        // Compression pointer: top two bits set.
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= payload.len() {
                return None;
            }
            let pointer = (((len & 0x3F) as usize) << 8) | payload[offset + 1] as usize;
            // Record where the name ends (after the 2-byte pointer) if
            // this is the first pointer we've followed.
            if end_offset.is_none() {
                end_offset = Some(offset + 2);
            }
            // Guard against infinite loops from malicious/corrupt packets.
            jumps += 1;
            if jumps > 10 || pointer >= original_offset {
                return None;
            }
            offset = pointer;
            continue;
        }

        // Zero byte terminates the name.
        if len == 0 {
            offset += 1;
            let final_end = end_offset.unwrap_or(offset);
            let name = if collect && !labels.is_empty() {
                Some(labels.join("."))
            } else {
                None
            };
            return Some((final_end, name));
        }

        // Regular label: `len` bytes of name data follow.
        let label_end = offset + 1 + len as usize;
        if label_end > payload.len() {
            return None;
        }
        if collect {
            if let Ok(s) = std::str::from_utf8(&payload[offset + 1..label_end]) {
                labels.push(s.to_string());
            } else {
                // Non-UTF8 label — bail to avoid garbage in hostnames.
                return None;
            }
        }
        offset = label_end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a DNS name encoding (uncompressed) at the end of a buffer.
    fn encode_name(buf: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
    }

    /// Build a minimal mDNS response with one PTR record pointing to
    /// an SRV record (with a hostname) and an instance name.
    fn build_mdns_response(service_type: &str, instance: &str, hostname: &str) -> Vec<u8> {
        let mut buf = Vec::new();

        // Header: ID=0, flags=0x8400 (response, authoritative), 1 answer.
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&[0x84, 0x00]);
        buf.extend_from_slice(&[0x00, 0x00]); // QDCOUNT
        buf.extend_from_slice(&[0x00, 0x02]); // ANCOUNT = 2
        buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

        // Answer 1: PTR record. Owner name = service_type, rdata = instance.
        encode_name(&mut buf, service_type);
        buf.extend_from_slice(&RECORD_TYPE_PTR.to_be_bytes()); // type
        buf.extend_from_slice(&[0x00, 0x01]); // class = IN
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]); // TTL = 120
        // rdata length (filled below)
        let rdlen_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]);
        let rdata_start = buf.len();
        encode_name(&mut buf, instance);
        let rdlen = (buf.len() - rdata_start) as u16;
        buf[rdlen_pos..rdlen_pos + 2].copy_from_slice(&rdlen.to_be_bytes());

        // Answer 2: SRV record. Owner name = instance, rdata = priority+weight+port+target.
        encode_name(&mut buf, instance);
        buf.extend_from_slice(&RECORD_TYPE_SRV.to_be_bytes()); // type
        buf.extend_from_slice(&[0x00, 0x01]); // class = IN
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]); // TTL = 120
        let rdlen_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]);
        let rdata_start = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]); // priority
        buf.extend_from_slice(&[0x00, 0x00]); // weight
        buf.extend_from_slice(&[0x1f, 0x90]); // port 8080
        encode_name(&mut buf, hostname);
        let rdlen = (buf.len() - rdata_start) as u16;
        buf[rdlen_pos..rdlen_pos + 2].copy_from_slice(&rdlen.to_be_bytes());

        buf
    }

    #[test]
    fn test_parse_mdns_extracts_hostname_and_instance() {
        let payload = build_mdns_response(
            "_airplay._tcp.local",
            "Living Room._airplay._tcp.local",
            "living-room-apple-tv.local",
        );
        let info = parse_mdns(&payload).expect("should parse");
        assert_eq!(info.hostname.as_deref(), Some("living-room-apple-tv.local"));
        assert_eq!(
            info.instance.as_deref(),
            Some("Living Room._airplay._tcp.local")
        );
        assert_eq!(info.service_type.as_deref(), Some("_airplay._tcp.local"));
    }

    #[test]
    fn test_parse_mdns_too_short() {
        assert!(parse_mdns(&[0u8; 5]).is_none());
    }

    #[test]
    fn test_parse_mdns_empty_response() {
        // Header with zero answers.
        let payload = [
            0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(parse_mdns(&payload).is_none());
    }

    #[test]
    fn test_parse_mdns_with_compression_pointer() {
        // Build a response where the SRV owner name uses a compression
        // pointer back to the PTR rdata (which is the same instance name).
        let service_type = "_airplay._tcp.local";
        let instance = "Living Room._airplay._tcp.local";
        let hostname = "apple-tv.local";

        let mut buf = Vec::new();
        // Header
        buf.extend_from_slice(&[
            0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        ]);

        // PTR record: owner = service_type, rdata = instance (uncompressed).
        let ptr_owner_start = buf.len();
        encode_name(&mut buf, service_type);
        buf.extend_from_slice(&RECORD_TYPE_PTR.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x01]);
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]);
        let rdlen_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]);
        let rdata_start = buf.len();
        encode_name(&mut buf, instance);
        let rdlen = (buf.len() - rdata_start) as u16;
        buf[rdlen_pos..rdlen_pos + 2].copy_from_slice(&rdlen.to_be_bytes());

        // SRV record: owner = instance (use compression pointer to the
        // PTR rdata, which is the same instance name).
        buf.push(0xC0);
        buf.push(rdata_start as u8);
        buf.extend_from_slice(&RECORD_TYPE_SRV.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x01]);
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]);
        let rdlen_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]);
        let rdata_start = buf.len();
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x50]);
        encode_name(&mut buf, hostname);
        let rdlen = (buf.len() - rdata_start) as u16;
        buf[rdlen_pos..rdlen_pos + 2].copy_from_slice(&rdlen.to_be_bytes());

        let _ = ptr_owner_start; // suppress unused warning
        let info = parse_mdns(&buf).expect("should parse with compression");
        assert_eq!(info.hostname.as_deref(), Some("apple-tv.local"));
        assert_eq!(
            info.instance.as_deref(),
            Some("Living Room._airplay._tcp.local")
        );
    }

    #[test]
    fn test_parse_mdns_question_only() {
        // A query (not a response) with one question and no answers.
        let mut buf = Vec::new();
        buf.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        encode_name(&mut buf, "_airplay._tcp.local");
        buf.extend_from_slice(&[0x00, 0x0C]); // type PTR
        buf.extend_from_slice(&[0x00, 0x01]); // class IN
        // No answers — nothing to extract.
        assert!(parse_mdns(&buf).is_none());
    }

    #[test]
    fn test_parse_mdns_srv_only() {
        // A response with only an SRV record (no PTR).
        let mut buf = Vec::new();
        buf.extend_from_slice(&[
            0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        encode_name(&mut buf, "printer._ipp._tcp.local");
        buf.extend_from_slice(&RECORD_TYPE_SRV.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x01]);
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]);
        let rdlen_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]);
        let rdata_start = buf.len();
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x06, 0x51]); // port 1617
        encode_name(&mut buf, "hp-printer.local");
        let rdlen = (buf.len() - rdata_start) as u16;
        buf[rdlen_pos..rdlen_pos + 2].copy_from_slice(&rdlen.to_be_bytes());

        let info = parse_mdns(&buf).expect("should parse");
        assert_eq!(info.hostname.as_deref(), Some("hp-printer.local"));
        assert!(info.instance.is_none());
    }

    #[test]
    fn test_parse_mdns_truncated_record() {
        // Header claims 1 answer but the record is truncated.
        let payload = [
            0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, // truncated name
        ];
        assert!(parse_mdns(&payload).is_none());
    }
}
