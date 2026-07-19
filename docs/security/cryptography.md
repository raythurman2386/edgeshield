# Cryptography

## Overview

EdgeShield does not currently implement any cryptographic operations. The MVP is a read-only network monitoring tool that operates on a local network and exposes an unauthenticated, plaintext HTTP API. Cryptography will be introduced in future phases as the system adds authentication, encryption, and integrity verification.

This document describes the cryptographic standards that will be used and the rationale for deferring cryptography in the MVP.

## Current State

| Operation | Status | Rationale |
|-----------|--------|-----------|
| TLS for API | Not implemented | MVP is read-only, no sensitive data in transit |
| API authentication | Not implemented | MVP is read-only, deployed on trusted networks |
| Password hashing | Not implemented | No user accounts in MVP |
| Data encryption at rest | Not implemented | No persistent storage in MVP |
| Binary signing | Not implemented | Pre-release, no distribution infrastructure |
| Configuration integrity | Not implemented | Configuration is not sensitive |

## TLS

### When needed

TLS will be required when:

1. The API is exposed beyond localhost
2. Authentication is added (API keys, passwords)
3. The web dashboard is deployed
4. The API serves sensitive data (future: alert details, network topology)

### Implementation

EdgeShield will use **rustls** for TLS, not OpenSSL. rustls is a pure-Rust TLS library that:

- Eliminates an entire class of memory safety vulnerabilities (OpenSSL has a long history of CVEs)
- Has no C dependencies (simpler build, no cross-compilation issues)
- Supports TLS 1.2 and TLS 1.3
- Is actively maintained by the Rust community

```toml
# Cargo.toml (future)
[dependencies]
rustls = "0.23"
axum-server = { version = "0.7", features = ["rustls"] }
```

### Configuration

```toml
[api]
tls_certificate = "/etc/edgeshield/cert.pem"
tls_key = "/etc/edgeshield/key.pem"
```

### Certificate management

- **Self-signed certificates**: Acceptable for homelab use. EdgeShield will generate a self-signed certificate on first run if no certificate is configured.
- **Let's Encrypt**: Recommended for production. EdgeShield will support automatic certificate renewal via `acme-client` (future).
- **Custom CA**: Supported for enterprise deployments with internal PKI.

### Cipher suites

When TLS is enabled, EdgeShield will use the following cipher suites (in order of preference):

1. `TLS_AES_256_GCM_SHA384` (TLS 1.3)
2. `TLS_CHACHA20_POLY1305_SHA256` (TLS 1.3)
3. `TLS_AES_128_GCM_SHA256` (TLS 1.3)

No TLS 1.2 or earlier cipher suites will be enabled. TLS 1.3 is mandatory.

## Hashing

### When needed

Hashing will be required when:

1. API keys are stored (store hash, not plaintext)
2. Configuration integrity is verified
3. Alert deduplication (hash of alert content)

### Algorithms

| Algorithm | Use Case | Status |
|-----------|----------|--------|
| SHA-256 | API key hashing, configuration integrity | Planned |
| BLAKE3 | Fast hashing for detection engine | Under consideration |

### API key storage

API keys will be stored as SHA-256 hashes:

```rust
use sha2::{Sha256, Digest};

fn hash_api_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}
```

The plaintext API key is shown to the user once at creation time and is never stored. If the key is lost, a new one must be generated.

## Certificates

### Self-signed certificate generation

EdgeShield will generate a self-signed certificate on first run if no certificate is configured:

```bash
edgeshield init-tls --hostname edgeshield.local
```

This generates:

- `/etc/edgeshield/cert.pem` — Self-signed X.509 certificate
- `/etc/edgeshield/key.pem` — Private key (permissions: 600)

### Certificate validation

- **Client-side**: EdgeShield will validate client certificates when mTLS is enabled
- **Server-side**: Clients should verify the EdgeShield certificate against a trusted CA
- **Self-signed**: EdgeShield will display the certificate fingerprint for manual verification

## Key Management

### Current state

EdgeShield does not manage any cryptographic keys in the MVP.

### Future key types

| Key Type | Purpose | Storage | Rotation |
|----------|---------|---------|----------|
| TLS private key | HTTPS termination | Filesystem (600 permissions) | Manual or ACME |
| API key | Client authentication | SHA-256 hash in config | Manual |
| Signing key | Binary and release signing | Offline HSM or air-gapped | Per-release |

### Key generation

All keys will be generated using the operating system's CSPRNG (`getrandom` on Linux, which uses `getrandom(2)` syscall or `/dev/urandom`).

```rust
use rand::rngs::OsRng;
use rand::RngCore;

fn generate_api_key() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
```

### Key storage best practices

- TLS private keys: `chmod 600`, owned by `root:root`
- API keys: Stored as SHA-256 hashes, never as plaintext
- No keys embedded in the binary
- No keys in environment variables (use files or key management services)

## Randomness

### Source

EdgeShield uses the operating system's CSPRNG for all cryptographic randomness:

- **Linux**: `getrandom(2)` syscall (via `rand::rngs::OsRng`)
- **Raspberry Pi**: Hardware random number generator (via `getrandom(2)`)

### Usage

| Use Case | Source | Notes |
|----------|--------|-------|
| API key generation | `OsRng` | 256-bit random hex string |
| TLS key generation | `OsRng` | Via rustls/rcgen |
| Session IDs (future) | `OsRng` | 128-bit random value |
| Nonce generation | `OsRng` | 64-bit random value |

### Quality

- All randomness comes from the kernel's CSPRNG
- No use of `std::collections::HashMap`'s random state (not cryptographic)
- No use of `rand::rngs::StdRng` for cryptographic purposes
- No seeding from time or PID

## Future Encryption Strategy

### Data at rest

When persistent storage is added (Phase 6), device data will be stored in SQLite without encryption. The threat model does not require encryption at rest because:

- Device data (MAC addresses, IP addresses) is not highly sensitive
- The database is on the local filesystem, protected by OS permissions
- Full-disk encryption (LUKS, BitLocker) is the operator's responsibility

Future versions may add optional encryption at rest using:

- **SQLite Encryption Extension (SEE)**: Commercial extension for SQLite encryption
- **sqlcipher**: Open-source encrypted SQLite
- **Application-level encryption**: Encrypt sensitive fields before writing to the database

### Data in transit

All API traffic will be encrypted with TLS 1.3 when TLS is enabled (Phase 8). Until then, API traffic is plaintext HTTP and should only be used on trusted networks.

### End-to-end encryption

EdgeShield does not plan to implement end-to-end encryption. The monitoring data is consumed locally and does not need to be protected from the EdgeShield host.

## Cryptographic Audit

Before the first release with cryptography enabled, a cryptographic audit will be performed:

1. **Algorithm review**: All algorithms are reviewed against current best practices
2. **Implementation review**: All cryptographic code is reviewed for correct usage
3. **Randomness review**: All randomness sources are verified
4. **Key management review**: All key storage and rotation procedures are verified

The audit will be performed by an external security firm for the commercial edition and by the community for the open-source edition.

## Compliance

### PCI DSS

EdgeShield does not process, store, or transmit payment card data. PCI DSS compliance is not required.

### HIPAA

EdgeShield does not process, store, or transmit protected health information (PHI). HIPAA compliance is not required.

### GDPR

EdgeShield processes MAC addresses and IP addresses, which may be considered personal data under GDPR. Operators are responsible for:

- Ensuring lawful basis for processing
- Implementing appropriate technical measures
- Responding to data subject requests
- Maintaining a record of processing activities

EdgeShield provides the following features to support GDPR compliance:

- **Data minimization**: Only MAC addresses, IP addresses, and protocol metadata are stored
- **Retention control**: Future retention policies will allow automatic data pruning
- **Export**: The API provides full data export
- **Deletion**: Future API will support device deletion
