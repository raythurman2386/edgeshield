# Security Policy

## Supported Versions

EdgeShield follows [Semantic Versioning](https://semver.org/). The following versions receive security updates:

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Active development — security fixes in next release |
| < 0.1   | ❌ Pre-release, not supported |

During the 0.x phase, security fixes are delivered in the next planned release. Patch releases are cut for critical vulnerabilities.

## Threat Model

EdgeShield is a passive network monitoring tool. Its threat model assumes:

### Assets
- **Device inventory data**: MAC addresses, IP addresses, hostnames, traffic patterns
- **Configuration files**: Interface selection, API port, log level
- **API access**: Read-only access to network metadata
- **System integrity**: The EdgeShield binary and its runtime process

### Trust Boundaries
1. **Network interface** → EdgeShield: The capture interface is the primary data source. A compromised network can feed malicious packets to EdgeShield.
2. **API port** → EdgeShield: The REST API is accessible to anyone who can reach the configured port.
3. **Filesystem** → EdgeShield: The configuration file and (future) database are on the local filesystem.

### Attack Surfaces
1. **Packet capture**: Malformed packets designed to exploit parsing vulnerabilities
2. **REST API**: Unauthenticated access, denial of service, information disclosure
3. **Configuration file**: Malicious configuration values
4. **Dependencies**: Vulnerabilities in third-party crates

### Threat Actors
- **Local network users**: Can observe or inject packets on the same LAN
- **Remote attackers**: Can reach the API port if exposed beyond localhost
- **Malware on the host**: Can access the device store and configuration

### Mitigations
- **Memory safety**: Rust eliminates buffer overflows, use-after-free, and double-free
- **Defensive parsing**: All packet parsing handles truncated and malformed data gracefully
- **No outbound connections**: EdgeShield never initiates network connections
- **Minimal API surface**: Four read-only endpoints in the MVP
- **Bounded resources**: All internal data structures have fixed capacity
- **Structured logging**: All errors are logged with context for forensic analysis

## Vulnerability Reporting

If you discover a security vulnerability in EdgeShield, please report it privately.

**Do not** file a public GitHub issue. Instead, send an email to **security@edgeshield.io**.

### What to include
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Suggested fix (if available)

### Response timeline
- **24 hours**: Acknowledgment of receipt
- **7 days**: Initial assessment and severity classification
- **30 days**: Fix released for critical vulnerabilities
- **90 days**: Fix released for moderate vulnerabilities

### Disclosure policy
We follow coordinated disclosure. We will work with the reporter to determine an appropriate disclosure timeline. We aim to release fixes before public disclosure.

## Cryptographic Standards

EdgeShield uses the following cryptographic standards:

| Standard | Usage | Status |
|----------|-------|--------|
| TLS 1.3 | Future: API server HTTPS | Planned |
| X.509 | Future: Certificate-based authentication | Planned |
| SHA-256 | Future: Configuration integrity verification | Planned |
| Ed25519 | Future: Binary signing | Planned |
| BLAKE3 | Future: Fast hashing for detection engine | Under consideration |

EdgeShield does not currently implement any cryptographic operations. All cryptography is deferred to well-audited libraries (rustls, ring, ed25519-dalek) when needed.

### Key management
- No keys are currently managed by EdgeShield
- Future API keys will be stored as SHA-256 hashes
- Future TLS certificates will use the system certificate store
- No private keys are embedded in the binary

## Dependency Auditing

EdgeShield uses `cargo audit` to scan dependencies for known vulnerabilities.

### Audit process
- **Every CI run**: `cargo audit` is run on every pull request
- **Every release**: Full dependency audit before tagging
- **Weekly**: Automated dependency scan with notification on new vulnerabilities

### Current audit status
- All dependencies are audited
- No known vulnerabilities in the dependency tree
- Dependencies are pinned to specific versions in `Cargo.lock`

### Dependency policy
- New dependencies require justification in the pull request
- Dependencies with known vulnerabilities are blocked at the CI level
- `unsafe` code in dependencies is flagged for review
- Minimal feature sets are used to reduce attack surface

## Secure Development Practices

### Code review
- All code changes require review by at least one maintainer
- Security-sensitive changes (packet parsing, API, authentication) require review by two maintainers
- Reviewers check for: unsafe code, error handling, input validation, resource leaks

### Testing
- Unit tests cover error paths and edge cases
- Fuzz testing for packet parsing (planned)
- Integration tests exercise the full pipeline
- No test dependencies on external services

### CI/CD
- `cargo clippy` with deny-level warnings
- `cargo audit` for dependency vulnerabilities
- `cargo test` with all targets
- `cargo fmt --check` for consistent formatting
- Builds on x86_64 Linux, aarch64 Linux, and armv7 Linux

### Release process
1. All tests pass on all target architectures
2. `cargo audit` reports zero vulnerabilities
3. Changelog is updated
4. Version is bumped according to semver
5. Binary is built with `--release` and stripped
6. Release is signed with the EdgeShield signing key
7. Release notes include checksums and vulnerability summary
