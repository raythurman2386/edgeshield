# Contributing

Thank you for your interest in contributing to EdgeShield. This document provides guidelines for contributing code, documentation, and issues.

## Local Setup

### Prerequisites

- Rust toolchain (MSRV: 1.75.0)
- `libpcap-dev` (Linux) or `libpcap` (macOS) for packet capture support
- `cmake` for pnet native dependencies

### Clone and build

```bash
git clone https://github.com/edgeshield/edgeshield.git
cd edgeshield
cargo build
cargo test
```

### Verify your setup

```bash
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo test --all-targets
```

## Branch Strategy

EdgeShield uses a simplified trunk-based development model:

- **`main`**: Stable branch. Always passes CI. Ready for release.
- **`develop`**: Integration branch for feature work. Must pass CI.
- **Feature branches**: Named `feat/<description>` or `fix/<description>`. Branch off `develop`, merge back via pull request.

### Branch naming

| Prefix | Purpose |
|--------|---------|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `docs/` | Documentation changes |
| `refactor/` | Code refactoring |
| `perf/` | Performance improvements |
| `test/` | Test additions or changes |
| `chore/` | Build process, CI, tooling |

## Commit Conventions

EdgeShield follows [Conventional Commits](https://www.conventionalcommits.org/).

### Format

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

| Type | Usage |
|------|-------|
| `feat` | A new feature |
| `fix` | A bug fix |
| `docs` | Documentation changes |
| `refactor` | Code refactoring |
| `perf` | Performance improvement |
| `test` | Test additions or changes |
| `chore` | Build, CI, tooling |
| `style` | Formatting, linting |

### Scopes

| Scope | Crate |
|-------|-------|
| `common` | `edgeshield-common` |
| `config` | `edgeshield-config` |
| `telemetry` | `edgeshield-telemetry` |
| `packet` | `edgeshield-packet` |
| `protocol` | `edgeshield-protocol` |
| `storage` | `edgeshield-storage` |
| `discovery` | `edgeshield-discovery` |
| `api` | `edgeshield-api` |
| `daemon` | `edgeshield-daemon` |
| `cli` | `edgeshield-cli` |
| `docs` | Documentation |
| `ci` | CI/CD |

### Examples

```
feat(packet): add ARP packet decoding

Implement ARP packet parsing for hardware type, protocol type,
hardware address length, protocol address length, operation,
sender and target MAC/IP addresses.

Closes #42
```

```
fix(storage): handle concurrent upsert race condition

The read-modify-write pattern in upsert was not atomic under
concurrent access. Fixed by using DashMap's alter() method.

Fixes #87
```

```
docs(api): document metrics endpoint response format
```

## Pull Request Expectations

### Before submitting

1. Branch is up to date with `develop`
2. All tests pass: `cargo test --all-targets`
3. No clippy warnings: `cargo clippy --all-targets -- -D warnings`
4. Code is formatted: `cargo fmt --check`
5. Dependencies are audited: `cargo audit` (if new dependencies added)
6. Commit messages follow conventional commits format

### PR description template

```markdown
## Description

Brief description of the change.

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Refactoring
- [ ] Performance

## Testing

- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Checklist

- [ ] Code follows the style guide
- [ ] Documentation updated
- [ ] Changelog entry added
- [ ] No new clippy warnings
- [ ] All existing tests pass
```

### PR size

- Keep PRs focused on a single change
- Aim for < 400 lines changed per PR
- Large features should be split into multiple PRs
- Refactoring and feature changes should be in separate PRs

## Code Review Standards

### Review process

1. PR is submitted against `develop`
2. CI runs automatically
3. At least one maintainer reviews
4. Reviewer approves or requests changes
5. Author addresses feedback
6. PR is merged (squash merge)

### What reviewers look for

- **Correctness**: Does the code do what it claims?
- **Safety**: Is there any unsafe code? Are error paths handled?
- **Performance**: Are there unnecessary allocations? Is the hot path efficient?
- **Test coverage**: Are there tests for new code? Do they cover error cases?
- **Documentation**: Are public APIs documented? Are design decisions explained?
- **Style**: Does the code follow the style guide?
- **Dependencies**: Are new dependencies justified? Are minimal features used?

### Review expectations

- First review within 48 hours
- Be constructive and specific in feedback
- Approve when the code is correct, not when it matches your personal style
- Use GitHub's "Request Changes" for blocking issues only

## Testing Requirements

### All code changes

- New functions must have unit tests
- Error paths must be tested
- Edge cases must be covered
- Tests must be deterministic (no timeouts, no network dependencies)

### Packet processing changes

- Synthetic packet fixtures must be added for new protocol support
- Truncated/malformed packet handling must be tested
- Existing protocol tests must not break

### API changes

- New endpoints must have integration tests
- Error responses must be tested (400, 404, 500)
- Response format must match documentation

### Storage changes

- New store implementations must pass all `DeviceStore` trait tests
- Concurrent access patterns must be tested
- Data integrity must be verified (roundtrip tests)

## Documentation Requirements

### Code documentation

- All public APIs must have doc comments
- Design decisions must be documented (use `//!` module-level docs)
- Performance characteristics must be documented for hot path functions

### Documentation changes

- API changes must update `docs/api/rest.md`
- Configuration changes must update `docs/configuration.md`
- Architecture changes must update `ARCHITECTURE.md` and relevant `docs/architecture/` files
- New features should be documented in the appropriate `docs/` directory

### Changelog

- Every user-facing change must have a changelog entry
- Use the format: `- **crate**: description ([#PR](link))`
- Group entries by type: Added, Changed, Deprecated, Removed, Fixed, Security
