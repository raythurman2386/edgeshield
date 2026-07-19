# Developer Setup

This guide walks through setting up a development environment for EdgeShield.

## Prerequisites

### Rust toolchain

EdgeShield requires Rust 1.75.0 or later. Install via [rustup](https://rustup.rs/):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update stable
```

Verify the installation:

```bash
rustc --version   # Should show 1.75.0 or later
cargo --version  # Should match rustc version
```

### System dependencies

**Debian/Ubuntu/Raspberry Pi OS**:

```bash
sudo apt update
sudo apt install -y \
    libpcap-dev \
    cmake \
    pkg-config \
    build-essential \
    clang \
    llvm
```

**Fedora/RHEL**:

```bash
sudo dnf install \
    libpcap-devel \
    cmake \
    pkg-config \
    gcc \
    clang \
    llvm
```

**macOS**:

```bash
brew install libpcap cmake
```

**Arch Linux**:

```bash
sudo pacman -S libpcap cmake base-devel clang llvm
```

## Clone and Build

```bash
git clone https://github.com/edgeshield/edgeshield.git
cd edgeshield
cargo build
```

The first build compiles all workspace crates and their dependencies. Subsequent builds are incremental.

### Build profiles

| Profile | Use Case | Binary Size | Optimization |
|---------|----------|-------------|--------------|
| `debug` | Development, testing | Large | None |
| `release` | Production deployment | Small | Full LTO |
| `release-lto` | Maximum performance | Smallest | LTO + PGO (future) |

```bash
# Development build (fast compile, slow runtime)
cargo build

# Release build (slow compile, fast runtime)
cargo build --release
```

## Testing

### Run all tests

```bash
cargo test --all-targets
```

### Run tests for a specific crate

```bash
cargo test -p edgeshield-packet
cargo test -p edgeshield-protocol
cargo test -p edgeshield-discovery
cargo test -p edgeshield-api
```

### Run tests with output

```bash
cargo test -- --nocapture
```

### Run a specific test

```bash
cargo test test_decode_ethernet_ipv4_tcp
```

### Run tests in release mode

```bash
cargo test --release --all-targets
```

## Formatting

EdgeShield uses `rustfmt` with the default configuration.

```bash
# Check formatting (CI enforces this)
cargo fmt --check

# Apply formatting
cargo fmt
```

## Linting

EdgeShield uses `clippy` with deny-level warnings.

```bash
# Check all targets
cargo clippy --all-targets -- -D warnings

# Check with additional lints
cargo clippy --all-targets -- \
    -D warnings \
    -W clippy::pedantic \
    -W clippy::cargo
```

### Clippy configuration

Clippy warnings are treated as errors in CI. The following lints are explicitly allowed:

- `clippy::module_name_repetitions` — Allowed for crate re-export modules
- `clippy::must_use_candidate` — Allowed for test helpers

## Debugging

### Logging

EdgeShield uses structured JSON logging via `tracing`. Set the log level with the `RUST_LOG` environment variable:

```bash
# Default: info
RUST_LOG=info cargo run -- run --config /etc/edgeshield/config.toml

# Debug level
RUST_LOG=debug cargo run -- run --config /etc/edgeshield/config.toml

# Trace level (per-packet logging)
RUST_LOG=trace cargo run -- run --config /etc/edgeshield/config.toml

# Per-module filtering
RUST_LOG=edgeshield_packet=debug,edgeshield_discovery=trace cargo run -- run --config /etc/edgeshield/config.toml
```

### Pretty-printed logging

For development, use the pretty formatter instead of JSON:

```bash
RUST_LOG=debug EDGESHIELD_LOG_FORMAT=pretty cargo run -- run --config /etc/edgeshield/config.toml
```

### Debugging with GDB/LLDB

```bash
# Build with debug symbols
cargo build

# Run under GDB
sudo gdb -ex run --args target/debug/edgeshield run --config /etc/edgeshield/config.toml
```

### Debugging with rr (record and replay)

```bash
# Record
sudo rr record target/debug/edgeshield run --config /etc/edgeshield/config.toml

# Replay
rr replay
```

## Cross-Compilation

### Raspberry Pi (aarch64)

```bash
# Install the cross-compilation target
rustup target add aarch64-unknown-linux-gnu

# Install the cross-compilation toolchain
# Debian/Ubuntu:
sudo apt install gcc-aarch64-linux-gnu

# Build
cargo build --release --target aarch64-unknown-linux-gnu
```

### Raspberry Pi (armv7)

```bash
# Install the cross-compilation target
rustup target add armv7-unknown-linux-gnueabihf

# Install the cross-compilation toolchain
sudo apt install gcc-arm-linux-gnueabihf

# Build
cargo build --release --target armv7-unknown-linux-gnueabihf
```

### Using cross (recommended for cross-compilation)

[cross](https://github.com/cross-rs/cross) provides Docker-based cross-compilation with pre-configured toolchains:

```bash
# Install cross
cargo install cross

# Build for Raspberry Pi 4 (aarch64)
cross build --release --target aarch64-unknown-linux-gnu

# Build for Raspberry Pi 3/Zero 2 W (armv7)
cross build --release --target armv7-unknown-linux-gnueabihf

# Build for x86_64 Linux
cross build --release --target x86_64-unknown-linux-gnu
```

### Stripping binaries

Release binaries should be stripped to reduce size:

```bash
# Using strip
strip target/release/edgeshield

# Using cargo-strip
cargo install cargo-strip
cargo strip --release
```

## Running Without Root

EdgeShield requires root privileges for raw socket access. For development, you can grant the binary the `CAP_NET_RAW` capability:

```bash
sudo setcap cap_net_raw+ep target/debug/edgeshield
```

This allows the binary to open raw sockets without running as root.

## Development Workflow

### Recommended workflow

1. **Branch**: Create a feature branch from `develop`
2. **Code**: Write code following the style guide
3. **Test**: Run `cargo test --all-targets`
4. **Lint**: Run `cargo clippy --all-targets -- -D warnings`
5. **Format**: Run `cargo fmt --check`
6. **Commit**: Use conventional commit format
7. **Push**: Push branch and open a pull request

### Pre-commit hook

Install a pre-commit hook to run checks automatically:

```bash
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/sh
cargo fmt --check || exit 1
cargo clippy --all-targets -- -D warnings || exit 1
cargo test --all-targets 2>&1 | tail -20
EOF
chmod +x .git/hooks/pre-commit
```

## IDE Setup

### VS Code

Recommended extensions:

- `rust-lang.rust-analyzer` — Language server
- `tamasfe.even-better-toml` — TOML support
- `vadimcn.vscode-lldb` — Debugger support

Settings (`.vscode/settings.json`):

```json
{
    "rust-analyzer.check.command": "clippy",
    "rust-analyzer.check.extraArgs": ["--", "-D", "warnings"],
    "rust-analyzer.cargo.allFeatures": true,
    "editor.formatOnSave": true,
    "[rust]": {
        "editor.defaultFormatter": "rust-lang.rust-analyzer"
    }
}
```

### Neovim

With `rustaceanvim` or `rust-tools.nvim`:

```lua
-- rustaceanvim configuration
vim.g.rustaceanvim = {
    tools = {
        -- Use clippy as the default checker
        runner = vim.fn.executable('cargo') and 'cargo' or nil,
    },
    server = {
        settings = {
            ['rust-analyzer'] = {
                check = {
                    command = 'clippy',
                    extraArgs = { '--', '-D', 'warnings' },
                },
            },
        },
    },
}
```

### CLion/RustRover

- Install the Rust plugin
- Enable `rustfmt` on save
- Set clippy as the external linter
