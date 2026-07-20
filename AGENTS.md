# AGENTS.md

Guidance for AI agents working in this Rust workspace. Read alongside `ARCHITECTURE.md` and `STYLE_GUIDE.md` — those have the long form; this file is the short form for things easy to get wrong.

## Toolchain

- Rust **2024 edition**, MSRV 1.85 (`docs/development/coding-standards.md`). `rust-toolchain.toml` pins `stable`. Note: `docs/development/setup.md` says 1.75 — that is stale; trust the coding-standards doc.
- System deps to build the `pcap`/`pnet` crates: `libpcap-dev`, `cmake`, `pkg-config` (CI also installs these). Without them `cargo build --workspace` fails.
- Cross-compile targets declared in `rust-toolchain.toml`: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `armv7-unknown-linux-gnueabihf`. Cross-compilation is **not** wired into CI yet.

## Commands

```bash
make test          # cargo test --workspace  (this is the canonical test invocation)
make clippy        # cargo clippy --all-targets -- -D warnings  (CI-fail on warnings)
make audit         # installs cargo-audit if missing, then cargo audit
make build         # release build
cargo fmt --check  # CI enforces formatting; no rustfmt.toml overrides — use defaults
```

CI runs `fmt --check`, `clippy -D warnings`, `test --workspace`, and `cargo audit`. All four must pass; do not weaken the `-D warnings` flag.

Run a single crate/test (CI's `--workspace` does not scope):

```bash
cargo test -p edgeshield-packet
cargo test -p edgeshield-api test_health_endpoint
cargo test -- --nocapture        # show println/log output
```

CI installs `cargo-audit` on the fly; locally run `make audit` once before relying on it.

## Workspace layout

14 crates under `crates/`, all prefixed `edgeshield-`. Dependency direction is **inward toward `common`** — never add a dependency from a lower layer (common/config/telemetry/packet/protocol/storage) to a higher one (discovery/api/notify/daemon/cli). See the layer table in `ARCHITECTURE.md`.

Entry points:
- Binary: `crates/cli/src/main.rs` → `edgeshield` binary. Subcommands: `run` (daemon), `tui`, `default-config`, `completions`.
- Daemon orchestration: `crates/daemon` wires every subsystem in its `run()` function — start there when tracing startup/wiring.
- TUI is feature-gated (`default = ["tui"]` on `edgeshield-cli`). For constrained targets: `cargo build -p edgeshield-cli --no-default-features`.

`edgeshield-oui` and `edgeshield-telemetry` exist as separate crates but are thin; `common` has **zero** workspace deps.

## Conventions that differ from defaults

- **No `unsafe` in application code.** Adding `unsafe` requires an ADR + `// SAFETY:` comment + two-maintainer review. Currently zero `unsafe` blocks.
- **All channels are bounded.** Never introduce an unbounded mpsc; the system intentionally drops packets under backpressure.
- **No allocations on the hot path** (capture → decode → classify → store upsert) after the initial `PacketBuf`. No `format!`, no `Arc` clones (move the `PacketBuf`), no `Mutex` contention (use `DashMap`), no `unwrap`/`expect`.
- **Never hold a lock across `.await`.** Use `try_send` (not `send`) on the hot path.
- Pipeline errors are **logged and the packet dropped** — `process_packet` does not return `Result`. Don't "fix" this by propagating.
- Error enums use `thiserror` with **structured context fields**, not `String` variants. Cross-crate conversion happens at boundaries; `anyhow` is only for CLI/daemon startup.
- Tests live inline as `#[cfg(test)] mod tests` and use **synthetic packet builders**, never real captures. Test names: `test_<function>_<scenario>`.
- Logging uses `tracing` structured fields (`info!(mac = %device.mac, ...)`), not string interpolation. JSON format by default; `EDGESHIELD_LOG_FORMAT=pretty` for dev. `RUST_LOG=edgeshield_discovery=trace` etc. for per-module filtering.
- Dependencies must be added to `[workspace.dependencies]` in root `Cargo.toml` first, then referenced with `workspace = true`. No GPL deps (Apache-2.0 license). Prefer minimal feature flags.

## Config / runtime

- `edgeshield.toml` at repo root is a sample config (it is gitignored — see `.gitignore`). `edgeshield default-config` generates a fresh one.
- SQLite stores use `rusqlite` with the **`bundled` feature** — no system SQLite needed. Schema migrations are idempotent (`ALTER TABLE ADD COLUMN` with error suppression). `SqliteStore` keeps a DashMap write-back cache; the last 5s of counter updates can be lost on unclean shutdown (by design).
- Raw socket capture needs `CAP_NET_RAW`: `sudo setcap cap_net_raw+ep target/debug/edgeshield` (avoids running as root in dev).

## Git workflow

- Conventional Commits (`feat:`, `fix:`, `docs:`, `ci:`, `perf:` — see `git log`). Squash merges.
- Branch model per `CONTRIBUTING.md`: `main` stable, `develop` integration, feature branches `feat/<desc>` / `fix/<desc>` off `develop`. PRs target `develop`.
- `Cargo.lock` is gitignored (library-style) — don't commit it.