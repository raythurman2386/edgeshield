//! Binary entry point for the standalone `edgeshield-tui` binary.
//!
//! Most users will invoke the TUI via `edgeshield tui` (the subcommand
//! wired into the main `edgeshield` binary). This binary exists so the
//! TUI can be built and shipped independently of the daemon binary —
//! useful for constrained targets where the daemon is built without
//! the `tui` feature.

use clap::Parser;
use edgeshield_tui::{app::Args, run};

fn main() {
    let args = Args::parse();
    if let Err(e) = run(args) {
        eprintln!("edgeshield-tui: {e:#}");
        std::process::exit(1);
    }
}
