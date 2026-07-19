//! EdgeShield CLI — command-line interface.
//!
//! This module provides the binary entry point with clap argument parsing.

use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;

/// Path to the PID file for single-instance guard.
const PID_FILE: &str = "/run/edgeshield.pid";

/// EdgeShield — a lightweight network security monitoring daemon.
#[derive(Parser, Debug)]
#[command(name = "edgeshield", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the EdgeShield daemon.
    Run {
        /// Path to the configuration file.
        #[arg(short, long, default_value = "/etc/edgeshield/config.toml")]
        config: String,
    },
    /// Print the default configuration.
    DefaultConfig,
    /// Generate shell completion script.
    Completions {
        /// Shell to generate for (bash or zsh).
        shell: String,
    },
}

/// Check if the process is running as root (UID 0).
fn check_root() {
    let uid = nix::unistd::Uid::current();
    if !uid.is_root() {
        eprintln!(
            "warning: not running as root — packet capture will fail on most systems.\n\
             Run with sudo or grant CAP_NET_RAW: sudo setcap cap_net_raw+ep $(which edgeshield)"
        );
    }
}

/// Check if the target interface is a wireless interface and warn.
fn check_interface(iface: &str) {
    // On Linux, wireless interfaces have a /sys/class/net/<iface>/wireless directory
    let wireless_path = format!("/sys/class/net/{}/wireless", iface);
    if std::path::Path::new(&wireless_path).exists() {
        eprintln!(
            "info: '{}' is a wireless interface. EdgeShield uses read-only capture mode\n\
             that should not disrupt normal WiFi connectivity. If you experience\n\
             network issues, switch to a wired interface or use a monitor-mode\n\
             capable secondary interface.",
            iface
        );
    }
}

/// Single-instance guard using a PID file.
fn acquire_pid_file() -> Result<(), anyhow::Error> {
    let path = PathBuf::from(PID_FILE);

    if let Ok(content) = fs::read_to_string(&path)
        && let Ok(pid) = content.trim().parse::<u32>()
        && unsafe { libc::kill(pid as i32, 0) == 0 }
    {
        anyhow::bail!(
            "EdgeShield is already running (PID {}). \
             If this is incorrect, remove {} and try again.",
            pid,
            PID_FILE
        );
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, format!("{}\n", std::process::id()))?;
    Ok(())
}

/// Remove the PID file on daemon exit.
fn release_pid_file() {
    let _ = fs::remove_file(PID_FILE);
}

/// Try to load config from the given path, falling back to common locations.
fn load_config(path: &str) -> Result<edgeshield_config::config::Config, anyhow::Error> {
    // Try the explicit path first
    if let Ok(cfg) = edgeshield_config::config::Config::from_file(path) {
        return Ok(cfg);
    }

    // Try common fallback paths
    let fallbacks = [
        "/etc/edgeshield/config.toml",
        "/usr/local/etc/edgeshield/config.toml",
        "edgeshield.toml",
        "config.toml",
    ];

    for fb in &fallbacks {
        if fb != &path
            && let Ok(cfg) = edgeshield_config::config::Config::from_file(fb)
        {
            eprintln!("info: loaded config from fallback path: {fb}");
            return Ok(cfg);
        }
    }

    Ok(edgeshield_config::config::Config::from_file(path)?)
}

/// Print a bash completion script to stdout.
fn print_bash_completion() {
    println!(
        r#"# EdgeShield bash completion
_edgeshield() {{
    local cur prev words cword
    _init_completion || return

    if [[ $cword -eq 1 ]]; then
        COMPREPLY=($(compgen -W "run default-config completions" -- "$cur"))
        return
    fi

    case "${{words[1]}}" in
        run)
            case "$prev" in
                -c|--config)
                    COMPREPLY=($(compgen -f -- "$cur"))
                    ;;
                *)
                    COMPREPLY=($(compgen -W "-c --config" -- "$cur"))
                    ;;
            esac
            ;;
    esac
}} && complete -F _edgeshield edgeshield
"#
    );
}

/// Print a zsh completion script to stdout.
fn print_zsh_completion() {
    println!(
        r#"#compdef edgeshield
# EdgeShield zsh completion
_edgeshield() {{
    local -a subcommands
    subcommands=(
        'run:Start the EdgeShield daemon'
        'default-config:Print the default configuration'
        'completions:Generate shell completion script'
    )

    _arguments \\
        '1: :->command' \\
        '*: :->args'

    case $state in
        command)
            _describe 'command' subcommands
            ;;
        args)
            case $words[1] in
                run)
                    _arguments \
                        '(-c --config)'{{-c,--config}}'[Path to configuration file]:config file:_files'
                    ;;
            esac
            ;;
    esac
}}

_edgeshield
"#
    );
}

/// Parse CLI arguments and run the appropriate command.
pub async fn run() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run { config } => {
            check_root();
            acquire_pid_file()?;
            let config = load_config(&config)?;
            check_interface(&config.interface);
            let result = edgeshield_daemon::daemon::run(config).await;
            release_pid_file();
            result
        }
        Command::DefaultConfig => {
            let default = r#"# EdgeShield Configuration
interface = "eth0"
api_port = 8080
log_level = "info"
capture_buffer = 4096
database_path = ""
"#;
            println!("{}", default);
            Ok(())
        }
        Command::Completions { shell } => {
            match shell.as_str() {
                "bash" => print_bash_completion(),
                "zsh" => print_zsh_completion(),
                _ => anyhow::bail!("unsupported shell '{}'. Use 'bash' or 'zsh'.", shell),
            }
            Ok(())
        }
    }
}
