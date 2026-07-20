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
#[allow(clippy::large_enum_variant)]
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
    /// Launch the read-only observability dashboard (TUI).
    ///
    /// Connects to a running daemon over its REST API and renders
    /// live device, alert, metrics, and health state. The TUI holds
    /// no authoritative state of its own — it is a thin client over
    /// the daemon's existing endpoints. The only mutation it performs
    /// is acknowledging an alert (`POST /alerts/:id/acknowledge`).
    #[cfg(feature = "tui")]
    Tui {
        /// Base URL of the daemon's REST API.
        #[arg(long, env = "EDGESHIELD_URL", default_value = "http://localhost:8080")]
        url: String,
        /// Bearer token for the daemon's REST API (admin key required for ack).
        #[arg(long, env = "EDGESHIELD_KEY")]
        key: Option<String>,
        /// Refresh interval in milliseconds.
        #[arg(long, default_value_t = 2000)]
        refresh_ms: u64,
    },
    /// First-run setup wizard — generate a config file interactively
    /// or non-interactively (from flags / env vars).
    ///
    /// Without flags, prompts for each setting. With `--non-interactive`,
    /// uses flag values and sensible defaults without prompting — this
    /// is what the Docker entrypoint uses to generate a first-run config.
    Setup {
        /// Path to write the config file.
        #[arg(short, long, default_value = "/etc/edgeshield/config.toml")]
        config: String,
        /// Run without prompting. Required values must come from flags.
        #[arg(long)]
        non_interactive: bool,
        /// Overwrite an existing config file.
        #[arg(long)]
        force: bool,
        /// Network interface to capture (e.g. eth0).
        #[arg(long)]
        interface: Option<String>,
        /// REST API port.
        #[arg(long)]
        api_port: Option<u16>,
        /// Address to bind the REST API to (default 0.0.0.0).
        #[arg(long)]
        bind: Option<String>,
        /// Log level (trace, debug, info, warn, error).
        #[arg(long)]
        log_level: Option<String>,
        /// SQLite database path (empty = in-memory).
        #[arg(long)]
        database_path: Option<String>,
        /// Generate a random API key and store its SHA-256 hash.
        #[arg(long)]
        generate_api_key: bool,
        /// Enable MQTT notifications.
        #[arg(long)]
        enable_mqtt: bool,
        /// MQTT broker host.
        #[arg(long)]
        mqtt_host: Option<String>,
        /// MQTT broker port.
        #[arg(long)]
        mqtt_port: Option<u16>,
        /// MQTT topic.
        #[arg(long)]
        mqtt_topic: Option<String>,
        /// Enable ntfy notifications.
        #[arg(long)]
        enable_ntfy: bool,
        /// ntfy server base URL.
        #[arg(long)]
        ntfy_url: Option<String>,
        /// ntfy topic.
        #[arg(long)]
        ntfy_topic: Option<String>,
        /// Enable webhook notifications.
        #[arg(long)]
        enable_webhook: bool,
        /// Webhook URL.
        #[arg(long)]
        webhook_url: Option<String>,
        /// Enable email notifications.
        #[arg(long)]
        enable_email: bool,
        /// SMTP host.
        #[arg(long)]
        email_host: Option<String>,
        /// SMTP port.
        #[arg(long)]
        email_port: Option<u16>,
        /// SMTP username.
        #[arg(long)]
        email_username: Option<String>,
        /// SMTP password.
        #[arg(long)]
        email_password: Option<String>,
        /// From email address.
        #[arg(long)]
        email_from: Option<String>,
        /// To email address.
        #[arg(long)]
        email_to: Option<String>,
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
        COMPREPLY=($(compgen -W "run default-config completions tui setup" -- "$cur"))
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
        tui)
            case "$prev" in
                --url)
                    ;;
                --key)
                    ;;
                --refresh-ms)
                    COMPREPLY=($(compgen -W "1000 2000 5000" -- "$cur"))
                    ;;
                *)
                    COMPREPLY=($(compgen -W "--url --key --refresh-ms" -- "$cur"))
                    ;;
            esac
            ;;
        setup)
            case "$prev" in
                -c|--config)
                    COMPREPLY=($(compgen -f -- "$cur"))
                    ;;
                --interface)
                    COMPREPLY=($(compgen -W "$(ls /sys/class/net 2>/dev/null)" -- "$cur"))
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "trace debug info warn error" -- "$cur"))
                    ;;
                *)
                    COMPREPLY=($(compgen -W "-c --config --non-interactive --force --interface --api-port --bind --log-level --database-path --generate-api-key --enable-mqtt --mqtt-host --mqtt-port --mqtt-topic --enable-ntfy --ntfy-url --ntfy-topic --enable-webhook --webhook-url --enable-email --email-host --email-port --email-username --email-password --email-from --email-to" -- "$cur"))
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
        'tui:Launch the read-only observability dashboard'
        'setup:First-run setup wizard'
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
                tui)
                    _arguments \
                        '--url[Base URL of the daemon REST API]:url' \
                        '--key[Bearer token for the daemon REST API]:key' \
                        '--refresh-ms[Refresh interval in milliseconds]:ms'
                    ;;
                setup)
                    _arguments \
                        '(-c --config)'{{-c,--config}}'[Path to write config file]:config file:_files' \
                        '--non-interactive[Run without prompting]' \
                        '--force[Overwrite existing config]' \
                        '--interface[Network interface]:interface' \
                        '--api-port[REST API port]:port' \
                        '--bind[Bind address]:addr' \
                        '--log-level[Log level]:level:(trace debug info warn error)' \
                        '--database-path[SQLite path]:path:_files' \
                        '--generate-api-key[Generate an API key]' \
                        '--enable-mqtt[Enable MQTT]' \
                        '--mqtt-host[MQTT host]:host' \
                        '--mqtt-port[MQTT port]:port' \
                        '--mqtt-topic[MQTT topic]:topic' \
                        '--enable-ntfy[Enable ntfy]' \
                        '--ntfy-url[ntfy URL]:url' \
                        '--ntfy-topic[ntfy topic]:topic' \
                        '--enable-webhook[Enable webhook]' \
                        '--webhook-url[Webhook URL]:url' \
                        '--enable-email[Enable email]' \
                        '--email-host[SMTP host]:host' \
                        '--email-port[SMTP port]:port' \
                        '--email-username[SMTP username]:user' \
                        '--email-password[SMTP password]:password' \
                        '--email-from[From address]:addr' \
                        '--email-to[To address]:addr'
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
        #[cfg(feature = "tui")]
        Command::Tui {
            url,
            key,
            refresh_ms,
        } => {
            let args = edgeshield_tui::Args {
                url,
                key,
                refresh_ms,
            };
            // The TUI owns its own tokio runtime (see `edgeshield_tui::run`).
            // We're already running inside the CLI's runtime here, so
            // calling `edgeshield_tui::run` directly would attempt to
            // `block_on` a new runtime from within an existing one —
            // which panics ("Cannot start a runtime from within a
            // runtime"). Spawn a dedicated OS thread that is *not*
            // affiliated with the outer runtime, build the TUI runtime
            // there, and join it. The outer runtime is idle during this
            // call (no other tasks are running), so blocking on the
            // join is safe.
            let handle = std::thread::spawn(move || edgeshield_tui::run(args));
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("TUI worker thread panicked"))?
        }
        Command::Setup {
            config,
            non_interactive,
            force,
            interface,
            api_port,
            bind,
            log_level,
            database_path,
            generate_api_key,
            enable_mqtt,
            mqtt_host,
            mqtt_port,
            mqtt_topic,
            enable_ntfy,
            ntfy_url,
            ntfy_topic,
            enable_webhook,
            webhook_url,
            enable_email,
            email_host,
            email_port,
            email_username,
            email_password,
            email_from,
            email_to,
        } => run_setup(
            config,
            non_interactive,
            force,
            interface,
            api_port,
            bind,
            log_level,
            database_path,
            generate_api_key,
            enable_mqtt,
            mqtt_host,
            mqtt_port,
            mqtt_topic,
            enable_ntfy,
            ntfy_url,
            ntfy_topic,
            enable_webhook,
            webhook_url,
            enable_email,
            email_host,
            email_port,
            email_username,
            email_password,
            email_from,
            email_to,
        ),
    }
}

/// Build `SetupInputs` from CLI flags, optionally prompt interactively,
/// then run the wizard. Shared by the `setup` subcommand.
#[allow(clippy::too_many_arguments)]
fn run_setup(
    config: String,
    non_interactive: bool,
    force: bool,
    interface: Option<String>,
    api_port: Option<u16>,
    bind: Option<String>,
    log_level: Option<String>,
    database_path: Option<String>,
    generate_api_key: bool,
    enable_mqtt: bool,
    mqtt_host: Option<String>,
    mqtt_port: Option<u16>,
    mqtt_topic: Option<String>,
    enable_ntfy: bool,
    ntfy_url: Option<String>,
    ntfy_topic: Option<String>,
    enable_webhook: bool,
    webhook_url: Option<String>,
    enable_email: bool,
    email_host: Option<String>,
    email_port: Option<u16>,
    email_username: Option<String>,
    email_password: Option<String>,
    email_from: Option<String>,
    email_to: Option<String>,
) -> Result<(), anyhow::Error> {
    use crate::setup::{EmailInputs, MqttInputs, NtfyInputs, SetupInputs, WebhookInputs};

    let mut inputs = SetupInputs {
        interface: interface.unwrap_or_default(),
        api_port: api_port.unwrap_or(8080),
        api_bind_address: bind.unwrap_or_else(|| "0.0.0.0".to_string()),
        log_level: log_level.unwrap_or_else(|| "info".to_string()),
        database_path: database_path.unwrap_or_default(),
        generate_api_key,
        mqtt: if enable_mqtt {
            Some(MqttInputs {
                host: mqtt_host.unwrap_or_default(),
                port: mqtt_port.unwrap_or(1883),
                topic: mqtt_topic.unwrap_or_else(|| "edgeshield/devices/new".to_string()),
                username: None,
                password: None,
            })
        } else {
            None
        },
        ntfy: if enable_ntfy {
            Some(NtfyInputs {
                base_url: ntfy_url.unwrap_or_default(),
                topic: ntfy_topic.unwrap_or_default(),
                token: None,
            })
        } else {
            None
        },
        webhook: if enable_webhook {
            Some(WebhookInputs {
                url: webhook_url.unwrap_or_default(),
                token: None,
            })
        } else {
            None
        },
        email: if enable_email {
            Some(EmailInputs {
                host: email_host.unwrap_or_default(),
                port: email_port.unwrap_or(587),
                username: email_username.unwrap_or_default(),
                password: email_password.unwrap_or_default(),
                from: email_from.unwrap_or_default(),
                to: email_to.unwrap_or_default(),
            })
        } else {
            None
        },
    };

    if !non_interactive {
        crate::setup::prompt_interactively(&mut inputs)?;
    } else if inputs.interface.trim().is_empty() {
        anyhow::bail!(
            "non-interactive setup requires --interface (or EDGESHIELD_INTERFACE env var)"
        );
    }

    let path = std::path::PathBuf::from(&config);
    let api_key = crate::setup::run(inputs, &path, force)?;

    println!("Config written to {}", path.display());
    if let Some(key) = api_key {
        crate::setup::print_api_key_warning(&key);
    }
    Ok(())
}
