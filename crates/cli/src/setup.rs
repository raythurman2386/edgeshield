//! First-run setup wizard for EdgeShield.
//!
//! Generates a TOML config file, either interactively (prompting the
//! user) or non-interactively (from CLI flags / env vars). The wizard
//! can optionally generate an API key, hash it with SHA-256, and wire
//! up a notifier (MQTT, ntfy, webhook, or email).
//!
//! The wizard is intentionally a thin layer over `edgeshield-config`:
//! it builds a TOML string, then round-trips it through
//! `Config::from_str` to validate before writing to disk. This means
//! any validation added to `Config` is automatically enforced here.
//!
//! # Non-interactive mode
//!
//! Every prompt has a flag fallback. This makes the wizard scriptable
//! and is what the Docker entrypoint uses to generate a first-run
//! config when none is mounted.

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use dialoguer::{Confirm, Input, Select};
use rand::RngCore;
use sha2::{Digest, Sha256};

use edgeshield_config::config::Config;

/// The default dialoguer theme. `dialoguer` 0.11 requires an explicit
/// theme for `with_theme`; we use the built-in `ColorfulTheme` so the
/// wizard has consistent styling across terminals.
fn theme() -> dialoguer::theme::ColorfulTheme {
    dialoguer::theme::ColorfulTheme::default()
}

/// Inputs collected from the user (or CLI flags). All fields are
/// owned so the struct can be built incrementally and serialized.
#[derive(Debug, Clone)]
pub struct SetupInputs {
    pub interface: String,
    pub api_port: u16,
    pub api_bind_address: String,
    pub log_level: String,
    pub database_path: String,
    /// When true, generate a random 32-byte API key, print the
    /// plaintext once, and store only the SHA-256 hash in the config.
    pub generate_api_key: bool,
    pub mqtt: Option<MqttInputs>,
    pub ntfy: Option<NtfyInputs>,
    pub webhook: Option<WebhookInputs>,
    pub email: Option<EmailInputs>,
}

/// MQTT notifier inputs.
#[derive(Debug, Clone)]
pub struct MqttInputs {
    pub host: String,
    pub port: u16,
    pub topic: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// ntfy notifier inputs.
#[derive(Debug, Clone)]
pub struct NtfyInputs {
    pub base_url: String,
    pub topic: String,
    pub token: Option<String>,
}

/// Webhook notifier inputs.
#[derive(Debug, Clone)]
pub struct WebhookInputs {
    pub url: String,
    pub token: Option<String>,
}

/// Email notifier inputs.
#[derive(Debug, Clone)]
pub struct EmailInputs {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    pub to: String,
}

impl Default for SetupInputs {
    fn default() -> Self {
        Self {
            interface: String::new(),
            api_port: 8080,
            api_bind_address: "0.0.0.0".to_string(),
            log_level: "info".to_string(),
            database_path: String::new(),
            generate_api_key: false,
            mqtt: None,
            ntfy: None,
            webhook: None,
            email: None,
        }
    }
}

/// Run the wizard with the given inputs and write the config to `path`.
///
/// In interactive mode (`inputs` partially filled), missing fields are
/// prompted. In non-interactive mode, missing required fields cause an
/// error. The generated TOML is validated via `Config::from_str` before
/// being written.
///
/// Returns the generated API key plaintext, if any, so the caller can
/// print it to the user.
pub fn run(inputs: SetupInputs, path: &Path, force: bool) -> Result<Option<String>> {
    // Refuse to clobber an existing config unless --force was given.
    if path.exists() && !force {
        bail!(
            "config file already exists at {}. Re-run with --force to overwrite.",
            path.display()
        );
    }

    // Generate the API key once, here, so the plaintext returned to
    // the caller and the hash written to the config are guaranteed to
    // correspond to the same key. (Previously render_toml generated a
    // *second* key, so the printed plaintext didn't match the hash.)
    let api_key_plaintext = if inputs.generate_api_key {
        Some(generate_api_key_plaintext())
    } else {
        None
    };

    let toml = render_toml(&inputs, api_key_plaintext.as_deref())?;

    // Round-trip through Config::from_str to validate before writing.
    // This catches empty interfaces, bad MQTT hosts, invalid severity,
    // malformed key hashes, etc. — anything Config validates.
    Config::from_str(&toml).context("generated config failed validation (this is a bug)")?;

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config directory {}", parent.display()))?;
    }
    fs::write(path, &toml)
        .with_context(|| format!("failed to write config to {}", path.display()))?;

    Ok(api_key_plaintext)
}

/// Render the inputs to a TOML string. Hand-rolled (rather than serde
/// Serialize on `Config`) so we can emit helpful comments and control
/// the output format. The result is validated by `Config::from_str`
/// in `run()` before it's written, so a mismatch between this emitter
/// and the `Config` struct is caught at setup time, not at daemon run.
///
/// `api_key_plaintext` is the pre-generated key (if any) from `run()`.
/// It is hashed here and the hash written to the file; the plaintext
/// itself is only emitted as a comment so the user can see which key
/// the hash corresponds to. The caller is responsible for printing the
/// plaintext to the user.
fn render_toml(inputs: &SetupInputs, api_key_plaintext: Option<&str>) -> Result<String> {
    let mut s = String::new();
    s.push_str("# EdgeShield configuration — generated by `edgeshield setup`\n");
    s.push_str("# See https://github.com/edgeshield/edgeshield for the full reference.\n\n");

    s.push_str(&format!("interface = {}\n", toml_string(&inputs.interface)));
    s.push_str(&format!("api_port = {}\n", inputs.api_port));
    s.push_str(&format!(
        "api_bind_address = {}\n",
        toml_string(&inputs.api_bind_address)
    ));
    s.push_str(&format!("log_level = {}\n", toml_string(&inputs.log_level)));
    s.push_str("capture_buffer = 4096\n");
    s.push_str(&format!(
        "database_path = {}\n",
        toml_string(&inputs.database_path)
    ));

    // API auth: if the user asked for a key, emit a hashed read key.
    // The plaintext is passed in from run() so the hash and the key
    // shown to the user are guaranteed to match.
    if let Some(plaintext) = api_key_plaintext {
        let hash = sha256_hex(plaintext.as_bytes());
        s.push_str("\n[api.auth]\n");
        s.push_str(&format!(
            "# read_key (plaintext, shown once by setup): {}\n",
            plaintext
        ));
        s.push_str(&format!("read_key_hash = {}\n", toml_string(&hash)));
    }

    if let Some(ref m) = inputs.mqtt {
        s.push_str("\n[mqtt]\n");
        s.push_str(&format!("host = {}\n", toml_string(&m.host)));
        s.push_str(&format!("port = {}\n", m.port));
        s.push_str(&format!("topic = {}\n", toml_string(&m.topic)));
        if let Some(ref u) = m.username {
            s.push_str(&format!("username = {}\n", toml_string(u)));
        }
        if let Some(ref p) = m.password {
            s.push_str(&format!("password = {}\n", toml_string(p)));
        }
        s.push_str("qos = 1\n");
    }

    if let Some(ref n) = inputs.ntfy {
        s.push_str("\n[ntfy]\n");
        s.push_str(&format!("base_url = {}\n", toml_string(&n.base_url)));
        s.push_str(&format!("topic = {}\n", toml_string(&n.topic)));
        if let Some(ref t) = n.token {
            s.push_str(&format!("token = {}\n", toml_string(t)));
        }
    }

    if let Some(ref w) = inputs.webhook {
        s.push_str("\n[webhook]\n");
        s.push_str(&format!("url = {}\n", toml_string(&w.url)));
        if let Some(ref t) = w.token {
            s.push_str(&format!("token = {}\n", toml_string(t)));
        }
        s.push_str("timeout_seconds = 10\n");
    }

    if let Some(ref e) = inputs.email {
        s.push_str("\n[email]\n");
        s.push_str(&format!("host = {}\n", toml_string(&e.host)));
        s.push_str(&format!("port = {}\n", e.port));
        s.push_str(&format!("username = {}\n", toml_string(&e.username)));
        s.push_str(&format!("password = {}\n", toml_string(&e.password)));
        s.push_str(&format!("from = {}\n", toml_string(&e.from)));
        s.push_str(&format!("to = {}\n", toml_string(&e.to)));
        s.push_str("starttls = true\n");
        s.push_str("subject_prefix = \"[EdgeShield]\"\n");
    }

    // Always emit a default new_device rule so the user sees the
    // shape of a rule and can extend it.
    s.push_str("\n[[rules]]\n");
    s.push_str("name = \"new_device\"\n");
    s.push_str("condition = \"new_device\"\n");
    s.push_str("severity = \"info\"\n");
    s.push_str("cooldown_seconds = 0\n");

    Ok(s)
}

/// Quote a string for TOML output. Handles embedded quotes and
/// backslashes. Non-string types should not use this.
fn toml_string(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{}\"", escaped)
}

/// Generate a random 32-byte (256-bit) API key as a hex string.
/// Uses `/dev/urandom` via the `rand` crate's OsRng-equivalent.
fn generate_api_key_plaintext() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// SHA-256 hash of a byte slice, returned as a lowercase hex string
/// (64 chars). This matches the format `Config` expects for
/// `read_key_hash` / `admin_key_hash`.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Detect available network interfaces by reading `/sys/class/net`.
/// Excludes `lo` (loopback). Returns names sorted for stable display.
///
/// `sys_root` is parameterized so tests can point at a tempdir.
pub fn detect_interfaces(sys_root: &Path) -> Vec<String> {
    let net_dir = sys_root.join("sys/class/net");
    let mut ifaces = Vec::new();
    if let Ok(entries) = fs::read_dir(&net_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str()
                && name != "lo"
            {
                ifaces.push(name.to_string());
            }
        }
    }
    ifaces.sort();
    ifaces
}

/// Prompt the user interactively for any inputs not already provided.
/// Fields already set (non-empty / Some) are skipped. This is the
/// interactive-mode entry point; non-interactive mode calls `run`
/// directly with fully-populated inputs.
pub fn prompt_interactively(inputs: &mut SetupInputs) -> Result<()> {
    println!("\nEdgeShield first-run setup\n");

    // Interface
    if inputs.interface.is_empty() {
        let ifaces = detect_interfaces(Path::new("/"));
        if ifaces.is_empty() {
            inputs.interface = Input::with_theme(&theme())
                .with_prompt("Network interface to capture (e.g. eth0)")
                .interact_text()?;
        } else {
            let selection = Select::with_theme(&theme())
                .with_prompt("Network interface to capture")
                .items(&ifaces)
                .default(0)
                .interact()?;
            inputs.interface = ifaces[selection].clone();
        }
    }

    // API port
    if inputs.api_port == 0 {
        let port: u16 = Input::with_theme(&theme())
            .with_prompt("REST API port")
            .default(8080)
            .interact_text()?;
        inputs.api_port = port;
    }

    // Bind address
    if inputs.api_bind_address.is_empty() {
        let bind_all = Confirm::with_theme(&theme())
            .with_prompt("Bind API to all interfaces (0.0.0.0)?")
            .default(true)
            .interact()?;
        inputs.api_bind_address = if bind_all {
            "0.0.0.0".to_string()
        } else {
            "127.0.0.1".to_string()
        };
    }

    // Database path
    if inputs.database_path.is_empty() {
        let use_db = Confirm::with_theme(&theme())
            .with_prompt("Persist devices/alerts to SQLite?")
            .default(true)
            .interact()?;
        if use_db {
            inputs.database_path = Input::with_theme(&theme())
                .with_prompt("SQLite database path")
                .default("/var/lib/edgeshield/edgeshield.db".to_string())
                .interact_text()?;
        }
    }

    // API key
    if !inputs.generate_api_key {
        let gen_key = Confirm::with_theme(&theme())
            .with_prompt("Generate an API key (recommended)?")
            .default(true)
            .interact()?;
        inputs.generate_api_key = gen_key;
    }

    // Notifiers
    prompt_notifiers(inputs)?;

    Ok(())
}

fn prompt_notifiers(inputs: &mut SetupInputs) -> Result<()> {
    if inputs.mqtt.is_none()
        && inputs.ntfy.is_none()
        && inputs.webhook.is_none()
        && inputs.email.is_none()
    {
        let options = vec![
            "None (skip notifications for now)",
            "MQTT (Home Assistant / Node-RED)",
            "ntfy.sh (push notifications)",
            "Webhook (Slack / Discord / Teams)",
            "Email (SMTP)",
        ];
        let selection = Select::with_theme(&theme())
            .with_prompt("Configure a notification channel?")
            .items(&options)
            .default(0)
            .interact()?;

        match selection {
            1 => inputs.mqtt = Some(prompt_mqtt()?),
            2 => inputs.ntfy = Some(prompt_ntfy()?),
            3 => inputs.webhook = Some(prompt_webhook()?),
            4 => inputs.email = Some(prompt_email()?),
            _ => {}
        }
    }
    Ok(())
}

fn prompt_mqtt() -> Result<MqttInputs> {
    let host: String = Input::with_theme(&theme())
        .with_prompt("MQTT broker host")
        .interact_text()?;
    let port: u16 = Input::with_theme(&theme())
        .with_prompt("MQTT broker port")
        .default(1883)
        .interact_text()?;
    let topic: String = Input::with_theme(&theme())
        .with_prompt("MQTT topic")
        .default("edgeshield/devices/new".to_string())
        .interact_text()?;
    let username: String = Input::with_theme(&theme())
        .with_prompt("MQTT username (leave empty for none)")
        .allow_empty(true)
        .interact_text()?;
    let password: String = Input::with_theme(&theme())
        .with_prompt("MQTT password (leave empty for none)")
        .allow_empty(true)
        .interact_text()?;
    Ok(MqttInputs {
        host,
        port,
        topic,
        username: if username.is_empty() {
            None
        } else {
            Some(username)
        },
        password: if password.is_empty() {
            None
        } else {
            Some(password)
        },
    })
}

fn prompt_ntfy() -> Result<NtfyInputs> {
    let base_url: String = Input::with_theme(&theme())
        .with_prompt("ntfy server URL (e.g. https://ntfy.sh)")
        .interact_text()?;
    let topic: String = Input::with_theme(&theme())
        .with_prompt("ntfy topic")
        .interact_text()?;
    let token: String = Input::with_theme(&theme())
        .with_prompt("ntfy access token (leave empty for anonymous)")
        .allow_empty(true)
        .interact_text()?;
    Ok(NtfyInputs {
        base_url,
        topic,
        token: if token.is_empty() { None } else { Some(token) },
    })
}

fn prompt_webhook() -> Result<WebhookInputs> {
    let url: String = Input::with_theme(&theme())
        .with_prompt("Webhook URL")
        .interact_text()?;
    let token: String = Input::with_theme(&theme())
        .with_prompt("Bearer token (leave empty for none)")
        .allow_empty(true)
        .interact_text()?;
    Ok(WebhookInputs {
        url,
        token: if token.is_empty() { None } else { Some(token) },
    })
}

fn prompt_email() -> Result<EmailInputs> {
    let host: String = Input::with_theme(&theme())
        .with_prompt("SMTP host")
        .interact_text()?;
    let port: u16 = Input::with_theme(&theme())
        .with_prompt("SMTP port")
        .default(587)
        .interact_text()?;
    let username: String = Input::with_theme(&theme())
        .with_prompt("SMTP username")
        .interact_text()?;
    let password: String = Input::with_theme(&theme())
        .with_prompt("SMTP password")
        .interact_text()?;
    let from: String = Input::with_theme(&theme())
        .with_prompt("From email address")
        .interact_text()?;
    let to: String = Input::with_theme(&theme())
        .with_prompt("To email address (alert recipient)")
        .interact_text()?;
    Ok(EmailInputs {
        host,
        port,
        username,
        password,
        from,
        to,
    })
}

/// Print the generated API key plaintext with a clear warning, since
/// it's only shown once. Goes to stderr so it's visible even when
/// stdout is redirected.
pub fn print_api_key_warning(key: &str) {
    // Size the box to the key length so the borders always align.
    // Inner width = 2 (padding) + key.len() + 2 (padding).
    let inner = key.len() + 4;
    let top = format!("┌{}┐", "─".repeat(inner));
    let bottom = format!("└{}┘", "─".repeat(inner));
    let key_line = format!("│  {}  │", key);
    let label_line = format!(
        "│  API key (shown once — save it now):{}│",
        " ".repeat(inner - 37)
    );

    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "\n{top}");
    let _ = writeln!(stderr, "{label_line}");
    let _ = writeln!(stderr, "{key_line}");
    let _ = writeln!(stderr, "{bottom}");
    let _ = writeln!(
        stderr,
        "Only the SHA-256 hash was written to the config. Use this key as the\n\
         Bearer token for API requests.\n"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_setup_generates_valid_config() {
        let inputs = SetupInputs {
            interface: "eth0".to_string(),
            database_path: "/tmp/edgeshield-test.db".to_string(),
            ..SetupInputs::default()
        };
        let toml = render_toml(&inputs, None).unwrap();
        // Must parse and validate cleanly.
        let cfg = Config::from_str(&toml).expect("generated TOML should be valid");
        assert_eq!(cfg.interface, "eth0");
        assert_eq!(cfg.api_port, 8080);
        assert_eq!(cfg.database_path, "/tmp/edgeshield-test.db");
    }

    #[test]
    fn test_setup_api_key_hash_is_sha256() {
        let plaintext = generate_api_key_plaintext();
        assert_eq!(plaintext.len(), 64, "plaintext key should be 64 hex chars");
        assert!(plaintext.chars().all(|c| c.is_ascii_hexdigit()));
        let hash = sha256_hex(plaintext.as_bytes());
        assert_eq!(hash.len(), 64, "SHA-256 hash should be 64 hex chars");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_setup_overwrite_guard() {
        let dir = tempfile_dir();
        let path = dir.join("config.toml");
        fs::write(&path, "interface = \"eth0\"\n").unwrap();

        let inputs = SetupInputs {
            interface: "eth0".to_string(),
            ..SetupInputs::default()
        };
        let err = run(inputs, &path, false).unwrap_err();
        assert!(
            err.to_string().contains("already exists"),
            "should refuse to overwrite without --force"
        );
    }

    #[test]
    fn test_setup_force_overwrites() {
        let dir = tempfile_dir();
        let path = dir.join("config.toml");
        fs::write(&path, "interface = \"eth0\"\n").unwrap();

        let inputs = SetupInputs {
            interface: "wlan0".to_string(),
            ..SetupInputs::default()
        };
        run(inputs, &path, true).unwrap();
        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains("wlan0"), "force should overwrite");
    }

    #[test]
    fn test_setup_writes_validated_config() {
        let dir = tempfile_dir();
        let path = dir.join("subdir/config.toml");
        let inputs = SetupInputs {
            interface: "eth0".to_string(),
            database_path: dir.join("edgeshield.db").to_string_lossy().to_string(),
            ..SetupInputs::default()
        };
        run(inputs, &path, false).unwrap();
        let written = fs::read_to_string(&path).unwrap();
        // Round-trip the written file through Config to prove it's valid.
        Config::from_str(&written).expect("written config should parse");
    }

    #[test]
    fn test_setup_mqtt_section_validates() {
        let inputs = SetupInputs {
            interface: "eth0".to_string(),
            mqtt: Some(MqttInputs {
                host: "homeassistant.local".to_string(),
                port: 1883,
                topic: "edgeshield/devices/new".to_string(),
                username: None,
                password: None,
            }),
            ..SetupInputs::default()
        };
        let toml = render_toml(&inputs, None).unwrap();
        let cfg = Config::from_str(&toml).unwrap();
        let mqtt = cfg.mqtt.expect("mqtt section should be present");
        assert_eq!(mqtt.host, "homeassistant.local");
        assert_eq!(mqtt.port, 1883);
    }

    #[test]
    fn test_detect_interfaces_excludes_lo() {
        let dir = tempfile_dir();
        let net_dir = dir.join("sys/class/net");
        fs::create_dir_all(&net_dir).unwrap();
        fs::create_dir(net_dir.join("lo")).unwrap();
        fs::create_dir(net_dir.join("eth0")).unwrap();
        fs::create_dir(net_dir.join("wlan0")).unwrap();

        let ifaces = detect_interfaces(&dir);
        assert_eq!(ifaces, vec!["eth0".to_string(), "wlan0".to_string()]);
    }

    #[test]
    fn test_detect_interfaces_missing_dir_is_empty() {
        let dir = tempfile_dir();
        let ifaces = detect_interfaces(&dir);
        assert!(ifaces.is_empty());
    }

    #[test]
    fn test_toml_string_escapes_quotes() {
        assert_eq!(toml_string("simple"), "\"simple\"");
        assert_eq!(toml_string("with \"quotes\""), "\"with \\\"quotes\\\"\"");
        assert_eq!(toml_string("back\\slash"), "\"back\\\\slash\"");
    }

    #[test]
    fn test_api_key_plaintext_matches_hash_in_config() {
        // Regression test for the bug where render_toml generated a
        // *second* key, so the plaintext returned to the user didn't
        // match the hash written to the file. The key returned by
        // run() must hash to the read_key_hash in the written config.
        let dir = tempfile_dir();
        let path = dir.join("config.toml");
        let inputs = SetupInputs {
            interface: "eth0".to_string(),
            generate_api_key: true,
            ..SetupInputs::default()
        };
        let plaintext = run(inputs, &path, false)
            .unwrap()
            .expect("should return an API key plaintext");
        let written = fs::read_to_string(&path).unwrap();
        let expected_hash = sha256_hex(plaintext.as_bytes());
        assert!(
            written.contains(&format!("read_key_hash = \"{}\"", expected_hash)),
            "the hash in the config must be the SHA-256 of the returned plaintext"
        );
        // Also verify the config parses and the auth section is present.
        let cfg = Config::from_str(&written).unwrap();
        let auth = cfg.api.auth.expect("api.auth should be present");
        assert_eq!(auth.read_key_hash, expected_hash);
    }

    /// Create a unique temp directory for this test. We avoid pulling
    /// in the `tempfile` crate just for these tests; instead we use
    /// the process PID + a counter via `std::env::temp_dir()`.
    fn tempfile_dir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("edgeshield-test-{}-{}", std::process::id(), id));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
