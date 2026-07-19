//! API authentication middleware.
//!
//! Implements Bearer token authentication with SHA-256 key hashing
//! and constant-time comparison. Supports two permission levels:
//! - **Read**: GET endpoints (except `/health` which is always open)
//! - **Admin**: POST and DELETE endpoints
//!
//! # Security design
//!
//! - Keys are stored as SHA-256 hashes in the config file. The
//!   plaintext key never touches the config — the user generates it,
//!   hashes it, and stores only the hash.
//! - Key comparison uses `subtle::ConstantTimeEq` to prevent timing
//!   attacks.
//! - Failed auth attempts are rate-limited per IP address. After
//!   `max_failures` failed attempts within `window_seconds`, the IP
//!   is blocked for `block_seconds`.
//! - `/health` is always exempt from authentication (load balancers
//!   and monitoring need unauthenticated access).
//! - When no `[api.auth]` is configured, auth is disabled and all
//!   endpoints are open (backward compat).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::warn;

use edgeshield_config::config::ApiAuthConfig;

/// The permission level required for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Read-only access (GET endpoints).
    Read,
    /// Admin access (POST, DELETE endpoints).
    Admin,
}

/// Authentication state shared across all requests.
///
/// Holds the hashed keys and the rate-limiter state. Cloned into
/// each request's middleware context.
#[derive(Clone)]
pub struct AuthState {
    /// SHA-256 hash of the read key (32 bytes). `None` if auth is
    /// disabled.
    read_key_hash: Option<[u8; 32]>,
    /// SHA-256 hash of the admin key (32 bytes). `None` if no admin
    /// key is configured (single-key mode: read key is used for all).
    admin_key_hash: Option<[u8; 32]>,
    /// Rate limiter for failed auth attempts.
    rate_limiter: Arc<RateLimiter>,
}

impl AuthState {
    /// Create auth state from config. If `auth_config` is `None`,
    /// auth is disabled (all requests pass).
    pub fn new(auth_config: Option<&ApiAuthConfig>) -> Self {
        match auth_config {
            Some(cfg) => {
                let read_hash = hex::decode(&cfg.read_key_hash)
                    .ok()
                    .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());

                let admin_hash = cfg
                    .admin_key_hash
                    .as_ref()
                    .and_then(|h| hex::decode(h).ok())
                    .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());

                Self {
                    read_key_hash: read_hash,
                    admin_key_hash: admin_hash,
                    rate_limiter: Arc::new(RateLimiter::new(
                        cfg.max_failures,
                        cfg.window_seconds,
                        cfg.block_seconds,
                    )),
                }
            }
            None => Self {
                read_key_hash: None,
                admin_key_hash: None,
                rate_limiter: Arc::new(RateLimiter::new(0, 0, 0)),
            },
        }
    }

    /// Returns `true` if authentication is enabled.
    pub fn is_enabled(&self) -> bool {
        self.read_key_hash.is_some()
    }

    /// Verify a Bearer token against the configured keys.
    ///
    /// Returns `Ok(Permission)` if the key is valid, `Err(AuthError)`
    /// otherwise. The permission level indicates which endpoints the
    /// key can access.
    fn verify_token(&self, token: &str) -> Result<Permission, AuthError> {
        // Hash the provided token.
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let provided_hash = hasher.finalize();

        let read_hash = self.read_key_hash.ok_or(AuthError::NoKeyConfigured)?;

        // Constant-time comparison against the read key.
        if provided_hash.as_slice().ct_eq(&read_hash).into() {
            // In single-key mode (no admin key), the read key grants
            // admin permission. In two-key mode, it only grants read.
            return Ok(if self.admin_key_hash.is_none() {
                Permission::Admin
            } else {
                Permission::Read
            });
        }

        // Check admin key if configured.
        if let Some(ref admin_hash) = self.admin_key_hash
            && provided_hash.as_slice().ct_eq(admin_hash).into()
        {
            return Ok(Permission::Admin);
        }

        Err(AuthError::InvalidKey)
    }

    /// Check if a request should be allowed, applying auth and rate
    /// limiting.
    pub fn check(
        &self,
        method: &axum::http::Method,
        _path: &str,
        auth_header: Option<&str>,
        client_ip: Option<IpAddr>,
    ) -> Result<Permission, AuthError> {
        // Auth disabled — all requests pass.
        if !self.is_enabled() {
            return Ok(Permission::Admin);
        }

        // Check rate limiter first (before consuming an attempt).
        if let Some(ip) = client_ip
            && self.rate_limiter.is_blocked(&ip)
        {
            return Err(AuthError::RateLimited);
        }

        // Determine required permission.
        let required = required_permission(method);

        // Extract and verify the Bearer token.
        let token = extract_bearer_token(auth_header)?;
        let granted = self.verify_token(&token).inspect_err(|_| {
            // Record the failed attempt for rate limiting.
            if let Some(ip) = client_ip {
                self.rate_limiter.record_failure(&ip);
            }
        })?;

        // Check permission level.
        if required == Permission::Admin && granted == Permission::Read {
            return Err(AuthError::InsufficientPermission);
        }

        Ok(granted)
    }
}

/// Determine the required permission level for a request.
///
/// `GET` → Read, `POST`/`DELETE` → Admin.
fn required_permission(method: &axum::http::Method) -> Permission {
    match method.as_str() {
        "POST" | "DELETE" | "PUT" | "PATCH" => Permission::Admin,
        _ => Permission::Read,
    }
}

/// Extract the Bearer token from an `Authorization` header.
///
/// Expects `Authorization: Bearer <token>`. Returns an error if the
/// header is missing or malformed.
fn extract_bearer_token(auth_header: Option<&str>) -> Result<String, AuthError> {
    let header = auth_header.ok_or(AuthError::MissingHeader)?;
    let token = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .ok_or(AuthError::MalformedHeader)?;
    if token.is_empty() {
        return Err(AuthError::MalformedHeader);
    }
    Ok(token.to_string())
}

/// Authentication errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// No `Authorization` header present.
    MissingHeader,
    /// `Authorization` header is not a valid Bearer token.
    MalformedHeader,
    /// The provided key doesn't match any configured key.
    InvalidKey,
    /// The key is valid but doesn't have the required permission
    /// (e.g., a read key used for a POST endpoint).
    InsufficientPermission,
    /// Auth is configured but no key was provided (shouldn't happen
    /// — means `verify_token` was called with auth disabled).
    NoKeyConfigured,
    /// The client IP has been rate-limited due to too many failed
    /// attempts.
    RateLimited,
}

impl AuthError {
    /// Map to an HTTP status code.
    pub fn status_code(&self) -> StatusCode {
        match self {
            AuthError::MissingHeader | AuthError::MalformedHeader | AuthError::InvalidKey => {
                StatusCode::UNAUTHORIZED
            }
            AuthError::InsufficientPermission => StatusCode::FORBIDDEN,
            AuthError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            AuthError::NoKeyConfigured => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        // Don't reveal whether a key exists — return a generic
        // "unauthorized" message for all auth failures.
        let body = match &self {
            AuthError::RateLimited => "rate limit exceeded — too many failed attempts",
            AuthError::InsufficientPermission => "insufficient permission — admin key required",
            _ => "unauthorized",
        };
        (self.status_code(), body).into_response()
    }
}

/// Per-IP rate limiter for failed auth attempts.
///
/// Tracks failed attempts per IP address within a sliding window. If
/// an IP exceeds `max_failures` within `window_seconds`, it is
/// blocked for `block_seconds`. After the block expires, the counter
/// resets.
///
/// # Concurrency
///
/// Uses `DashMap` for lock-free concurrent access. The map is cleaned
/// up lazily — expired entries are removed when they're accessed.
pub struct RateLimiter {
    /// Maximum failed attempts before blocking. 0 = disabled.
    max_failures: u32,
    /// Window for counting failures (seconds).
    window_seconds: u64,
    /// How long to block an IP (seconds).
    block_seconds: u64,
    /// Per-IP failure tracking.
    failures: DashMap<IpAddr, FailureEntry>,
}

/// Per-IP failure tracking entry.
#[derive(Debug, Clone)]
struct FailureEntry {
    /// Timestamps of recent failures within the window.
    timestamps: Vec<Instant>,
    /// If `Some`, the IP is blocked until this time.
    blocked_until: Option<Instant>,
}

impl RateLimiter {
    /// Create a new rate limiter. If `max_failures` is 0, rate
    /// limiting is disabled.
    pub fn new(max_failures: u32, window_seconds: u64, block_seconds: u64) -> Self {
        Self {
            max_failures,
            window_seconds,
            block_seconds,
            failures: DashMap::new(),
        }
    }

    /// Check if an IP is currently blocked.
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        if self.max_failures == 0 {
            return false;
        }
        let Some(entry) = self.failures.get(ip) else {
            return false;
        };
        if let Some(until) = entry.blocked_until
            && Instant::now() < until
        {
            return true;
        }
        false
    }

    /// Record a failed auth attempt for an IP. If the IP exceeds
    /// `max_failures` within the window, it is blocked.
    pub fn record_failure(&self, ip: &IpAddr) {
        if self.max_failures == 0 {
            return;
        }

        let now = Instant::now();
        let window = Duration::from_secs(self.window_seconds);

        let mut entry = self.failures.entry(*ip).or_insert(FailureEntry {
            timestamps: Vec::new(),
            blocked_until: None,
        });

        // If currently blocked, don't extend the block.
        if let Some(until) = entry.blocked_until
            && now < until
        {
            return;
        }

        // Remove timestamps outside the window.
        entry.timestamps.retain(|t| now.duration_since(*t) < window);
        entry.timestamps.push(now);
        entry.blocked_until = None;

        // Check if we've exceeded the threshold.
        if entry.timestamps.len() as u32 >= self.max_failures {
            entry.blocked_until = Some(now + Duration::from_secs(self.block_seconds));
            entry.timestamps.clear();
            warn!(
                ip = %ip,
                block_seconds = self.block_seconds,
                "IP rate-limited due to failed auth attempts"
            );
        }
    }
}

/// Axum middleware: authenticate the request.
///
/// This is applied as a layer on all routes except `/health`. It
/// extracts the `Authorization` header, verifies the Bearer token,
/// checks the permission level, and applies rate limiting.
///
/// The `AuthState` is passed via `from_fn_with_state` (not extracted
/// from the router's `AppState`) to avoid Axum extractor ordering
/// constraints.
pub async fn auth_middleware(
    State(auth): State<AuthState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let client_ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .or_else(|| {
            request
                .extensions()
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|ci| ci.0.ip())
        });

    match auth.check(&method, &path, auth_header.as_deref(), client_ip) {
        Ok(_permission) => next.run(request).await,
        Err(e) => {
            warn!(
                method = %method,
                path = %path,
                error = ?e,
                "API auth failed"
            );
            e.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edgeshield_config::config::ApiAuthConfig;

    fn sha256_hex(input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn auth_config(read_key: &str, admin_key: Option<&str>) -> ApiAuthConfig {
        ApiAuthConfig {
            read_key_hash: sha256_hex(read_key),
            admin_key_hash: admin_key.map(sha256_hex),
            max_failures: 5,
            window_seconds: 60,
            block_seconds: 300,
        }
    }

    const TEST_READ_KEY: &str = "test-read-key-1234567890abcdef";
    const TEST_ADMIN_KEY: &str = "test-admin-key-1234567890abcdef";

    #[test]
    fn test_auth_disabled_allows_all() {
        let state = AuthState::new(None);
        assert!(!state.is_enabled());
        let result = state.check(&axum::http::Method::GET, "/devices", None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_valid_read_key_get() {
        let cfg = auth_config(TEST_READ_KEY, Some(TEST_ADMIN_KEY));
        let state = AuthState::new(Some(&cfg));
        let result = state.check(
            &axum::http::Method::GET,
            "/devices",
            Some(&format!("Bearer {TEST_READ_KEY}")),
            None,
        );
        assert_eq!(result.unwrap(), Permission::Read);
    }

    #[test]
    fn test_valid_admin_key_get() {
        let cfg = auth_config(TEST_READ_KEY, Some(TEST_ADMIN_KEY));
        let state = AuthState::new(Some(&cfg));
        let result = state.check(
            &axum::http::Method::GET,
            "/devices",
            Some(&format!("Bearer {TEST_ADMIN_KEY}")),
            None,
        );
        assert_eq!(result.unwrap(), Permission::Admin);
    }

    #[test]
    fn test_valid_admin_key_post() {
        let cfg = auth_config(TEST_READ_KEY, Some(TEST_ADMIN_KEY));
        let state = AuthState::new(Some(&cfg));
        let result = state.check(
            &axum::http::Method::POST,
            "/alerts/1/acknowledge",
            Some(&format!("Bearer {TEST_ADMIN_KEY}")),
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_read_key_cannot_post() {
        let cfg = auth_config(TEST_READ_KEY, Some(TEST_ADMIN_KEY));
        let state = AuthState::new(Some(&cfg));
        let result = state.check(
            &axum::http::Method::POST,
            "/alerts/1/acknowledge",
            Some(&format!("Bearer {TEST_READ_KEY}")),
            None,
        );
        assert_eq!(result.unwrap_err(), AuthError::InsufficientPermission);
    }

    #[test]
    fn test_single_key_mode_read_key_can_post() {
        // When admin_key_hash is None, read key is used for all.
        let cfg = auth_config(TEST_READ_KEY, None);
        let state = AuthState::new(Some(&cfg));
        let result = state.check(
            &axum::http::Method::POST,
            "/alerts/1/acknowledge",
            Some(&format!("Bearer {TEST_READ_KEY}")),
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_missing_header() {
        let cfg = auth_config(TEST_READ_KEY, None);
        let state = AuthState::new(Some(&cfg));
        let result = state.check(&axum::http::Method::GET, "/devices", None, None);
        assert_eq!(result.unwrap_err(), AuthError::MissingHeader);
    }

    #[test]
    fn test_malformed_header() {
        let cfg = auth_config(TEST_READ_KEY, None);
        let state = AuthState::new(Some(&cfg));
        let result = state.check(
            &axum::http::Method::GET,
            "/devices",
            Some("Basic abc123"),
            None,
        );
        assert_eq!(result.unwrap_err(), AuthError::MalformedHeader);
    }

    #[test]
    fn test_empty_bearer_token() {
        let cfg = auth_config(TEST_READ_KEY, None);
        let state = AuthState::new(Some(&cfg));
        let result = state.check(&axum::http::Method::GET, "/devices", Some("Bearer "), None);
        assert_eq!(result.unwrap_err(), AuthError::MalformedHeader);
    }

    #[test]
    fn test_invalid_key() {
        let cfg = auth_config(TEST_READ_KEY, None);
        let state = AuthState::new(Some(&cfg));
        let result = state.check(
            &axum::http::Method::GET,
            "/devices",
            Some("Bearer wrong-key"),
            None,
        );
        assert_eq!(result.unwrap_err(), AuthError::InvalidKey);
    }

    #[test]
    fn test_case_insensitive_bearer_prefix() {
        let cfg = auth_config(TEST_READ_KEY, None);
        let state = AuthState::new(Some(&cfg));
        let result = state.check(
            &axum::http::Method::GET,
            "/devices",
            Some(&format!("bearer {TEST_READ_KEY}")),
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_rate_limiting_blocks_after_max_failures() {
        let cfg = ApiAuthConfig {
            read_key_hash: sha256_hex(TEST_READ_KEY),
            admin_key_hash: None,
            max_failures: 3,
            window_seconds: 60,
            block_seconds: 300,
        };
        let state = AuthState::new(Some(&cfg));
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        // First 3 failures should return InvalidKey.
        for _ in 0..3 {
            let result = state.check(
                &axum::http::Method::GET,
                "/devices",
                Some("Bearer wrong"),
                Some(ip),
            );
            assert_eq!(result.unwrap_err(), AuthError::InvalidKey);
        }

        // 4th attempt should be rate-limited.
        let result = state.check(
            &axum::http::Method::GET,
            "/devices",
            Some(&format!("Bearer {TEST_READ_KEY}")),
            Some(ip),
        );
        assert_eq!(result.unwrap_err(), AuthError::RateLimited);
    }

    #[test]
    fn test_rate_limiting_disabled_when_max_failures_zero() {
        let cfg = ApiAuthConfig {
            read_key_hash: sha256_hex(TEST_READ_KEY),
            admin_key_hash: None,
            max_failures: 0,
            window_seconds: 60,
            block_seconds: 300,
        };
        let state = AuthState::new(Some(&cfg));
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        // Many failures should never trigger rate limiting.
        for _ in 0..100 {
            let _ = state.check(
                &axum::http::Method::GET,
                "/devices",
                Some("Bearer wrong"),
                Some(ip),
            );
        }
        // A valid key should still work.
        let result = state.check(
            &axum::http::Method::GET,
            "/devices",
            Some(&format!("Bearer {TEST_READ_KEY}")),
            Some(ip),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_rate_limiting_different_ips_independent() {
        let cfg = ApiAuthConfig {
            read_key_hash: sha256_hex(TEST_READ_KEY),
            admin_key_hash: None,
            max_failures: 2,
            window_seconds: 60,
            block_seconds: 300,
        };
        let state = AuthState::new(Some(&cfg));
        let ip1: IpAddr = "192.168.1.100".parse().unwrap();
        let ip2: IpAddr = "192.168.1.200".parse().unwrap();

        // Exhaust ip1's attempts.
        for _ in 0..2 {
            let _ = state.check(
                &axum::http::Method::GET,
                "/devices",
                Some("Bearer wrong"),
                Some(ip1),
            );
        }
        assert!(state.rate_limiter.is_blocked(&ip1));

        // ip2 should still be able to authenticate.
        let result = state.check(
            &axum::http::Method::GET,
            "/devices",
            Some(&format!("Bearer {TEST_READ_KEY}")),
            Some(ip2),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_constant_time_comparison() {
        // Verify that ct_eq is used (not ==). This is a smoke test —
        // a real timing attack test would need statistical analysis.
        let cfg = auth_config(TEST_READ_KEY, None);
        let state = AuthState::new(Some(&cfg));

        // A key that differs in the last byte should still fail.
        let wrong_key = format!("{}X", &TEST_READ_KEY[..TEST_READ_KEY.len() - 1]);
        let result = state.check(
            &axum::http::Method::GET,
            "/devices",
            Some(&format!("Bearer {wrong_key}")),
            None,
        );
        assert_eq!(result.unwrap_err(), AuthError::InvalidKey);
    }
}
