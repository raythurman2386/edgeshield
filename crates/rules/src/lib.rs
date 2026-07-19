//! Rule engine for EdgeShield.
//!
//! This crate consumes `DiscoveryEvent`s from the discovery pipeline,
//! evaluates user-configured rules, and emits `Alert`s to the
//! notification fanout. It also persists alerts to the `AlertStore`
//! for the `/alerts` API endpoint.
//!
//! # Architecture
//!
//! ```text
//! DiscoveryEvent rx → RuleEngine → Alert tx → NotifierFanout
//!                                      ↓
//!                                  AlertStore
//! ```
//!
//! # Dependency direction
//!
//! ```text
//! rules → common, discovery, storage
//! ```
//!
//! `rules` never depends on `notify`, `api`, `packet`, or `daemon`.

pub mod config_bridge;
pub mod engine;
pub mod store;

pub use engine::{Rule, RuleCondition, RuleEngine};
pub use store::{AlertFilter, AlertStore, InMemoryAlertStore};