//! Storage abstraction for EdgeShield.
//!
//! This crate defines the storage traits and provides implementations:
//! - `MemoryStore` — in-memory device store backed by DashMap (default)
//! - `SqliteStore` — persistent device store backed by SQLite
//! - `SqliteAlertStore` — persistent alert store backed by SQLite
//! - `SqliteHistoryStore` — persistent device history store backed by SQLite

pub mod alert_sqlite;
pub mod history_sqlite;
pub mod memory;
pub mod sqlite;
pub mod store;

pub use alert_sqlite::SqliteAlertStore;
pub use history_sqlite::SqliteHistoryStore;
pub use memory::MemoryStore;
pub use sqlite::SqliteStore;
pub use store::DeviceStore;
