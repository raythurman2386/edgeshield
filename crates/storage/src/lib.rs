//! Storage abstraction for EdgeShield.
//!
//! This crate defines the storage trait and provides two implementations:
//! - `MemoryStore` — in-memory backed by DashMap (default)
//! - `SqliteStore` — persistent backed by SQLite

pub mod memory;
pub mod sqlite;
pub mod store;

pub use memory::MemoryStore;
pub use sqlite::SqliteStore;
pub use store::DeviceStore;
