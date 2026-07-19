# ADR-0005: Storage Backend

## Status

Accepted

## Context

EdgeShield needs to store device records (MAC addresses, IP addresses, counters, protocols) that are:

- **Accessed concurrently**: The pipeline task writes device records while the API server reads them
- **Queried by primary key**: Most lookups are by MAC address
- **Listed in full**: The API returns all devices
- **Persisted across restarts** (future): Device data should survive daemon restarts

The MVP does not require persistence, but the storage architecture must support it from day one.

### Considered options

1. **DashMap (in-memory)**: Concurrent hash map with sharded locks
2. **SQLite**: Embedded SQL database
3. **HashMap + RwLock**: Standard library hash map with a read-write lock
4. **sled**: Embedded database written in Rust
5. **Redb**: Embedded database written in Rust

## Decision

Use a trait-based abstraction (`DeviceStore`) with an in-memory `DashMap` implementation for the MVP. SQLite will be added in Phase 6.

## Rationale

### Trait abstraction

The `DeviceStore` trait is introduced from day one, even though there is only one implementation. This ensures:

- The discovery and API layers depend on an abstraction, not a concrete implementation
- Adding SQLite in Phase 6 requires no changes to the discovery or API crates
- Testing can use a mock store without modifying production code

```rust
pub trait DeviceStore: Send + Sync {
    fn get(&self, mac: &MacAddress) -> Result<Option<Device>, StorageError>;
    fn upsert(&self, device: Device) -> Result<(), StorageError>;
    fn list(&self) -> Result<Vec<Device>, StorageError>;
    fn count(&self) -> Result<usize, StorageError>;
}
```

### DashMap for MVP

`DashMap` is chosen for the in-memory implementation because:

- **Lock-free reads**: Multiple threads can read simultaneously without contention
- **Sharded writes**: Writes to different MAC addresses proceed in parallel
- **No `unsafe` code**: DashMap is implemented in safe Rust
- **Proven in production**: Used by Tokio, TiKV, and other production systems
- **Simple API**: Familiar `HashMap`-like interface

### Why not alternatives

- **HashMap + RwLock**: Single global lock serializes all access. Poor concurrency for our read-heavy workload.
- **sled**: Excellent embedded database, but adds complexity (log-structured merge tree, crash recovery) that is unnecessary for the MVP.
- **Redb**: Similar to sled — excellent but over-engineered for the MVP.
- **SQLite**: The right choice for persistence, but adds a build dependency (C library via `rusqlite`) and complexity that is unnecessary for the MVP.

### SQLite for Phase 6

SQLite is chosen for persistent storage because:

- **Embedded**: No separate database server required
- **Zero configuration**: A single file on disk
- **Reliable**: Billions of deployments, ACID compliance
- **Rust bindings**: `rusqlite` provides a safe, well-maintained API
- **Cross-platform**: Works on all target architectures (x86_64, aarch64, armv7)
- **Schema migrations**: Well-understood migration patterns

## Consequences

### Positive

- Clean separation between storage and application logic
- In-memory store provides maximum performance for the MVP
- SQLite store can be added without changing discovery or API code
- Testing with mock stores is straightforward
- DashMap provides excellent concurrent performance

### Negative

- Trait abstraction adds a small amount of indirection (dynamic dispatch via `dyn DeviceStore`)
- In-memory store loses all data on restart
- SQLite store will require a C library dependency (`libsqlite3-dev` or bundled via `bundled` feature)

### Neutral

- The `DeviceStore` trait may need additional methods for the SQLite implementation (e.g., `search`, `query_by_ip`)
- The trait is designed to be minimal — additional methods can be added without breaking existing implementations

## Future Storage Backends

The `DeviceStore` trait enables future backends:

```rust
// SQLite (Phase 6)
pub struct SqliteStore {
    conn: Mutex<rusqlite::Connection>,
}

// PostgreSQL (future)
pub struct PostgresStore {
    pool: deadpool_postgres::Pool,
}

// Redis (future)
pub struct RedisStore {
    conn: redis::Connection,
}
```

## References

- [DashMap documentation](https://docs.rs/dashmap/)
- [rusqlite documentation](https://docs.rs/rusqlite/)
- [SQLite documentation](https://www.sqlite.org/docs.html)
