# ADR-0003: Tokio Runtime

## Status

Accepted

## Context

EdgeShield has three concurrent execution contexts:

1. **Packet capture**: Blocking I/O that reads raw packets from a network interface
2. **Pipeline processing**: CPU-bound work that decodes, classifies, and stores packet metadata
3. **API server**: Network I/O that serves HTTP requests

These contexts have different execution requirements:

- Packet capture must run on a dedicated thread (pnet's datalink API is blocking)
- Pipeline processing is CPU-bound and should not block the async runtime
- The API server is I/O-bound and benefits from async I/O

### Considered options

1. **Tokio (multi-thread)**: Default multi-thread scheduler with work-stealing
2. **Tokio (current-thread)**: Single-threaded scheduler
3. **smol**: Lightweight async runtime
4. **async-std**: Async runtime modeled after std
5. **No async runtime**: Thread-per-task model with blocking I/O everywhere

## Decision

Use the Tokio runtime with the multi-thread scheduler and the `full` features feature set.

## Rationale

### Multi-thread scheduler

The multi-thread scheduler uses one worker thread per CPU core with work-stealing. This is appropriate because:

- The pipeline task and API server task can run in parallel on different cores
- Work-stealing ensures load balancing if one task is idle
- The number of worker threads matches the hardware (4 cores on Pi 4, 1 core on Pi Zero 2 W)

### Blocking I/O on OS threads

Tokio's `spawn_blocking` is not used for packet capture. Instead, a dedicated OS thread is spawned with `std::thread::Builder`. This is because:

- The capture thread runs for the lifetime of the application
- It has a fixed, predictable workload (no need for dynamic thread pool sizing)
- It needs a specific name (`pcap-{interface}`) for observability
- The thread-to-async bridge is a single bounded mpsc channel

### Bounded channels

All inter-task communication uses bounded mpsc channels. This is a Tokio best practice that prevents unbounded memory growth under load.

### Full features

The `"full"` features feature set is used because EdgeShield needs:

- `rt-multi-thread`: Multi-threaded runtime
- `sync`: `Mutex`, `RwLock` for shared state
- `signal`: Signal handling for graceful shutdown
- `net`: TCP listener for the API server
- `macros`: `#[tokio::test]` for async tests

## Consequences

### Positive

- Mature, well-documented runtime with a large ecosystem
- Multi-threaded work-stealing scheduler for parallel task execution
- Bounded channels for backpressure
- Signal handling for graceful shutdown
- `#[tokio::test]` for ergonomic async testing

### Negative

- Larger dependency than minimal runtimes (smol, async-std)
- Multi-threaded runtime has more overhead than single-threaded
- Tokio's `"full"` features include some features we don't use

### Neutral

- The capture thread is an OS thread, not a tokio task — this is a deliberate design choice
- The pipeline and API server share the same runtime, which is appropriate for their workloads

## Threading Model

```text
OS Thread 1: Main thread
  - Parse CLI arguments
  - Initialize subsystems
  - Spawn capture thread
  - Start tokio runtime
  - Wait for shutdown signal

OS Thread 2: Capture thread (pcap-eth0)
  - Blocking loop: read packets from pnet
  - Send packets over mpsc channel
  - Stop on signal

Tokio Worker Threads (N = CPU count):
  - Pipeline task: receive packets, decode, classify, update store
  - API server task: accept HTTP connections, serve requests
```

## References

- [Tokio Documentation](https://docs.rs/tokio/)
- [Tokio: The Async Ecosystem](https://tokio.rs/tokio/topics/ecosystem)
- [Tokio: Spawning](https://tokio.rs/tokio/tutorial/spawning)
