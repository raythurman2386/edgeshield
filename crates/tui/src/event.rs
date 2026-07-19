//! Async terminal event handling via crossterm's event-stream feature.
//!
//! The render loop [`tokio::select!`]s between user input (from this
//! module) and a redraw tick. This keeps the poller task running
//! during input waits — critical, since the dashboard must keep
//! refreshing while the user is idle.

use std::time::Duration;

use crossterm::event::{Event, EventStream};
use futures::StreamExt;

/// Poll for the next terminal event, waiting up to `timeout`.
///
/// Returns `Ok(None)` if no event arrived within `timeout`. This lets
/// the render loop interleave input with periodic redraws.
pub async fn poll(timeout: Duration) -> Option<Event> {
    let mut stream = EventStream::new();
    match tokio::time::timeout(timeout, stream.next()).await {
        Ok(Some(Ok(ev))) => Some(ev),
        _ => None,
    }
}
