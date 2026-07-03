//! Per-session handle: owns the environment and the bookkeeping needed to
//! shut down cleanly without firing a callback after `LibwalletDestroy`
//! returns. This is the Rust counterpart of the `handle` struct in
//! `cshared/ffi.go`, including its WaitGroup-vs-shutdown ordering.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use crate::Env;

use crate::EventCallback;

pub struct Handle {
    pub env: Arc<Env>,
    pub shutdown: AtomicBool,
    /// Registered host event callback (set via LibwalletSetEventCallback).
    pub event_cb: Mutex<Option<(EventCallback, usize)>>,
    /// Count of in-flight request worker threads. Destroy waits on this
    /// hitting zero so no callback fires after the consumer tears down.
    inflight: Mutex<usize>,
    idle: Condvar,
}

impl Handle {
    pub fn new(env: Env) -> Handle {
        Handle {
            env: Arc::new(env),
            shutdown: AtomicBool::new(false),
            event_cb: Mutex::new(None),
            inflight: Mutex::new(0),
            idle: Condvar::new(),
        }
    }

    /// Try to register a new in-flight request. Returns false if the handle is
    /// shutting down (the check happens under the same lock that `wait_idle`
    /// takes, so a request can never slip in past the shutdown barrier).
    pub fn begin_request(self: &Arc<Self>) -> Option<InflightGuard> {
        let mut n = self.inflight.lock().unwrap();
        if self.shutdown.load(Ordering::SeqCst) {
            return None;
        }
        *n += 1;
        Some(InflightGuard(self.clone()))
    }

    fn end_request(&self) {
        let mut n = self.inflight.lock().unwrap();
        *n -= 1;
        if *n == 0 {
            self.idle.notify_all();
        }
    }

    /// Mark shutting down and block until all in-flight workers have finished.
    pub fn shutdown_and_wait(&self) {
        // Take the inflight lock so this is ordered against begin_request:
        // once we set the flag under the lock, no new guard can be created.
        let mut n = self.inflight.lock().unwrap();
        self.shutdown.store(true, Ordering::SeqCst);
        *self.event_cb.lock().unwrap() = None;
        while *n > 0 {
            n = self.idle.wait(n).unwrap();
        }
    }
}

/// Decrements the in-flight counter when a request worker finishes.
pub struct InflightGuard(Arc<Handle>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.end_request();
    }
}
