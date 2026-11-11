//! Native async driver. The C-ABI FFI processes each request on a sync worker
//! thread (see `LibwalletRequest`), so to run the target-agnostic async handlers
//! (chain I/O via `rpc::call_async`, …) it blocks that thread on a shared Tokio
//! runtime. The browser has no equivalent: wasm awaits the very same futures on
//! the JS event loop via the Promise returned from `libwallet_request`. Keeping
//! the handlers async-and-shared means native and wasm run identical logic —
//! only the driver differs (block_on here vs. `.await` there).

use std::future::Future;
use std::sync::OnceLock;

use tokio::runtime::{Builder, Runtime};

static RT: OnceLock<Runtime> = OnceLock::new();

/// The process-wide multi-thread runtime (built on first use). Multi-thread so
/// `block_on` can be called concurrently from several worker threads.
fn runtime() -> &'static Runtime {
    RT.get_or_init(|| {
        Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("failed to build the libwallet Tokio runtime")
    })
}

/// Block the calling (worker) thread until `fut` resolves, driving it on the
/// shared runtime. Safe to call concurrently from multiple worker threads.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    runtime().block_on(fut)
}

/// Give hidapi a thread that never ends, before anything else touches it.
///
/// macOS: `hid_init` schedules hidapi's one IOHIDManager on the run loop of
/// the thread that calls it first, and IOKit keeps that run loop without
/// retaining it. Requests run on short-lived worker threads, so left alone the
/// manager would point at a freed run loop as soon as the first HID request
/// returned, and the next enumeration (`IOHIDManagerSetDeviceMatching` adds
/// every device's sources to that run loop) would crash the process once the
/// memory was reused. Call this before every use of hidapi, ours or lsdk's.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
pub fn hid_init() {
    #[cfg(target_os = "macos")]
    {
        static PINNED: OnceLock<()> = OnceLock::new();
        PINNED.get_or_init(|| {
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            let spawned = std::thread::Builder::new().name("libwallet-hid".into()).spawn(move || {
                // The first HidApi is what calls hid_init: on this thread.
                let _ = hidapi::HidApi::new();
                let _ = tx.send(());
                loop {
                    std::thread::park();
                }
            });
            if spawned.is_ok() {
                let _ = rx.recv();
            }
        });
    }
}
