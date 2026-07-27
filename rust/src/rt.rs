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
