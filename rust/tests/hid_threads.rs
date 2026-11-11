//! The USB device lists are asked for from short-lived request threads (one
//! per `LibwalletRequest`). On macOS hidapi ties its IOHIDManager to the run
//! loop of the first thread that uses it, and IOKit does not retain that run
//! loop: once that thread is gone, the next enumeration adds sources to freed
//! memory and the process dies (SIGTRAP in `CFRunLoopAddSource`) as soon as the
//! allocator has reused it. The lists must survive the thread that asked first.
#![cfg(target_os = "macos")]

fn list_on_a_new_thread() {
    std::thread::spawn(|| {
        // Whether devices are found (or HID is usable at all) is not the point.
        let _ = libwallet::rt::block_on(libwallet::ledger::transport::list());
        let _ = libwallet::rt::block_on(libwallet::catcard::transport::list());
    })
    .join()
    .unwrap();
}

#[test]
fn device_lists_outlive_the_thread_that_asked_first() {
    list_on_a_new_thread();
    for _ in 0..20 {
        // Reuse what the first thread freed: a CFRunLoop is ~3 KB.
        let churn: Vec<Vec<u8>> = (0..2000).map(|k| vec![0xAAu8; 2100 + (k % 900)]).collect();
        list_on_a_new_thread();
        drop(churn);
    }
}
