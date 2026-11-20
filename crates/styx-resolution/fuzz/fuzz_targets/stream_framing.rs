#![no_main]

//! Drives the shared stream framing (plaintext TCP and DNS over TLS) over arbitrary bytes,
//! reading frames until the stream ends or a frame is rejected.

use std::sync::OnceLock;
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use styx_resolution::infrastructure::framing::read_frame;
use tokio::runtime::Runtime;

fn runtime() -> Option<&'static Runtime> {
    static RUNTIME: OnceLock<Option<Runtime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .ok()
        })
        .as_ref()
}

fuzz_target!(|data: &[u8]| {
    let Some(runtime) = runtime() else {
        return;
    };
    runtime.block_on(async {
        let mut stream = data;
        while let Ok(Some(frame)) = read_frame(&mut stream, Duration::from_millis(10)).await {
            assert!(!frame.is_empty() && frame.len() <= usize::from(u16::MAX));
        }
    });
});
