#![no_main]

use libfuzzer_sys::fuzz_target;
use styx_proto::Message;

fuzz_target!(|data: &[u8]| {
    let _ = Message::decode(data);
});
