#![no_main]

use libfuzzer_sys::fuzz_target;
use styx_proto::Message;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = Message::decode(data) {
        let mut buf = vec![0u8; 4096];
        if let Ok(written) = msg.encode(&mut buf, 4096) {
            let redecoded = Message::decode(&buf[..written])
                .expect("re-decoding successfully encoded message failed");
            assert_eq!(msg, redecoded);
        }
    }
});
