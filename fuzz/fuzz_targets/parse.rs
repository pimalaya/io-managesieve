#![no_main]

//! Coverage-guided fuzz target for the response parser. The oracle:
//! whatever a server sends, `ManagesieveResponse::parse` answers a
//! response, an incomplete signal or a typed error, never a panic, and
//! a response it answers holds together. The bytes it consumed lie
//! within the buffer, no string it carries is longer than them, it
//! renders, and the same bytes parse into the same response again.

use io_managesieve::rfc5804::response::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|wire: &[u8]| {
    let Ok(Some((response, consumed))) = ManagesieveResponse::parse(wire) else {
        return;
    };

    assert!(consumed <= wire.len());

    for line in &response.data {
        for token in &line.tokens {
            if let ManagesieveToken::String(string) = token {
                assert!(string.len() <= consumed);
            }
        }
    }

    let _ = response.to_string();

    let again = ManagesieveResponse::parse(&wire[..consumed]);
    assert_eq!(again, Ok(Some((response, consumed))));
});
