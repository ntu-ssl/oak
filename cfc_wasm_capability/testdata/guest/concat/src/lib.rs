// `concat` ConfidentialTransform session component: the wasm port of
// containers/confidential_transform_test_concat's TestConcatSession. It
// accumulates the plaintext written across `write` calls and, on `finalize`,
// emits the concatenation through the host-provided `context` capability.
//
// It has no WASI imports; its only import is the host `context` capability, so
// the derived claim shows exactly that (no network / fs / clock / random).
#[allow(warnings)]
mod bindings;

use std::cell::RefCell;

use bindings::cfc::transform::context::{self, Kv};
use bindings::exports::cfc::transform::session::Guest;

thread_local! {
    // Accumulated plaintext across `write` calls (single-threaded wasm).
    static STATE: RefCell<Vec<u8>> = RefCell::new(Vec::new());
}

struct Component;

impl Guest for Component {
    fn configure(_config: Vec<u8>) {
        STATE.with(|s| s.borrow_mut().clear());
    }

    fn write(data: Vec<u8>) {
        STATE.with(|s| s.borrow_mut().extend_from_slice(&data));
    }

    fn commit() {}

    fn finalize() {
        STATE.with(|s| {
            let value = s.borrow().clone();
            context::emit_unencrypted(&Kv { key: "result".to_string(), value });
        });
    }
}

bindings::export!(Component with_types_in bindings);