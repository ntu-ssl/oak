// `compute_clock` fixture: reads wall-clock time (its single WASI import) and
// appends the current seconds to the input. The computation is irrelevant; the
// point is that the component structurally imports wasi:clocks/wall-clock, so
// derivation must report `wall_clock` GRANTED and nothing else.
#[allow(warnings)]
mod bindings;

use bindings::wasi::clocks::wall_clock;
use bindings::Guest;

struct Component;

impl Guest for Component {
    fn run(input: Vec<u8>) -> Vec<u8> {
        let now = wall_clock::now();
        let mut out = input;
        out.extend_from_slice(&now.seconds.to_le_bytes());
        out
    }
}

bindings::export!(Component with_types_in bindings);
