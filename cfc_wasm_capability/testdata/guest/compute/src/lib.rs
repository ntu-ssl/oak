// Toy `compute` component: interpret the input as little-endian u32s and return
// their wrapping sum as a little-endian u32. Pure function, no WASI imports, so
// the derived capability set is empty and every runtime property is DENIED.
#[allow(warnings)]
mod bindings;

use bindings::exports::cfc::transform::compute::Guest;

struct Component;

impl Guest for Component {
    fn transform(input: Vec<u8>) -> Vec<u8> {
        let sum: u32 = input
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .fold(0u32, u32::wrapping_add);
        sum.to_le_bytes().to_vec()
    }
}

bindings::export!(Component with_types_in bindings);
