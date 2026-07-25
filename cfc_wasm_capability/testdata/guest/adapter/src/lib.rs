// Toy `adapter` component: the top-level entry the host calls. It imports the
// `compute` interface and forwards to it, demonstrating host-mediated wiring
// (adapter -> compute) rather than a fused single component. The adapter itself
// has no WASI imports, so it contributes no ambient authority; its import of
// `compute` is composition wiring, captured in the graph as an edge.
#[allow(warnings)]
mod bindings;

use bindings::cfc::transform::compute;
use bindings::exports::cfc::transform::app::Guest;

struct Component;

impl Guest for Component {
    fn run(input: Vec<u8>) -> Vec<u8> {
        // Forward the input to the wired-in compute component.
        compute::transform(&input)
    }
}

bindings::export!(Component with_types_in bindings);
