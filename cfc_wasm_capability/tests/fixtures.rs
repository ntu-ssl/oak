// Copyright 2026 Confidential Federated Compute Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Integration tests that run capability derivation over the real toy
//! component fixtures. These require the fixtures to have been built (see
//! `testdata/guest/build.sh`) and checked in; they are embedded at compile time
//! with `include_bytes!`, so this target will not compile until the `.wasm`
//! files exist.

use cfc_wasm_capability::proto::composition_graph::Edge;
use cfc_wasm_capability::proto::runtime_properties::Enforcement;
use cfc_wasm_capability::{derive_claim, ComponentInput, SCHEMA_VERSION};

const COMPUTE: &[u8] = include_bytes!("../testdata/compute.wasm");
const ADAPTER: &[u8] = include_bytes!("../testdata/adapter.wasm");
const COMPUTE_CLOCK: &[u8] = include_bytes!("../testdata/compute_clock.wasm");

// Fully-qualified name of the interface the adapter imports and the compute
// component exports. If the "no grants" assertion below fails with a spurious
// `cfc:transform/compute...` grant, update this string to exactly what
// cap-host-selftest prints for the adapter's imports.
const COMPUTE_IFACE: &str = "cfc:transform/compute@0.1.0";

fn denied(e: i32) -> bool {
    e == Enforcement::Denied as i32
}

fn is_granted(e: i32) -> bool {
    e == Enforcement::Granted as i32
}

fn all_denied_except_wall_clock(props: &cfc_wasm_capability::proto::RuntimeProperties) -> bool {
    denied(props.network)
        && denied(props.persistent_storage)
        && denied(props.randomness)
        && denied(props.environment)
        && denied(props.spawn)
}

fn adapter_compute_graph() -> ([ComponentInput<'static>; 2], [Edge; 1]) {
    let components = [
        ComponentInput {
            id: "adapter".to_string(),
            role: "public_input_adapter".to_string(),
            bytes: ADAPTER,
        },
        ComponentInput {
            id: "compute".to_string(),
            role: "private_computation".to_string(),
            bytes: COMPUTE,
        },
    ];
    let edges = [Edge {
        from: "compute".to_string(),
        to: "adapter".to_string(),
        interface: COMPUTE_IFACE.to_string(),
    }];
    (components, edges)
}

#[test]
fn pure_adapter_compute_graph_has_no_grants_and_all_denied() {
    let (components, edges) = adapter_compute_graph();
    let claim = derive_claim(&components, &edges).expect("derivation should succeed");

    assert_eq!(claim.schema_version, SCHEMA_VERSION);
    assert!(
        claim.granted_capabilities.is_empty(),
        "a pure host-mediated composition must grant no host capabilities, got: {:?}",
        claim.granted_capabilities
    );

    let props = claim.runtime_properties.expect("runtime_properties present");
    assert!(denied(props.wall_clock));
    assert!(all_denied_except_wall_clock(&props));

    assert_eq!(claim.components.len(), 2);
    for c in &claim.components {
        assert_eq!(c.digest.len(), 32, "component digest is a SHA-256");
    }
    // The two components are distinct binaries.
    assert_ne!(claim.components[0].digest, claim.components[1].digest);

    // The graph records the adapter<-compute wiring, canonicalized.
    let graph = claim.graph.expect("graph present");
    assert_eq!(graph.nodes, vec!["adapter".to_string(), "compute".to_string()]);
    assert_eq!(graph.edges.len(), 1);

    assert_eq!(claim.application_commitment.len(), 32);

    let runtime = claim.runtime_info.expect("runtime_info present");
    assert_eq!(runtime.engine, "wasmtime");
    assert!(runtime.component_model);
    assert!(!runtime.dynamic_loading);
}

#[test]
fn commitment_is_deterministic_across_runs() {
    let (components, edges) = adapter_compute_graph();
    let a = derive_claim(&components, &edges).expect("derive a");
    let b = derive_claim(&components, &edges).expect("derive b");
    assert_eq!(a.application_commitment, b.application_commitment);
    assert!(!a.application_commitment.is_empty());
}

#[test]
fn clock_component_grants_only_wall_clock() {
    let components = [ComponentInput {
        id: "clock".to_string(),
        role: "private_computation".to_string(),
        bytes: COMPUTE_CLOCK,
    }];
    let claim = derive_claim(&components, &[]).expect("derivation should succeed");

    let props = claim.runtime_properties.expect("runtime_properties present");
    assert!(is_granted(props.wall_clock), "wall_clock must be GRANTED");
    assert!(
        all_denied_except_wall_clock(&props),
        "no property other than wall_clock may be granted"
    );

    assert_eq!(
        claim.granted_capabilities.len(),
        1,
        "exactly one host capability expected, got: {:?}",
        claim.granted_capabilities
    );
    assert!(claim.granted_capabilities[0]
        .interface
        .contains("wasi:clocks/wall-clock"));
}