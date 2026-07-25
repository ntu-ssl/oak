//
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

//! Integration test for the orchestrator's host-mediated wasm composition
//! runtime, run against the committed adapter->compute fixtures (no VM).

use std::collections::BTreeMap;

use cfc_wasm_capability::proto::{WasmComponentRef, WasmCompositionEdge, WasmWorkloadConfig};
use oak_containers_orchestrator::wasm_runtime::Composition;

const COMPUTE_IFACE: &str = "cfc:transform/compute@0.1.0";
const APP_IFACE: &str = "cfc:transform/app@0.1.0";

fn read_fixture(name: &str) -> Vec<u8> {
    let path = oak_file_utils::data_path(format!("cfc_wasm_capability/testdata/{name}"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading fixture {name}: {e}"))
}

fn adapter_compute_config() -> (WasmWorkloadConfig, BTreeMap<String, Vec<u8>>) {
    let mut files = BTreeMap::new();
    files.insert("compute.wasm".to_string(), read_fixture("compute.wasm"));
    files.insert("adapter.wasm".to_string(), read_fixture("adapter.wasm"));

    let wasm = WasmWorkloadConfig {
        components: vec![
            WasmComponentRef {
                id: "compute".into(),
                role: "private_computation".into(),
                path: "compute.wasm".into(),
            },
            WasmComponentRef {
                id: "adapter".into(),
                role: "public_input_adapter".into(),
                path: "adapter.wasm".into(),
            },
        ],
        // adapter imports compute's interface; the host mediates the edge.
        edges: vec![WasmCompositionEdge {
            from: "compute".into(),
            to: "adapter".into(),
            interface: COMPUTE_IFACE.into(),
        }],
        entry_component: "adapter".into(),
        entry_interface: APP_IFACE.into(),
        entry_function: "run".into(),
    };
    (wasm, files)
}

#[test]
fn host_mediated_adapter_compute_runs() {
    let (wasm, files) = adapter_compute_config();
    let mut composition = Composition::load(&wasm, &files).expect("load composition");

    // compute sums little-endian u32s; adapter forwards to it. [1,2,3] -> 6.
    let input: Vec<u8> = [1u32, 2u32, 3u32].iter().flat_map(|v| v.to_le_bytes()).collect();
    let output = composition.invoke(&input).expect("invoke entry");

    let sum = u32::from_le_bytes(output.as_slice().try_into().expect("4-byte output"));
    assert_eq!(sum, 6, "adapter->compute host-mediated sum");
}

#[test]
fn different_input_gives_different_sum() {
    let (wasm, files) = adapter_compute_config();
    let mut composition = Composition::load(&wasm, &files).expect("load composition");

    let input: Vec<u8> = [10u32, 20u32].iter().flat_map(|v| v.to_le_bytes()).collect();
    let output = composition.invoke(&input).expect("invoke entry");

    let sum = u32::from_le_bytes(output.as_slice().try_into().expect("4-byte output"));
    assert_eq!(sum, 30);
}