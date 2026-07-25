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

//! Phase 1a de-risk binary: `bazel run //cfc_wasm_capability:cap_host_selftest`.
//!
//! Runs entirely on the host (no VM, no DICE, no system image). It:
//!   1. loads each toy component and prints its resolved imports/exports (the
//!      exploration surface for capability derivation),
//!   2. derives and prints the [`WasmCapabilityClaim`] for the adapter->compute
//!      graph and for the clock-importing component, and
//!   3. instantiates and invokes the standalone compute component over in-memory
//!      input, printing input and output.
//!
//! Step 3 exercises wasmtime component instantiation; if its API needs a tweak
//! it fails independently of steps 1-2 (the novel derivation logic).

use anyhow::Result;
use cfc_wasm_capability::proto::composition_graph::Edge;
use cfc_wasm_capability::{derive_claim, ComponentInput};
use wasmtime::component::types::ComponentItem;
use wasmtime::component::{Component, Linker, Val};
use wasmtime::{Engine, Store};

const COMPUTE: &[u8] = include_bytes!("../testdata/compute.wasm");
const ADAPTER: &[u8] = include_bytes!("../testdata/adapter.wasm");
const COMPUTE_CLOCK: &[u8] = include_bytes!("../testdata/compute_clock.wasm");

const COMPUTE_IFACE: &str = "cfc:transform/compute@0.1.0";

fn main() -> Result<()> {
    let engine = Engine::default();

    println!("== 1. component introspection ==");
    for (name, bytes) in [
        ("compute", COMPUTE),
        ("adapter", ADAPTER),
        ("compute_clock", COMPUTE_CLOCK),
    ] {
        print_interface(&engine, name, bytes)?;
    }

    println!("\n== 2. derived capability claims ==");
    let graph_components = [
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
    let graph_claim = derive_claim(&graph_components, &edges)?;
    println!("\n-- adapter->compute graph --\n{graph_claim:#?}");

    let clock_claim = derive_claim(
        &[ComponentInput {
            id: "clock".to_string(),
            role: "private_computation".to_string(),
            bytes: COMPUTE_CLOCK,
        }],
        &[],
    )?;
    println!("\n-- compute_clock --\n{clock_claim:#?}");

    println!("\n== 3. run standalone compute component ==");
    // Input: two little-endian u32s (1 and 2); expected output: u32 3.
    let input: Vec<u8> = [1u32, 2u32].iter().flat_map(|v| v.to_le_bytes()).collect();
    let output = run_compute(&engine, COMPUTE, &input)?;
    println!("input  = {input:?}");
    println!("output = {output:?}");
    let sum = u32::from_le_bytes(output.as_slice().try_into().unwrap_or([0; 4]));
    println!("decoded sum = {sum} (expected 3)");
    assert_eq!(sum, 3, "compute component returned an unexpected sum");

    println!("\nselftest OK");
    Ok(())
}

/// Print the resolved import/export interface names of a component.
fn print_interface(engine: &Engine, name: &str, bytes: &[u8]) -> Result<()> {
    let component = Component::new(engine, bytes)?;
    let ty = component.component_type();
    println!("\n[{name}]");
    for (import_name, item) in ty.imports(engine) {
        println!("  import  {import_name}  ({})", item_kind(&item));
    }
    for (export_name, item) in ty.exports(engine) {
        println!("  export  {export_name}  ({})", item_kind(&item));
    }
    Ok(())
}

fn item_kind(item: &ComponentItem) -> &'static str {
    match item {
        ComponentItem::ComponentFunc(_) => "func",
        ComponentItem::CoreFunc(_) => "core-func",
        ComponentItem::Module(_) => "module",
        ComponentItem::Component(_) => "component",
        ComponentItem::ComponentInstance(_) => "instance",
        ComponentItem::Type(_) => "type",
        ComponentItem::Resource(_) => "resource",
    }
}

/// Instantiate the standalone compute component and invoke
/// `cfc:transform/compute#transform` over `input`, returning the output bytes.
/// Uses the dynamic `Val` API so no build-time bindgen is required.
fn run_compute(engine: &Engine, bytes: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    let component = Component::new(engine, bytes)?;
    let linker: Linker<()> = Linker::new(engine);
    let mut store = Store::new(engine, ());
    let instance = linker.instantiate(&mut store, &component)?;

    // Navigate to the exported interface instance, then its `transform` func.
    let iface = instance
        .get_export(&mut store, None, COMPUTE_IFACE)
        .ok_or_else(|| anyhow::anyhow!("missing exported interface {COMPUTE_IFACE}"))?;
    let func_idx = instance
        .get_export(&mut store, Some(&iface), "transform")
        .ok_or_else(|| anyhow::anyhow!("missing exported func transform"))?;
    let func = instance
        .get_func(&mut store, func_idx)
        .ok_or_else(|| anyhow::anyhow!("transform export is not a function"))?;

    let params = [Val::List(input.iter().map(|b| Val::U8(*b)).collect())];
    let mut results = [Val::Bool(false)];
    func.call(&mut store, &params, &mut results)?;
    func.post_return(&mut store)?;

    match &results[0] {
        Val::List(items) => Ok(items
            .iter()
            .map(|v| match v {
                Val::U8(b) => *b,
                _ => 0,
            })
            .collect()),
        other => anyhow::bail!("unexpected result value: {other:?}"),
    }
}
