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

//! Orchestrator-hosted confined WebAssembly workload mode.
//!
//! When the (measured) application config selects `WORKLOAD_KIND_WASM`, the
//! orchestrator runs a wasm component composition itself instead of handing a
//! runc bundle to the container runtime. The components are never fused: each
//! runs as its own instance and the orchestrator mediates every edge (Phase
//! 1b-B3 data plane). This module owns:
//!
//!   * decoding the workload-kind envelope from the application config;
//!   * deriving the [`WasmCapabilityClaim`] from the bundle's component bytes so
//!     the orchestrator can attest it (Phase 1b-B2, this file);
//!   * running the composition over the data plane (Phase 1b-B3).

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::Read,
};

use anyhow::{bail, Context, Result};
use bytes::Buf;
use cfc_wasm_capability::{
    derive_claim_from_loaded,
    proto::{
        composition_graph::Edge, orchestrator_workload_config::WorkloadKind,
        OrchestratorWorkloadConfig, WasmWorkloadConfig,
    },
    LoadedComponent,
};
use prost::Message;
use wasmtime::{
    component::{types::ComponentItem, Component, Func, Instance, Linker, Val},
    Engine, Store,
};

/// Decodes the workload-selection envelope from the launcher-provided
/// application config.
///
/// Lenient by design: arbitrary legacy container-config bytes that do not decode
/// as this envelope decode to the default (`WORKLOAD_KIND_UNSPECIFIED`), so
/// [`wasm_config`] returns `None` and the caller runs the existing container
/// path over the original raw bytes.
pub fn decode_workload_config(application_config: &[u8]) -> OrchestratorWorkloadConfig {
    OrchestratorWorkloadConfig::decode(application_config).unwrap_or_default()
}

/// Returns the wasm workload configuration iff this config selects wasm mode.
pub fn wasm_config(config: &OrchestratorWorkloadConfig) -> Option<&WasmWorkloadConfig> {
    if config.workload_kind() == WorkloadKind::Wasm {
        config.wasm.as_ref()
    } else {
        None
    }
}

/// Runs the confined wasm composition over the data plane.
///
/// A loaded, instantiated wasm component composition, ready to be driven over the
/// data plane.
///
/// The components are **never fused**: each is its own instance in a single
/// [`Store`], and the orchestrator (the trusted host) sits on every edge. Each
/// component's [`Linker`] is populated only with (a) the exports of its declared
/// producers (host-mediated wiring) and (b) *nothing else* — no ambient WASI —
/// so any unsatisfied import is a forbidden capability and instantiation fails
/// closed. That absence is exactly what the capability claim attests.
///
/// The capability claim is derived from the same compiled components used to run
/// (compile once), so what is attested is exactly what executes.
pub struct Composition {
    store: Store<()>,
    entry: Func,
    // Canonical encoding of the derived WasmCapabilityClaim (opaque to Oak;
    // embedded in the WasmWorkloadLayerData event).
    claim_bytes: Vec<u8>,
    // Retained so the compiled components (Arc-backed) outlive the instances that
    // the `store` holds. Never read directly.
    _components: BTreeMap<String, Component>,
}

impl Composition {
    /// Unpacks the bundle tar once, then [`load`s](Self::load) the composition.
    pub fn load_bundle<B: Buf>(wasm: &WasmWorkloadConfig, bundle: B) -> Result<Self> {
        let files = unpack_bundle(bundle).context("couldn't unpack wasm workload bundle")?;
        Self::load(wasm, &files)
    }

    /// The canonical encoding of the derived capability claim.
    pub fn claim_bytes(&self) -> &[u8] {
        &self.claim_bytes
    }

    /// Compiles every component from `files` **once**, derives the capability
    /// claim from those compiled components, then instantiates them in dependency
    /// order with host-mediated edges and resolves the entry function.
    pub fn load(wasm: &WasmWorkloadConfig, files: &BTreeMap<String, Vec<u8>>) -> Result<Self> {
        let engine = Engine::default();

        // Compile every component once (also rejects core modules).
        let mut components: BTreeMap<String, Component> = BTreeMap::new();
        for c in &wasm.components {
            let bytes = lookup(files, &c.path).with_context(|| {
                format!("component '{}' not found in bundle at path '{}'", c.id, c.path)
            })?;
            let component = Component::new(&engine, bytes)
                .with_context(|| format!("loading component '{}'", c.id))?;
            components.insert(c.id.clone(), component);
        }

        // Derive the capability claim from the same compiled components (no
        // recompile), so the attested claim describes exactly what will run.
        let edges: Vec<Edge> = wasm
            .edges
            .iter()
            .map(|e| Edge {
                from: e.from.clone(),
                to: e.to.clone(),
                interface: e.interface.clone(),
            })
            .collect();
        let claim_bytes = {
            let loaded = wasm
                .components
                .iter()
                .map(|c| {
                    Ok(LoadedComponent {
                        id: c.id.clone(),
                        role: c.role.clone(),
                        bytes: lookup(files, &c.path).context("component bytes missing")?,
                        component: components.get(&c.id).context("component not compiled")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            derive_claim_from_loaded(&engine, &loaded, &edges)
                .context("wasm capability derivation failed")?
                .encode_to_vec()
            // `loaded` (which borrows `components`) is dropped here, before the
            // instantiation loop and the final move of `components`.
        };

        let mut store = Store::new(&engine, ());
        let mut instances: BTreeMap<String, Instance> = BTreeMap::new();

        for id in topo_order(wasm)? {
            let component = components.get(&id).context("component missing after ordering")?;
            let mut linker: Linker<()> = Linker::new(&engine);

            // Satisfy this component's inter-component imports from already
            // instantiated producers. Edges whose producer is not a component
            // (external "" input endpoint) are supplied by the data plane, not
            // linked here.
            for edge in wasm.edges.iter().filter(|e| e.to == id) {
                let producer_id = edge.from.as_str();
                let Some(producer_instance) = instances.get(producer_id).copied() else {
                    continue;
                };
                let producer_component =
                    components.get(producer_id).context("producer component missing")?;

                let iface_export = producer_instance
                    .get_export(&mut store, None, &edge.interface)
                    .with_context(|| {
                        format!(
                            "producer '{producer_id}' does not export interface '{}'",
                            edge.interface
                        )
                    })?;
                let mut linker_iface = linker
                    .instance(&edge.interface)
                    .with_context(|| format!("defining import interface '{}'", edge.interface))?;

                for func_name in interface_funcs(&engine, producer_component, &edge.interface)? {
                    let func_export = producer_instance
                        .get_export(&mut store, Some(&iface_export), &func_name)
                        .with_context(|| {
                            format!("producer '{producer_id}' missing export '{func_name}'")
                        })?;
                    let producer_func =
                        producer_instance.get_func(&mut store, func_export).with_context(|| {
                            format!("producer export '{func_name}' is not a function")
                        })?;
                    // Host-configured forwarding: when the consumer calls this
                    // import, the host invokes the producer's export and passes
                    // its result straight back (same value types).
                    linker_iface.func_new(&func_name, move |mut store, params, results| {
                        producer_func.call(&mut store, params, results)?;
                        producer_func.post_return(&mut store)?;
                        Ok(())
                    })?;
                }
            }

            let instance = linker.instantiate(&mut store, component).with_context(|| {
                format!(
                    "instantiating component '{id}' (an unsatisfied import means it requires \
                     ambient authority the confined runtime does not grant)"
                )
            })?;
            instances.insert(id, instance);
        }

        // Resolve the entry function.
        let entry_instance = instances
            .get(&wasm.entry_component)
            .copied()
            .with_context(|| format!("entry component '{}' not found", wasm.entry_component))?;
        let entry_iface = entry_instance
            .get_export(&mut store, None, &wasm.entry_interface)
            .with_context(|| format!("entry interface '{}' not exported", wasm.entry_interface))?;
        let entry_export = entry_instance
            .get_export(&mut store, Some(&entry_iface), &wasm.entry_function)
            .with_context(|| format!("entry function '{}' not exported", wasm.entry_function))?;
        let entry = entry_instance
            .get_func(&mut store, entry_export)
            .context("entry export is not a function")?;

        Ok(Self { store, entry, claim_bytes, _components: components })
    }

    /// Drives the composition over the data plane.
    ///
    /// Phase 1b-B3.1: run a fixed probe over the composition to prove
    /// host-mediated, in-enclave execution, then keep the process alive (evidence
    /// has been sent; exiting would tear down the VM). Phase 1b-B3.2 replaces the
    /// probe with the plaintext-loopback data plane, and B3.3 with the full
    /// ConfidentialTransform server.
    pub async fn serve(mut self) -> Result<()> {
        // The toy compute sums the input as little-endian u32s, so [1, 2] -> 3.
        let probe: Vec<u8> = [1u32, 2u32].iter().flat_map(|v| v.to_le_bytes()).collect();
        let output = self.invoke(&probe).context("wasm composition self-check failed")?;
        log::info!("wasm composition self-check ok: {probe:?} -> {output:?}");
        log::info!("wasm workload running; data-plane I/O lands in Phase 1b-B3.2");

        std::future::pending::<()>().await;
        Ok(())
    }

    /// Invokes the entry function over `input`, returning the output bytes.
    ///
    /// Targets the `list<u8> -> list<u8>` transform shape (single list result);
    /// other signatures are a later generalization.
    pub fn invoke(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let params = [Val::List(input.iter().map(|b| Val::U8(*b)).collect())];
        let mut results = [Val::Bool(false)];
        self.entry.call(&mut self.store, &params, &mut results)?;
        self.entry.post_return(&mut self.store)?;
        match &results[0] {
            Val::List(items) => Ok(items
                .iter()
                .map(|v| match v {
                    Val::U8(b) => *b,
                    _ => 0,
                })
                .collect()),
            other => bail!("entry function returned an unexpected value: {other:?}"),
        }
    }
}

/// Returns the names of the functions exported by `interface` on `component`.
fn interface_funcs(engine: &Engine, component: &Component, interface: &str) -> Result<Vec<String>> {
    let component_type = component.component_type();
    for (name, item) in component_type.exports(engine) {
        if name == interface {
            return match item {
                ComponentItem::ComponentInstance(inst) => Ok(inst
                    .exports(engine)
                    .filter_map(|(fname, it)| {
                        matches!(it, ComponentItem::ComponentFunc(_)).then(|| fname.to_string())
                    })
                    .collect()),
                _ => bail!("export '{interface}' is not an interface instance"),
            };
        }
    }
    bail!("component does not export interface '{interface}'")
}

/// Orders component ids so every producer precedes its consumers.
fn topo_order(wasm: &WasmWorkloadConfig) -> Result<Vec<String>> {
    let ids: BTreeSet<&str> = wasm.components.iter().map(|c| c.id.as_str()).collect();
    let mut indegree: BTreeMap<&str, usize> = ids.iter().map(|id| (*id, 0usize)).collect();
    let mut successors: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for edge in &wasm.edges {
        // Only edges between two real components constrain instantiation order;
        // external endpoints ("") are data-plane I/O, not components.
        if ids.contains(edge.from.as_str()) && ids.contains(edge.to.as_str()) {
            successors.entry(edge.from.as_str()).or_default().push(edge.to.as_str());
            *indegree.get_mut(edge.to.as_str()).expect("id present") += 1;
        }
    }

    let mut queue: VecDeque<&str> =
        indegree.iter().filter(|(_, d)| **d == 0).map(|(id, _)| *id).collect();
    let mut order = Vec::with_capacity(ids.len());
    while let Some(id) = queue.pop_front() {
        order.push(id.to_string());
        for next in successors.get(id).into_iter().flatten() {
            let d = indegree.get_mut(next).expect("id present");
            *d -= 1;
            if *d == 0 {
                queue.push_back(next);
            }
        }
    }
    if order.len() != ids.len() {
        bail!("composition graph has a cycle");
    }
    Ok(order)
}

/// Reads every regular file in the bundle tar into memory, keyed by normalized
/// path.
pub fn unpack_bundle<B: Buf>(bundle: B) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut archive = tar::Archive::new(bundle.reader());
    let mut files = BTreeMap::new();
    for entry in archive.entries().context("reading bundle entries")? {
        let mut entry = entry.context("reading bundle entry")?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry
            .path()
            .context("reading bundle entry path")?
            .to_string_lossy()
            .into_owned();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).context("reading bundle entry bytes")?;
        files.insert(normalize(&path), buf);
    }
    Ok(files)
}

/// Looks up a component by its configured path, tolerating a leading `./`.
pub fn lookup<'a>(files: &'a BTreeMap<String, Vec<u8>>, path: &str) -> Option<&'a [u8]> {
    files.get(&normalize(path)).map(Vec::as_slice)
}

fn normalize(path: &str) -> String {
    path.trim_start_matches("./").trim_start_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use cfc_wasm_capability::proto::{
        orchestrator_workload_config::WorkloadKind, OrchestratorWorkloadConfig, WasmComponentRef,
        WasmWorkloadConfig,
    };
    use prost::Message;

    use super::*;

    #[test]
    fn arbitrary_bytes_decode_to_container_path() {
        // Bytes that are not our envelope must not be mistaken for a wasm
        // workload. (Even if they happen to decode, kind != WASM => None.)
        let cfg = decode_workload_config(b"\x0a\x05hello-not-a-real-config");
        assert!(wasm_config(&cfg).is_none());
    }

    #[test]
    fn empty_config_is_container_path() {
        let cfg = decode_workload_config(&[]);
        assert_eq!(cfg.workload_kind(), WorkloadKind::Unspecified);
        assert!(wasm_config(&cfg).is_none());
    }

    #[test]
    fn wasm_kind_envelope_selects_wasm() {
        let envelope = OrchestratorWorkloadConfig {
            workload_kind: WorkloadKind::Wasm as i32,
            wasm: Some(WasmWorkloadConfig {
                components: vec![WasmComponentRef {
                    id: "compute".into(),
                    role: "compute".into(),
                    path: "compute.wasm".into(),
                }],
                edges: vec![],
                entry_component: "compute".into(),
                entry_interface: "cfc:transform/compute@0.1.0".into(),
                entry_function: "transform".into(),
            }),
        };
        let bytes = envelope.encode_to_vec();

        let cfg = decode_workload_config(&bytes);
        let wasm = wasm_config(&cfg).expect("wasm workload selected");
        assert_eq!(wasm.components.len(), 1);
        assert_eq!(wasm.entry_function, "transform");
    }

    #[test]
    fn container_kind_stays_on_container_path() {
        let envelope = OrchestratorWorkloadConfig {
            workload_kind: WorkloadKind::Container as i32,
            wasm: None,
        };
        let cfg = decode_workload_config(&envelope.encode_to_vec());
        assert!(wasm_config(&cfg).is_none());
    }
}
