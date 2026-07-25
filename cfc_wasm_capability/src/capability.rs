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

//! Static derivation of a [`WasmCapabilityClaim`] from wasm component binaries.
//!
//! The derivation is purely static: it loads each component with wasmtime,
//! reads the *resolved* import/export type tree via
//! [`wasmtime::component::Component::component_type`], and maps imported WASI
//! interfaces to capabilities. Nothing in the guest executes. Absence of an
//! import means the guest structurally cannot call that interface, so the
//! corresponding runtime property is reported `DENIED` (never `UNKNOWN`).

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use wasmtime::component::types::ComponentItem;
use wasmtime::component::Component;
use wasmtime::Engine;

use crate::proto::{
    composition_graph::Edge, granted_wasi_capability::Provenance, runtime_properties::Enforcement,
    ComponentClaim, CompositionGraph, GrantedWasiCapability, RuntimeProperties, WasmCapabilityClaim,
    WasmRuntimeInfo,
};

/// Schema identifier emitted in every claim; the KMS rejects anything else.
pub const SCHEMA_VERSION: &str = "cfc-wasm-claim-v1";
/// Domain-separation tag for the application commitment preimage.
pub const COMMITMENT_TAG: &str = "cfc-wasm-commit-v1";
/// WASI version this derivation targets.
pub const WASI_VERSION: &str = "0.2.x";
/// The wasmtime engine version, pinned in `bazel/crates/oak_crates.bzl`. Kept in
/// sync manually with that spec (there is no compile-time accessor for it).
pub const ENGINE_VERSION: &str = "25.0.3";

/// One component to be analyzed, with its logical manifest identity.
pub struct ComponentInput<'a> {
    /// Logical name from the manifest (stable across builds).
    pub id: String,
    /// Role from the manifest, e.g. "public_input_adapter".
    pub role: String,
    /// Exact component binary bytes (as instantiated).
    pub bytes: &'a [u8],
}

/// Derive a [`WasmCapabilityClaim`] over the given components and wiring.
///
/// `edges` describes host-mediated wiring between components plus the
/// distinguished external input/output endpoints (`from`/`to` == "" mean
/// external). It comes from the manifest and is trusted only as a hint here;
/// every component import is still checked against the resolved type tree.
pub fn derive_claim(
    components: &[ComponentInput<'_>],
    edges: &[Edge],
) -> Result<WasmCapabilityClaim> {
    let engine = Engine::default();
    derive_claim_with_engine(&engine, components, edges)
}

/// As [`derive_claim`], but reusing a caller-provided [`Engine`] (the
/// orchestrator instantiates against the same engine it analyzes with).
pub fn derive_claim_with_engine(
    engine: &Engine,
    components: &[ComponentInput<'_>],
    edges: &[Edge],
) -> Result<WasmCapabilityClaim> {
    if components.is_empty() {
        bail!("a composition must contain at least one component");
    }

    // Compile each component once (also rejects core modules).
    let compiled = components
        .iter()
        .map(|input| {
            Component::new(engine, input.bytes).with_context(|| {
                format!(
                    "loading component '{}' as a WASI 0.2 component (core modules are rejected)",
                    input.id
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let loaded: Vec<LoadedComponent<'_>> = components
        .iter()
        .zip(compiled.iter())
        .map(|(input, component)| LoadedComponent {
            id: input.id.clone(),
            role: input.role.clone(),
            bytes: input.bytes,
            component,
        })
        .collect();

    derive_claim_from_loaded(engine, &loaded, edges)
}

/// A component that the caller has already compiled, letting derivation reuse it
/// (e.g. the orchestrator compiles once and both derives the claim and runs the
/// composition from the same [`Component`]).
pub struct LoadedComponent<'a> {
    /// Logical name from the manifest.
    pub id: String,
    /// Role from the manifest.
    pub role: String,
    /// Exact component binary bytes (hashed into the component digest).
    pub bytes: &'a [u8],
    /// The compiled component (introspected for its resolved import tree).
    pub component: &'a Component,
}

/// As [`derive_claim_with_engine`], but over already-compiled components so the
/// caller avoids recompiling. `bytes` is still required for the component digest.
pub fn derive_claim_from_loaded(
    engine: &Engine,
    components: &[LoadedComponent<'_>],
    edges: &[Edge],
) -> Result<WasmCapabilityClaim> {
    if components.is_empty() {
        bail!("a composition must contain at least one component");
    }

    let mut component_claims = Vec::with_capacity(components.len());
    let mut granted = Vec::new();
    // Start every ambient-authority property DENIED. A property is flipped to
    // GRANTED only when a matching interface import is structurally present.
    let mut props = RuntimeProperties {
        network: Enforcement::Denied as i32,
        persistent_storage: Enforcement::Denied as i32,
        wall_clock: Enforcement::Denied as i32,
        randomness: Enforcement::Denied as i32,
        environment: Enforcement::Denied as i32,
        spawn: Enforcement::Denied as i32,
    };

    for input in components {
        // Iterate the resolved import tree. Interface imports surface as
        // `ComponentInstance` whose name is the fully-qualified WIT interface
        // id (e.g. "wasi:clocks/wall-clock@0.2.0"); that resolved name is the
        // source of truth for capability derivation, not the manifest.
        let ty = input.component.component_type();
        for (import_name, item) in ty.imports(engine) {
            if let ComponentItem::ComponentInstance(_) = item {
                // An import satisfied by a declared edge is intra-composition
                // wiring (this component is fed by another component). That is
                // captured in the graph, not counted as host-granted ambient
                // authority, and it never flips a runtime property: calling
                // another confined component is not ambient authority.
                let mediated = edges
                    .iter()
                    .any(|e| e.to == input.id && e.interface == import_name);
                if mediated {
                    continue;
                }
                // Otherwise the import must be satisfied by the host. Only
                // host-provided imports represent real ambient authority.
                if let Some(property) = classify_interface(import_name) {
                    set_granted(&mut props, property);
                }
                granted.push(GrantedWasiCapability {
                    interface: import_name.to_string(),
                    component_id: input.id.clone(),
                    operations: Vec::new(),
                    resources: Vec::new(),
                    provenance: Provenance::HostProvided as i32,
                });
            }
        }

        component_claims.push(ComponentClaim {
            id: input.id.clone(),
            role: input.role.clone(),
            digest: sha256(input.bytes).to_vec(),
            confidential: false,
        });
    }

    // Canonicalize the graph: nodes sorted byte-wise, edges sorted by
    // (from, to, interface).
    let mut nodes: Vec<String> = component_claims.iter().map(|c| c.id.clone()).collect();
    nodes.sort();
    let mut sorted_edges = edges.to_vec();
    sorted_edges.sort_by(|a, b| {
        (&a.from, &a.to, &a.interface).cmp(&(&b.from, &b.to, &b.interface))
    });
    let graph = CompositionGraph { nodes, edges: sorted_edges };

    // Canonicalize granted capabilities for a stable commitment.
    granted.sort_by(|a, b| {
        (&a.interface, &a.component_id).cmp(&(&b.interface, &b.component_id))
    });

    let runtime_info = WasmRuntimeInfo {
        engine: "wasmtime".to_string(),
        engine_version: ENGINE_VERSION.to_string(),
        wasi_version: WASI_VERSION.to_string(),
        component_model: true,
        dynamic_loading: false,
    };

    let application_commitment =
        commitment(&component_claims, &graph, &granted, &runtime_info).to_vec();

    Ok(WasmCapabilityClaim {
        schema_version: SCHEMA_VERSION.to_string(),
        application_commitment,
        runtime_info: Some(runtime_info),
        graph: Some(graph),
        components: component_claims,
        granted_capabilities: granted,
        runtime_properties: Some(props),
    })
}

/// Map a fully-qualified WASI interface id to the coarse runtime property it
/// grants, or `None` if it is not an ambient-authority interface.
fn classify_interface(interface: &str) -> Option<RuntimeProperty> {
    // Strip any "@version" suffix, then match on the "ns:pkg/iface" head.
    let head = interface.split('@').next().unwrap_or(interface);
    if head.starts_with("wasi:sockets/") {
        Some(RuntimeProperty::Network)
    } else if head.starts_with("wasi:filesystem/") {
        Some(RuntimeProperty::PersistentStorage)
    } else if head == "wasi:clocks/wall-clock" {
        Some(RuntimeProperty::WallClock)
    } else if head.starts_with("wasi:random/") {
        Some(RuntimeProperty::Randomness)
    } else if head == "wasi:cli/environment" {
        Some(RuntimeProperty::Environment)
    } else if head.starts_with("wasi:threads/") {
        Some(RuntimeProperty::Spawn)
    } else {
        None
    }
}

#[derive(Clone, Copy)]
enum RuntimeProperty {
    Network,
    PersistentStorage,
    WallClock,
    Randomness,
    Environment,
    Spawn,
}

fn set_granted(props: &mut RuntimeProperties, property: RuntimeProperty) {
    let granted = Enforcement::Granted as i32;
    match property {
        RuntimeProperty::Network => props.network = granted,
        RuntimeProperty::PersistentStorage => props.persistent_storage = granted,
        RuntimeProperty::WallClock => props.wall_clock = granted,
        RuntimeProperty::Randomness => props.randomness = granted,
        RuntimeProperty::Environment => props.environment = granted,
        RuntimeProperty::Spawn => props.spawn = granted,
    }
}

/// Compute the application commitment (overall plan section 6).
///
/// SHA-256 over the domain tag, then for each component sorted by id:
/// len-prefixed id, role, and binary digest; then the canonical graph
/// encoding; then the canonical granted-capability encoding; then the runtime
/// config. All variable-length fields are length-prefixed to avoid ambiguity.
fn commitment(
    components: &[ComponentClaim],
    graph: &CompositionGraph,
    granted: &[GrantedWasiCapability],
    runtime_info: &WasmRuntimeInfo,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(COMMITMENT_TAG.as_bytes());

    let mut sorted: Vec<&ComponentClaim> = components.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    for c in sorted {
        update_bytes(&mut h, c.id.as_bytes());
        update_bytes(&mut h, c.role.as_bytes());
        update_bytes(&mut h, &c.digest);
    }

    // Canonical graph encoding.
    update_len(&mut h, graph.nodes.len());
    for node in &graph.nodes {
        update_bytes(&mut h, node.as_bytes());
    }
    update_len(&mut h, graph.edges.len());
    for e in &graph.edges {
        update_bytes(&mut h, e.from.as_bytes());
        update_bytes(&mut h, e.to.as_bytes());
        update_bytes(&mut h, e.interface.as_bytes());
    }

    // Canonical granted-capability encoding.
    update_len(&mut h, granted.len());
    for g in granted {
        update_bytes(&mut h, g.interface.as_bytes());
        update_bytes(&mut h, g.component_id.as_bytes());
    }

    // Runtime config.
    update_bytes(&mut h, runtime_info.engine.as_bytes());
    update_bytes(&mut h, runtime_info.engine_version.as_bytes());
    update_bytes(&mut h, runtime_info.wasi_version.as_bytes());

    h.finalize().into()
}

fn update_len(h: &mut Sha256, len: usize) {
    h.update((len as u64).to_le_bytes());
}

fn update_bytes(h: &mut Sha256, bytes: &[u8]) {
    update_len(h, bytes.len());
    h.update(bytes);
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Bytes of an empty *core* wasm module: magic || version=1, layer=0.
    // `Component::new` must reject this (it is not a component).
    const EMPTY_CORE_MODULE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    fn granted(enforcement: i32) -> bool {
        enforcement == Enforcement::Granted as i32
    }

    #[test]
    fn empty_composition_is_rejected() {
        assert!(derive_claim(&[], &[]).is_err());
    }

    #[test]
    fn core_module_is_rejected() {
        let input = ComponentInput {
            id: "core".to_string(),
            role: "compute".to_string(),
            bytes: &EMPTY_CORE_MODULE[..],
        };
        let err = derive_claim(&[input], &[]).expect_err("core module must be rejected");
        // The error should mention the component-load failure context.
        assert!(format!("{err:#}").contains("component"));
    }

    #[test]
    fn classify_maps_each_ambient_interface() {
        assert!(matches!(
            classify_interface("wasi:sockets/tcp@0.2.0"),
            Some(RuntimeProperty::Network)
        ));
        assert!(matches!(
            classify_interface("wasi:filesystem/types@0.2.0"),
            Some(RuntimeProperty::PersistentStorage)
        ));
        assert!(matches!(
            classify_interface("wasi:clocks/wall-clock@0.2.0"),
            Some(RuntimeProperty::WallClock)
        ));
        assert!(matches!(
            classify_interface("wasi:random/random@0.2.0"),
            Some(RuntimeProperty::Randomness)
        ));
        assert!(matches!(
            classify_interface("wasi:cli/environment@0.2.0"),
            Some(RuntimeProperty::Environment)
        ));
        assert!(matches!(
            classify_interface("wasi:threads/threads@0.2.0"),
            Some(RuntimeProperty::Spawn)
        ));
    }

    #[test]
    fn classify_strips_version_and_ignores_non_ambient() {
        // Version suffix must not affect classification.
        assert!(matches!(
            classify_interface("wasi:clocks/wall-clock@0.2.3"),
            Some(RuntimeProperty::WallClock)
        ));
        // monotonic-clock is a clock package but not wall-clock: not ambient
        // authority we track as wall_clock.
        assert!(classify_interface("wasi:clocks/monotonic-clock@0.2.0").is_none());
        // Inter-component wiring interfaces are never ambient authority.
        assert!(classify_interface("cfc:transform/compute@0.1.0").is_none());
    }

    #[test]
    fn set_granted_flips_only_the_named_property() {
        let mut props = RuntimeProperties {
            network: Enforcement::Denied as i32,
            persistent_storage: Enforcement::Denied as i32,
            wall_clock: Enforcement::Denied as i32,
            randomness: Enforcement::Denied as i32,
            environment: Enforcement::Denied as i32,
            spawn: Enforcement::Denied as i32,
        };
        set_granted(&mut props, RuntimeProperty::WallClock);
        assert!(granted(props.wall_clock));
        assert!(!granted(props.network));
        assert!(!granted(props.persistent_storage));
        assert!(!granted(props.randomness));
        assert!(!granted(props.environment));
        assert!(!granted(props.spawn));
    }
}