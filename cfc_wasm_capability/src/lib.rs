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

//! CFC wasm capability derivation.
//!
//! This crate statically derives a capability claim
//! ([`proto::WasmCapabilityClaim`]) from the binaries of a confined WebAssembly
//! component composition. It is the shared library that Phase 1a's selftest and
//! Phase 1b's orchestrator wasm mode both call; the CFC KMS reuses the same
//! canonical encoders (application commitment, graph) when it later evaluates
//! the claim.

/// Generated prost types for the `fcp.confidentialcompute` capability schema.
pub mod proto {
    #![allow(clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/fcp.confidentialcompute.rs"));
}

pub mod capability;

pub use capability::{
    derive_claim, derive_claim_from_loaded, derive_claim_with_engine, ComponentInput,
    LoadedComponent, COMMITMENT_TAG, SCHEMA_VERSION, WASI_VERSION,
};
