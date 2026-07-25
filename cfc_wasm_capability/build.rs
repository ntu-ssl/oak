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

//! Generates prost bindings for the CFC wasm capability claim schema.
//!
//! The proto is self-contained (proto3, no imports), so this is a minimal
//! prost-build invocation. `PROTOC` is supplied by the Bazel
//! `cargo_build_script` rule via `build_script_env`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = prost_build::Config::new();
    // Deterministic map ordering, matching oak's convention.
    config.btree_map(["."]);
    config.compile_protos(
        &["proto/wasm_capability.proto", "proto/wasm_workload_config.proto"],
        &["proto"],
    )?;
    Ok(())
}
