# cfc_wasm_capability (Phase 1a)

Shared library that statically derives a **capability claim**
(`fcp.confidentialcompute.WasmCapabilityClaim`) from the binaries of a confined
WebAssembly component composition. This is the de-risk target for the CFC
capability-based-wasm work: it validates the wasmtime + Component Model + WASI
0.2 toolchain inside the oak workspace and the capability-derivation logic,
before any orchestrator/system-image changes (Phase 1b).

## Layout

```
proto/wasm_capability.proto   CFC-owned claim schema (package fcp.confidentialcompute)
src/lib.rs                    crate root; re-exports; generated proto module
src/capability.rs             derivation logic + fixture-free unit tests
selftest/cap_host_selftest.rs `bazel run` binary: introspect + derive + run
tests/fixtures.rs             integration tests over the real .wasm fixtures
testdata/*.wasm               checked-in component fixtures (built out-of-band)
testdata/guest/               guest crates + WIT + build.sh that produce them
```

## Derivation model

* Each component is loaded with `wasmtime::component::Component::new` (core
  modules are rejected). Nothing in the guest executes.
* The resolved import tree (`Component::component_type().imports()`) is the
  source of truth. An imported interface is either:
  * satisfied by a declared **graph edge** → intra-composition wiring, recorded
    in the graph, never ambient authority; or
  * **host-provided** → recorded as a `GrantedWasiCapability`, and if it is a
    known WASI ambient-authority interface it flips the matching
    `RuntimeProperties` field to `GRANTED`.
* Every `RuntimeProperties` field defaults to `DENIED` (absence of an import
  means the guest structurally cannot call it). `UNKNOWN` is never emitted by
  derivation; it exists only for the KMS to reject malformed claims.

## Fixture build target: `wasm32-unknown-unknown`, not `wasm32-wasip1`

The toy components are built for **`wasm32-unknown-unknown`** (see
`testdata/guest/build.sh`). This matters for the capability model:
`cargo component`'s default `wasm32-wasip1` target splices in the
preview1->preview2 adapter, which makes *even a trivial pure function* import
the entire `wasi:cli` / `wasi:io` / `wasi:filesystem` / `wasi:clocks` surface.
Targeting `wasm32-unknown-unknown` yields a component that imports **exactly**
what its WIT world declares — nothing for `compute`, only
`wasi:clocks/wall-clock` for `compute_clock`. That is the confinement the
capability claim is meant to attest, and it is a constraint the Phase 1b
orchestrator build of real workloads must honor (or the claim will faithfully
report broad ambient authority).

## Building and testing

Host crate + fixture-free unit tests (no guest toolchain needed):

```
bazel build //cfc_wasm_capability:cfc_wasm_capability
bazel test  //cfc_wasm_capability:cfc_wasm_capability_test
```

The fixtures for `fixtures_test` and `cap_host_selftest` are built out-of-band
(they need `cargo-component`); see `testdata/guest/build.sh`. After the `.wasm`
files exist in `testdata/`:

```
bazel run  //cfc_wasm_capability:cap_host_selftest
bazel test //cfc_wasm_capability:fixtures_test
```

`cap_host_selftest` prints each component's resolved imports/exports — use that
output to confirm the exact interface strings (e.g. the adapter's import of
`cfc:transform/compute@0.1.0`) if a fixture test needs the constant adjusted.