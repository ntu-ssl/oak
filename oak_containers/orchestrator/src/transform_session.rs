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

//! Orchestrator-side driver for a ConfidentialTransform **session** implemented
//! in wasm.
//!
//! This is the wasm counterpart of the C++ `Session` subclass split: the
//! orchestrator (the trusted base — gRPC, HPKE, KMS) drives the wasm
//! `session` business logic (`configure`/`write`/`commit`/`finalize`) and
//! provides the `context` capability the wasm imports to emit results. The wasm
//! never holds keys or a socket; it hands the host plaintext to emit, and the
//! host (later, B3.3) encrypts.
//!
//! B3.2 (this file) wires the plaintext path: `write` receives plaintext,
//! `emit-unencrypted` collects a plaintext output blob. The `emit-encrypted` /
//! `emit-releasable` host functions are declared and record their blobs, but the
//! actual HPKE/KMS crypto is deferred to B3.3.

use anyhow::{bail, Context, Result};
use cfc_wasm_capability::proto::{RandomGrant, StdioGrant, WasiRuntimeGrant};
use wasmtime::{
    component::{Component, Func, Linker, Val},
    Engine, Store,
};
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiView};

/// WIT interface ids (see `testdata/guest/wit/transform.wit`).
pub const SESSION_IFACE: &str = "cfc:transform/session@0.1.0";
const CONTEXT_IFACE: &str = "cfc:transform/context@0.1.0";

/// The exact WASI grant the confined session runtime enforces: deny-all except
/// the clock and a secure RNG (which wasmtime-wasi always provides and which
/// std-based compute genuinely needs). This is the **single source of truth**:
/// it both builds the `WasiCtx` (via [`build_wasi_ctx`]) and is embedded into the
/// attested capability claim, so the claim cannot misdescribe the runtime.
///
/// Widening it (preopens / network / env) means extending both this value and
/// [`build_wasi_ctx`] together.
pub fn session_wasi_grant() -> WasiRuntimeGrant {
    WasiRuntimeGrant {
        preopens: Vec::new(), // no filesystem reachable
        network: false,       // no sockets
        env_names: Vec::new(),
        args: Vec::new(),
        stdin: StdioGrant::Closed as i32,
        stdout: StdioGrant::Sink as i32,
        stderr: StdioGrant::Sink as i32,
        wall_clock: true,
        monotonic_clock: true,
        random: RandomGrant::Secure as i32,
    }
}

/// Builds the `WasiCtx` realizing `grant`. The deny-all grant maps exactly to
/// `WasiCtxBuilder`'s defaults (stdin closed; stdout/stderr a discarding sink;
/// real clock + secure RNG; no preopens/env/args/network); only non-default
/// stdio is applied here. Preopens/network/env are asserted absent for now.
fn build_wasi_ctx(grant: &WasiRuntimeGrant) -> WasiCtx {
    debug_assert!(
        grant.preopens.is_empty() && !grant.network && grant.env_names.is_empty(),
        "build_wasi_ctx only realizes the deny-all grant; extend it before widening",
    );
    let mut b = WasiCtxBuilder::new();
    if grant.stdin == StdioGrant::Inherit as i32 {
        b.inherit_stdin();
    }
    if grant.stdout == StdioGrant::Inherit as i32 {
        b.inherit_stdout();
    }
    if grant.stderr == StdioGrant::Inherit as i32 {
        b.inherit_stderr();
    }
    b.build()
}

/// How a blob was emitted, mirroring the C++ `Context::Emit*` variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmitKind {
    /// Plaintext output (`emit-unencrypted`).
    Unencrypted,
    /// Intermediate result re-encrypted for pipeline stage `index` (B3.3).
    Encrypted(u32),
    /// Final KMS-releasable result for stage `index` (B3.3).
    Releasable(u32),
}

/// A result blob emitted by the session through the `context` capability.
#[derive(Clone, Debug)]
pub struct EmittedBlob {
    pub key: String,
    pub value: Vec<u8>,
    pub kind: EmitKind,
}

/// Host state threaded through the wasm `Store`: the blobs the session emits via
/// the `context` capability, plus a locked-down (deny-all) WASI context.
///
/// The WASI context grants no filesystem, network, environment, args, or stdio;
/// it exists only so that std-based components (e.g. the ONNX workload, whose
/// runtime seeds HashMaps from `wasi:random` and reads `wasi:clocks`) can
/// instantiate at all. Whatever WASI a component actually imports is still
/// surfaced honestly in its derived capability claim.
struct SessionHostState {
    emitted: Vec<EmittedBlob>,
    wasi: WasiCtx,
    table: ResourceTable,
}

impl Default for SessionHostState {
    fn default() -> Self {
        Self {
            emitted: Vec::new(),
            wasi: build_wasi_ctx(&session_wasi_grant()),
            table: ResourceTable::new(),
        }
    }
}

impl WasiView for SessionHostState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
}

/// A loaded wasm ConfidentialTransform session, ready to be driven.
pub struct TransformSession {
    store: Store<SessionHostState>,
    configure: Func,
    write: Func,
    commit: Func,
    finalize: Func,
    // Retained so the compiled component outlives the instance in `store`.
    _component: Component,
}

impl TransformSession {
    /// Compiles and instantiates a `session-world` component. Convenience for
    /// tests; a server compiles once and calls [`instantiate`](Self::instantiate)
    /// per session.
    pub fn load(component_bytes: &[u8]) -> Result<Self> {
        let engine = Engine::default();
        let component =
            Component::new(&engine, component_bytes).context("loading session component")?;
        Self::instantiate(&engine, &component)
    }

    /// Instantiates a fresh session from an already-compiled component, wiring
    /// the host `context` capability plus a locked-down (deny-all) WASI. A
    /// component importing anything outside standard WASI + `context` still fails
    /// closed; whatever WASI it does import is recorded in its capability claim.
    pub fn instantiate(engine: &Engine, component: &Component) -> Result<Self> {
        let mut store = Store::new(engine, SessionHostState::default());

        let mut linker: Linker<SessionHostState> = Linker::new(engine);
        Self::define_context(&mut linker).context("defining host context capability")?;
        // Provide a locked-down WASI (deny-all: no fs/net/env/args/stdio) so
        // std-based components can instantiate. Enforcement is preserved: a
        // component importing anything outside standard WASI + `context` fails
        // closed here.
        wasmtime_wasi::add_to_linker_sync(&mut linker)
            .context("adding locked-down WASI to linker")?;

        let instance =
            linker.instantiate(&mut store, component).context("instantiating session component")?;

        // Resolve the exported `session` interface and its functions.
        let session_iface = instance
            .get_export(&mut store, None, SESSION_IFACE)
            .with_context(|| format!("component does not export '{SESSION_IFACE}'"))?;
        let resolve = |store: &mut Store<SessionHostState>, name: &str| -> Result<Func> {
            let idx = instance
                .get_export(&mut *store, Some(&session_iface), name)
                .with_context(|| format!("session missing export '{name}'"))?;
            instance
                .get_func(&mut *store, idx)
                .with_context(|| format!("session export '{name}' is not a function"))
        };
        let configure = resolve(&mut store, "configure")?;
        let write = resolve(&mut store, "write")?;
        let commit = resolve(&mut store, "commit")?;
        let finalize = resolve(&mut store, "finalize")?;

        Ok(Self { store, configure, write, commit, finalize, _component: component.clone() })
    }

    /// Defines the host `context` capability the wasm session imports.
    fn define_context(linker: &mut Linker<SessionHostState>) -> Result<()> {
        let mut ctx = linker.instance(CONTEXT_IFACE)?;

        ctx.func_new("emit-unencrypted", |mut store, params, _results| {
            let (key, value) = as_kv(params.first().context("emit-unencrypted: missing kv")?)?;
            store.data_mut().emitted.push(EmittedBlob { key, value, kind: EmitKind::Unencrypted });
            Ok(())
        })?;

        // B3.3 will encrypt inside these; for now they record the blob and its
        // requested treatment so the plaintext bring-up exercises the whole
        // interface.
        ctx.func_new("emit-encrypted", |mut store, params, _results| {
            let index = as_u32(params.first().context("emit-encrypted: missing key index")?)?;
            let (key, value) = as_kv(params.get(1).context("emit-encrypted: missing kv")?)?;
            store
                .data_mut()
                .emitted
                .push(EmittedBlob { key, value, kind: EmitKind::Encrypted(index) });
            Ok(())
        })?;

        ctx.func_new("emit-releasable", |mut store, params, _results| {
            let index = as_u32(params.first().context("emit-releasable: missing key index")?)?;
            let (key, value) = as_kv(params.get(1).context("emit-releasable: missing kv")?)?;
            store
                .data_mut()
                .emitted
                .push(EmittedBlob { key, value, kind: EmitKind::Releasable(index) });
            Ok(())
        })?;

        Ok(())
    }

    /// `session.configure(config)`.
    pub fn configure(&mut self, config: &[u8]) -> Result<()> {
        let f = self.configure;
        self.call_with_bytes(f, config)
    }

    /// `session.write(data)` — `data` is plaintext (the base already decrypted).
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        let f = self.write;
        self.call_with_bytes(f, data)
    }

    /// `session.commit()`.
    pub fn commit(&mut self) -> Result<()> {
        let f = self.commit;
        self.call_unit(f)
    }

    /// `session.finalize()`.
    pub fn finalize(&mut self) -> Result<()> {
        let f = self.finalize;
        self.call_unit(f)
    }

    /// Drains the blobs emitted so far via the `context` capability.
    pub fn take_emitted(&mut self) -> Vec<EmittedBlob> {
        std::mem::take(&mut self.store.data_mut().emitted)
    }

    fn call_with_bytes(&mut self, func: Func, data: &[u8]) -> Result<()> {
        let params = [Val::List(data.iter().map(|b| Val::U8(*b)).collect())];
        let mut results: [Val; 0] = [];
        func.call(&mut self.store, &params, &mut results)?;
        func.post_return(&mut self.store)?;
        Ok(())
    }

    fn call_unit(&mut self, func: Func) -> Result<()> {
        let params: [Val; 0] = [];
        let mut results: [Val; 0] = [];
        func.call(&mut self.store, &params, &mut results)?;
        func.post_return(&mut self.store)?;
        Ok(())
    }
}

/// Parses a `context.kv` record `Val` into `(key, value)`.
fn as_kv(v: &Val) -> Result<(String, Vec<u8>)> {
    let Val::Record(fields) = v else {
        bail!("expected a kv record, got {v:?}");
    };
    let mut key = String::new();
    let mut value = Vec::new();
    for (name, val) in fields {
        match (name.as_str(), val) {
            ("key", Val::String(s)) => key = s.clone(),
            ("value", Val::List(items)) => {
                value = items
                    .iter()
                    .map(|x| match x {
                        Val::U8(b) => *b,
                        _ => 0,
                    })
                    .collect();
            }
            _ => {}
        }
    }
    Ok((key, value))
}

fn as_u32(v: &Val) -> Result<u32> {
    match v {
        Val::U32(n) => Ok(*n),
        other => bail!("expected u32, got {other:?}"),
    }
}
