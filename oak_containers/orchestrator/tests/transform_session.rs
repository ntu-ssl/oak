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

//! Integration test for the wasm ConfidentialTransform session driver, run
//! against the committed `concat.wasm` fixture (no VM).

use oak_containers_orchestrator::transform_session::{EmitKind, TransformSession};

fn concat_wasm() -> Vec<u8> {
    let path = oak_file_utils::data_path("cfc_wasm_capability/testdata/concat.wasm");
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading concat.wasm: {e}"))
}

#[test]
fn concat_session_concatenates_plaintext_writes() {
    let mut session = TransformSession::load(&concat_wasm()).expect("load session");

    session.configure(b"").expect("configure");
    session.write(b"hello ").expect("write 1");
    session.write(b"confidential ").expect("write 2");
    session.write(b"world").expect("write 3");
    session.commit().expect("commit");
    session.finalize().expect("finalize");

    let emitted = session.take_emitted();
    assert_eq!(emitted.len(), 1, "concat emits exactly one blob on finalize");
    assert_eq!(emitted[0].kind, EmitKind::Unencrypted);
    assert_eq!(emitted[0].key, "result");
    assert_eq!(emitted[0].value, b"hello confidential world");
}

#[test]
fn configure_resets_accumulated_state() {
    let mut session = TransformSession::load(&concat_wasm()).expect("load session");

    session.configure(b"").expect("configure");
    session.write(b"stale").expect("write");
    // Re-configure should clear the accumulator (mirrors a fresh session).
    session.configure(b"").expect("reconfigure");
    session.write(b"fresh").expect("write");
    session.finalize().expect("finalize");

    let emitted = session.take_emitted();
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0].value, b"fresh");
}
