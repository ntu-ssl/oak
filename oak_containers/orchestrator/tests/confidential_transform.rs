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

//! Drives the plaintext ConfidentialTransform Session state machine end to end
//! over the proto messages against the committed `concat.wasm` fixture (no VM).

use oak_containers_orchestrator::{
    confidential_transform::ConfidentialTransformSession, transform_session::TransformSession,
};
use oak_proto_rust::fcp::confidentialcompute as ct;

fn concat_wasm() -> Vec<u8> {
    let path = oak_file_utils::data_path("cfc_wasm_capability/testdata/concat.wasm");
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading concat.wasm: {e}"))
}

fn configure() -> ct::SessionRequest {
    ct::SessionRequest {
        kind: Some(ct::session_request::Kind::Configure(ct::ConfigureRequest::default())),
    }
}

fn write_unencrypted(data: &[u8]) -> ct::SessionRequest {
    let metadata = ct::BlobMetadata {
        total_size_bytes: data.len() as i64,
        compression_type: ct::blob_metadata::CompressionType::None as i32,
        encryption_metadata: Some(ct::blob_metadata::EncryptionMetadata::Unencrypted(
            ct::blob_metadata::Unencrypted::default(),
        )),
    };
    ct::SessionRequest {
        kind: Some(ct::session_request::Kind::Write(ct::WriteRequest {
            first_request_metadata: Some(metadata),
            first_request_configuration: None,
            commit: true,
            data: data.to_vec(),
        })),
    }
}

fn commit() -> ct::SessionRequest {
    ct::SessionRequest {
        kind: Some(ct::session_request::Kind::Commit(ct::CommitRequest::default())),
    }
}

fn finalize() -> ct::SessionRequest {
    ct::SessionRequest {
        kind: Some(ct::session_request::Kind::Finalize(ct::FinalizeRequest::default())),
    }
}

#[test]
fn plaintext_concat_session_end_to_end() {
    let session = TransformSession::load(&concat_wasm()).expect("load session");
    // No keys released: the plaintext path (Unencrypted blobs) only.
    let mut handler = ConfidentialTransformSession::new(session, None);

    // Configure -> ConfigureResponse.
    let responses = handler.handle(configure()).expect("configure");
    assert!(matches!(
        responses.as_slice(),
        [ct::SessionResponse { kind: Some(ct::session_response::Kind::Configure(_)) }]
    ));

    // Two writes, each acked with a WriteFinishedResponse.
    for chunk in [b"hello ".as_slice(), b"world".as_slice()] {
        let responses = handler.handle(write_unencrypted(chunk)).expect("write");
        match responses.as_slice() {
            [ct::SessionResponse { kind: Some(ct::session_response::Kind::Write(w)) }] => {
                assert_eq!(w.committed_size_bytes, chunk.len() as i64);
            }
            other => panic!("unexpected write response: {other:?}"),
        }
    }

    // Commit -> CommitResponse.
    let responses = handler.handle(commit()).expect("commit");
    assert!(matches!(
        responses.as_slice(),
        [ct::SessionResponse { kind: Some(ct::session_response::Kind::Commit(_)) }]
    ));

    // Finalize -> one Unencrypted ReadResponse with the concatenation, then a
    // FinalizeResponse.
    let responses = handler.handle(finalize()).expect("finalize");
    assert_eq!(responses.len(), 2, "one read + one finalize");
    match &responses[0].kind {
        Some(ct::session_response::Kind::Read(read)) => {
            assert_eq!(read.data, b"hello world");
            assert!(read.finish_read);
            assert!(matches!(
                read.first_response_metadata
                    .as_ref()
                    .and_then(|m| m.encryption_metadata.as_ref()),
                Some(ct::blob_metadata::EncryptionMetadata::Unencrypted(_))
            ));
        }
        other => panic!("expected ReadResponse, got {other:?}"),
    }
    assert!(matches!(
        responses[1].kind,
        Some(ct::session_response::Kind::Finalize(_))
    ));
}
