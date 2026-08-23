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

//! End-to-end gRPC round trip: a real tonic ConfidentialTransform client drives
//! the orchestrator's server (backed by the concat wasm session) over a loopback
//! TCP channel — exercising the actual streaming transport, not just the handler.

use std::{collections::BTreeMap, sync::Arc};

use cfc_wasm_capability::proto::{WasmComponentRef, WasmWorkloadConfig};
use oak_containers_orchestrator::confidential_transform::{self, SessionWorkload};
use oak_grpc::fcp::confidentialcompute::confidential_transform_client::ConfidentialTransformClient;
use oak_proto_rust::fcp::confidentialcompute as ct;

fn concat_workload() -> Arc<SessionWorkload> {
    let bytes = std::fs::read(oak_file_utils::data_path("cfc_wasm_capability/testdata/concat.wasm"))
        .expect("read concat.wasm");
    let wasm = WasmWorkloadConfig {
        components: vec![WasmComponentRef {
            id: "concat".into(),
            role: "session".into(),
            path: "concat.wasm".into(),
        }],
        edges: vec![],
        entry_component: "concat".into(),
        entry_interface: "cfc:transform/session@0.1.0".into(),
        entry_function: String::new(),
    };
    let mut files = BTreeMap::new();
    files.insert("concat.wasm".to_string(), bytes);
    Arc::new(SessionWorkload::load(&wasm, &files).expect("load session workload"))
}

fn configure() -> ct::SessionRequest {
    ct::SessionRequest {
        kind: Some(ct::session_request::Kind::Configure(ct::ConfigureRequest::default())),
    }
}

fn write_unencrypted(data: &[u8]) -> ct::SessionRequest {
    ct::SessionRequest {
        kind: Some(ct::session_request::Kind::Write(ct::WriteRequest {
            first_request_metadata: Some(ct::BlobMetadata {
                total_size_bytes: data.len() as i64,
                compression_type: ct::blob_metadata::CompressionType::None as i32,
                encryption_metadata: Some(ct::blob_metadata::EncryptionMetadata::Unencrypted(
                    ct::blob_metadata::Unencrypted::default(),
                )),
            }),
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

#[tokio::test]
async fn plaintext_session_over_grpc() {
    let workload = concat_workload();

    // Serve on an ephemeral loopback port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let incoming = async_stream::stream! {
        loop {
            yield listener.accept().await.map(|(stream, _)| stream);
        }
    };
    // Plaintext path: an instance key is required to construct the service, but
    // no protected_response is sent, so no released keys are used.
    let (instance_key, _instance_pub) =
        oak_crypto::encryption_key::generate_encryption_key_pair();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(confidential_transform::server(workload, instance_key))
            .serve_with_incoming(incoming)
            .await
            .expect("server");
    });

    let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect_lazy();
    let mut client = ConfidentialTransformClient::new(channel);

    // StreamInitialize (client-streaming) — empty init stream on the plaintext path.
    client
        .stream_initialize(tokio_stream::iter(Vec::<ct::StreamInitializeRequest>::new()))
        .await
        .expect("stream_initialize");

    // Session (bidi) — configure, two writes, commit, finalize.
    let requests = vec![
        configure(),
        write_unencrypted(b"hello "),
        write_unencrypted(b"world"),
        commit(),
        finalize(),
    ];
    let mut responses = client
        .session(tokio_stream::iter(requests))
        .await
        .expect("session")
        .into_inner();

    let mut collected = Vec::new();
    while let Some(response) = responses.message().await.expect("response") {
        collected.push(response);
    }

    // Configure + 2 Writes + Commit + Read + Finalize.
    assert_eq!(collected.len(), 6, "responses: {collected:?}");
    let read = collected
        .iter()
        .find_map(|r| match &r.kind {
            Some(ct::session_response::Kind::Read(read)) => Some(read),
            _ => None,
        })
        .expect("a ReadResponse");
    assert_eq!(read.data, b"hello world");
    assert!(matches!(
        collected.last().and_then(|r| r.kind.as_ref()),
        Some(ct::session_response::Kind::Finalize(_))
    ));
}