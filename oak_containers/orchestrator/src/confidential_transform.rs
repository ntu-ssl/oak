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

//! Orchestrator-hosted ConfidentialTransform base for wasm workloads.
//!
//! This is the Rust equivalent of the C++ `ConfidentialTransformBase`: it drives
//! a wasm [`TransformSession`] over the `ConfidentialTransform.Session`
//! protocol. The wasm side is the business logic (the C++ `Session` subclass);
//! this side is the shared plumbing.
//!
//! B3.2 (this file) implements the **plaintext** path: `WriteRequest`s carry
//! `Unencrypted` blobs whose `data` is fed straight to `session.write`, and
//! `emit-unencrypted` outputs come back as `Unencrypted` `ReadResponse`s. B3.3
//! adds HPKE decrypt-before-write / encrypt-in-emit and the KMS handshake on
//! this same state machine.

use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::{bail, Context, Result};
use cfc_wasm_capability::{derive_claim_from_loaded, proto::WasmWorkloadConfig, LoadedComponent};
use oak_crypto::encryption_key::EncryptionKey;
use oak_grpc::fcp::confidentialcompute::confidential_transform_server::{
    ConfidentialTransform, ConfidentialTransformServer,
};
use oak_proto_rust::{fcp::confidentialcompute as ct, google::rpc::Status as RpcStatus};
use prost::Message as _;
use tokio_stream::Stream;
use tonic::{transport::Server, Request, Response, Status, Streaming};
use wasmtime::{component::Component, Engine};

use crate::{
    transform_crypto::TransformKeys,
    transform_session::{TransformSession, SESSION_IFACE},
    wasm_runtime,
};

/// Drives a wasm session over the `ConfidentialTransform.Session` request/
/// response protocol.
pub struct ConfidentialTransformSession {
    session: TransformSession,
    /// The keys the KMS released for this transform, shared across all sessions.
    /// `None` until a `StreamInitialize` with a `protected_response` arrives; in
    /// that state only plaintext (`Unencrypted`) blobs can be written.
    keys: Option<Arc<TransformKeys>>,
}

impl ConfidentialTransformSession {
    pub fn new(session: TransformSession, keys: Option<Arc<TransformKeys>>) -> Self {
        Self { session, keys }
    }

    /// Handles one `SessionRequest`, returning the `SessionResponse`s it
    /// produces (a `finalize` yields a `ReadResponse` per emitted blob followed
    /// by a `FinalizeResponse`).
    pub fn handle(&mut self, request: ct::SessionRequest) -> Result<Vec<ct::SessionResponse>> {
        use ct::session_request::Kind;
        match request.kind {
            Some(Kind::Configure(configure)) => self.configure(configure),
            Some(Kind::Write(write)) => self.write(write),
            Some(Kind::Commit(commit)) => self.commit(commit),
            Some(Kind::Finalize(finalize)) => self.finalize(finalize),
            None => bail!("SessionRequest had no kind"),
        }
    }

    fn configure(&mut self, request: ct::ConfigureRequest) -> Result<Vec<ct::SessionResponse>> {
        let config = request.configuration.map(|any| any.value).unwrap_or_default();
        let config_len = config.len();
        let t = Instant::now();
        self.session.configure(&config)?;
        log::info!(
            "[timing] configure: session.configure ({config_len} B config) took {:.3} ms",
            t.elapsed().as_secs_f64() * 1e3
        );
        Ok(vec![wrap(ct::session_response::Kind::Configure(ct::ConfigureResponse::default()))])
    }

    fn write(&mut self, request: ct::WriteRequest) -> Result<Vec<ct::SessionResponse>> {
        let t_decrypt = Instant::now();
        let plaintext = self.decrypt_write(&request)?;
        let decrypt_ms = t_decrypt.elapsed().as_secs_f64() * 1e3;
        let committed_size_bytes = plaintext.len() as i64;
        let t_write = Instant::now();
        self.session.write(&plaintext)?;
        log::info!(
            "[timing] write: decrypt {committed_size_bytes} B in {decrypt_ms:.3} ms, \
             session.write took {:.3} ms",
            t_write.elapsed().as_secs_f64() * 1e3
        );
        Ok(vec![wrap(ct::session_response::Kind::Write(ct::WriteFinishedResponse {
            committed_size_bytes,
            status: Some(ok_status()),
        }))])
    }

    fn commit(&mut self, _request: ct::CommitRequest) -> Result<Vec<ct::SessionResponse>> {
        let t = Instant::now();
        self.session.commit()?;
        log::info!("[timing] commit: session.commit took {:.3} ms", t.elapsed().as_secs_f64() * 1e3);
        Ok(vec![wrap(ct::session_response::Kind::Commit(ct::CommitResponse {
            status: Some(ok_status()),
            stats: None,
        }))])
    }

    fn finalize(&mut self, _request: ct::FinalizeRequest) -> Result<Vec<ct::SessionResponse>> {
        let t = Instant::now();
        self.session.finalize()?;
        log::info!(
            "[timing] finalize: session.finalize took {:.3} ms",
            t.elapsed().as_secs_f64() * 1e3
        );

        let mut responses = Vec::new();
        for blob in self.session.take_emitted() {
            // Plaintext path: emit every result as an Unencrypted blob. B3.3
            // will HPKE/KMS-encrypt the Encrypted/Releasable kinds here.
            responses.push(wrap(ct::session_response::Kind::Read(ct::ReadResponse {
                first_response_configuration: None,
                first_response_metadata: Some(unencrypted_metadata(&blob)),
                finish_read: true,
                data: blob.value,
            })));
        }
        responses.push(wrap(ct::session_response::Kind::Finalize(ct::FinalizeResponse::default())));
        Ok(responses)
    }
}

impl ConfidentialTransformSession {
    /// Returns the plaintext bytes a `WriteRequest` carries, decrypting an
    /// `HpkePlusAead` blob with the KMS-released keys. An `Unencrypted` blob (or
    /// one with no encryption metadata) passes through. An encrypted blob before
    /// any keys were released is rejected.
    fn decrypt_write(&self, request: &ct::WriteRequest) -> Result<Vec<u8>> {
        let encryption = request
            .first_request_metadata
            .as_ref()
            .and_then(|metadata| metadata.encryption_metadata.as_ref());
        match encryption {
            None | Some(ct::blob_metadata::EncryptionMetadata::Unencrypted(_)) => {
                Ok(request.data.clone())
            }
            Some(ct::blob_metadata::EncryptionMetadata::HpkePlusAeadData(metadata)) => {
                let keys = self.keys.as_ref().context(
                    "received an encrypted blob but no keys were released; a StreamInitialize \
                     carrying a protected_response is required first",
                )?;
                keys.decrypt_blob(metadata, &request.data)
            }
        }
    }
}

fn unencrypted_metadata(blob: &crate::transform_session::EmittedBlob) -> ct::BlobMetadata {
    ct::BlobMetadata {
        total_size_bytes: blob.value.len() as i64,
        compression_type: ct::blob_metadata::CompressionType::None as i32,
        encryption_metadata: Some(ct::blob_metadata::EncryptionMetadata::Unencrypted(
            ct::blob_metadata::Unencrypted { blob_id: blob.key.clone().into_bytes() },
        )),
    }
}

fn wrap(kind: ct::session_response::Kind) -> ct::SessionResponse {
    ct::SessionResponse { kind: Some(kind) }
}

fn ok_status() -> RpcStatus {
    RpcStatus::default()
}

/// A compiled `session-world` workload. The component is compiled **once** and
/// its capability claim derived from it; each incoming `Session` stream spins up
/// a fresh session instance (fresh state), so concurrent clients are isolated.
pub struct SessionWorkload {
    engine: Engine,
    component: Component,
    claim_bytes: Vec<u8>,
}

impl SessionWorkload {
    /// Compiles the workload's (single) session component and derives its claim.
    pub fn load(wasm: &WasmWorkloadConfig, files: &BTreeMap<String, Vec<u8>>) -> Result<Self> {
        let entry = wasm
            .components
            .iter()
            .find(|c| c.id == wasm.entry_component)
            .with_context(|| format!("entry component '{}' not in config", wasm.entry_component))?;
        let bytes = wasm_runtime::lookup(files, &entry.path).with_context(|| {
            format!("session component '{}' not in bundle at '{}'", entry.id, entry.path)
        })?;

        let engine = Engine::default();
        log::info!(
            "[timing]   Component::new: compiling {} B wasm (this is the heavy step)...",
            bytes.len()
        );
        let t = Instant::now();
        let component = Component::new(&engine, bytes).context("compiling session component")?;
        log::info!(
            "[timing]   Component::new (compile {} B wasm) took {:.3} ms",
            bytes.len(),
            t.elapsed().as_secs_f64() * 1e3
        );

        // Derive the capability claim from the same compiled component, against
        // the exact WASI grant the session runtime enforces. The grant is the
        // single source of truth: `transform_session` builds the `WasiCtx` from
        // it and the claim reports the effective (imported ∩ granted) authority.
        let loaded = [LoadedComponent {
            id: entry.id.clone(),
            role: entry.role.clone(),
            bytes,
            component: &component,
        }];
        let grant = crate::transform_session::session_wasi_grant();
        let t = Instant::now();
        let claim_bytes = derive_claim_from_loaded(&engine, &loaded, &[], Some(&grant))
            .context("wasm capability derivation failed")?
            .encode_to_vec();
        log::info!(
            "[timing]   derive_claim_from_loaded took {:.3} ms",
            t.elapsed().as_secs_f64() * 1e3
        );

        Ok(Self { engine, component, claim_bytes })
    }

    /// The canonical encoding of the derived capability claim.
    pub fn claim_bytes(&self) -> &[u8] {
        &self.claim_bytes
    }

    /// Instantiates a fresh session from the compiled component (no recompile).
    fn new_session(&self) -> Result<TransformSession> {
        TransformSession::instantiate(&self.engine, &self.component)
    }
}

/// True if this workload is a ConfidentialTransform session (vs a pure-transform
/// composition), dispatched on the configured entry interface.
pub fn is_session_workload(wasm: &WasmWorkloadConfig) -> bool {
    wasm.entry_interface == SESSION_IFACE
}

/// The tonic `ConfidentialTransform` service backed by a wasm session workload.
pub struct ConfidentialTransformService {
    workload: Arc<SessionWorkload>,
    /// The transform's application encryption key, used to unwrap the KMS's
    /// `protected_response` during `StreamInitialize`.
    instance_key: EncryptionKey,
    /// The keys released by the KMS, populated by `StreamInitialize` and shared
    /// by every `Session` stream this service serves.
    keys: Arc<Mutex<Option<Arc<TransformKeys>>>>,
}

/// Builds the tonic `ConfidentialTransform` server for `workload`. `instance_key`
/// is the transform's application encryption key (the private half of the
/// attested `hybrid_encryption_public_key`), used to unwrap the KMS's released
/// keys. Exposed so tests can drive the service over an in-process channel.
pub fn server(
    workload: Arc<SessionWorkload>,
    instance_key: EncryptionKey,
) -> ConfidentialTransformServer<ConfidentialTransformService> {
    ConfidentialTransformServer::new(ConfidentialTransformService {
        workload,
        instance_key,
        keys: Arc::new(Mutex::new(None)),
    })
}

#[tonic::async_trait]
impl ConfidentialTransform for ConfidentialTransformService {
    async fn stream_initialize(
        &self,
        request: Request<Streaming<ct::StreamInitializeRequest>>,
    ) -> Result<Response<ct::InitializeResponse>, Status> {
        // Unwrap the KMS's released keys from the `protected_response` carried in
        // the `InitializeRequest`, and retain them for the Session streams. A
        // stream with no `protected_response` leaves the transform in the
        // plaintext-only state.
        let mut stream = request.into_inner();
        while let Some(message) = stream.message().await? {
            if let Some(ct::stream_initialize_request::Kind::InitializeRequest(init)) = message.kind
            {
                if let Some(protected_response) = init.protected_response {
                    let t = Instant::now();
                    let keys = TransformKeys::from_protected_response(
                        &protected_response,
                        &self.instance_key,
                    )
                    .map_err(|e| {
                        Status::invalid_argument(format!("invalid protected_response: {e:?}"))
                    })?;
                    log::info!(
                        "[timing] stream_initialize: unwrap KMS protected_response (release keys) \
                         took {:.3} ms",
                        t.elapsed().as_secs_f64() * 1e3
                    );
                    *self.keys.lock().expect("keys mutex poisoned") = Some(Arc::new(keys));
                }
            }
        }
        Ok(Response::new(ct::InitializeResponse::default()))
    }

    type SessionStream = Pin<Box<dyn Stream<Item = Result<ct::SessionResponse, Status>> + Send>>;

    async fn session(
        &self,
        request: Request<Streaming<ct::SessionRequest>>,
    ) -> Result<Response<Self::SessionStream>, Status> {
        let t = Instant::now();
        let session = self
            .workload
            .new_session()
            .map_err(|e| Status::internal(format!("couldn't start session: {e:?}")))?;
        log::info!(
            "[timing] session: new_session (instantiate component) took {:.3} ms",
            t.elapsed().as_secs_f64() * 1e3
        );
        let keys = self.keys.lock().expect("keys mutex poisoned").clone();
        let mut handler = ConfidentialTransformSession::new(session, keys);
        let mut incoming = request.into_inner();

        let output = async_stream::try_stream! {
            while let Some(request) = incoming.message().await? {
                let responses = handler
                    .handle(request)
                    .map_err(|e| Status::internal(format!("{e:?}")))?;
                for response in responses {
                    yield response;
                }
            }
        };
        Ok(Response::new(Box::pin(output)))
    }
}

/// Serves the ConfidentialTransform gRPC API for `workload` on `addr` until the
/// process exits.
pub async fn serve(
    workload: Arc<SessionWorkload>,
    instance_key: EncryptionKey,
    addr: std::net::SocketAddr,
) -> Result<()> {
    Server::builder()
        .add_service(server(workload, instance_key))
        .serve(addr)
        .await
        .context("ConfidentialTransform server failed")?;
    Ok(())
}

/// As [`serve`], but on an already-bound listener. The orchestrator binds first
/// and notifies the launcher (app-ready) before serving, so the launcher can
/// proxy to a socket that is already listening.
pub async fn serve_on_listener(
    workload: Arc<SessionWorkload>,
    instance_key: EncryptionKey,
    listener: tokio::net::TcpListener,
) -> Result<()> {
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    Server::builder()
        .add_service(server(workload, instance_key))
        .serve_with_incoming(incoming)
        .await
        .context("ConfidentialTransform server failed")?;
    Ok(())
}
