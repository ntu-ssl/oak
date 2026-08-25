//
// Copyright 2026 The Project Oak Authors
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
//

use anyhow::Context;
use oak_attestation_verification_types::policy::Policy;
use oak_proto_rust::oak::{
    attestation::v1::{EventAttestationResults, WasmWorkloadLayerData},
    Variant,
};
use oak_time::Instant;

use crate::{
    results::{
        set_hybrid_encryption_public_key, set_session_binding_public_key, set_signing_public_key,
    },
    util::decode_event_proto,
};

/// Type URL of the [`WasmWorkloadLayerData`] event a capability-based wasm workload
/// emits into the event log.
pub(crate) const WASM_WORKLOAD_LAYER_DATA_TYPE_URL: &str =
    "type.googleapis.com/oak.attestation.v1.WasmWorkloadLayerData";

/// Verifies the wasm-workload layer of the event log.
///
/// Unlike [`crate::policy::container::ContainerPolicy`], this policy is deliberately
/// **measurement-agnostic**: a capability-based wasm workload is authorized by its
/// attested `fcp.confidentialcompute.WasmCapabilityClaim` (which CFC's KMS decodes and
/// evaluates during key release), NOT by pinning the bundle/config digest. The policy
/// therefore skips the bundle/config measurement comparison and only surfaces the
/// workload's public keys (session-binding / hybrid-encryption / signing) into the
/// attestation results. The `capability_claim` bytes are opaque to Oak and left in the
/// event for CFC to decode; this policy neither inspects nor endorses them.
#[derive(Default)]
pub struct WasmWorkloadPolicy {}

impl WasmWorkloadPolicy {
    pub fn new() -> Self {
        Self {}
    }
}

// We have to use [`Policy<[u8]>`] instead of [`EventPolicy`], because
// Rust doesn't yet support implementing trait aliases.
// <https://github.com/rust-lang/rfcs/blob/master/text/1733-trait-alias.md>
impl Policy<[u8]> for WasmWorkloadPolicy {
    fn verify(
        &self,
        _verification_time: Instant,
        evidence: &[u8],
        _endorsement: &Variant,
    ) -> anyhow::Result<EventAttestationResults> {
        let event =
            decode_event_proto::<WasmWorkloadLayerData>(WASM_WORKLOAD_LAYER_DATA_TYPE_URL, evidence)
                .context("decoding wasm workload layer event")?;

        // Measurement (bundle/config) is intentionally NOT compared: authority for a
        // wasm workload comes from its capability claim, not a pinned digest.
        let mut results = EventAttestationResults { ..Default::default() };
        if !event.session_binding_public_key.is_empty() {
            set_session_binding_public_key(&mut results, &event.session_binding_public_key);
        }
        if !event.hybrid_encryption_public_key.is_empty() {
            set_hybrid_encryption_public_key(&mut results, &event.hybrid_encryption_public_key);
        }
        if !event.signing_public_key.is_empty() {
            set_signing_public_key(&mut results, &event.signing_public_key);
        }

        // TODO: b/356631062 - Return detailed attestation results.
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use oak_proto_rust::oak::attestation::v1::{AttestationResults, Event};
    use prost::Message;
    use prost_types::Any;

    use super::*;
    use crate::results::{unique_hybrid_encryption_public_key, unique_signing_public_key};

    /// Serializes a [`WasmWorkloadLayerData`] into an encoded [`Event`], as it would
    /// appear in the evidence event log.
    fn encoded_wasm_event(data: WasmWorkloadLayerData) -> Vec<u8> {
        Event {
            tag: "wasm_workload".into(),
            event: Some(Any {
                type_url: WASM_WORKLOAD_LAYER_DATA_TYPE_URL.into(),
                value: data.encode_to_vec(),
            }),
        }
        .encode_to_vec()
    }

    fn sample_data() -> WasmWorkloadLayerData {
        WasmWorkloadLayerData {
            bundle: None,
            config: None,
            hybrid_encryption_public_key: vec![0x11; 32],
            signing_public_key: vec![0x22; 32],
            session_binding_public_key: vec![0x33; 32],
            capability_claim: vec![0xde, 0xad, 0xbe, 0xef],
        }
    }

    /// Wraps a single event's results the way the verifier assembles them, so the
    /// `unique_*` accessors (which scan `event_attestation_results`) can read them.
    fn wrap(results: EventAttestationResults) -> AttestationResults {
        AttestationResults { event_attestation_results: vec![results], ..Default::default() }
    }

    #[test]
    fn extracts_public_keys_and_skips_measurement() {
        let data = sample_data();
        let encoded = encoded_wasm_event(data.clone());

        let results = WasmWorkloadPolicy::new()
            .verify(Instant::from_unix_millis(0), &encoded, &Variant::default())
            .expect("verify should succeed without any reference values / endorsement");
        let attestation = wrap(results);

        assert_eq!(
            unique_hybrid_encryption_public_key(&attestation).unwrap(),
            &data.hybrid_encryption_public_key
        );
        assert_eq!(unique_signing_public_key(&attestation).unwrap(), &data.signing_public_key);
    }

    #[test]
    fn missing_public_keys_are_omitted() {
        let data = WasmWorkloadLayerData {
            hybrid_encryption_public_key: vec![],
            signing_public_key: vec![],
            session_binding_public_key: vec![],
            ..sample_data()
        };
        let encoded = encoded_wasm_event(data);

        let results = WasmWorkloadPolicy::new()
            .verify(Instant::from_unix_millis(0), &encoded, &Variant::default())
            .expect("verify should still succeed with no keys");
        assert!(results.artifacts.is_empty(), "no key artifacts should be set");
    }

    #[test]
    fn wrong_type_url_is_rejected() {
        // A container event must NOT be accepted by the wasm workload policy.
        let encoded = Event {
            tag: "container".into(),
            event: Some(Any {
                type_url: "type.googleapis.com/oak.attestation.v1.ContainerLayerData".into(),
                value: vec![],
            }),
        }
        .encode_to_vec();

        assert!(WasmWorkloadPolicy::new()
            .verify(Instant::from_unix_millis(0), &encoded, &Variant::default())
            .is_err());
    }
}
