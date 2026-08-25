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
    attestation::v1::{ContainerLayerReferenceValues, Event, EventAttestationResults},
    Variant,
};
use oak_time::Instant;
use prost::Message;

use crate::policy::{
    container::ContainerPolicy,
    wasm_workload::{WasmWorkloadPolicy, WASM_WORKLOAD_LAYER_DATA_TYPE_URL},
};

/// Type URL of the classic container workload event.
const CONTAINER_LAYER_DATA_TYPE_URL: &str =
    "type.googleapis.com/oak.attestation.v1.ContainerLayerData";

/// Verifies the workload layer of the event log, accepting **either** workload shape:
///
///  * a classic container ([`ContainerLayerData`]) — verified by measurement via
///    [`ContainerPolicy`], or
///  * a capability-based wasm workload ([`WasmWorkloadLayerData`]) — measurement-agnostic
///    via [`WasmWorkloadPolicy`] (authority comes from the attested capability claim).
///
/// The event's type URL selects the branch; both surface the same session-binding /
/// hybrid-encryption / signing public keys into the results. Using this in the workload
/// event-log slot lets one verifier serve both workload kinds without committing to either
/// up front.
///
/// [`ContainerLayerData`]: oak_proto_rust::oak::attestation::v1::ContainerLayerData
/// [`WasmWorkloadLayerData`]: oak_proto_rust::oak::attestation::v1::WasmWorkloadLayerData
pub struct WorkloadPolicy {
    container: ContainerPolicy,
    wasm: WasmWorkloadPolicy,
}

impl WorkloadPolicy {
    /// `container_reference_values` are used only for the container branch; the wasm branch
    /// is measurement-agnostic and ignores them.
    pub fn new(container_reference_values: &ContainerLayerReferenceValues) -> Self {
        Self {
            container: ContainerPolicy::new(container_reference_values),
            wasm: WasmWorkloadPolicy::new(),
        }
    }
}

// We have to use [`Policy<[u8]>`] instead of [`EventPolicy`], because
// Rust doesn't yet support implementing trait aliases.
impl Policy<[u8]> for WorkloadPolicy {
    fn verify(
        &self,
        verification_time: Instant,
        evidence: &[u8],
        endorsement: &Variant,
    ) -> anyhow::Result<EventAttestationResults> {
        let event = Event::decode(evidence).context("decoding workload event")?;
        match event.event.as_ref().map(|any| any.type_url.as_str()) {
            Some(WASM_WORKLOAD_LAYER_DATA_TYPE_URL) => {
                self.wasm.verify(verification_time, evidence, endorsement)
            }
            Some(CONTAINER_LAYER_DATA_TYPE_URL) => {
                self.container.verify(verification_time, evidence, endorsement)
            }
            other => anyhow::bail!("unsupported workload event type: {:?}", other),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use oak_proto_rust::oak::{
        attestation::v1::{
            binary_reference_value, AttestationResults, BinaryReferenceValue, ContainerLayerData,
            EventAttestationResults, SkipVerification, WasmWorkloadLayerData,
        },
        RawDigest,
    };
    use prost_types::Any;

    use super::*;
    use crate::results::{unique_hybrid_encryption_public_key, unique_signing_public_key};

    /// Container reference values that skip the bundle/config measurement, so the
    /// container branch verifies purely by key extraction (as in the KMS's skip mode).
    fn skip_container_reference_values() -> ContainerLayerReferenceValues {
        let skip = BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Skip(SkipVerification {})),
        };
        ContainerLayerReferenceValues { binary: Some(skip.clone()), configuration: Some(skip) }
    }

    fn encoded_event(type_url: &str, value: Vec<u8>) -> Vec<u8> {
        Event { tag: "workload".into(), event: Some(Any { type_url: type_url.into(), value }) }
            .encode_to_vec()
    }

    /// Wraps a single event's results the way the verifier assembles them, so the
    /// `unique_*` accessors (which scan `event_attestation_results`) can read them.
    fn wrap(results: EventAttestationResults) -> AttestationResults {
        AttestationResults { event_attestation_results: vec![results], ..Default::default() }
    }

    #[test]
    fn accepts_wasm_event() {
        let hybrid = vec![0x11; 32];
        let signing = vec![0x22; 32];
        let encoded = encoded_event(
            WASM_WORKLOAD_LAYER_DATA_TYPE_URL,
            WasmWorkloadLayerData {
                hybrid_encryption_public_key: hybrid.clone(),
                signing_public_key: signing.clone(),
                ..Default::default()
            }
            .encode_to_vec(),
        );

        let results = WorkloadPolicy::new(&skip_container_reference_values())
            .verify(Instant::from_unix_millis(0), &encoded, &Variant::default())
            .expect("wasm event should be accepted");
        let attestation = wrap(results);
        assert_eq!(unique_hybrid_encryption_public_key(&attestation).unwrap(), &hybrid);
        assert_eq!(unique_signing_public_key(&attestation).unwrap(), &signing);
    }

    #[test]
    fn accepts_container_event() {
        let hybrid = vec![0x44; 32];
        let signing = vec![0x55; 32];
        // A real container event always carries bundle/config measurement digests; the
        // container `compare` dereferences them even when the reference values skip the
        // comparison. Values are irrelevant here since the ref-values are `skip`.
        let digest = RawDigest { sha2_256: vec![0x99; 32], ..Default::default() };
        let encoded = encoded_event(
            CONTAINER_LAYER_DATA_TYPE_URL,
            ContainerLayerData {
                bundle: Some(digest.clone()),
                config: Some(digest),
                hybrid_encryption_public_key: hybrid.clone(),
                signing_public_key: signing.clone(),
                ..Default::default()
            }
            .encode_to_vec(),
        );

        let results = WorkloadPolicy::new(&skip_container_reference_values())
            .verify(Instant::from_unix_millis(0), &encoded, &Variant::default())
            .expect("container event should be accepted (skip measurement)");
        let attestation = wrap(results);
        assert_eq!(unique_hybrid_encryption_public_key(&attestation).unwrap(), &hybrid);
        assert_eq!(unique_signing_public_key(&attestation).unwrap(), &signing);
    }

    #[test]
    fn rejects_unknown_event() {
        let encoded = encoded_event("type.googleapis.com/some.Other", vec![]);
        assert!(WorkloadPolicy::new(&skip_container_reference_values())
            .verify(Instant::from_unix_millis(0), &encoded, &Variant::default())
            .is_err());
    }
}
