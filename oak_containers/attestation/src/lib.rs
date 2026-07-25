//
// Copyright 2024 The Project Oak Authors
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

extern crate alloc;

use alloc::{string::ToString, vec};

use anyhow::Context;
use bytes::Buf;
use ciborium::Value;
use coset::cwt::ClaimName;
use oak_crypto::{
    encryption_key::{generate_encryption_key_pair, EncryptionKey},
    encryptor::ServerEncryptor,
};
use oak_dice::cert::{generate_ecdsa_key_pair, SHA2_256_ID};
use oak_proto_rust::oak::{
    attestation::v1::{Event, SystemLayerData},
    crypto::v1::EncryptedRequest,
    key_provisioning::v1::GroupKeys as GroupKeysProto,
};
use prost::Message;

/// Measures the system image and returns a corresponding event log entry.
pub fn create_system_layer_event<B: oak_attestation::MeasureDigest>(system_image: B) -> Event {
    let digest = system_image.measure_digest();
    Event {
        tag: "stage1".to_string(),
        event: Some(prost_types::Any {
            type_url: "type.googleapis.com/oak.attestation.v1.SystemLayerData".to_string(),
            value: SystemLayerData { system_image: Some(digest) }.encode_to_vec(),
        }),
    }
}

/// Creates a container event that includes image bytes and configuration
/// measurements and public keys used by the container.
pub fn create_container_event<A: Buf, B: Buf>(
    container_bytes: A,
    config_bytes: B,
    instance_public_keys: &InstancePublicKeys,
) -> Event {
    let container_digest = oak_attestation::MeasureDigest::measure_digest(container_bytes);
    let config_digest = oak_attestation::MeasureDigest::measure_digest(config_bytes);
    Event {
        tag: "ORCHESTRATOR".to_string(),
        event: Some(prost_types::Any {
            type_url: "type.googleapis.com/oak.attestation.v1.ContainerLayerData".to_string(),
            value: oak_proto_rust::oak::attestation::v1::ContainerLayerData {
                bundle: Some(container_digest),
                config: Some(config_digest),
                hybrid_encryption_public_key: instance_public_keys.encryption_public_key.to_vec(),
                signing_public_key: instance_public_keys
                    .signing_public_key
                    .to_sec1_bytes()
                    .to_vec(),
                session_binding_public_key: instance_public_keys
                    .session_binding_public_key
                    .to_sec1_bytes()
                    .to_vec(),
            }
            .encode_to_vec(),
        }),
    }
}

/// Creates a wasm-workload event that includes the workload bundle and
/// configuration measurements, the instance public keys, and the (opaque to
/// Oak) CFC capability claim describing what the attested wasm composition can
/// do. Mirrors [`create_container_event`]; the extra `capability_claim` bytes
/// are replayed verbatim into the DICE event log and interpreted only by CFC's
/// KMS during key release.
pub fn create_wasm_workload_event<A: Buf, B: Buf>(
    bundle_bytes: A,
    config_bytes: B,
    capability_claim: alloc::vec::Vec<u8>,
    instance_public_keys: &InstancePublicKeys,
) -> Event {
    let bundle_digest = oak_attestation::MeasureDigest::measure_digest(bundle_bytes);
    let config_digest = oak_attestation::MeasureDigest::measure_digest(config_bytes);
    Event {
        tag: "ORCHESTRATOR".to_string(),
        event: Some(prost_types::Any {
            type_url: "type.googleapis.com/oak.attestation.v1.WasmWorkloadLayerData".to_string(),
            value: oak_proto_rust::oak::attestation::v1::WasmWorkloadLayerData {
                bundle: Some(bundle_digest),
                config: Some(config_digest),
                hybrid_encryption_public_key: instance_public_keys.encryption_public_key.to_vec(),
                signing_public_key: instance_public_keys
                    .signing_public_key
                    .to_sec1_bytes()
                    .to_vec(),
                session_binding_public_key: instance_public_keys
                    .session_binding_public_key
                    .to_sec1_bytes()
                    .to_vec(),
                capability_claim,
            }
            .encode_to_vec(),
        }),
    }
}

/// Measures the provided event and returns as an additional CWT claim.
pub fn create_container_dice_layer(event: &Event) -> oak_attestation::dice::LayerData {
    let encoded_event = event.encode_to_vec();
    let event_digest = oak_attestation::MeasureDigest::measure_digest(&encoded_event[..]);
    oak_attestation::LayerData {
        additional_claims: vec![(
            ClaimName::PrivateUse(oak_dice::cert::EVENT_ID),
            Value::Map(vec![(
                Value::Integer(SHA2_256_ID.into()),
                Value::Bytes(event_digest.sha2_256),
            )]),
        )],
        encoded_event,
    }
}

pub fn generate_instance_keys() -> (InstanceKeys, InstancePublicKeys) {
    let (encryption_key, encryption_public_key) = generate_encryption_key_pair();
    let (signing_key, signing_public_key) = generate_ecdsa_key_pair();
    let (session_binding_key, session_binding_public_key) = generate_ecdsa_key_pair();
    (
        InstanceKeys { encryption_key, signing_key, session_binding_key },
        InstancePublicKeys {
            encryption_public_key,
            signing_public_key,
            session_binding_public_key,
        },
    )
}

pub struct InstanceKeys {
    pub encryption_key: EncryptionKey,
    pub signing_key: p256::ecdsa::SigningKey,
    pub session_binding_key: p256::ecdsa::SigningKey,
}

pub struct InstancePublicKeys {
    pub encryption_public_key: Vec<u8>,
    pub signing_public_key: p256::ecdsa::VerifyingKey,
    pub session_binding_public_key: p256::ecdsa::VerifyingKey,
}

impl InstanceKeys {
    pub fn generate_group_keys(&self) -> (GroupKeys, GroupPublicKeys) {
        let (group_encryption_key, group_encryption_public_key) = generate_encryption_key_pair();
        (
            GroupKeys { encryption_key: group_encryption_key },
            GroupPublicKeys { encryption_public_key: group_encryption_public_key },
        )
    }

    pub fn provide_group_keys(&self, group_keys: GroupKeysProto) -> anyhow::Result<GroupKeys> {
        // Create server encryptor for decrypting the group keys received from the
        // leader enclave.
        let encrypted_encryption_private_key = group_keys
            .encrypted_encryption_private_key
            .context("encrypted encryption key wasn't provided")?;

        // Decrypt group keys.
        let (_, mut decrypted_encryption_private_key, _) =
            ServerEncryptor::decrypt(&encrypted_encryption_private_key, &self.encryption_key)
                .context("couldn't decrypt the encryption private key")?;

        let group_encryption_key =
            EncryptionKey::deserialize(&mut decrypted_encryption_private_key)
                .context("couldn't deserialize private key")?;

        Ok(GroupKeys { encryption_key: group_encryption_key })
    }
}

pub struct GroupKeys {
    pub encryption_key: EncryptionKey,
}

pub struct GroupPublicKeys {
    pub encryption_public_key: Vec<u8>,
}

impl GroupKeys {
    /// Returns group encryption private key which was encrypted with the
    /// `peer_public_key`.
    pub fn encrypted_group_encryption_key(
        &self,
        peer_public_key: &[u8],
    ) -> anyhow::Result<EncryptedRequest> {
        self.encryption_key.encrypted_private_key(peer_public_key)
    }
}

#[cfg(test)]
mod tests {
    use oak_proto_rust::oak::attestation::v1::WasmWorkloadLayerData;

    use super::*;

    #[test]
    fn wasm_workload_event_round_trips() {
        let (_instance_keys, public_keys) = generate_instance_keys();
        let claim = b"cfc-wasm-claim-opaque-bytes".to_vec();

        let event = create_wasm_workload_event(
            &b"bundle-bytes"[..],
            &b"config-bytes"[..],
            claim.clone(),
            &public_keys,
        );

        assert_eq!(event.tag, "ORCHESTRATOR");
        let any = event.event.expect("event payload present");
        assert_eq!(
            any.type_url,
            "type.googleapis.com/oak.attestation.v1.WasmWorkloadLayerData"
        );

        let decoded = WasmWorkloadLayerData::decode(&any.value[..]).expect("decodes");
        assert!(decoded.bundle.is_some(), "bundle digest measured");
        assert!(decoded.config.is_some(), "config digest measured");
        // The claim bytes are replayed verbatim (opaque to Oak).
        assert_eq!(decoded.capability_claim, claim);
        // Fields 3-5 mirror ContainerLayerData so key extraction is identical.
        assert_eq!(decoded.hybrid_encryption_public_key, public_keys.encryption_public_key);
        assert_eq!(
            decoded.signing_public_key,
            public_keys.signing_public_key.to_sec1_bytes().to_vec()
        );
        assert_eq!(
            decoded.session_binding_public_key,
            public_keys.session_binding_public_key.to_sec1_bytes().to_vec()
        );
    }
}
