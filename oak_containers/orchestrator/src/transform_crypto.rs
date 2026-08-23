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

//! CFC confidential-transform crypto for the wasm session workload.
//!
//! Two distinct schemes meet here:
//!
//! 1. **Key release.** The KMS wraps the released key bundle
//!    (`fcp.confidentialcompute` `ProtectedResponse`) as an
//!    `oak.crypto.v1.EncryptedRequest`, encrypted to the transform's application
//!    (instance) encryption key. [`TransformKeys::from_protected_response`]
//!    unwraps it with the instance [`EncryptionKey`] (via oak's
//!    [`ServerEncryptor`]) and parses the COSE decryption keys out of it.
//!
//! 2. **The data plane** uses the two-layer FCP blob format: the payload is
//!    encrypted with a fresh AES-128-GCM-SIV symmetric key, and that symmetric
//!    key (itself a COSE_Key) is HPKE-sealed to one of the released public keys.
//!    [`TransformKeys::decrypt_blob`] reverses both layers with the released
//!    decryption keys.
//!
//! This is the Rust counterpart of the crypto in the C++ `ConfidentialTransform`
//! stack; it is kept wire-compatible with the client-side implementation used by
//! the demo harness (see `containers/demo_cluster/src/key_derivation.rs`).

use aes_gcm_siv::{
    aead::{Aead, Payload},
    Aes128GcmSiv, KeyInit,
};
use anyhow::{anyhow, bail, Context, Result};
use coset::{iana, Algorithm, CborSerializable, CoseKey, KeyType, Label};
use hpke::{
    aead::AesGcm128, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeR,
};
use oak_crypto::{encryption_key::EncryptionKey, encryptor::ServerEncryptor};
use oak_proto_rust::{
    fcp::confidentialcompute::{blob_metadata, ProtectedResponse},
    oak::crypto::v1::EncryptedRequest,
};
use prost::Message;

/// COSE algorithm id for HPKE-Base-X25519-SHA256-AES128GCM (used to wrap the
/// per-blob symmetric key).
const HPKE_BASE_X25519_SHA256_AES128GCM: i64 = -65537;
/// COSE algorithm id for AEAD_AES_128_GCM_SIV with a fixed nonce (the symmetric
/// layer that protects the payload itself).
const AEAD_AES_128_GCM_SIV_FIXED_NONCE: i64 = -65538;

/// HPKE info string. The FCP wrapping scheme leaves this empty.
const HPKE_INFO: [u8; 0] = [];

/// Fixed AES-GCM-SIV nonce. Safe to reuse because each symmetric key is used
/// exactly once. Must match the client-side value byte-for-byte.
const NONCE: [u8; 12] =
    [0x74, 0xDF, 0x8F, 0xD4, 0xBE, 0x34, 0xAF, 0x64, 0x7F, 0x5E, 0x54, 0xF6];

/// An HPKE private key the KMS released for decrypting inputs, parsed from its
/// COSE_Key form.
struct DecryptionKey {
    /// The COSE `kid`; also the `key_id` in each blob's `BlobHeader`.
    key_id: Vec<u8>,
    /// Raw X25519 private key bytes (the COSE `d` parameter).
    private_key: Vec<u8>,
}

/// The keys the KMS released to this transform. Currently only the input
/// decryption keys are retained; result-encryption keys will be added with the
/// output path (P3).
pub struct TransformKeys {
    decryption_keys: Vec<DecryptionKey>,
}

impl TransformKeys {
    /// Decrypts and parses the KMS's released key bundle.
    ///
    /// `protected_response` is the `oak.crypto.v1.EncryptedRequest` carried in
    /// `InitializeRequest.protected_response`; `instance_key` is the transform's
    /// application encryption key (the private half of the attested
    /// `hybrid_encryption_public_key`).
    pub fn from_protected_response(
        protected_response: &EncryptedRequest,
        instance_key: &EncryptionKey,
    ) -> Result<Self> {
        let (_encryptor, plaintext, _associated_data) =
            ServerEncryptor::decrypt(protected_response, instance_key)
                .context("decrypting protected_response with the instance key")?;
        let bundle = ProtectedResponse::decode(plaintext.as_slice())
            .context("decoding ProtectedResponse")?;
        let decryption_keys = bundle
            .decryption_keys
            .iter()
            .map(|cose| parse_decryption_key(cose))
            .collect::<Result<Vec<_>>>()
            .context("parsing released decryption keys")?;
        if decryption_keys.is_empty() {
            bail!("ProtectedResponse contained no decryption keys");
        }
        Ok(Self { decryption_keys })
    }

    /// Decrypts one `HpkePlusAead`-encrypted input blob to plaintext.
    ///
    /// `ciphertext` is the `WriteRequest.data`; `metadata` is the blob's
    /// `HpkePlusAeadMetadata`.
    pub fn decrypt_blob(
        &self,
        metadata: &blob_metadata::HpkePlusAeadMetadata,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        // The associated data bound into the HPKE wrapping is the serialized
        // BlobHeader carried in the KMS associated-data component. We only need
        // it as opaque AAD, not its parsed fields.
        let record_header = match metadata.symmetric_key_associated_data_components.as_ref() {
            Some(
                blob_metadata::hpke_plus_aead_metadata::SymmetricKeyAssociatedDataComponents::KmsSymmetricKeyAssociatedData(kms),
            ) => kms.record_header.as_slice(),
            Some(_) => bail!("blob uses a non-KMS (deprecated) associated-data component"),
            None => bail!("blob is missing symmetric-key associated data"),
        };

        // Recover the per-blob symmetric key by HPKE-opening the wrapped key with
        // whichever released decryption key succeeds. HPKE open is authenticated,
        // so a non-matching key fails cleanly rather than returning garbage.
        let symmetric_cose = self
            .unwrap_symmetric_key(
                &metadata.encrypted_symmetric_key,
                &metadata.encapsulated_public_key,
                record_header,
            )
            .context("unwrapping the blob's symmetric key")?;

        let raw_symmetric_key = parse_symmetric_key(&symmetric_cose)
            .context("parsing the unwrapped symmetric key")?;

        let cipher = Aes128GcmSiv::new_from_slice(&raw_symmetric_key)
            .map_err(|err| anyhow!("loading AES-128-GCM-SIV key: {err:?}"))?;
        cipher
            .decrypt(
                (&NONCE).into(),
                Payload { msg: ciphertext, aad: &metadata.ciphertext_associated_data },
            )
            .map_err(|err| anyhow!("decrypting blob payload: {err:?}"))
    }

    /// HPKE-opens the wrapped symmetric key, trying each released decryption key.
    fn unwrap_symmetric_key(
        &self,
        encrypted_symmetric_key: &[u8],
        encapsulated_public_key: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let encapped_key =
            <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(encapsulated_public_key)
                .map_err(|err| anyhow!("loading encapsulated key: {err:?}"))?;

        let mut last_err = anyhow!("no released decryption keys");
        for key in &self.decryption_keys {
            let sk = match <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&key.private_key) {
                Ok(sk) => sk,
                Err(err) => {
                    last_err = anyhow!("loading private key {:?}: {err:?}", key.key_id);
                    continue;
                }
            };
            match hpke::single_shot_open::<AesGcm128, HkdfSha256, X25519HkdfSha256>(
                &OpModeR::Base,
                &sk,
                &encapped_key,
                &HPKE_INFO,
                encrypted_symmetric_key,
                associated_data,
            ) {
                Ok(plaintext) => return Ok(plaintext),
                Err(err) => last_err = anyhow!("HPKE open with key {:?}: {err:?}", key.key_id),
            }
        }
        Err(last_err)
    }
}

/// Parses a COSE_Key HPKE private key (OKP / X25519, alg -65537) into a
/// [`DecryptionKey`].
fn parse_decryption_key(cose_bytes: &[u8]) -> Result<DecryptionKey> {
    let cose = CoseKey::from_slice(cose_bytes)
        .map_err(|err| anyhow!("decoding COSE decryption key: {err:?}"))?;
    if cose.kty != KeyType::Assigned(iana::KeyType::OKP) {
        bail!("decryption key is not an OKP key: {:?}", cose.kty);
    }
    if cose.alg != Some(Algorithm::PrivateUse(HPKE_BASE_X25519_SHA256_AES128GCM)) {
        bail!("decryption key has unexpected algorithm: {:?}", cose.alg);
    }
    let private_key = cose
        .params
        .iter()
        .find(|(label, _)| label == &Label::Int(iana::OkpKeyParameter::D as i64))
        .and_then(|(_, value)| value.as_bytes())
        .ok_or_else(|| anyhow!("COSE decryption key missing the `d` parameter"))?
        .clone();
    Ok(DecryptionKey { key_id: cose.key_id, private_key })
}

/// Extracts the raw symmetric key bytes from an unwrapped COSE_Key (Symmetric,
/// alg -65538).
fn parse_symmetric_key(cose_bytes: &[u8]) -> Result<Vec<u8>> {
    let cose = CoseKey::from_slice(cose_bytes)
        .map_err(|err| anyhow!("decoding COSE symmetric key: {err:?}"))?;
    if cose.kty != KeyType::Assigned(iana::KeyType::Symmetric)
        || cose.alg != Some(Algorithm::PrivateUse(AEAD_AES_128_GCM_SIV_FIXED_NONCE))
    {
        bail!("unexpected symmetric key type/alg: {:?}/{:?}", cose.kty, cose.alg);
    }
    cose.params
        .iter()
        .find(|(label, _)| label == &Label::Int(iana::SymmetricKeyParameter::K as i64))
        .and_then(|(_, value)| value.as_bytes())
        .cloned()
        .ok_or_else(|| anyhow!("COSE symmetric key missing the `k` parameter"))
}

#[cfg(test)]
mod tests {
    use hpke::{OpModeS, Serializable};
    use oak_crypto::{encryption_key::generate_encryption_key_pair, encryptor::ClientEncryptor};
    use rand_core::{OsRng, RngCore};

    use super::*;

    /// Builds a COSE_Key for an X25519 HPKE private key, mirroring the client.
    fn private_cose_key(key_id: &[u8], private_key: &[u8]) -> Vec<u8> {
        CoseKey {
            kty: KeyType::Assigned(iana::KeyType::OKP),
            key_id: key_id.to_vec(),
            alg: Some(Algorithm::PrivateUse(HPKE_BASE_X25519_SHA256_AES128GCM)),
            params: vec![
                (
                    Label::Int(iana::OkpKeyParameter::Crv as i64),
                    (iana::EllipticCurve::X25519 as u64).into(),
                ),
                (
                    Label::Int(iana::OkpKeyParameter::D as i64),
                    coset::cbor::value::Value::Bytes(private_key.to_vec()),
                ),
            ],
            ..Default::default()
        }
        .to_vec()
        .unwrap()
    }

    /// Builds a COSE_Key wrapping a raw AES-128-GCM-SIV symmetric key.
    fn symmetric_cose_key(raw: &[u8]) -> Vec<u8> {
        CoseKey {
            kty: KeyType::Assigned(iana::KeyType::Symmetric),
            alg: Some(Algorithm::PrivateUse(AEAD_AES_128_GCM_SIV_FIXED_NONCE)),
            params: vec![(
                Label::Int(iana::SymmetricKeyParameter::K as i64),
                coset::cbor::value::Value::Bytes(raw.to_vec()),
            )],
            ..Default::default()
        }
        .to_vec()
        .unwrap()
    }

    // Generates an X25519 keypair and returns (public, private).
    fn gen_x25519() -> (Vec<u8>, Vec<u8>) {
        let (private_key, public_key) = <X25519HkdfSha256 as Kem>::gen_keypair(&mut OsRng);
        (public_key.to_bytes().to_vec(), private_key.to_bytes().to_vec())
    }

    #[test]
    fn round_trip_protected_response_and_blob() {
        // The KMS-derived input keypair the client encrypts to.
        let key_id = b"kid-1".to_vec();
        let (input_pub, input_priv) = gen_x25519();

        // The KMS wraps the released bundle to the transform's instance key.
        let (instance_key, instance_pub) = generate_encryption_key_pair();
        let bundle = ProtectedResponse {
            decryption_keys: vec![private_cose_key(&key_id, &input_priv)],
            result_encryption_keys: vec![],
        };
        let protected_response = ClientEncryptor::create(&instance_pub)
            .unwrap()
            .encrypt(&bundle.encode_to_vec(), b"")
            .unwrap();

        // Transform side: unwrap the bundle with the instance key.
        let keys = TransformKeys::from_protected_response(&protected_response, &instance_key)
            .expect("protected response decrypts");

        // Client side: encrypt a payload to the released input public key.
        let plaintext = b"the quick brown fox";
        let record_header = b"serialized-blob-header";
        let ciphertext_aad = b"ciphertext-aad";
        let (metadata, ciphertext) = client_encrypt_blob_full(
            plaintext,
            &input_pub,
            record_header,
            ciphertext_aad,
        );

        // Transform side: decrypt the blob.
        let recovered = keys.decrypt_blob(&metadata, &ciphertext).expect("blob decrypts");
        assert_eq!(recovered, plaintext);
    }

    /// Client-side two-layer blob encryption, mirroring the demo harness:
    /// AES-128-GCM-SIV over the payload, then HPKE-seal the symmetric COSE key to
    /// the recipient public key. Returns the blob metadata and the ciphertext.
    fn client_encrypt_blob_full(
        plaintext: &[u8],
        recipient_public_key: &[u8],
        record_header: &[u8],
        ciphertext_associated_data: &[u8],
    ) -> (blob_metadata::HpkePlusAeadMetadata, Vec<u8>) {
        let mut raw_key = [0u8; 16];
        OsRng.fill_bytes(&mut raw_key);
        let cipher = Aes128GcmSiv::new_from_slice(&raw_key).unwrap();
        let ciphertext = cipher
            .encrypt(
                (&NONCE).into(),
                Payload { msg: plaintext, aad: ciphertext_associated_data },
            )
            .unwrap();

        let pk = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(recipient_public_key).unwrap();
        let (encapped, encrypted_symmetric_key) =
            hpke::single_shot_seal::<AesGcm128, HkdfSha256, X25519HkdfSha256, _>(
                &OpModeS::Base,
                &pk,
                &HPKE_INFO,
                &symmetric_cose_key(&raw_key),
                record_header,
                &mut OsRng,
            )
            .unwrap();

        let metadata = blob_metadata::HpkePlusAeadMetadata {
            ciphertext_associated_data: ciphertext_associated_data.to_vec(),
            encrypted_symmetric_key,
            encapsulated_public_key: encapped.to_bytes().to_vec(),
            blob_id: b"blob-1".to_vec(),
            symmetric_key_associated_data_components: Some(
                blob_metadata::hpke_plus_aead_metadata::SymmetricKeyAssociatedDataComponents::KmsSymmetricKeyAssociatedData(
                    blob_metadata::hpke_plus_aead_metadata::KmsAssociatedData {
                        record_header: record_header.to_vec(),
                    },
                ),
            ),
            // Deprecated fields (e.g. `counter`) default to their zero values.
            ..Default::default()
        };
        (metadata, ciphertext)
    }

    #[test]
    fn wrong_instance_key_fails() {
        let (input_pub, input_priv) = gen_x25519();
        let _ = input_pub;
        let (_instance_key, instance_pub) = generate_encryption_key_pair();
        let (other_key, _other_pub) = generate_encryption_key_pair();
        let bundle = ProtectedResponse {
            decryption_keys: vec![private_cose_key(b"kid-1", &input_priv)],
            result_encryption_keys: vec![],
        };
        let protected_response = ClientEncryptor::create(&instance_pub)
            .unwrap()
            .encrypt(&bundle.encode_to_vec(), b"")
            .unwrap();
        // Decrypting with the wrong instance key must fail.
        assert!(
            TransformKeys::from_protected_response(&protected_response, &other_key).is_err()
        );
    }
}