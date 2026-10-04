use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use kerosene_contracts::{
    member_id, CanonicalSignable, DiscoveryPlane, PeerHelloV1, DISCOVERY_CONTRACT_VERSION,
};
use rand::rngs::OsRng;
use thiserror::Error;

#[derive(Debug, Error)]
/// Failures raised while loading identities or authenticating signed peer messages.
pub enum IdentityError {
    /// Filesystem operation on the identity key failed.
    #[error("identity key IO failed: {0}")]
    Io(#[from] std::io::Error),
    /// Secret material was not exactly 32 bytes of lowercase hexadecimal text.
    #[error("identity key must contain exactly 32 bytes encoded as lowercase hex")]
    InvalidSecret,
    /// Peer public-key encoding or curve point was invalid.
    #[error("peer public key is invalid")]
    InvalidPublicKey,
    /// Peer signature encoding or signature verification was invalid.
    #[error("peer signature is invalid")]
    InvalidSignature,
    /// Network-bound member ID did not correspond to the supplied root key.
    #[error("peer member ID does not match its network-bound root key")]
    MemberIdMismatch,
}

/// Long-lived node identity scoped to one network and discovery plane.
///
/// The signing key remains private to this object. Peer messages expose only
/// its public key and a signature over the canonical contract representation.
pub struct NodeIdentity {
    network_id: String,
    plane: DiscoveryPlane,
    signing_key: SigningKey,
    member_id: String,
}

impl NodeIdentity {
    /// Generates a fresh operating-system-random Ed25519 identity.
    ///
    /// The returned identity is not persisted; use [`NodeIdentity::load_or_create`] when it
    /// must survive process restarts.
    pub fn generate(network_id: impl Into<String>, plane: DiscoveryPlane) -> Self {
        Self::from_signing_key(network_id.into(), plane, SigningKey::generate(&mut OsRng))
    }

    /// Constructs an identity from a 32-byte Ed25519 secret seed.
    ///
    /// Callers are responsible for securely sourcing and handling `secret`;
    /// the seed is not persisted by this method.
    pub fn from_secret(
        network_id: impl Into<String>,
        plane: DiscoveryPlane,
        secret: [u8; 32],
    ) -> Self {
        Self::from_signing_key(network_id.into(), plane, SigningKey::from_bytes(&secret))
    }

    /// Loads an existing identity file or creates it atomically if absent.
    ///
    /// Delegates to [`crate::adapters::FileIdentityStore::load_or_create`].
    pub fn load_or_create(
        path: &Path,
        network_id: impl Into<String>,
        plane: DiscoveryPlane,
    ) -> Result<Self, IdentityError> {
        crate::adapters::FileIdentityStore::load_or_create(path, network_id, plane)
    }

    /// Exposes raw secret bytes for persistent storage adapters within the crate.
    pub(crate) fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Returns the network-bound identifier derived from the root public key.
    pub fn member_id(&self) -> &str {
        &self.member_id
    }

    /// Returns the Ed25519 root public key as lowercase hexadecimal text.
    pub fn root_public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().as_bytes())
    }

    /// Returns the network namespace to which this identity belongs.
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// Returns the discovery plane this identity is authorized to represent.
    pub fn plane(&self) -> DiscoveryPlane {
        self.plane
    }

    /// Creates and signs a canonical peer hello for this identity's scope.
    ///
    /// The challenge and endpoint are included in the signed contract bytes,
    /// binding authentication to the current handshake and advertised address.
    pub fn sign_hello(
        &self,
        challenge: impl Into<String>,
        endpoint: impl Into<String>,
        issued_at_epoch_ms: u64,
    ) -> PeerHelloV1 {
        let mut hello = PeerHelloV1 {
            contract_version: DISCOVERY_CONTRACT_VERSION.into(),
            network_id: self.network_id.clone(),
            plane: self.plane,
            member_id: self.member_id.clone(),
            root_public_key: self.root_public_key_hex(),
            challenge: challenge.into(),
            issued_at_epoch_ms,
            endpoint: endpoint.into(),
            signature: String::new(),
        };
        hello.signature = hex::encode(self.signing_key.sign(&hello.signing_bytes()).to_bytes());
        hello
    }

    /// Verifies a peer hello's key encoding, member ID, and canonical signature.
    ///
    /// This check proves possession of the advertised key; callers must still
    /// validate network/plane scope, freshness, challenge use, and membership.
    pub fn verify_hello_signature(hello: &PeerHelloV1) -> Result<(), IdentityError> {
        let public_bytes = decode_array::<32>(&hello.root_public_key)
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        let verifying_key =
            VerifyingKey::from_bytes(&public_bytes).map_err(|_| IdentityError::InvalidPublicKey)?;
        if member_id(&hello.network_id, &public_bytes) != hello.member_id {
            return Err(IdentityError::MemberIdMismatch);
        }
        let signature_bytes =
            decode_array::<64>(&hello.signature).map_err(|_| IdentityError::InvalidSignature)?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify(&hello.signing_bytes(), &signature)
            .map_err(|_| IdentityError::InvalidSignature)
    }

    /// Derives this identity's member ID and stores its signing key and scope.
    fn from_signing_key(
        network_id: String,
        plane: DiscoveryPlane,
        signing_key: SigningKey,
    ) -> Self {
        let id = member_id(&network_id, signing_key.verifying_key().as_bytes());
        Self {
            network_id,
            plane,
            signing_key,
            member_id: id,
        }
    }
}

/// Decodes hexadecimal bytes and requires exactly `N` output bytes.
fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], hex::FromHexError> {
    let bytes = hex::decode(value)?;
    bytes
        .try_into()
        .map_err(|_| hex::FromHexError::InvalidStringLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_persists_and_does_not_change_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        let first = NodeIdentity::load_or_create(&path, "network-a", DiscoveryPlane::Bank).unwrap();
        let second =
            NodeIdentity::load_or_create(&path, "network-a", DiscoveryPlane::Bank).unwrap();
        assert_eq!(first.member_id(), second.member_id());
    }

    #[test]
    fn hello_binds_challenge_endpoint_plane_and_network() {
        let identity = NodeIdentity::from_secret("network-a", DiscoveryPlane::Vault, [9; 32]);
        let hello = identity.sign_hello(
            "a".repeat(64),
            format!("https://{}.onion", "b".repeat(56)),
            42,
        );
        NodeIdentity::verify_hello_signature(&hello).unwrap();

        let mut spoofed = hello.clone();
        spoofed.endpoint = format!("https://{}.onion", "c".repeat(56));
        assert!(matches!(
            NodeIdentity::verify_hello_signature(&spoofed),
            Err(IdentityError::InvalidSignature)
        ));
    }
}
