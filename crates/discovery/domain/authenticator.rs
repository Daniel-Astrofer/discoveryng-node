use std::sync::Arc;

use kerosene_contracts::{DiscoveryPlane, PeerHelloV1, DISCOVERY_CONTRACT_VERSION};
use kerosene_identity_core::NodeIdentity;
use kerosene_membership::MembershipVerifier;
use parking_lot::RwLock;

use super::challenge::ChallengeStore;
use super::error::DiscoveryError;
use super::peer::{validate_onion_endpoint, AuthenticatedPeer};

/// Validates peer hello scope, freshness, endpoint, signature, challenge, and membership.
pub struct PeerAuthenticator {
    network_id: String,
    plane: DiscoveryPlane,
    max_clock_skew_ms: u64,
    challenges: Arc<ChallengeStore>,
    membership: Arc<RwLock<MembershipVerifier>>,
}

impl PeerAuthenticator {
    /// Creates an authenticator bound to one network, plane, skew limit, and membership view.
    pub fn new(
        network_id: impl Into<String>,
        plane: DiscoveryPlane,
        max_clock_skew_ms: u64,
        challenges: Arc<ChallengeStore>,
        membership: Arc<RwLock<MembershipVerifier>>,
    ) -> Self {
        Self {
            network_id: network_id.into(),
            plane,
            max_clock_skew_ms,
            challenges,
            membership,
        }
    }

    /// Authenticates a hello and returns a peer record only after all gates pass.
    ///
    /// Validation order checks scope and timestamp before endpoint and signature;
    /// the one-time challenge is consumed before membership is accepted.
    pub fn authenticate(
        &self,
        hello: &PeerHelloV1,
        now_epoch_ms: u64,
    ) -> Result<AuthenticatedPeer, DiscoveryError> {
        if hello.contract_version != DISCOVERY_CONTRACT_VERSION
            || hello.network_id != self.network_id
            || hello.plane != self.plane
        {
            return Err(DiscoveryError::ScopeMismatch);
        }
        if hello.issued_at_epoch_ms.abs_diff(now_epoch_ms) > self.max_clock_skew_ms {
            return Err(DiscoveryError::ClockSkew);
        }
        validate_onion_endpoint(&hello.endpoint)?;
        NodeIdentity::verify_hello_signature(hello)?;
        self.challenges.consume(&hello.challenge, now_epoch_ms)?;
        if !self
            .membership
            .read()
            .is_member(&hello.member_id, &hello.root_public_key)
        {
            return Err(DiscoveryError::NotMember);
        }
        Ok(AuthenticatedPeer {
            member_id: hello.member_id.clone(),
            plane: hello.plane,
            root_public_key: hello.root_public_key.clone(),
            endpoint: hello.endpoint.clone(),
            authenticated_at_epoch_ms: now_epoch_ms,
        })
    }
}
