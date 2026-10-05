use kerosene_contracts::{DiscoveryPlane, ManifestMember, MembershipManifestV1};
use serde::{Deserialize, Serialize};

use super::error::DiscoveryError;

/// Peer identity and endpoint accepted by the authentication boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    /// Network-bound member identifier verified from the root key.
    pub member_id: String,
    /// Discovery plane in which this peer was authenticated.
    pub plane: DiscoveryPlane,
    /// Lowercase-hex root public key that signed the peer hello.
    pub root_public_key: String,
    /// Validated HTTPS onion service endpoint.
    pub endpoint: String,
    /// Local authentication time in Unix epoch milliseconds.
    pub authenticated_at_epoch_ms: u64,
}

/// Persisted authentication record retained for future connection ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPeer {
    /// Verified network member identifier.
    pub member_id: String,
    /// Discovery plane associated with the authenticated identity.
    pub plane: DiscoveryPlane,
    /// Verified root public key encoded as lowercase hex.
    pub root_public_key: String,
    /// Last authenticated onion endpoint for this peer.
    pub endpoint: String,
    /// Time at which the peer identity was authenticated.
    pub authenticated_at_epoch_ms: u64,
    /// Most recent successful connection time, if it has connected before.
    pub last_success_epoch_ms: Option<u64>,
}

/// One discovered endpoint with the source and observation time preserved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRecord {
    /// Member expected to be reachable at this endpoint.
    pub member_id: String,
    /// HTTPS onion URL to try during peer connection.
    pub endpoint: String,
    /// Discovery mechanism that supplied the endpoint.
    pub source: DiscoverySource,
    /// Source observation time in Unix epoch milliseconds.
    pub observed_at_epoch_ms: u64,
}

/// Provenance category used when endpoints are merged into connection candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    /// Endpoint succeeded in a previous connection attempt.
    PreviousConnection,
    /// Endpoint is listed by the currently accepted membership manifest.
    CurrentManifest,
    /// Endpoint came from the network's initial bootstrap list.
    Genesis,
    /// Endpoint came from a configured manifest mirror.
    Mirror,
    /// Endpoint was advertised by a cryptographically authenticated peer.
    AuthenticatedPeer,
}

/// Record of a completed connection used to prioritize future attempts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessfulConnection {
    /// Verified member that was reached.
    pub member_id: String,
    /// Onion endpoint that completed the connection.
    pub endpoint: String,
    /// Successful connection time in Unix epoch milliseconds.
    pub connected_at_epoch_ms: u64,
}

/// Accepts only HTTPS v3 onion URLs without credentials, paths, query, or fragment.
///
/// Delegates directly to [`kerosene_membership::validate_onion_endpoint`].
pub fn validate_onion_endpoint(endpoint: &str) -> Result<(), DiscoveryError> {
    kerosene_membership::validate_onion_endpoint(endpoint)
        .map_err(|_| DiscoveryError::InvalidEndpoint)
}

/// Converts manifest members to endpoint records while preserving manifest order.
pub fn manifest_endpoint_records(manifest: &MembershipManifestV1) -> Vec<EndpointRecord> {
    manifest
        .members
        .iter()
        .map(manifest_member_to_endpoint)
        .collect()
}

/// Maps one manifest member to an endpoint candidate with manifest provenance.
fn manifest_member_to_endpoint(member: &ManifestMember) -> EndpointRecord {
    EndpointRecord {
        member_id: member.member_id.clone(),
        endpoint: member.endpoint.clone(),
        source: DiscoverySource::CurrentManifest,
        observed_at_epoch_ms: 0,
    }
}
