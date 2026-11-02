use kerosene_identity_core::IdentityError;
use thiserror::Error;

#[derive(Debug, Error)]
/// Errors returned by peer authentication, endpoint discovery, and persistence.
pub enum DiscoveryError {
    /// Endpoint is not a credential-free HTTPS v3 onion URL.
    #[error("only HTTPS v3 onion endpoints are accepted")]
    InvalidEndpoint,
    /// Peer hello has a different contract version, network, or discovery plane.
    #[error("peer hello contract, network, or plane mismatch")]
    ScopeMismatch,
    /// Peer hello timestamp exceeds the configured clock-skew window.
    #[error("peer hello timestamp is outside the accepted window")]
    ClockSkew,
    /// Challenge is unknown, expired, or was already consumed.
    #[error("challenge is unknown, expired, or already consumed")]
    ChallengeRejected,
    /// Peer authenticated cryptographically but is absent from verified membership.
    #[error("peer is authenticated but is not a verified member")]
    NotMember,
    /// Local node attempted to authenticate itself as a remote peer.
    #[error("a node cannot authenticate itself as a remote peer")]
    SelfConnection,
    /// Identity key or signature validation failed.
    #[error("peer identity verification failed: {0}")]
    Identity(#[from] IdentityError),
    /// Peer-store filesystem operation failed.
    #[error("peer-store IO failed: {0}")]
    Io(#[from] std::io::Error),
    /// Peer-store JSON could not be decoded or encoded.
    #[error("peer-store data is invalid: {0}")]
    Json(#[from] serde_json::Error),
    /// Tor, TLS, HTTP, or response decoding failed.
    #[error("Tor transport failed: {0}")]
    Transport(String),
}
