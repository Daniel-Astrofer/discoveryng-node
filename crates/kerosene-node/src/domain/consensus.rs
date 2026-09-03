//! Consensus port for the node runtime.
//!
//! The node owns lifecycle and validation decisions, while a consensus engine
//! owns ordering and commit.  Keeping this port small prevents the HTTP and
//! discovery adapters from depending on a specific CometBFT client.  A
//! CometBFT implementation can be added behind this trait without changing
//! the node's public API or the wire contracts.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusProposal {
    pub height: u64,
    pub round: u32,
    /// Hash of canonical contract bytes, never an arbitrary JSON rendering.
    pub payload_hash: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitCertificate {
    pub height: u64,
    pub block_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusError(pub String);

impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConsensusError {}

/// Application-facing consensus boundary.  Implementations must be
/// deterministic for a given proposal and must not mutate node state before a
/// commit certificate is returned.
pub trait ConsensusPort: Send + Sync {
    fn submit(&self, proposal: ConsensusProposal) -> Result<CommitCertificate, ConsensusError>;
}

/// Explicit adapter used until a consensus backend is configured.  It keeps
/// consensus absence observable rather than silently pretending a proposal was
/// committed.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnconfiguredConsensus;

impl ConsensusPort for UnconfiguredConsensus {
    fn submit(&self, _proposal: ConsensusProposal) -> Result<CommitCertificate, ConsensusError> {
        Err(ConsensusError("consensus backend is not configured".into()))
    }
}
