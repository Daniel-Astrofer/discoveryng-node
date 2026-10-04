//! Consensus port for the node runtime.
//!
//! The node owns lifecycle and validation decisions, while a consensus engine
//! owns ordering and commit.  Keeping this port small prevents the HTTP and
//! discovery adapters from depending on a specific CometBFT client.  A
//! CometBFT implementation can be added behind this trait without changing
//! the node's public API or the wire contracts.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Canonical proposal submitted to a consensus engine for ordering and commit.
pub struct ConsensusProposal {
    /// Consensus block height targeted by this proposal.
    pub height: u64,
    /// Consensus round within the proposal height.
    pub round: u32,
    /// Hash of canonical contract bytes, never an arbitrary JSON rendering.
    pub payload_hash: String,
    /// Canonical contract payload to be ordered and committed.
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Proof returned by a consensus implementation after committing a proposal.
pub struct CommitCertificate {
    /// Height at which the committed block was finalized.
    pub height: u64,
    /// Canonical hash identifying the committed block.
    pub block_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Human-readable consensus integration failure.
pub struct ConsensusError(pub String);

impl fmt::Display for ConsensusError {
    /// Writes the underlying consensus error message unchanged.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConsensusError {}

/// Application-facing consensus boundary.  Implementations must be
/// deterministic for a given proposal and must not mutate node state before a
/// commit certificate is returned.
pub trait ConsensusPort: Send + Sync {
    /// Submits a proposal and returns evidence that consensus committed it.
    ///
    /// # Errors
    /// Returns [`ConsensusError`] when no backend is configured or the engine
    /// cannot commit the proposal.
    fn submit(&self, proposal: ConsensusProposal) -> Result<CommitCertificate, ConsensusError>;
}

/// Explicit adapter used until a consensus backend is configured.  It keeps
/// consensus absence observable rather than silently pretending a proposal was
/// committed.
#[derive(Debug, Default, Clone, Copy)]
/// Placeholder consensus adapter that fails explicitly until a backend is configured.
pub struct UnconfiguredConsensus;

impl ConsensusPort for UnconfiguredConsensus {
    /// Returns an error without claiming that the proposal was committed.
    fn submit(&self, _proposal: ConsensusProposal) -> Result<CommitCertificate, ConsensusError> {
        Err(ConsensusError("consensus backend is not configured".into()))
    }
}
