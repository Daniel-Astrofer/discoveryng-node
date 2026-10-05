//! Consensus-facing certificates, chain observations and membership gates.

/// Quorum signatures and certified checkpoint representations.
pub mod certificate;
/// Chain observations, UTXO transitions, and reorganization handling.
pub mod chain;
/// Membership admission and voting eligibility rules.
pub mod membership;

pub use certificate::{CertifiedSnapshot, Checkpoint, NodeSignature, QuorumCertificate};
pub use chain::{
    apply_rbf_replacement, compute_utxo_root, ChainObservationType, DetectUtxoPayload, Observation,
    OnchainState, OutPoint, ReorgHandler, ReorgPayload, UtxoEntry, UtxoSet, UtxoTransitionGate,
};
pub use membership::{
    validate_role_transition, AdmissionFlow, InMemoryMembershipStore, MembershipGate,
    MembershipStore, NodeMembership, NodeRole, VotingGate,
};
