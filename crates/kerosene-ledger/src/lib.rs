#[path = "domain/account.rs"]
pub mod account;
#[path = "domain/account_state.rs"]
pub mod account_state;
#[path = "domain/balance.rs"]
pub mod balance;
#[path = "consensus/certificate.rs"]
pub mod certificate;
#[path = "consensus/chain.rs"]
pub mod chain;
#[path = "domain/command.rs"]
pub mod command;
#[path = "domain/double_entry.rs"]
pub mod double_entry;
#[path = "domain/error.rs"]
pub mod error;
#[path = "application/gates.rs"]
pub mod gates;
#[path = "domain/idempotency.rs"]
pub mod idempotency;
#[path = "adapters/in_memory.rs"]
pub mod in_memory;
#[path = "domain/invariants.rs"]
pub mod invariants;
#[path = "consensus/membership.rs"]
pub mod membership;
#[path = "application/metrics.rs"]
pub mod metrics;
#[path = "domain/nonce.rs"]
pub mod nonce;
#[path = "ports/observer.rs"]
pub mod observer;
#[path = "adapters/persistent.rs"]
pub mod persistent;
#[path = "application/reconciliation.rs"]
pub mod reconciliation;
#[path = "application/replication.rs"]
pub mod replication;
#[path = "domain/reservation.rs"]
pub mod reservation;
#[path = "domain/settlement.rs"]
pub mod settlement;
#[path = "ports/snapshot.rs"]
pub mod snapshot;
#[path = "domain/state_machine.rs"]
pub mod state_machine;
#[path = "integrity/state_root.rs"]
pub mod state_root;
#[path = "ports/traits.rs"]
pub mod traits;
#[path = "ports/utxo_store.rs"]
pub mod utxo_store;
#[path = "domain/wallet.rs"]
pub mod wallet;
#[path = "domain/withdrawal.rs"]
pub mod withdrawal;

pub use account::{AccountClass, StandardAccount};
pub use account_state::AccountState;
pub use balance::AccountBalanceState;
pub use certificate::{CertifiedSnapshot, Checkpoint, NodeSignature, QuorumCertificate};
pub use chain::{
    apply_rbf_replacement, compute_utxo_root, ChainObservationType, DetectUtxoPayload, Observation,
    OnchainState, OutPoint, ReorgHandler, ReorgPayload, UtxoEntry, UtxoSet, UtxoTransitionGate,
};
pub use command::{BalanceCommand, BalanceOperation, InternalTransferCommand};
pub use double_entry::{
    AccountBalance, InMemoryLedger, JournalEntry, JournalReceipt, LedgerPort, Posting,
};
pub use error::LedgerError;
pub use gates::{DegradedMode, GateResult, ProductionGates};
pub use idempotency::IdempotencyRecord;
pub use in_memory::{
    InMemoryIdempotencyStore, InMemoryReservationStore, InMemoryVersionedAccountStore,
};
pub use membership::{
    validate_role_transition, AdmissionFlow, InMemoryMembershipStore, MembershipGate,
    MembershipStore, NodeMembership, NodeRole, VotingGate,
};
pub use metrics::{BasicMetricsCollector, LedgerMetrics, MetricsCollector};
pub use observer::ChainObserverPort;
pub use reconciliation::{
    ReconciliationEngine, ReconciliationInputs, ReconciliationReport, ReconciliationStatus,
};
pub use replication::{
    can_vote, execute_catch_up, recover_divergence, CatchUpPlan, CatchUpStrategy, DivergenceReport,
    DivergenceResult, ReplicationStatus, SyncManager, SyncStatus, DIVERGENCE_CHECK_INTERVAL,
    MAX_REPLAY_COMMANDS,
};
pub use reservation::{Reservation, ReservationState};
pub use snapshot::{InMemorySnapshotStore, SnapshotStore};
pub use state_machine::{
    ConsensusProfile, DeterministicStateMachine, LedgerCommand, LedgerCommandType, LedgerState,
    MembershipView, StateMachine, StateTransitionReceipt,
};
pub use state_root::compute_state_root;
pub use traits::{IdempotencyStore, ReservationStore, VersionedAccountStore};
pub use utxo_store::{InMemoryUtxoStore, UtxoStore};
pub use wallet::{BalanceView, WalletControl};

// Persistent sled-backed stores (production-ready)
pub use persistent::{
    SledIdempotencyStore, SledLedgerDb, SledMembershipStore, SledNonceChecker,
    SledReservationStore, SledSnapshotStore, SledUtxoStore, SledVersionedAccountStore,
    SledWithdrawalStore,
};

// Wave 6 — Settlement authorization, PSBT binding, withdrawal lifecycle
pub use nonce::{InMemoryNonceChecker, NonceChecker};
pub use settlement::{
    NonceChecker as SyncNonceChecker, PsbtCommitment, SettlementAuthorization, SettlementPolicy,
    SettlementValidator, VaultAuthorizationVerifier, VaultVerificationError,
};
pub use withdrawal::{
    InMemoryWithdrawalStore, WithdrawalRecord, WithdrawalStatus, WithdrawalStore,
};

#[cfg(test)]
mod tests;
