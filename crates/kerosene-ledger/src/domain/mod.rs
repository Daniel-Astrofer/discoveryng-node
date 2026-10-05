//! Deterministic financial state rules.

/// Account classes and canonical ledger account identifiers.
pub mod account;
/// Versioned account state and balance tracking.
pub mod account_state;
/// Balance query and projection types.
pub mod balance;
/// Command DTOs and operation-specific transfer inputs.
pub mod command;
/// Double-entry journal model and in-memory ledger implementation.
pub mod double_entry;
/// Domain errors returned by ledger validation and state transitions.
pub mod error;
/// Durable idempotency records for command processing.
pub mod idempotency;
/// Invariants enforced across deterministic ledger state.
pub mod invariants;
/// Nonce tracking and replay prevention.
pub mod nonce;
/// Atomic balance reservation model and lifecycle.
pub mod reservation;
/// Settlement authorization, PSBT commitment, and validation policy.
pub mod settlement;
/// Deterministic command state machine and serialized state transitions.
pub mod state_machine;
/// Wallet balance projection and control types.
pub mod wallet;
/// Withdrawal records and persistence contracts.
pub mod withdrawal;

pub use account::{AccountClass, StandardAccount};
pub use account_state::AccountState;
pub use balance::AccountBalanceState;
pub use command::{BalanceCommand, BalanceOperation, InternalTransferCommand};
pub use double_entry::{
    AccountBalance, InMemoryLedger, JournalEntry, JournalReceipt, LedgerPort, Posting,
};
pub use error::LedgerError;
pub use idempotency::IdempotencyRecord;
pub use nonce::{InMemoryNonceChecker, NonceChecker};
pub use reservation::{Reservation, ReservationState};
pub use settlement::{
    NonceChecker as SyncNonceChecker, PsbtCommitment, SettlementAuthorization, SettlementPolicy,
    SettlementValidator, VaultAuthorizationVerifier, VaultVerificationError,
};
pub use state_machine::{
    ConsensusProfile, DeterministicStateMachine, LedgerCommand, LedgerCommandType, LedgerState,
    MembershipView, StateMachine, StateTransitionReceipt,
};
pub use wallet::{BalanceView, WalletControl};
pub use withdrawal::{
    InMemoryWithdrawalStore, WithdrawalRecord, WithdrawalStatus, WithdrawalStore,
};
