//! In-memory and persistent ledger adapters.

/// Volatile implementations intended for tests and single-process operation.
pub mod in_memory;
/// Sled-backed implementations for durable ledger state.
pub mod persistent;

pub use in_memory::{
    InMemoryIdempotencyStore, InMemoryReservationStore, InMemoryVersionedAccountStore,
};
pub use persistent::{
    SledIdempotencyStore, SledLedgerDb, SledMembershipStore, SledNonceChecker,
    SledReservationStore, SledSnapshotStore, SledUtxoStore, SledVersionedAccountStore,
    SledWithdrawalStore,
};
