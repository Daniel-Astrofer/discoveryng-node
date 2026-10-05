//! Storage and observation capabilities required by the ledger core.

/// External chain observation capability.
pub mod observer;
/// Certified snapshot persistence capability.
pub mod snapshot;
/// Core account, reservation, and idempotency storage capabilities.
pub mod traits;
/// UTXO persistence and query capability.
pub mod utxo_store;

pub use observer::ChainObserverPort;
pub use snapshot::{InMemorySnapshotStore, SnapshotStore};
pub use traits::{IdempotencyStore, ReservationStore, VersionedAccountStore};
pub use utxo_store::{InMemoryUtxoStore, UtxoStore};
