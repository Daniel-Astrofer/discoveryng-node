use async_trait::async_trait;

use crate::domain::{StateSnapshot, SyncError};

#[async_trait]
/// Port implemented by adapters that fetch and reconcile a peer state snapshot.
pub trait StateSynchronizer: Send + Sync {
    /// Retrieves the snapshot selected by the adapter's synchronization policy.
    ///
    /// Implementations should return only after the payload and its metadata are
    /// available for the caller to verify with [`StateSnapshot::verify`].
    ///
    /// # Errors
    /// Returns [`SyncError::Synchronization`] for protocol or reconciliation
    /// failures; adapters may also surface persistence or decoding failures.
    async fn synchronize(&self) -> Result<StateSnapshot, SyncError>;
}
