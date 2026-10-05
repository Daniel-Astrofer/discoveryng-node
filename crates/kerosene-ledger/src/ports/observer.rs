use async_trait::async_trait;

use crate::consensus::chain::Observation;
use crate::domain::error::LedgerError;

// ---------------------------------------------------------------------------
// ChainObserverPort
// ---------------------------------------------------------------------------

/// Component that observes Bitcoin Core / LND and produces observations.
///
/// Never writes directly to the ledger — produces observations that must
/// go through consensus.
#[async_trait]
pub trait ChainObserverPort: Send + Sync {
    /// Poll Bitcoin Core for new blocks/transactions.
    async fn observe(&self) -> Result<Vec<Observation>, LedgerError>;
}
