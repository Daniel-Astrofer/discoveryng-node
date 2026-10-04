use async_trait::async_trait;
use kerosene_contracts::DiscoveryPlane;

use crate::domain::{DiscoveryError, EndpointRecord};

#[async_trait]
/// Supplies endpoint candidates for one discovery plane.
pub trait PeerDiscovery: Send + Sync {
    /// Discovers peer endpoints from the implementation's configured sources.
    async fn discover(&self, plane: DiscoveryPlane) -> Result<Vec<EndpointRecord>, DiscoveryError>;
}
