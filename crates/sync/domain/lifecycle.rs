use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
/// Ordered stages a node must complete before it can participate as active.
pub enum LifecycleState {
    /// Runtime exists but identity setup has not completed.
    Created,
    /// Local identity and signing material are ready.
    IdentityReady,
    /// Required transport endpoints are configured and available.
    TransportReady,
    /// Peer discovery is in progress.
    Discovering,
    /// A peer identity has been authenticated.
    Authenticated,
    /// Membership proofs and admission policy have been verified.
    MemberVerified,
    /// State synchronization is in progress.
    Syncing,
    /// The synchronized snapshot has passed integrity verification.
    StateVerified,
    /// The node satisfies eligibility requirements but is not yet active.
    Eligible,
    /// The node is admitted to active participation.
    Active,
}

impl LifecycleState {
    /// Returns the only legal next lifecycle stage, or `None` at the terminal stage.
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Created => Some(Self::IdentityReady),
            Self::IdentityReady => Some(Self::TransportReady),
            Self::TransportReady => Some(Self::Discovering),
            Self::Discovering => Some(Self::Authenticated),
            Self::Authenticated => Some(Self::MemberVerified),
            Self::MemberVerified => Some(Self::Syncing),
            Self::Syncing => Some(Self::StateVerified),
            Self::StateVerified => Some(Self::Eligible),
            Self::Eligible => Some(Self::Active),
            Self::Active => None,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
/// Failures encountered while advancing lifecycle or verifying/persisting state.
pub enum SyncError {
    #[error("invalid lifecycle transition from {from:?} to {to:?}")]
    /// A requested transition skips or reverses a required lifecycle stage.
    InvalidTransition {
        /// Current lifecycle stage.
        from: LifecycleState,
        /// Requested lifecycle stage.
        to: LifecycleState,
    },
    #[error("snapshot state root mismatch")]
    /// Snapshot bytes do not hash to the declared state root.
    StateRootMismatch,
    #[error("lifecycle persistence failed: {0}")]
    /// Filesystem read or write failed while persisting lifecycle state.
    Io(String),
    #[error("lifecycle persistence is invalid: {0}")]
    /// Persisted lifecycle bytes could not be decoded as the lifecycle format.
    Json(String),
    #[error("state synchronization failed: {0}")]
    /// A synchronizer could not retrieve or reconcile the node state.
    Synchronization(String),
}

impl From<std::io::Error> for SyncError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<serde_json::Error> for SyncError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Persistable lifecycle cursor; transitions are checked by [`Lifecycle::advance`].
pub struct Lifecycle {
    /// Current stage in the node admission and synchronization sequence.
    state: LifecycleState,
}

impl Default for Lifecycle {
    /// Starts a new node at [`LifecycleState::Created`].
    fn default() -> Self {
        Self {
            state: LifecycleState::Created,
        }
    }
}

impl Lifecycle {
    /// Returns the current admission stage.
    pub fn state(&self) -> LifecycleState {
        self.state
    }

    /// Advances exactly one stage, rejecting skipped, repeated, or backward moves.
    ///
    /// # Errors
    /// Returns [`SyncError::InvalidTransition`] unless `target` equals the
    /// immediate successor of the current state.
    pub fn advance(&mut self, target: LifecycleState) -> Result<(), SyncError> {
        if self.state.next() != Some(target) {
            return Err(SyncError::InvalidTransition {
                from: self.state,
                to: target,
            });
        }
        self.state = target;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cannot_skip_authentication_or_membership() {
        let mut lifecycle = Lifecycle::default();
        assert!(matches!(
            lifecycle.advance(LifecycleState::Active),
            Err(SyncError::InvalidTransition { .. })
        ));
        lifecycle.advance(LifecycleState::IdentityReady).unwrap();
        lifecycle.advance(LifecycleState::TransportReady).unwrap();
        lifecycle.advance(LifecycleState::Discovering).unwrap();
        assert!(lifecycle.advance(LifecycleState::MemberVerified).is_err());
    }
}
