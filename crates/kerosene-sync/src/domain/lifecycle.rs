use std::fs;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleState {
    Created,
    IdentityReady,
    TransportReady,
    Discovering,
    Authenticated,
    MemberVerified,
    Syncing,
    StateVerified,
    Eligible,
    Active,
}

impl LifecycleState {
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
pub enum SyncError {
    #[error("invalid lifecycle transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: LifecycleState,
        to: LifecycleState,
    },
    #[error("snapshot state root mismatch")]
    StateRootMismatch,
    #[error("snapshot epoch regressed")]
    SnapshotEpochRegression,
    #[error("snapshot epoch was reused with a different state root")]
    SnapshotEpochConflict,
    #[error("lifecycle persistence failed: {0}")]
    Io(String),
    #[error("lifecycle persistence is invalid: {0}")]
    Json(String),
    #[error("state synchronization failed: {0}")]
    Synchronization(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lifecycle {
    state: LifecycleState,
    #[serde(default)]
    verified_state: Option<VerifiedStateBinding>,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            state: LifecycleState::Created,
            verified_state: None,
        }
    }
}

impl Lifecycle {
    pub fn state(&self) -> LifecycleState {
        self.state
    }

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

    pub fn bind_verified_state(&mut self, binding: VerifiedStateBinding) -> Result<(), SyncError> {
        if let Some(current) = &self.verified_state {
            if binding.snapshot_epoch < current.snapshot_epoch {
                return Err(SyncError::SnapshotEpochRegression);
            }
            if binding.snapshot_epoch == current.snapshot_epoch
                && (binding.state_root != current.state_root
                    || binding.membership_manifest_hash != current.membership_manifest_hash)
            {
                return Err(SyncError::SnapshotEpochConflict);
            }
            self.verified_state = Some(binding);
            return Ok(());
        }
        self.advance(LifecycleState::StateVerified)?;
        self.verified_state = Some(binding);
        Ok(())
    }

    pub fn verified_state(&self) -> Option<&VerifiedStateBinding> {
        self.verified_state.as_ref()
    }

    pub fn require_state_revalidation(&mut self) {
        if matches!(
            self.state,
            LifecycleState::StateVerified | LifecycleState::Eligible | LifecycleState::Active
        ) {
            self.state = LifecycleState::Syncing;
        }
        self.verified_state = None;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedStateBinding {
    pub membership_manifest_hash: String,
    pub snapshot_epoch: u64,
    pub state_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSnapshot {
    pub epoch: u64,
    pub bytes: Vec<u8>,
    pub state_root: String,
}

impl StateSnapshot {
    pub fn verify(&self) -> Result<(), SyncError> {
        let actual = hex::encode(Sha256::digest(&self.bytes));
        if actual != self.state_root {
            return Err(SyncError::StateRootMismatch);
        }
        Ok(())
    }
}

#[async_trait]
pub trait StateSynchronizer: Send + Sync {
    async fn synchronize(&self) -> Result<StateSnapshot, SyncError>;
}

pub struct LifecycleStore {
    path: PathBuf,
}

impl LifecycleStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load(&self) -> Result<Lifecycle, SyncError> {
        if !self.path.exists() {
            return Ok(Lifecycle::default());
        }
        let bytes = fs::read(&self.path).map_err(|error| SyncError::Io(error.to_string()))?;
        serde_json::from_slice(&bytes).map_err(|error| SyncError::Json(error.to_string()))
    }

    pub fn save(&self, lifecycle: &Lifecycle) -> Result<(), SyncError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|error| SyncError::Io(error.to_string()))?;
        }
        let temporary = temporary_path(&self.path);
        let bytes =
            serde_json::to_vec(lifecycle).map_err(|error| SyncError::Json(error.to_string()))?;
        fs::write(&temporary, bytes).map_err(|error| SyncError::Io(error.to_string()))?;
        fs::rename(temporary, &self.path).map_err(|error| SyncError::Io(error.to_string()))
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    temporary.into()
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

    #[test]
    fn state_root_is_verified_before_state_can_be_accepted() {
        let bytes = b"deterministic-state".to_vec();
        let snapshot = StateSnapshot {
            epoch: 7,
            state_root: hex::encode(Sha256::digest(&bytes)),
            bytes,
        };
        snapshot.verify().unwrap();
        let mut corrupt = snapshot;
        corrupt.bytes.push(0);
        assert_eq!(corrupt.verify(), Err(SyncError::StateRootMismatch));
    }

    #[test]
    fn lifecycle_survives_restart() {
        let directory = tempfile::tempdir().unwrap();
        let store = LifecycleStore::new(directory.path().join("lifecycle.db"));
        let mut lifecycle = Lifecycle::default();
        lifecycle.advance(LifecycleState::IdentityReady).unwrap();
        store.save(&lifecycle).unwrap();
        assert_eq!(store.load().unwrap().state(), LifecycleState::IdentityReady);
    }
}
