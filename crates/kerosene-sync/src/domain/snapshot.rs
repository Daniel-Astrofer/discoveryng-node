use sha2::{Digest, Sha256};

use super::lifecycle::SyncError;

#[derive(Debug, Clone, PartialEq, Eq)]
/// State payload received from a synchronizer with its epoch and integrity digest.
pub struct StateSnapshot {
    /// Ledger or membership epoch represented by `bytes`.
    pub epoch: u64,
    /// Serialized state data whose digest is checked before acceptance.
    pub bytes: Vec<u8>,
    /// Lowercase hexadecimal SHA-256 digest expected for `bytes`.
    pub state_root: String,
}

impl StateSnapshot {
    /// Checks that the SHA-256 digest of the snapshot bytes matches `state_root`.
    ///
    /// # Errors
    /// Returns [`SyncError::StateRootMismatch`] when the declared root differs.
    pub fn verify(&self) -> Result<(), SyncError> {
        let actual = hex::encode(Sha256::digest(&self.bytes));
        if actual != self.state_root {
            return Err(SyncError::StateRootMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
