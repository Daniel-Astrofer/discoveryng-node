use std::fs;
use std::path::{Path, PathBuf};

use crate::domain::{Lifecycle, SyncError};

/// Filesystem-backed store that atomically replaces serialized lifecycle state.
pub struct LifecycleStore {
    /// Destination file for the JSON lifecycle record.
    path: PathBuf,
}

impl LifecycleStore {
    /// Creates a lifecycle store targeting `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Loads the saved lifecycle, defaulting to [`LifecycleState::Created`] if absent.
    ///
    /// # Errors
    /// Returns [`SyncError::Io`] for filesystem errors or [`SyncError::Json`]
    /// when the stored record cannot be decoded.
    pub fn load(&self) -> Result<Lifecycle, SyncError> {
        if !self.path.exists() {
            return Ok(Lifecycle::default());
        }
        let bytes = fs::read(&self.path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Serializes lifecycle state to a sibling temporary file and renames it into place.
    ///
    /// # Errors
    /// Returns [`SyncError::Io`] for directory/file/rename failures and
    /// [`SyncError::Json`] if serialization fails.
    pub fn save(&self, lifecycle: &Lifecycle) -> Result<(), SyncError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = temporary_path(&self.path);
        let bytes = serde_json::to_vec(lifecycle)?;
        fs::write(&temporary, bytes)?;
        fs::rename(temporary, &self.path)?;
        Ok(())
    }
}

/// Derives the temporary sibling path used for an atomic lifecycle save.
fn temporary_path(path: &Path) -> PathBuf {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    temporary.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::LifecycleState;

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
