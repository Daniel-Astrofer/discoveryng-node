use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use kerosene_contracts::DiscoveryPlane;
use zeroize::Zeroize;

use crate::domain::{IdentityError, NodeIdentity};

/// Filesystem adapter for loading or persisting network identity seeds.
pub struct FileIdentityStore;

impl FileIdentityStore {
    /// Loads an existing identity file or creates it atomically if absent.
    ///
    /// The file contains lowercase hex encoding of exactly 32 secret bytes.
    /// New files are created with mode `0600` on Unix, synchronized to disk,
    /// and the temporary secret buffers are cleared before return.
    pub fn load_or_create(
        path: &Path,
        network_id: impl Into<String>,
        plane: DiscoveryPlane,
    ) -> Result<NodeIdentity, IdentityError> {
        let network_id = network_id.into();
        match OpenOptions::new().read(true).open(path) {
            Ok(mut file) => {
                let mut encoded = String::new();
                file.read_to_string(&mut encoded)?;
                let mut bytes =
                    hex::decode(encoded.trim()).map_err(|_| IdentityError::InvalidSecret)?;
                if bytes.len() != 32 {
                    bytes.zeroize();
                    return Err(IdentityError::InvalidSecret);
                }
                let mut secret = [0_u8; 32];
                secret.copy_from_slice(&bytes);
                bytes.zeroize();
                let identity = NodeIdentity::from_secret(network_id, plane, secret);
                secret.zeroize();
                Ok(identity)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let identity = NodeIdentity::generate(network_id, plane);
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = options.open(path)?;
                let mut encoded = hex::encode(identity.secret_bytes());
                file.write_all(encoded.as_bytes())?;
                file.write_all(b"\n")?;
                file.sync_all()?;
                encoded.zeroize();
                Ok(identity)
            }
            Err(error) => Err(error.into()),
        }
    }
}
