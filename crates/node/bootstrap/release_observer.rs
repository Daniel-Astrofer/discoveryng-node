use anyhow::{anyhow, Context};
use ed25519_dalek::{pkcs8::DecodePrivateKey, SigningKey};
use kerosene_contracts::DiscoveryPlane;
use kerosene_release_observer::{BankEndpoint, BankTransport, ReleaseObserver};
use serde::Deserialize;
use std::{fs, path::PathBuf};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    observer_id: String,
    network_id: String,
    signing_key_der_path: PathBuf,
    state_path: PathBuf,
    banks: Vec<BankEndpoint>,
}
pub(super) fn from_env(
    plane: DiscoveryPlane,
    network: &str,
    identity_pem: Option<&PathBuf>,
    ca_path: &PathBuf,
    socks_proxy: &str,
) -> anyhow::Result<Option<ReleaseObserver>> {
    let Some(path) = std::env::var_os("KEROSENE_RELEASE_OBSERVER_CONFIG") else {
        return Ok(None);
    };
    if plane != DiscoveryPlane::Bank {
        return Err(anyhow!("release observer requires the Bank plane"));
    }
    let config: Config = serde_json::from_slice(&fs::read(path).context("read observer config")?)
        .context("parse observer config")?;
    if config.network_id != network {
        return Err(anyhow!("observer network mismatch"));
    }
    let identity_path = identity_pem
        .ok_or_else(|| anyhow!("observer requires KEROSENE_TLS_CLIENT_IDENTITY_PEM"))?;
    for key_path in [&config.signing_key_der_path, identity_path] {
        let metadata =
            fs::symlink_metadata(key_path).context("observer private credential metadata")?;
        if !metadata.is_file() {
            return Err(anyhow!(
                "observer private credential must be a regular file"
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(anyhow!(
                    "observer private credentials require mode 0600 or stricter"
                ));
            }
        }
    }
    let encoded = Zeroizing::new(
        fs::read(&config.signing_key_der_path).context("read observer signing key")?,
    );
    let key =
        SigningKey::from_pkcs8_der(&encoded).context("observer key must be Ed25519 PKCS8 DER")?;
    let identity = Zeroizing::new(fs::read(identity_path).context("read observer mTLS identity")?);
    let transport = BankTransport::new_mtls(
        &identity,
        &fs::read(ca_path).context("read observer Bank CA")?,
        Some(socks_proxy),
    )?;
    Ok(Some(ReleaseObserver::open(
        config.observer_id,
        config.network_id,
        key,
        config.banks,
        transport,
        &config.state_path,
    )?))
}
