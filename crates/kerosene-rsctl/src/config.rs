use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
/// Top-level shape of the optional named profile configuration file.
pub struct ProfilesFile {
    /// Profile names mapped to their endpoint and credential defaults.
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

#[derive(Debug, Clone, Default, Deserialize)]
/// Optional endpoint and credential defaults loaded for a selected profile.
pub struct Profile {
    /// Default discovery-node API endpoint.
    pub node_endpoint: Option<String>,
    /// Default vault admin API endpoint.
    pub vault_endpoint: Option<String>,
    /// Default path to outbound client identity PEM.
    pub identity_file: Option<PathBuf>,
    /// Default CA bundle path for remote TLS validation.
    pub ca_file: Option<PathBuf>,
    /// Default SOCKS5H proxy URL for Tor-routed requests.
    pub socks5h: Option<String>,
    /// Default local Unix socket path for vault admin requests.
    pub vault_socket: Option<PathBuf>,
}

/// Loads one named profile from the TOML file selected by environment or user config.
///
/// # Errors
/// Rejects unsafe profile names, missing configuration files, malformed TOML,
/// and names absent from the profiles map.
pub fn load_profile(name: Option<&str>) -> Result<Option<Profile>> {
    let Some(name) = name else {
        return Ok(None);
    };
    if name.is_empty()
        || !name
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_'))
    {
        bail!("profile name contains unsupported characters");
    }
    let path = std::env::var_os("KEROSENE_PROFILES_FILE")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".config/kerosene/profiles.toml"))
        })
        .ok_or_else(|| anyhow!("HOME or KEROSENE_PROFILES_FILE is required for --profile"))?;
    let profiles: ProfilesFile = toml::from_str(
        &fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?,
    )
    .with_context(|| format!("parse {}", path.display()))?;
    profiles
        .profiles
        .get(name)
        .cloned()
        .map(Some)
        .ok_or_else(|| anyhow!("profile {name} is absent from {}", path.display()))
}

/// Resolves an endpoint from CLI override, environment, or profile in that precedence order.
///
/// # Errors
/// Returns an error when no non-empty value exists or when the URL is not HTTPS.
pub fn endpoint(cli: Option<&str>, env_name: &str, profile: Option<&str>) -> Result<String> {
    let value = cli
        .map(str::to_owned)
        .or_else(|| std::env::var(env_name).ok())
        .or_else(|| profile.map(str::to_owned))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("--endpoint, {env_name}, or a profile endpoint is required"))?;
    if !value.starts_with("https://") {
        bail!("operator endpoints must use https:// mTLS");
    }
    Ok(value)
}
