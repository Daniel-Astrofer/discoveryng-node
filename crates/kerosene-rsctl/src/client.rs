use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Result};
use serde_json::Value;

use crate::cli::Output;

/// Constructs an HTTPS-only admin client using the configured mTLS and Tor credentials.
///
/// # Errors
/// Rejects Unix sockets, missing credentials, non-SOCKS5H proxies, permissive
/// identity-file permissions, and invalid PEM or client configuration.
pub fn admin_client(
    timeout: u64,
    identity_pem: Option<&Path>,
    ca: Option<&Path>,
    socks5h: Option<&str>,
    unix_socket: Option<&Path>,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(timeout));
    if unix_socket.is_some() {
        bail!("Unix-socket administration was removed");
    }
    let (identity_pem, ca, proxy) = match (identity_pem, ca, socks5h) {
        (Some(identity_pem), Some(ca), Some(proxy)) => (identity_pem, ca, proxy),
        _ => bail!("operator identity, CA and socks5h Tor proxy are required"),
    };
    if !proxy.starts_with("socks5h://") {
        bail!("proxy must use socks5h:// so DNS is resolved through Tor");
    }
    ensure_private_file(identity_pem)?;
    builder = builder
        .https_only(true)
        .identity(reqwest::Identity::from_pem(&fs::read(identity_pem)?)?)
        .add_root_certificate(reqwest::Certificate::from_pem(&fs::read(ca)?)?)
        .proxy(reqwest::Proxy::all(proxy)?);
    Ok(builder.build()?)
}

/// Sends an authenticated GET request with a request ID and decodes its JSON body.
///
/// # Errors
/// Returns transport, non-success HTTP status, or JSON decoding errors.
pub async fn get_json(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    request_id: &str,
) -> Result<Value> {
    Ok(client
        .get(format!("{}{}", base.trim_end_matches('/'), path))
        .header("X-Request-Id", request_id)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

/// Returns the supplied correlation ID or creates a process-scoped default.
pub fn request_id(value: Option<String>) -> String {
    value.unwrap_or_else(|| format!("rsctl-{}", std::process::id()))
}

/// Rejects credential files that are readable or writable by group or other users.
///
/// # Errors
/// Returns filesystem or permission-policy errors.
pub fn ensure_private_file(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        bail!("credential path must be a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("credential file permissions must not grant group or other access");
        }
    }
    Ok(())
}

/// Prints a JSON value using the requested text, compact JSON, or pretty JSON format.
///
/// # Errors
/// Returns serialization or stdout write errors.
pub fn print_value(output: Output, value: &Value) -> Result<()> {
    match output {
        Output::Text | Output::JsonPretty => println!("{}", serde_json::to_string_pretty(value)?),
        Output::Json => println!("{}", serde_json::to_string(value)?),
    }
    Ok(())
}
