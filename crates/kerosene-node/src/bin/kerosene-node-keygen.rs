//! Command-line utility for creating or displaying a node's public identity metadata.

use std::env;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use kerosene_contracts::DiscoveryPlane;
use kerosene_identity_core::NodeIdentity;
use serde_json::json;

/// Loads or creates the Bank-plane node identity and prints its public identifiers as JSON.
///
/// Expects exactly `<network-id> <identity-key-path>`. The identity file stores
/// the private seed; stdout contains only the network ID, derived member ID,
/// public key, and file path.
///
/// # Errors
/// Returns an error for missing or extra arguments, invalid UTF-8 network IDs,
/// identity file failures, or JSON serialization errors.
fn main() -> Result<()> {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_else(|| "kerosene-node-keygen".into());
    let Some(network_id) = args.next() else {
        bail!(
            "usage: {} <network-id> <identity-key-path>",
            PathBuf::from(program).display()
        );
    };
    let Some(identity_key_path) = args.next() else {
        bail!(
            "usage: {} <network-id> <identity-key-path>",
            PathBuf::from(program).display()
        );
    };
    if args.next().is_some() {
        bail!("unexpected extra arguments");
    }

    let network_id = network_id
        .into_string()
        .map_err(|_| anyhow::anyhow!("network ID must be valid UTF-8"))?;
    let identity_key_path = PathBuf::from(identity_key_path);
    let identity =
        NodeIdentity::load_or_create(&identity_key_path, &network_id, DiscoveryPlane::Bank)
            .with_context(|| {
                format!(
                    "failed to load or create identity at {}",
                    identity_key_path.display()
                )
            })?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "network_id": identity.network_id(),
            "member_id": identity.member_id(),
            "root_public_key": identity.root_public_key_hex(),
            "identity_key_path": identity_key_path,
        }))?
    );
    Ok(())
}
