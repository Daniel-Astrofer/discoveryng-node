//! Infrastructure administration CLI for node, vault, quorum, membership, and artifact operations.

pub mod cli;
pub mod client;
pub mod commands;
pub mod config;

use anyhow::{bail, Result};
use clap::Parser;
use kerosene_contracts::DISCOVERY_CONTRACT_VERSION;
use serde_json::json;

use crate::cli::{
    CeremonyCommand, Cli, Command, NodeCommand, NodeMembershipCommand, QuorumCommand, VaultCommand,
};
use crate::client::{admin_client, get_json, print_value, request_id};
use crate::commands::{artifact_verify, membership};
use crate::config::{endpoint, load_profile};

#[tokio::main]
/// Parses CLI input, loads profile defaults, executes one operation, and formats its result.
///
/// Network commands require an mTLS identity, CA bundle, and SOCKS5H proxy;
/// endpoint overrides are restricted to HTTPS.
///
/// # Errors
/// Returns command-line, profile, transport, response, manifest, artifact, or
/// serialization errors without printing successful output.
async fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(if cli.verbose { "debug" } else { "warn" })
        .with_writer(std::io::stderr)
        .init();
    let profile = load_profile(cli.profile.as_deref())?;
    let identity_pem = cli.identity_pem.as_deref().or_else(|| {
        profile
            .as_ref()
            .and_then(|value| value.identity_file.as_deref())
    });
    let ca = cli
        .ca
        .as_deref()
        .or_else(|| profile.as_ref().and_then(|value| value.ca_file.as_deref()));
    let socks5h = cli
        .socks5h
        .as_deref()
        .or_else(|| profile.as_ref().and_then(|value| value.socks5h.as_deref()));
    if profile
        .as_ref()
        .and_then(|value| value.vault_socket.as_ref())
        .is_some()
    {
        bail!(
            "Unix-socket administration was removed; use the Vault HTTPS mTLS endpoint through Tor"
        );
    }
    let request_id = request_id(cli.request_id.clone());
    let needs_network_client = matches!(
        &cli.command,
        Command::Node { .. } | Command::Vault { .. } | Command::Quorum { .. } | Command::Doctor
    );
    let network_client = if needs_network_client {
        Some(admin_client(cli.timeout, identity_pem, ca, socks5h, None)?)
    } else {
        None
    };

    let value = match cli.command {
        Command::Node { command } => {
            let node_endpoint = endpoint(
                cli.endpoint.as_deref(),
                "KEROSENE_NODE_ENDPOINT",
                profile
                    .as_ref()
                    .and_then(|value| value.node_endpoint.as_deref()),
            )?;
            match command {
                NodeCommand::Status
                | NodeCommand::Membership {
                    command: NodeMembershipCommand::List,
                } => {
                    let path = if matches!(command, NodeCommand::Status) {
                        "/v1/readiness"
                    } else {
                        "/v1/membership/current"
                    };
                    get_json(
                        network_client.as_ref().expect("network client"),
                        &node_endpoint,
                        path,
                        &request_id,
                    )
                    .await?
                }
                NodeCommand::Peers => {
                    get_json(
                        network_client.as_ref().expect("network client"),
                        &node_endpoint,
                        "/v1/discovery/peers",
                        &request_id,
                    )
                    .await?
                }
            }
        }
        Command::Vault { command } => {
            let endpoint = endpoint(
                cli.endpoint.as_deref(),
                "KEROSENE_VAULT_ENDPOINT",
                profile
                    .as_ref()
                    .and_then(|value| value.vault_endpoint.as_deref()),
            )?;
            match command {
                VaultCommand::Status => {
                    get_json(
                        network_client.as_ref().expect("network client"),
                        &endpoint,
                        "/v1/admin/status",
                        &request_id,
                    )
                    .await?
                }
                VaultCommand::Health => {
                    get_json(
                        network_client.as_ref().expect("network client"),
                        &endpoint,
                        "/v1/health",
                        &request_id,
                    )
                    .await?
                }
                VaultCommand::Ceremony {
                    command: CeremonyCommand::Inspect,
                } => {
                    get_json(
                        network_client.as_ref().expect("network client"),
                        &endpoint,
                        "/v1/admin/ceremony",
                        &request_id,
                    )
                    .await?
                }
            }
        }
        Command::Quorum {
            command: QuorumCommand::Status,
        } => {
            let endpoint = endpoint(
                cli.endpoint.as_deref(),
                "KEROSENE_NODE_ENDPOINT",
                profile
                    .as_ref()
                    .and_then(|value| value.node_endpoint.as_deref()),
            )?;
            get_json(
                network_client.as_ref().expect("network client"),
                &endpoint,
                "/v1/readiness",
                &request_id,
            )
            .await?
        }
        Command::Compatibility {
            command: crate::cli::CompatibilityCommand::Check,
        } => json!({
            "compatible": true,
            "discovery_contract_version": DISCOVERY_CONTRACT_VERSION,
            "request_id": request_id
        }),
        Command::Artifact {
            command: crate::cli::ArtifactCommand::Verify { path, sha256 },
        } => artifact_verify(&path, sha256.as_deref())?,
        Command::Membership { command } => membership(command).await?,
        Command::Doctor => {
            let node_endpoint = endpoint(
                cli.endpoint.as_deref(),
                "KEROSENE_NODE_ENDPOINT",
                profile
                    .as_ref()
                    .and_then(|value| value.node_endpoint.as_deref()),
            )?;
            let live = get_json(
                network_client.as_ref().expect("network client"),
                &node_endpoint,
                "/live",
                &request_id,
            )
            .await?;
            let readiness = get_json(
                network_client.as_ref().expect("network client"),
                &node_endpoint,
                "/v1/readiness",
                &request_id,
            )
            .await?;
            let vault = if profile
                .as_ref()
                .and_then(|value| value.vault_endpoint.as_ref())
                .is_some()
            {
                let vault_endpoint = endpoint(
                    None,
                    "KEROSENE_VAULT_ENDPOINT",
                    profile
                        .as_ref()
                        .and_then(|value| value.vault_endpoint.as_deref()),
                )?;
                Some(
                    get_json(
                        network_client.as_ref().expect("network client"),
                        &vault_endpoint,
                        "/v1/admin/status",
                        &request_id,
                    )
                    .await?,
                )
            } else {
                None
            };
            json!({"healthy": true, "live": live, "readiness": readiness, "vault": vault})
        }
    };
    print_value(cli.output, &value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::membership::read_secret;
    use sha2::{Digest, Sha256};
    use std::fs;

    #[test]
    fn artifact_digest_is_verified() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("artifact");
        fs::write(&path, b"kerosene").unwrap();
        let digest = hex::encode(Sha256::digest(b"kerosene"));

        assert!(artifact_verify(&path, Some(&digest)).is_ok());
        assert!(artifact_verify(&path, Some(&"00".repeat(32))).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn identity_key_rejects_group_access() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity");
        fs::write(&path, "00".repeat(32)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        assert!(read_secret(&path).is_err());
    }
}
