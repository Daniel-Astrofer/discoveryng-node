use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use ed25519_dalek::{Signer, SigningKey};
use kerosene_contracts::{
    canonical_hash, member_id, CanonicalSignable, DiscoveryPlane, GenesisTrustBundleV1,
    ManifestMember, ManifestSignature, MembershipManifestV1, MembershipPhase,
    StateSnapshotAttestationV1, DISCOVERY_CONTRACT_VERSION,
};
use kerosene_membership::MembershipVerifier;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(
    name = "kerosene-rsctl",
    version,
    about = "Kerosene infrastructure administration client"
)]
struct Cli {
    #[arg(long, global = true, value_enum, default_value = "text")]
    output: Output,
    #[arg(long, global = true, default_value_t = 10)]
    timeout: u64,
    #[arg(long, global = true)]
    endpoint: Option<String>,
    #[arg(long, global = true)]
    profile: Option<String>,
    #[arg(long, global = true)]
    identity_pem: Option<PathBuf>,
    #[arg(long, global = true)]
    ca: Option<PathBuf>,
    #[arg(long, global = true)]
    socks5h: Option<String>,
    #[arg(long, global = true)]
    request_id: Option<String>,
    #[arg(long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Output {
    Text,
    Json,
    JsonPretty,
}

#[derive(Subcommand)]
enum Command {
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    Quorum {
        #[command(subcommand)]
        command: QuorumCommand,
    },
    Membership {
        #[command(subcommand)]
        command: MembershipCommand,
    },
    Snapshot {
        #[command(subcommand)]
        command: SnapshotCommand,
    },
    Artifact {
        #[command(subcommand)]
        command: ArtifactCommand,
    },
    Compatibility {
        #[command(subcommand)]
        command: CompatibilityCommand,
    },
    Doctor,
}

#[derive(Subcommand)]
enum NodeCommand {
    Status,
    Peers,
    Membership {
        #[command(subcommand)]
        command: NodeMembershipCommand,
    },
}

#[derive(Subcommand)]
enum NodeMembershipCommand {
    List,
}

#[derive(Subcommand)]
enum VaultCommand {
    Status,
    Health,
    Ceremony {
        #[command(subcommand)]
        command: CeremonyCommand,
    },
}

#[derive(Subcommand)]
enum CeremonyCommand {
    Inspect,
}

#[derive(Subcommand)]
enum QuorumCommand {
    Status,
}

#[derive(Subcommand)]
enum ArtifactCommand {
    Verify {
        path: PathBuf,
        #[arg(long)]
        sha256: Option<String>,
    },
}

#[derive(Subcommand)]
enum CompatibilityCommand {
    Check,
}

#[derive(Subcommand)]
enum MembershipCommand {
    Create(CreateManifest),
    Sign(SignManifest),
    Assemble(AssembleManifest),
    Verify(VerifyManifest),
    Publish(PublishManifest),
}

#[derive(Subcommand)]
enum SnapshotCommand {
    Create(CreateSnapshot),
    Sign(SignSnapshot),
    Assemble(AssembleSnapshot),
    Verify(VerifySnapshot),
}

#[derive(Args)]
struct CreateSnapshot {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    payload: PathBuf,
    #[arg(long)]
    snapshot_epoch: u64,
    #[arg(long)]
    created_at_epoch_ms: u64,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
struct SignSnapshot {
    #[arg(long)]
    attestation: PathBuf,
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    identity: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
struct AssembleSnapshot {
    #[arg(long)]
    attestation: PathBuf,
    #[arg(long = "signed-attestation", required = true)]
    signed_attestations: Vec<PathBuf>,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
struct VerifySnapshot {
    #[arg(long)]
    attestation: PathBuf,
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    payload: PathBuf,
    #[arg(long)]
    trust_bundle: PathBuf,
}

#[derive(Args)]
struct CreateManifest {
    #[arg(long)]
    network: String,
    #[arg(long, value_enum)]
    plane: Plane,
    #[arg(long)]
    epoch: u64,
    #[arg(long)]
    threshold: u16,
    #[arg(long)]
    members: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = false)]
    joint: bool,
    #[arg(
        long,
        default_value = "0000000000000000000000000000000000000000000000000000000000000000"
    )]
    previous_manifest_hash: String,
    #[arg(long)]
    next_epoch: Option<u64>,
}

#[derive(Args)]
struct SignManifest {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    identity: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
struct AssembleManifest {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long = "signed-manifest", required = true)]
    signed_manifests: Vec<PathBuf>,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
struct VerifyManifest {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    trust_bundle: PathBuf,
}

#[derive(Args)]
struct PublishManifest {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    endpoint: String,
    #[arg(long)]
    identity_pem: PathBuf,
    #[arg(long)]
    ca: PathBuf,
    #[arg(long)]
    socks5h: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Plane {
    Bank,
    Vault,
}

#[derive(Debug, Default, Deserialize)]
struct ProfilesFile {
    #[serde(default)]
    profiles: BTreeMap<String, Profile>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct Profile {
    node_endpoint: Option<String>,
    vault_endpoint: Option<String>,
    identity_file: Option<PathBuf>,
    ca_file: Option<PathBuf>,
    socks5h: Option<String>,
    vault_socket: Option<PathBuf>,
}

impl From<Plane> for DiscoveryPlane {
    fn from(value: Plane) -> Self {
        match value {
            Plane::Bank => Self::Bank,
            Plane::Vault => Self::Vault,
        }
    }
}

#[tokio::main]
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
    let needs_network_client = matches!(
        &cli.command,
        Command::Node { .. } | Command::Vault { .. } | Command::Quorum { .. } | Command::Doctor
    );
    if needs_network_client && (identity_pem.is_none() || ca.is_none() || socks5h.is_none()) {
        bail!("operator identity, CA and socks5h Tor proxy are required");
    }
    let request_id = request_id(cli.request_id.clone());
    let network_client = needs_network_client
        .then(|| admin_client(cli.timeout, identity_pem, ca, socks5h, None))
        .transpose()?;

    let value = match cli.command {
        Command::Node { command } => {
            let network_client = network_client
                .as_ref()
                .expect("network client was required");
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
                    get_json(network_client, &node_endpoint, path, &request_id).await?
                }
                NodeCommand::Peers => {
                    get_json(
                        network_client,
                        &node_endpoint,
                        "/v1/discovery/peers",
                        &request_id,
                    )
                    .await?
                }
            }
        }
        Command::Vault { command } => {
            let vault_client = network_client
                .as_ref()
                .expect("network client was required");
            let endpoint = endpoint(
                cli.endpoint.as_deref(),
                "KEROSENE_VAULT_ENDPOINT",
                profile
                    .as_ref()
                    .and_then(|value| value.vault_endpoint.as_deref()),
            )?;
            match command {
                VaultCommand::Status => {
                    get_json(vault_client, &endpoint, "/v1/admin/status", &request_id).await?
                }
                VaultCommand::Health => {
                    get_json(vault_client, &endpoint, "/v1/health", &request_id).await?
                }
                VaultCommand::Ceremony {
                    command: CeremonyCommand::Inspect,
                } => get_json(vault_client, &endpoint, "/v1/admin/ceremony", &request_id).await?,
            }
        }
        Command::Quorum {
            command: QuorumCommand::Status,
        } => {
            let network_client = network_client
                .as_ref()
                .expect("network client was required");
            let endpoint = endpoint(
                cli.endpoint.as_deref(),
                "KEROSENE_NODE_ENDPOINT",
                profile
                    .as_ref()
                    .and_then(|value| value.node_endpoint.as_deref()),
            )?;
            get_json(network_client, &endpoint, "/v1/readiness", &request_id).await?
        }
        Command::Compatibility {
            command: CompatibilityCommand::Check,
        } => json!({
            "compatible": true,
            "discovery_contract_version": DISCOVERY_CONTRACT_VERSION,
            "request_id": request_id
        }),
        Command::Artifact {
            command: ArtifactCommand::Verify { path, sha256 },
        } => artifact_verify(&path, sha256.as_deref())?,
        Command::Membership { command } => membership(command).await?,
        Command::Snapshot { command } => snapshot(command)?,
        Command::Doctor => {
            let network_client = network_client
                .as_ref()
                .expect("network client was required");
            let vault_client = network_client;
            let node_endpoint = endpoint(
                cli.endpoint.as_deref(),
                "KEROSENE_NODE_ENDPOINT",
                profile
                    .as_ref()
                    .and_then(|value| value.node_endpoint.as_deref()),
            )?;
            let live = get_json(network_client, &node_endpoint, "/live", &request_id).await?;
            let readiness =
                get_json(network_client, &node_endpoint, "/v1/readiness", &request_id).await?;
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
                        vault_client,
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

fn snapshot(command: SnapshotCommand) -> Result<Value> {
    match command {
        SnapshotCommand::Create(args) => {
            if args.snapshot_epoch == 0 || args.created_at_epoch_ms == 0 {
                bail!("snapshot epoch and creation time must be nonzero");
            }
            let manifest: MembershipManifestV1 = read_json(&args.manifest)?;
            let payload = fs::read(&args.payload)?;
            let membership_manifest_hash = canonical_hash(&manifest);
            let attestation = StateSnapshotAttestationV1 {
                contract_version: DISCOVERY_CONTRACT_VERSION.into(),
                network_id: manifest.network_id,
                plane: manifest.plane,
                membership_manifest_hash,
                snapshot_epoch: args.snapshot_epoch,
                state_root: hex::encode(Sha256::digest(payload)),
                created_at_epoch_ms: args.created_at_epoch_ms,
                signatures: Vec::new(),
            };
            write_private_json(&args.output, &attestation)?;
            Ok(
                json!({"created": true, "attestation_hash": canonical_hash(&attestation), "path": args.output}),
            )
        }
        SnapshotCommand::Sign(args) => {
            let mut attestation: StateSnapshotAttestationV1 = read_json(&args.attestation)?;
            let manifest: MembershipManifestV1 = read_json(&args.manifest)?;
            if attestation.network_id != manifest.network_id
                || attestation.plane != manifest.plane
                || attestation.membership_manifest_hash != canonical_hash(&manifest)
            {
                bail!("snapshot attestation is not bound to the membership manifest");
            }
            let secret = read_secret(&args.identity)?;
            let key = SigningKey::from_bytes(&secret);
            let signer_id = member_id(&manifest.network_id, key.verifying_key().as_bytes());
            if !manifest
                .members
                .iter()
                .any(|member| member.member_id == signer_id)
            {
                bail!("signing identity is absent from the membership roster");
            }
            attestation
                .signatures
                .retain(|signature| signature.signer_id != signer_id);
            attestation.signatures.push(ManifestSignature {
                signer_id,
                signature: hex::encode(key.sign(&attestation.signing_bytes()).to_bytes()),
            });
            write_private_json(&args.output, &attestation)?;
            Ok(
                json!({"signed": true, "attestation_hash": canonical_hash(&attestation), "path": args.output}),
            )
        }
        SnapshotCommand::Assemble(args) => {
            let mut attestation: StateSnapshotAttestationV1 = read_json(&args.attestation)?;
            let expected = attestation.signing_bytes();
            for path in args.signed_attestations {
                let signed: StateSnapshotAttestationV1 = read_json(&path)?;
                if signed.signing_bytes() != expected {
                    bail!(
                        "signed attestation {} does not describe the same snapshot",
                        path.display()
                    );
                }
                for signature in signed.signatures {
                    attestation
                        .signatures
                        .retain(|existing| existing.signer_id != signature.signer_id);
                    attestation.signatures.push(signature);
                }
            }
            attestation
                .signatures
                .sort_by(|left, right| left.signer_id.cmp(&right.signer_id));
            write_private_json(&args.output, &attestation)?;
            Ok(
                json!({"assembled": true, "signature_count": attestation.signatures.len(), "attestation_hash": canonical_hash(&attestation), "path": args.output}),
            )
        }
        SnapshotCommand::Verify(args) => {
            let attestation: StateSnapshotAttestationV1 = read_json(&args.attestation)?;
            let manifest: MembershipManifestV1 = read_json(&args.manifest)?;
            let bundle: GenesisTrustBundleV1 = read_json(&args.trust_bundle)?;
            if attestation.state_root != hex::encode(Sha256::digest(fs::read(&args.payload)?)) {
                bail!("snapshot payload digest differs from the attestation");
            }
            let mut verifier = MembershipVerifier::new(&bundle, manifest.plane)?;
            verifier.accept(manifest)?;
            verifier.verify_state_snapshot_attestation(&attestation)?;
            Ok(json!({"valid": true, "attestation_hash": canonical_hash(&attestation)}))
        }
    }
}

async fn membership(command: MembershipCommand) -> Result<Value> {
    match command {
        MembershipCommand::Create(args) => {
            let members: Vec<ManifestMember> = read_json(&args.members)?;
            if members.is_empty() {
                bail!("membership roster cannot be empty");
            }
            let manifest = MembershipManifestV1 {
                contract_version: DISCOVERY_CONTRACT_VERSION.into(),
                network_id: args.network,
                plane: args.plane.into(),
                epoch: args.epoch,
                phase: if args.joint {
                    MembershipPhase::Joint
                } else {
                    MembershipPhase::Stable
                },
                previous_manifest_hash: args.previous_manifest_hash,
                threshold: args.threshold,
                members,
                next_epoch: args.next_epoch,
                signatures: Vec::new(),
            };
            write_private_json(&args.output, &manifest)?;
            Ok(
                json!({"created": true, "manifest_hash": canonical_hash(&manifest), "path": args.output}),
            )
        }
        MembershipCommand::Sign(args) => {
            let mut manifest: MembershipManifestV1 = read_json(&args.manifest)?;
            let secret = read_secret(&args.identity)?;
            let key = SigningKey::from_bytes(&secret);
            let signer_id = member_id(&manifest.network_id, key.verifying_key().as_bytes());
            if !manifest
                .members
                .iter()
                .any(|member| member.member_id == signer_id)
            {
                bail!("signing identity is absent from the proposed roster");
            }
            manifest
                .signatures
                .retain(|signature| signature.signer_id != signer_id);
            manifest.signatures.push(ManifestSignature {
                signer_id,
                signature: hex::encode(key.sign(&manifest.signing_bytes()).to_bytes()),
            });
            write_private_json(&args.output, &manifest)?;
            Ok(
                json!({"signed": true, "manifest_hash": canonical_hash(&manifest), "path": args.output}),
            )
        }
        MembershipCommand::Assemble(args) => {
            let mut manifest: MembershipManifestV1 = read_json(&args.manifest)?;
            let expected = manifest.signing_bytes();
            for path in args.signed_manifests {
                let signed: MembershipManifestV1 = read_json(&path)?;
                if signed.signing_bytes() != expected {
                    bail!(
                        "signed manifest {} does not describe the same proposal",
                        path.display()
                    );
                }
                for signature in signed.signatures {
                    manifest
                        .signatures
                        .retain(|existing| existing.signer_id != signature.signer_id);
                    manifest.signatures.push(signature);
                }
            }
            manifest
                .signatures
                .sort_by(|left, right| left.signer_id.cmp(&right.signer_id));
            write_private_json(&args.output, &manifest)?;
            Ok(json!({
                "assembled": true,
                "signature_count": manifest.signatures.len(),
                "manifest_hash": canonical_hash(&manifest),
                "path": args.output
            }))
        }
        MembershipCommand::Verify(args) => {
            let manifest: MembershipManifestV1 = read_json(&args.manifest)?;
            let bundle: GenesisTrustBundleV1 = read_json(&args.trust_bundle)?;
            let mut verifier = MembershipVerifier::new(&bundle, manifest.plane)?;
            verifier.accept(manifest.clone())?;
            Ok(json!({"valid": true, "manifest_hash": canonical_hash(&manifest)}))
        }
        MembershipCommand::Publish(args) => {
            let manifest: MembershipManifestV1 = read_json(&args.manifest)?;
            let identity = reqwest::Identity::from_pem(&fs::read(args.identity_pem)?)?;
            let ca = reqwest::Certificate::from_pem(&fs::read(args.ca)?)?;
            let mut builder = reqwest::Client::builder()
                .https_only(true)
                .identity(identity)
                .add_root_certificate(ca)
                .timeout(Duration::from_secs(15));
            if let Some(proxy) = args.socks5h {
                if !proxy.starts_with("socks5h://") {
                    bail!("membership publish proxy must use socks5h://");
                }
                builder = builder.proxy(reqwest::Proxy::all(proxy)?);
            }
            let response = builder
                .build()?
                .post(format!(
                    "{}/v1/membership",
                    args.endpoint.trim_end_matches('/')
                ))
                .json(&manifest)
                .send()
                .await?
                .error_for_status()?
                .json::<Value>()
                .await?;
            Ok(response)
        }
    }
}

fn admin_client(
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

async fn get_json(
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

fn endpoint(cli: Option<&str>, env_name: &str, profile: Option<&str>) -> Result<String> {
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

fn load_profile(name: Option<&str>) -> Result<Option<Profile>> {
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

fn ensure_private_file(path: &Path) -> Result<()> {
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

fn request_id(value: Option<String>) -> String {
    value.unwrap_or_else(|| format!("rsctl-{}", std::process::id()))
}

fn artifact_verify(path: &Path, expected: Option<&str>) -> Result<Value> {
    let digest = hex::encode(Sha256::digest(fs::read(path)?));
    if expected.is_some_and(|value| !value.eq_ignore_ascii_case(&digest)) {
        bail!("artifact SHA-256 mismatch");
    }
    Ok(json!({"valid": true, "sha256": digest, "path": path}))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&fs::read(path).with_context(|| format!("read {}", path.display()))?)
        .with_context(|| format!("parse {}", path.display()))
}

fn read_secret(path: &Path) -> Result<[u8; 32]> {
    ensure_private_file(path)?;
    let bytes = hex::decode(fs::read_to_string(path)?.trim())?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("identity key must contain 32 bytes"))
}

fn write_private_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options.open(path)?.write_all(&bytes)?;
    Ok(())
}

fn print_value(output: Output, value: &Value) -> Result<()> {
    match output {
        Output::Text | Output::JsonPretty => println!("{}", serde_json::to_string_pretty(value)?),
        Output::Json => println!("{}", serde_json::to_string(value)?),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerosene_contracts::{TrustMember, TrustPlane};

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

    #[cfg(unix)]
    #[test]
    fn snapshot_ceremony_creates_signs_assembles_and_verifies() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let keys = [
            SigningKey::from_bytes(&[1; 32]),
            SigningKey::from_bytes(&[2; 32]),
        ];
        let members = keys
            .iter()
            .enumerate()
            .map(|(index, key)| ManifestMember {
                member_id: member_id("testnet", key.verifying_key().as_bytes()),
                root_public_key: hex::encode(key.verifying_key().as_bytes()),
                endpoint: format!(
                    "https://{}.onion:8800",
                    if index == 0 { "a" } else { "b" }.repeat(56)
                ),
            })
            .collect::<Vec<_>>();
        let mut manifest = MembershipManifestV1 {
            contract_version: DISCOVERY_CONTRACT_VERSION.into(),
            network_id: "testnet".into(),
            plane: DiscoveryPlane::Bank,
            epoch: 1,
            phase: MembershipPhase::Stable,
            previous_manifest_hash: "0".repeat(64),
            threshold: 2,
            members: members.clone(),
            next_epoch: None,
            signatures: Vec::new(),
        };
        manifest.signatures = keys
            .iter()
            .map(|key| ManifestSignature {
                signer_id: member_id("testnet", key.verifying_key().as_bytes()),
                signature: hex::encode(key.sign(&manifest.signing_bytes()).to_bytes()),
            })
            .collect();
        let trust_members = members
            .iter()
            .map(|member| TrustMember {
                member_id: member.member_id.clone(),
                root_public_key: member.root_public_key.clone(),
            })
            .collect::<Vec<_>>();
        let bundle = GenesisTrustBundleV1 {
            contract_version: DISCOVERY_CONTRACT_VERSION.into(),
            network_id: "testnet".into(),
            bank: TrustPlane {
                threshold: 2,
                members: trust_members.clone(),
            },
            vault: TrustPlane {
                threshold: 2,
                members: trust_members,
            },
            created_at_epoch_ms: 1,
        };
        let manifest_path = directory.path().join("manifest.json");
        let bundle_path = directory.path().join("genesis.json");
        let payload_path = directory.path().join("snapshot.bin");
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();
        fs::write(&payload_path, b"initial-state").unwrap();

        let unsigned = directory.path().join("unsigned.json");
        snapshot(SnapshotCommand::Create(CreateSnapshot {
            manifest: manifest_path.clone(),
            payload: payload_path.clone(),
            snapshot_epoch: 1,
            created_at_epoch_ms: 1,
            output: unsigned.clone(),
        }))
        .unwrap();
        let mut signed = Vec::new();
        for (index, key) in keys.iter().enumerate() {
            let identity = directory.path().join(format!("identity-{index}"));
            fs::write(&identity, hex::encode(key.to_bytes())).unwrap();
            fs::set_permissions(&identity, fs::Permissions::from_mode(0o600)).unwrap();
            let output = directory.path().join(format!("signed-{index}.json"));
            snapshot(SnapshotCommand::Sign(SignSnapshot {
                attestation: unsigned.clone(),
                manifest: manifest_path.clone(),
                identity,
                output: output.clone(),
            }))
            .unwrap();
            signed.push(output);
        }
        let assembled = directory.path().join("assembled.json");
        snapshot(SnapshotCommand::Assemble(AssembleSnapshot {
            attestation: unsigned,
            signed_attestations: signed,
            output: assembled.clone(),
        }))
        .unwrap();
        let result = snapshot(SnapshotCommand::Verify(VerifySnapshot {
            attestation: assembled,
            manifest: manifest_path,
            payload: payload_path,
            trust_bundle: bundle_path,
        }))
        .unwrap();
        assert_eq!(result["valid"], true);
    }
}
