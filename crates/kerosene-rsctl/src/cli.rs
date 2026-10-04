use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use kerosene_contracts::DiscoveryPlane;

#[derive(Parser)]
/// Global CLI options and selected administration command.
#[command(
    name = "kerosene-rsctl",
    version,
    about = "Kerosene infrastructure administration client"
)]
pub struct Cli {
    #[arg(
        id = "format",
        long = "format",
        global = true,
        value_enum,
        default_value = "text"
    )]
    /// Output encoding shared by commands that return structured data.
    pub output: Output,
    #[arg(long, global = true, default_value_t = 10)]
    /// Per-request HTTP timeout in seconds.
    pub timeout: u64,
    #[arg(long, global = true)]
    /// Command endpoint override, normally an HTTPS service base URL.
    pub endpoint: Option<String>,
    #[arg(long, global = true)]
    /// Named profile loaded from the configured profiles TOML file.
    pub profile: Option<String>,
    #[arg(long, global = true)]
    /// Client certificate and key PEM used for authenticated admin requests.
    pub identity_pem: Option<PathBuf>,
    #[arg(long, global = true)]
    /// CA bundle for validating the remote service certificate.
    pub ca: Option<PathBuf>,
    #[arg(long, global = true)]
    /// Optional SOCKS5 proxy URL with remote hostname resolution.
    pub socks5h: Option<String>,
    #[arg(long, global = true)]
    /// Correlation ID sent with requests; a process-specific value is generated if absent.
    pub request_id: Option<String>,
    #[arg(long, global = true)]
    /// Enables debug-level CLI logs on stderr.
    pub verbose: bool,
    #[command(subcommand)]
    /// Administrative command tree selected by the caller.
    pub command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
/// Supported output encodings for command results.
pub enum Output {
    /// Human-readable text output.
    Text,
    /// Compact JSON output.
    Json,
    /// Indented JSON output for inspection or scripting.
    JsonPretty,
}

#[derive(Subcommand)]
/// Top-level resource groups exposed by the administration CLI.
pub enum Command {
    /// Inspect the discovery node and its peers.
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    /// Inspect vault status, health, and ceremony state.
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    /// Inspect cross-node quorum readiness.
    Quorum {
        #[command(subcommand)]
        command: QuorumCommand,
    },
    /// Create, sign, assemble, verify, or publish membership manifests.
    Membership {
        #[command(subcommand)]
        command: MembershipCommand,
    },
    /// Verify a local artifact against an optional SHA-256 digest.
    Artifact {
        #[command(subcommand)]
        command: ArtifactCommand,
    },
    /// Check service contract compatibility.
    Compatibility {
        #[command(subcommand)]
        command: CompatibilityCommand,
    },
    /// Run local environment and connectivity diagnostics.
    Doctor,
}

#[derive(Subcommand)]
/// Commands that query node status or membership endpoints.
pub enum NodeCommand {
    /// Fetch node readiness status.
    Status,
    /// List authenticated peer endpoints.
    Peers,
    /// Query node membership data.
    Membership {
        #[command(subcommand)]
        command: NodeMembershipCommand,
    },
}

#[derive(Subcommand)]
/// Read-only commands for node membership state.
pub enum NodeMembershipCommand {
    /// List accepted membership records.
    List,
}

#[derive(Subcommand)]
/// Commands for inspecting a vault process.
pub enum VaultCommand {
    /// Fetch vault status.
    Status,
    /// Fetch vault health.
    Health,
    /// Inspect DKG ceremony configuration and progress.
    Ceremony {
        #[command(subcommand)]
        command: CeremonyCommand,
    },
}

#[derive(Subcommand)]
/// Read-only ceremony inspection commands.
pub enum CeremonyCommand {
    /// Display current ceremony state.
    Inspect,
}

#[derive(Subcommand)]
/// Commands for quorum status queries.
pub enum QuorumCommand {
    /// Fetch current quorum membership and readiness.
    Status,
}

#[derive(Subcommand)]
/// Commands for validating files and local artifacts.
pub enum ArtifactCommand {
    /// Compute a file digest and optionally compare it with the expected value.
    Verify {
        /// File whose bytes are checked.
        path: PathBuf,
        /// Optional expected lowercase hexadecimal SHA-256 digest.
        #[arg(long)]
        sha256: Option<String>,
    },
}

#[derive(Subcommand)]
/// Commands for checking CLI/service contract compatibility.
pub enum CompatibilityCommand {
    /// Query compatibility metadata from the configured service.
    Check,
}

#[derive(Subcommand)]
/// Membership-manifest lifecycle operations.
pub enum MembershipCommand {
    /// Construct a manifest from a roster file.
    Create(CreateManifest),
    /// Sign a manifest using a local identity seed.
    Sign(SignManifest),
    /// Assemble signatures into a manifest.
    Assemble(AssembleManifest),
    /// Verify a manifest against a genesis trust bundle.
    Verify(VerifyManifest),
    /// Publish a verified manifest through the authenticated node API.
    Publish(PublishManifest),
}

#[derive(Args)]
/// Inputs used to construct a stable or joint-consensus membership manifest.
pub struct CreateManifest {
    /// Network namespace included in the manifest.
    #[arg(long)]
    pub network: String,
    /// Bank or vault membership plane.
    #[arg(long, value_enum)]
    pub plane: Plane,
    /// Epoch assigned to the manifest.
    #[arg(long)]
    pub epoch: u64,
    /// Signature quorum required by the proposed roster.
    #[arg(long)]
    pub threshold: u16,
    /// JSON roster input containing member IDs, root keys, and endpoints.
    #[arg(long)]
    pub members: PathBuf,
    /// Destination path for the generated manifest JSON.
    #[arg(long)]
    pub output: PathBuf,
    /// Whether to create a JOINT phase manifest for a proposed roster change.
    #[arg(long, default_value_t = false)]
    pub joint: bool,
    /// Hash of the previous manifest; zero hash is used for an initial manifest.
    #[arg(
        long,
        default_value = "0000000000000000000000000000000000000000000000000000000000000000"
    )]
    pub previous_manifest_hash: String,
    /// Next epoch to enter after the joint-consensus phase, when applicable.
    #[arg(long)]
    pub next_epoch: Option<u64>,
}

#[derive(Args)]
/// Inputs for signing a membership manifest with a local identity.
pub struct SignManifest {
    /// Manifest JSON to sign.
    #[arg(long)]
    pub manifest: PathBuf,
    /// Local identity seed file used to produce the signature.
    #[arg(long)]
    pub identity: PathBuf,
    /// Destination path for the signed manifest JSON.
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args)]
/// Inputs for collecting signed manifests into one quorum-signed manifest.
pub struct AssembleManifest {
    /// Unsigned manifest whose signature list will be populated.
    #[arg(long)]
    pub manifest: PathBuf,
    /// Signed copies whose signatures are collected.
    #[arg(long = "signed-manifest", required = true)]
    pub signed_manifests: Vec<PathBuf>,
    /// Destination path for the assembled manifest JSON.
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args)]
/// Inputs for offline verification of a manifest against genesis trust.
pub struct VerifyManifest {
    /// Manifest JSON to validate.
    #[arg(long)]
    pub manifest: PathBuf,
    /// Genesis trust bundle establishing the initial signer quorums.
    #[arg(long)]
    pub trust_bundle: PathBuf,
}

#[derive(Args)]
/// Inputs for publishing a manifest to a peer over authenticated Tor transport.
pub struct PublishManifest {
    /// Manifest JSON to send to the node.
    #[arg(long)]
    pub manifest: PathBuf,
    /// HTTPS onion endpoint of the receiving node.
    #[arg(long)]
    pub endpoint: String,
    /// Outbound mTLS client certificate and key PEM.
    #[arg(long)]
    pub identity_pem: PathBuf,
    /// CA bundle for validating the receiving node certificate.
    #[arg(long)]
    pub ca: PathBuf,
    /// Optional SOCKS5H proxy URL used for onion transport.
    #[arg(long)]
    pub socks5h: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
/// Membership plane encoded in manifest operations.
pub enum Plane {
    /// Bank discovery and membership plane.
    Bank,
    /// Vault discovery and membership plane.
    Vault,
}

impl From<Plane> for DiscoveryPlane {
    /// Converts the CLI plane selector into the canonical wire-contract enum.
    fn from(value: Plane) -> Self {
        match value {
            Plane::Bank => Self::Bank,
            Plane::Vault => Self::Vault,
        }
    }
}
