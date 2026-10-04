use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::{now_epoch_ms, NodeService};
use anyhow::{anyhow, Context};
use kerosene_contracts::{DiscoveryPlane, GenesisTrustBundleV1};
use kerosene_discovery::{
    validate_onion_endpoint, DiscoverySource, EndpointRecord, PersistentPeerStore,
    TorHandshakeClient,
};
use kerosene_identity_core::NodeIdentity;
use kerosene_ledger::SledLedgerDb;
use kerosene_membership::MembershipVerifier;
use kerosene_sync::LifecycleStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tracing::{info, warn};

/// Validated configuration loaded from node runtime environment variables.
struct Config {
    /// Network namespace to which identity and membership are bound.
    network_id: String,
    /// Membership plane operated by this process.
    plane: DiscoveryPlane,
    /// Local TCP address on which the HTTP server listens.
    listen_addr: SocketAddr,
    /// Public HTTPS onion endpoint advertised to peers.
    onion_endpoint: String,
    /// File containing the local Ed25519 identity seed.
    identity_key: PathBuf,
    /// Genesis trust bundle used to seed membership verification.
    genesis_bundle: PathBuf,
    /// Directory containing durable peer, manifest, and lifecycle data.
    peer_store: PathBuf,
    /// Server certificate presented by the HTTP listener.
    tls_cert: PathBuf,
    /// Private key corresponding to the server certificate.
    tls_key: PathBuf,
    /// CA bundle used to validate inbound mTLS client certificates.
    tls_client_ca: PathBuf,
    /// Optional PEM identity used for outbound authenticated peer connections.
    tls_client_identity: Option<PathBuf>,
    /// SOCKS proxy URL; remote DNS resolution is required for onion hosts.
    socks_proxy: String,
    /// Configured genesis peer endpoints.
    genesis_endpoints: Vec<EndpointRecord>,
    /// Optional discovery mirror endpoints.
    mirrors: Vec<EndpointRecord>,
    /// Whether this node observes manifests without initiating peer handshakes.
    observer: bool,
    /// Lifetime of issued peer challenges in milliseconds.
    challenge_ttl_ms: u64,
    /// Maximum peer last-seen age counted as live, in milliseconds.
    peer_live_window_ms: u64,
    /// Delay between discovery rounds in milliseconds.
    discovery_interval_ms: u64,
    /// Directory for the persistent ledger database.
    ledger_db_path: PathBuf,
}

impl Config {
    /// Reads required settings, applies defaults, and validates security-sensitive values.
    ///
    /// This rejects non-`socks5h` Tor proxies and clearnet publication, validates
    /// onion endpoints, and parses endpoint sources before returning a config.
    ///
    /// # Errors
    /// Returns an error for missing required variables, invalid values, malformed
    /// endpoints, or forbidden clearnet settings.
    fn from_env() -> anyhow::Result<Self> {
        let network_id = required("KEROSENE_NETWORK_ID")?;
        let plane = match required("KEROSENE_DISCOVERY_PLANE")?.as_str() {
            "bank" => DiscoveryPlane::Bank,
            "vault" => DiscoveryPlane::Vault,
            other => return Err(anyhow!("unknown KEROSENE_DISCOVERY_PLANE={other}")),
        };
        let listen_addr = env::var("KEROSENE_NODE_LISTEN_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8800".into())
            .parse()
            .context("KEROSENE_NODE_LISTEN_ADDR is invalid")?;
        let onion_endpoint = onion_endpoint()?;
        validate_onion_endpoint(&onion_endpoint)?;
        let socks_proxy = required("KEROSENE_TOR_SOCKS_PROXY")?;
        if !socks_proxy.starts_with("socks5h://") {
            return Err(anyhow!(
                "KEROSENE_TOR_SOCKS_PROXY must use socks5h remote resolution"
            ));
        }
        if env_flag("KEROSENE_CLEARNET_PUBLISH") {
            return Err(anyhow!("KEROSENE_CLEARNET_PUBLISH is forbidden"));
        }
        let genesis_endpoints = endpoints_from_env(
            "KEROSENE_GENESIS_ENDPOINTS",
            "KEROSENE_DISCOVERY_SEEDS",
            DiscoverySource::Genesis,
        )?;
        let mirrors =
            endpoints_from_env("KEROSENE_DISCOVERY_MIRRORS", "", DiscoverySource::Mirror)?;
        Ok(Self {
            network_id,
            plane,
            listen_addr,
            onion_endpoint,
            identity_key: path("KEROSENE_IDENTITY_KEY_PATH", "peer-store/identity.key"),
            genesis_bundle: PathBuf::from(required("KEROSENE_GENESIS_TRUST_BUNDLE")?),
            peer_store: path("KEROSENE_PEER_STORE", "peer-store"),
            tls_cert: PathBuf::from(required("KEROSENE_TLS_CERT_PATH")?),
            tls_key: PathBuf::from(required("KEROSENE_TLS_KEY_PATH")?),
            tls_client_ca: PathBuf::from(required("KEROSENE_TLS_CLIENT_CA_PATH")?),
            tls_client_identity: env::var("KEROSENE_TLS_CLIENT_IDENTITY_PEM")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from),
            socks_proxy,
            genesis_endpoints,
            mirrors,
            observer: env_flag("KEROSENE_DISCOVERY_OBSERVER"),
            challenge_ttl_ms: integer("KEROSENE_CHALLENGE_TTL_MS", 30_000)?,
            peer_live_window_ms: integer("KEROSENE_PEER_LIVE_WINDOW_MS", 90_000)?,
            discovery_interval_ms: integer("KEROSENE_DISCOVERY_INTERVAL_MS", 15_000)?,
            ledger_db_path: path("KEROSENE_LEDGER_DB_PATH", "ledger-data"),
        })
    }
}

/// Initializes persistent state, discovery transports, TLS, and serves the node API.
///
/// Startup restores genesis membership and identity before accepting requests.
/// When discovery sources exist, it also requires outbound mTLS credentials and
/// runs periodic peer discovery through Tor.
///
/// # Errors
/// Returns errors from configuration, trust/identity loading, storage setup,
/// TLS construction, or the HTTP server.
pub async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kerosene_node=info".into()),
        )
        .init();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let config = Config::from_env()?;
    let bundle: GenesisTrustBundleV1 = serde_json::from_slice(
        &fs::read(&config.genesis_bundle).context("read GenesisTrustBundle")?,
    )
    .context("parse GenesisTrustBundle")?;
    if bundle.network_id != config.network_id {
        return Err(anyhow!("GenesisTrustBundle network mismatch"));
    }

    // Validate accessibility and schema readiness of persistent ledger database at startup
    // (full consensus and ledger state machine wiring is deferred pending an accepted ADR).
    info!(
        path = %config.ledger_db_path.display(),
        "initializing persistent ledger database"
    );
    let _ledger_db = SledLedgerDb::open(&config.ledger_db_path)
        .map_err(|e| anyhow!("failed to open ledger database: {}", e))?;

    let peer_store = Arc::new(PersistentPeerStore::open(&config.peer_store)?);
    let membership = MembershipVerifier::restore(&bundle, config.plane, peer_store.manifests()?)?;
    let identity = Arc::new(NodeIdentity::load_or_create(
        &config.identity_key,
        &config.network_id,
        config.plane,
    )?);
    let service = NodeService::new(
        identity.clone(),
        config.onion_endpoint.clone(),
        config.plane,
        membership,
        peer_store.clone(),
        LifecycleStore::new(config.peer_store.join("lifecycle.db")),
        config.challenge_ttl_ms,
        config.peer_live_window_ms,
    )?;

    info!(
        "ledger stores initialized: nonce, accounts, reservations, idempotency, utxos, withdrawals, snapshots, membership"
    );

    let discovery_configured = !config.genesis_endpoints.is_empty()
        || !config.mirrors.is_empty()
        || peer_store.authenticated_count(config.plane)? > 0;
    if discovery_configured {
        let identity_path = config.tls_client_identity.as_ref().ok_or_else(|| {
            anyhow!("KEROSENE_TLS_CLIENT_IDENTITY_PEM is required when discovery endpoints exist")
        })?;
        let client_identity =
            fs::read(identity_path).context("read outbound mTLS client identity")?;
        let ca_pem = fs::read(&config.tls_client_ca).context("read mTLS CA")?;
        let tor_client = Arc::new(TorHandshakeClient::new_mtls(
            &config.socks_proxy,
            &client_identity,
            &ca_pem,
        )?);
        spawn_discovery(
            service.clone(),
            identity,
            tor_client,
            peer_store,
            config.plane,
            config.genesis_endpoints,
            config.mirrors,
            config.onion_endpoint,
            config.observer,
            config.discovery_interval_ms,
        );
    }

    let tls = tls_config(&config.tls_cert, &config.tls_key, &config.tls_client_ca)?;
    info!(
        plane = ?config.plane,
        listen = %config.listen_addr,
        "kerosene-node discovery runtime started"
    );
    axum_server::bind_rustls(config.listen_addr, tls)
        .serve(service.router().into_make_service())
        .await
        .context("serve discovery API")
}

/// Starts a background task that periodically discovers, authenticates, and records peers.
#[allow(clippy::too_many_arguments)]
fn spawn_discovery(
    service: NodeService,
    identity: Arc<NodeIdentity>,
    client: Arc<TorHandshakeClient>,
    peer_store: Arc<PersistentPeerStore>,
    plane: DiscoveryPlane,
    genesis_endpoints: Vec<EndpointRecord>,
    mirrors: Vec<EndpointRecord>,
    local_endpoint: String,
    observer: bool,
    interval_ms: u64,
) {
    tokio::spawn(async move {
        let interval = Duration::from_millis(interval_ms.max(1_000));
        loop {
            let authenticated = peer_store.authenticated_endpoints(plane);
            let candidates = authenticated.and_then(|authenticated| {
                peer_store.ordered_candidates(
                    plane,
                    service.current_manifest().as_ref(),
                    &genesis_endpoints,
                    &mirrors,
                    &authenticated,
                )
            });
            let candidates = match candidates {
                Ok(candidates) => candidates,
                Err(error) => {
                    warn!(%error, "could not build discovery candidates");
                    tokio::time::sleep(interval).await;
                    continue;
                }
            };
            for candidate in candidates {
                let endpoint = &candidate.endpoint;
                // Membership manifests and persisted discovery sources include the
                // local member. A self-handshake is intentionally rejected by the
                // protocol, so never send it over Tor or report it as a peer failure.
                if endpoint == &local_endpoint {
                    continue;
                }
                let result = if observer {
                    client
                        .fetch_manifest(endpoint)
                        .await
                        .map_err(|error| error.to_string())
                        .and_then(|manifest| {
                            service
                                .accept_membership(manifest)
                                .map_err(|error| error.to_string())
                        })
                } else {
                    let now = now_epoch_ms();
                    let response_challenge = service.issue_challenge(now);
                    match client
                        .exchange(
                            endpoint,
                            &identity,
                            &local_endpoint,
                            response_challenge,
                            now,
                        )
                        .await
                    {
                        Ok(hello) => {
                            let observed = service
                                .observe_peer(&hello, now)
                                .map_err(|error| error.to_string());
                            if observed.is_ok() {
                                if let Ok(manifest) = client.fetch_manifest(endpoint).await {
                                    if let Err(error) = service.accept_membership(manifest) {
                                        warn!(%endpoint, %error, "failed to accept fetched manifest");
                                    }
                                }
                            }
                            observed
                        }
                        Err(error) => Err(error.to_string()),
                    }
                };
                if let Err(error) = result {
                    warn!(%endpoint, %error, "discovery attempt failed closed");
                }
            }
            tokio::time::sleep(interval).await;
        }
    });
}

/// Builds a server TLS configuration requiring client certificates from the configured CA.
///
/// # Errors
/// Returns errors for unreadable or malformed PEM files and invalid TLS configuration.
fn tls_config(
    cert_path: &PathBuf,
    key_path: &PathBuf,
    client_ca_path: &PathBuf,
) -> anyhow::Result<axum_server::tls_rustls::RustlsConfig> {
    let cert_pem = fs::read(cert_path).context("read TLS cert")?;
    let certificates = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .context("parse TLS cert")?;
    let key_pem = fs::read(key_path).context("read TLS key")?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem).context("parse TLS key")?;
    let ca_pem = fs::read(client_ca_path).context("read client CA")?;
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(&ca_pem) {
        roots.add(certificate.context("parse client CA")?)?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("build mTLS client verifier")?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, key)
        .context("build TLS server config")?;
    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        Arc::new(config),
    ))
}

/// Reads a required non-empty environment variable.
///
/// # Errors
/// Returns an error naming `name` when the variable is unset or blank.
fn required(name: &str) -> anyhow::Result<String> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("{name} is required"))
}

/// Reads a path-valued environment variable or returns its default path.
fn path(name: &str, default: &str) -> PathBuf {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map_or_else(|| PathBuf::from(default), PathBuf::from)
}

/// Parses a numeric environment variable, using `default` when it is unset.
///
/// # Errors
/// Returns an error identifying `name` when the configured value is not an integer.
fn integer(name: &str, default: u64) -> anyhow::Result<u64> {
    env::var(name)
        .map(|value| value.parse().with_context(|| format!("{name} is invalid")))
        .unwrap_or(Ok(default))
}

/// Parses a conventional truthy environment value; unset or other values are false.
fn env_flag(name: &str) -> bool {
    env::var(name).is_ok_and(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

/// Resolves the advertised onion endpoint directly or waits for Tor's hostname file.
///
/// # Errors
/// Returns errors for missing configuration, invalid port/endpoint, or a hostname
/// file that remains unavailable until its configured timeout.
fn onion_endpoint() -> anyhow::Result<String> {
    if let Ok(endpoint) = required("KEROSENE_NODE_ONION_ENDPOINT") {
        return Ok(endpoint);
    }
    let hostname_path = PathBuf::from(required("KEROSENE_NODE_ONION_HOSTNAME_PATH")?);
    let port = integer("KEROSENE_NODE_ONION_PORT", 8800)?;
    if port == 0 || port > u64::from(u16::MAX) {
        return Err(anyhow!("KEROSENE_NODE_ONION_PORT is invalid"));
    }
    let timeout_ms = integer("KEROSENE_NODE_ONION_WAIT_TIMEOUT_MS", 120_000)?;
    let started = std::time::Instant::now();
    loop {
        match fs::read_to_string(&hostname_path) {
            Ok(hostname) if !hostname.trim().is_empty() => {
                let hostname = hostname.trim();
                let endpoint = format!("https://{hostname}:{port}");
                validate_onion_endpoint(&endpoint)?;
                return Ok(endpoint);
            }
            Ok(_) | Err(_) if started.elapsed() < Duration::from_millis(timeout_ms) => {
                thread::sleep(Duration::from_millis(250));
            }
            Ok(_) => {
                return Err(anyhow!(
                    "onion hostname file remained empty: {}",
                    hostname_path.display()
                ));
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "read onion hostname after waiting {} ms: {}",
                        timeout_ms,
                        hostname_path.display()
                    )
                });
            }
        }
    }
}

fn endpoints_from_env(
    primary_name: &str,
    fallback_name: &str,
    source: DiscoverySource,
) -> anyhow::Result<Vec<EndpointRecord>> {
    let raw = env::var(primary_name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            (!fallback_name.is_empty())
                .then(|| env::var(fallback_name).ok())
                .flatten()
        })
        .unwrap_or_default();
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .enumerate()
        .map(|(index, endpoint)| {
            validate_onion_endpoint(endpoint)?;
            Ok(EndpointRecord {
                member_id: format!("{source:?}-{index}").to_ascii_lowercase(),
                endpoint: endpoint.to_owned(),
                source,
                observed_at_epoch_ms: 0,
            })
        })
        .collect()
}
