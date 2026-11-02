//! Node application service coordinating discovery, membership, and readiness.

use super::KfeLedgerCheckpoint;
use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use kerosene_contracts::{canonical_hash, DiscoveryPlane, MembershipManifestV1, PeerHelloV1};
use kerosene_discovery::{
    ChallengeStore, DiscoveryError, HelloExchangeRequest, PeerAuthenticator, PersistentPeerStore,
};
use kerosene_identity_core::NodeIdentity;
use kerosene_membership::{MembershipError, MembershipVerifier};
use kerosene_sync::{
    Lifecycle, LifecycleState, LifecycleStore, StateSnapshot, StateSynchronizer, SyncError,
};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
/// Failures encountered by the node coordination service.
pub enum NodeServiceError {
    #[error("discovery error: {0}")]
    Discovery(#[from] DiscoveryError),
    #[error("membership error: {0}")]
    Membership(#[from] MembershipError),
    #[error("lifecycle sync error: {0}")]
    Sync(#[from] SyncError),
    #[error("peer store persistence error: {0}")]
    Storage(String),
}

#[derive(Clone)]
/// Coordinates a node's peer authentication, membership, sync, and readiness state.
pub struct NodeService {
    /// Shared mutable implementation state used by cloned service handles.
    inner: Arc<NodeServiceInner>,
}

/// State shared across `NodeService` handles and asynchronous request handlers.
struct NodeServiceInner {
    /// Local network-scoped identity used to authenticate peer handshakes.
    identity: Arc<NodeIdentity>,
    /// Advertised HTTPS onion endpoint for this node.
    endpoint: String,
    /// Discovery plane whose membership roster authorizes this node.
    plane: DiscoveryPlane,
    /// Short-lived store of outstanding peer challenge nonces.
    challenges: Arc<ChallengeStore>,
    /// Validates peer signatures and membership against the current verifier.
    authenticator: PeerAuthenticator,
    /// Current accepted membership verifier, replaceable after a valid manifest.
    membership: Arc<RwLock<MembershipVerifier>>,
    /// Durable store for authenticated endpoints and accepted manifests.
    peer_store: Arc<PersistentPeerStore>,
    /// In-memory lifecycle cursor guarded during transitions.
    lifecycle: Mutex<Lifecycle>,
    /// Durable lifecycle checkpoint restored during service construction.
    lifecycle_store: LifecycleStore,
    /// Last-seen times for peers authenticated during the current process.
    active_peers: RwLock<HashMap<String, u64>>,
    /// Maximum age of an authenticated peer observation before it expires.
    peer_live_window_ms: u64,
    requires_kfe_ledger: AtomicBool,
    kfe_ledger_key: RwLock<Option<VerifyingKey>>,
    kfe_checkpoint: RwLock<Option<KfeLedgerCheckpoint>>,
    ledger_challenges: ChallengeStore,
}

#[derive(Debug, Clone, Serialize)]
/// Public readiness projection computed from local lifecycle, membership, and live quorum.
pub struct Readiness {
    /// Whether the process can answer the readiness query.
    pub live: bool,
    /// Whether identity and transport bootstrap has advanced beyond `Created`.
    pub local_ready: bool,
    /// Whether the local identity appears in the accepted membership roster.
    pub member_ready: bool,
    /// Whether enough authorized members, including this node, are live.
    pub quorum_ready: bool,
    /// Whether the node is active and the membership quorum is currently satisfied.
    pub financial_ready: bool,
    pub financial_blockers: Vec<&'static str>,
    pub ledger_source: Option<LedgerSourceStatus>,
    /// Bank or vault discovery plane used to compute this view.
    pub plane: DiscoveryPlane,
    /// Current monotonic admission and synchronization stage.
    pub lifecycle: LifecycleState,
    /// Stable operational label derived from lifecycle and quorum conditions.
    pub operational_state: &'static str,
    /// Number of members in the currently verified roster.
    pub verified_members: usize,
    /// Number of currently live authorized members, including local member if valid.
    pub live_members: usize,
    /// Minimum live member count required for quorum.
    pub required_threshold: usize,
    /// Canonical hash of the accepted membership manifest, if present.
    pub manifest_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LedgerSourceStatus {
    pub source: &'static str,
    pub ledger_root: String,
    pub observed_at_ms: u64,
    pub expires_at_ms: u64,
    pub balances_count: u64,
    pub postings_count: u64,
}

impl NodeService {
    /// Creates the node service and advances persisted local bootstrap stages.
    ///
    /// The endpoint is validated before constructing challenge authentication;
    /// restored lifecycle state is advanced through identity and transport setup
    /// and persisted before the service is returned.
    ///
    /// # Errors
    /// Returns a string describing an invalid endpoint, lifecycle load/transition,
    /// or lifecycle persistence failure.
    ///
    /// # Parameters
    /// * `identity` - this node's durable network identity.
    /// * `endpoint` - externally advertised HTTPS v3 onion endpoint.
    /// * `plane` - membership plane served by this node.
    /// * `membership` - verifier restored from genesis and persisted manifests.
    /// * `peer_store` - durable store for manifests and authenticated endpoints.
    /// * `lifecycle_store` - filesystem checkpoint for startup lifecycle.
    /// * `challenge_ttl_ms` - maximum challenge age accepted during handshake.
    /// * `peer_live_window_ms` - maximum last-seen age counted as live.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: Arc<NodeIdentity>,
        endpoint: String,
        plane: DiscoveryPlane,
        membership: MembershipVerifier,
        peer_store: Arc<PersistentPeerStore>,
        lifecycle_store: LifecycleStore,
        challenge_ttl_ms: u64,
        peer_live_window_ms: u64,
    ) -> Result<Self, NodeServiceError> {
        kerosene_discovery::validate_onion_endpoint(&endpoint)?;
        let membership = Arc::new(RwLock::new(membership));
        let challenges = Arc::new(ChallengeStore::new(challenge_ttl_ms));
        let authenticator = PeerAuthenticator::new(
            identity.network_id(),
            plane,
            challenge_ttl_ms,
            challenges.clone(),
            membership.clone(),
        );
        let mut lifecycle = lifecycle_store.load()?;
        bootstrap_local_lifecycle(&mut lifecycle)?;
        lifecycle_store.save(&lifecycle)?;
        Ok(Self {
            inner: Arc::new(NodeServiceInner {
                identity,
                endpoint,
                plane,
                challenges,
                authenticator,
                membership,
                peer_store,
                lifecycle: Mutex::new(lifecycle),
                lifecycle_store,
                active_peers: RwLock::new(HashMap::new()),
                peer_live_window_ms,
                requires_kfe_ledger: AtomicBool::new(false),
                kfe_ledger_key: RwLock::new(None),
                kfe_checkpoint: RwLock::new(None),
                ledger_challenges: ChallengeStore::new(120_000),
            }),
        })
    }

    /// Computes health and quorum readiness after expiring stale peer observations.
    ///
    /// Membership count and threshold come from the accepted manifest, falling
    /// back to genesis trust until a manifest has been accepted.
    pub fn readiness(&self, now_epoch_ms: u64) -> Readiness {
        self.expire_peers(now_epoch_ms);
        let membership = self.inner.membership.read();
        let local_member = membership.is_member(
            self.inner.identity.member_id(),
            &self.inner.identity.root_public_key_hex(),
        );
        let authorized = membership.authorized_keys();
        let live_remote = self
            .inner
            .active_peers
            .read()
            .keys()
            .filter(|member_id| authorized.contains_key(*member_id))
            .count();
        let live_members = live_remote + usize::from(local_member);
        let threshold = membership.threshold();
        let quorum = local_member && live_members >= threshold;
        let verified_members = membership.member_count();
        let manifest_hash = membership.current_hash();
        drop(membership);
        let lifecycle = self.inner.lifecycle.lock().state();
        let checkpoint = self.inner.kfe_checkpoint.read().clone();
        let mut financial_blockers = Vec::new();
        if self.inner.requires_kfe_ledger.load(Ordering::Acquire) {
            if self.inner.kfe_ledger_key.read().is_none() {
                financial_blockers.push("KFE_LEDGER_AUTHORITY_UNCONFIGURED");
            } else if checkpoint.as_ref().is_none_or(|c| {
                c.expires_at_ms <= now_epoch_ms
                    || c.generated_at_ms > now_epoch_ms.saturating_add(5_000)
            }) {
                financial_blockers.push("KFE_LEDGER_CHECKPOINT_UNAVAILABLE_OR_STALE");
            }
        }
        let runtime_ready = financial_blockers.is_empty();
        let ledger_source = checkpoint.map(|c| LedgerSourceStatus {
            source: "KFE",
            ledger_root: c.ledger_root,
            observed_at_ms: c.generated_at_ms,
            expires_at_ms: c.expires_at_ms,
            balances_count: c.balances_count,
            postings_count: c.postings_count,
        });
        let state_verified = matches!(
            lifecycle,
            LifecycleState::StateVerified | LifecycleState::Eligible | LifecycleState::Active
        );
        Readiness {
            live: true,
            local_ready: lifecycle != LifecycleState::Created,
            member_ready: local_member,
            quorum_ready: quorum,
            financial_ready: quorum && lifecycle == LifecycleState::Active && runtime_ready,
            financial_blockers,
            ledger_source,
            plane: self.inner.plane,
            lifecycle,
            operational_state: if !runtime_ready {
                "WAITING_FOR_KFE_LEDGER"
            } else if lifecycle == LifecycleState::Active && quorum {
                "ACTIVE"
            } else if state_verified {
                "ELIGIBLE_WAITING_FOR_QUORUM"
            } else {
                "ACTIVE_LOCAL_WAITING_FOR_PEERS"
            },
            verified_members,
            live_members,
            required_threshold: threshold,
            manifest_hash,
        }
    }

    /// Issues a one-time challenge that a connecting peer must sign.
    pub fn issue_challenge(&self, now_epoch_ms: u64) -> String {
        self.inner.challenges.issue(now_epoch_ms)
    }

    /// Runtime composition pins the authoritative KFE signing key. Missing keys
    /// block readiness; they never fall back to an independent empty Rust ledger.
    pub fn configure_kfe_ledger_source(&self, public_key: Option<&str>) -> Result<(), String> {
        let key = public_key
            .map(|value| {
                let bytes: [u8; 32] = hex::decode(value)
                    .map_err(|_| "invalid KFE public key")?
                    .try_into()
                    .map_err(|_| "invalid KFE public key length")?;
                VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid KFE public key")
            })
            .transpose()?;
        *self.inner.kfe_ledger_key.write() = key;
        *self.inner.kfe_checkpoint.write() = None;
        self.inner
            .requires_kfe_ledger
            .store(true, Ordering::Release);
        Ok(())
    }

    pub fn issue_ledger_challenge(&self, now: u64) -> Result<String, String> {
        if self.inner.kfe_ledger_key.read().is_none() {
            return Err("KFE ledger authority is not configured".into());
        }
        self.inner
            .ledger_challenges
            .issue_bounded(now, 128)
            .map_err(|e| e.to_string())
    }

    /// Verifies a fresh, single-use KFE attestation. KFE retains all balances and
    /// journal ownership; this node stores only the source's integrity checkpoint.
    pub fn accept_kfe_checkpoint(
        &self,
        checkpoint: KfeLedgerCheckpoint,
        now: u64,
    ) -> Result<(), String> {
        let authority = self.inner.kfe_ledger_key.read();
        let key = authority
            .as_ref()
            .ok_or("KFE ledger authority is not configured")?;
        checkpoint.verify(self.inner.identity.network_id(), key, now)?;
        self.inner
            .ledger_challenges
            .consume(&checkpoint.challenge, now)
            .map_err(|e| e.to_string())?;
        let mut lifecycle = self.inner.lifecycle.lock();
        let mut previous = self.inner.kfe_checkpoint.write();
        if previous.as_ref().is_some_and(|p| {
            checkpoint.generated_at_ms < p.generated_at_ms
                || (checkpoint.generated_at_ms == p.generated_at_ms
                    && checkpoint.ledger_root != p.ledger_root)
        }) {
            return Err("older or conflicting KFE checkpoint".into());
        }
        let mut candidate = lifecycle.clone();
        match candidate.state() {
            LifecycleState::Syncing => {
                candidate
                    .advance(LifecycleState::StateVerified)
                    .map_err(|e| e.to_string())?;
                candidate
                    .advance(LifecycleState::Eligible)
                    .map_err(|e| e.to_string())?;
            }
            LifecycleState::StateVerified => {
                candidate
                    .advance(LifecycleState::Eligible)
                    .map_err(|e| e.to_string())?;
            }
            LifecycleState::Eligible | LifecycleState::Active => {}
            _ => return Err("membership must be verified before ledger synchronization".into()),
        }
        self.inner
            .lifecycle_store
            .save(&candidate)
            .map_err(|e| e.to_string())?;
        *lifecycle = candidate;
        *previous = Some(checkpoint);
        drop(previous);
        drop(lifecycle);
        drop(authority);
        self.activate_if_quorum(now);
        Ok(())
    }

    /// Authenticates and records a remote peer hello without producing a response.
    ///
    /// # Errors
    /// Rejects self-connections and propagates authentication or peer-store errors.
    pub fn observe_peer(
        &self,
        hello: &PeerHelloV1,
        now_epoch_ms: u64,
    ) -> Result<(), DiscoveryError> {
        if hello.member_id == self.inner.identity.member_id() {
            return Err(DiscoveryError::SelfConnection);
        }
        let peer = self.inner.authenticator.authenticate(hello, now_epoch_ms)?;
        self.record_authenticated_peer(peer, now_epoch_ms)?;
        Ok(())
    }

    /// Authenticates a peer hello and returns this node's signed response hello.
    ///
    /// # Errors
    /// Rejects self-connections and propagates authentication or persistence errors.
    pub fn exchange_hello(
        &self,
        request: &HelloExchangeRequest,
        now_epoch_ms: u64,
    ) -> Result<PeerHelloV1, DiscoveryError> {
        if request.hello.member_id == self.inner.identity.member_id() {
            return Err(DiscoveryError::SelfConnection);
        }
        let peer = self
            .inner
            .authenticator
            .authenticate(&request.hello, now_epoch_ms)?;
        self.record_authenticated_peer(peer, now_epoch_ms)?;
        Ok(self.inner.identity.sign_hello(
            request.response_challenge.clone(),
            self.inner.endpoint.clone(),
            now_epoch_ms,
        ))
    }

    /// Validates and durably accepts a membership manifest before publishing it locally.
    ///
    /// Duplicate current manifests are idempotent. The new verifier state is
    /// installed only after validation and manifest persistence both succeed.
    ///
    /// # Errors
    /// Returns membership validation or peer-store storage errors.
    pub fn accept_membership(
        &self,
        manifest: MembershipManifestV1,
    ) -> Result<(), NodeServiceError> {
        let manifest_hash = canonical_hash(&manifest);
        if self.inner.membership.read().current_hash().as_deref() == Some(manifest_hash.as_str()) {
            return Ok(());
        }
        let mut candidate = self.inner.membership.read().clone();
        candidate.accept(manifest.clone())?;
        self.inner.peer_store.append_manifest(&manifest)?;
        *self.inner.membership.write() = candidate;
        self.activate_if_quorum(now_epoch_ms());
        Ok(())
    }

    /// Returns a clone of the currently accepted manifest, if available.
    pub fn current_manifest(&self) -> Option<MembershipManifestV1> {
        self.inner.membership.read().current().cloned()
    }

    /// Lists durable authenticated peer endpoints for this node's discovery plane.
    ///
    /// # Errors
    /// Returns storage errors while reading the peer store.
    pub fn authenticated_peers(
        &self,
    ) -> Result<Vec<kerosene_discovery::EndpointRecord>, DiscoveryError> {
        self.inner
            .peer_store
            .authenticated_endpoints(self.inner.plane)
    }

    /// Fetches a state snapshot and advances lifecycle after verifying its digest.
    ///
    /// # Errors
    /// Propagates synchronization, snapshot-integrity, lifecycle-transition, or
    /// lifecycle-persistence errors.
    pub async fn synchronize_state(
        &self,
        synchronizer: &dyn StateSynchronizer,
    ) -> Result<StateSnapshot, SyncError> {
        let snapshot = synchronizer.synchronize().await?;
        self.verify_state_snapshot(&snapshot)?;
        Ok(snapshot)
    }

    /// Verifies a snapshot and moves the node from `Syncing` through `Eligible`.
    ///
    /// Once persisted, current quorum state may promote the node to `Active`.
    ///
    /// # Errors
    /// Returns state-root mismatch, invalid lifecycle transition, or persistence
    /// errors from the lifecycle store.
    pub fn verify_state_snapshot(&self, snapshot: &StateSnapshot) -> Result<(), SyncError> {
        snapshot.verify()?;
        let mut lifecycle = self.inner.lifecycle.lock();
        if lifecycle.state() != LifecycleState::Syncing {
            return Err(SyncError::InvalidTransition {
                from: lifecycle.state(),
                to: LifecycleState::StateVerified,
            });
        }
        lifecycle.advance(LifecycleState::StateVerified)?;
        lifecycle.advance(LifecycleState::Eligible)?;
        self.inner.lifecycle_store.save(&lifecycle)?;
        drop(lifecycle);
        self.activate_if_quorum(now_epoch_ms());
        Ok(())
    }

    /// Advances lifecycle after a peer is authenticated and local membership is known.
    fn advance_after_authentication(&self) {
        let mut lifecycle = self.inner.lifecycle.lock();
        if lifecycle.state() == LifecycleState::Discovering {
            let _ = lifecycle.advance(LifecycleState::Authenticated);
        }
        let local_member = self.inner.membership.read().is_member(
            self.inner.identity.member_id(),
            &self.inner.identity.root_public_key_hex(),
        );
        if local_member && lifecycle.state() == LifecycleState::Authenticated {
            let _ = lifecycle.advance(LifecycleState::MemberVerified);
            let _ = lifecycle.advance(LifecycleState::Syncing);
        }
        let _ = self.inner.lifecycle_store.save(&lifecycle);
    }

    /// Persists a peer observation, refreshes its liveness, then reevaluates activation.
    ///
    /// # Errors
    /// Returns peer-store failures before changing the active-peer timestamp map.
    fn record_authenticated_peer(
        &self,
        peer: kerosene_discovery::AuthenticatedPeer,
        now_epoch_ms: u64,
    ) -> Result<(), DiscoveryError> {
        self.inner.peer_store.upsert_authenticated(peer.clone())?;
        self.inner
            .peer_store
            .record_success(&peer.member_id, &peer.endpoint, now_epoch_ms)?;
        self.inner
            .active_peers
            .write()
            .insert(peer.member_id, now_epoch_ms);
        self.advance_after_authentication();
        self.activate_if_quorum(now_epoch_ms);
        Ok(())
    }

    /// Promotes an eligible node to active when the currently computed readiness meets quorum.
    fn activate_if_quorum(&self, now_epoch_ms: u64) {
        let readiness = self.readiness(now_epoch_ms);
        let mut lifecycle = self.inner.lifecycle.lock();
        if readiness.quorum_ready && lifecycle.state() == LifecycleState::Eligible {
            let mut candidate = lifecycle.clone();
            if let Err(error) = candidate
                .advance(LifecycleState::Active)
                .and_then(|()| self.inner.lifecycle_store.save(&candidate))
            {
                tracing::error!(%error, "could not persist active lifecycle");
            } else {
                *lifecycle = candidate;
            }
        }
    }

    /// Removes live-peer observations older than the configured liveness window.
    fn expire_peers(&self, now_epoch_ms: u64) {
        self.inner.active_peers.write().retain(|_, last_seen| {
            now_epoch_ms.saturating_sub(*last_seen) <= self.inner.peer_live_window_ms
        });
    }
}

/// Restores minimum local lifecycle progress for a process that has just booted.
///
/// The node is advanced to `Discovering`; authentication, membership, state
/// verification, and activation remain contingent on runtime protocol events.
///
/// # Errors
/// Returns an invalid-transition error if persisted state cannot advance legally.
fn bootstrap_local_lifecycle(lifecycle: &mut Lifecycle) -> Result<(), kerosene_sync::SyncError> {
    while matches!(
        lifecycle.state(),
        LifecycleState::Created | LifecycleState::IdentityReady | LifecycleState::TransportReady
    ) {
        let next = lifecycle.state().next().expect("bootstrap state has next");
        lifecycle.advance(next)?;
    }
    Ok(())
}

/// Returns the current Unix epoch time in milliseconds, saturating on conversion overflow.
pub fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
