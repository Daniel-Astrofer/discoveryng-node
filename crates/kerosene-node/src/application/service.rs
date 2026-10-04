use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use kerosene_contracts::{
    canonical_hash, DiscoveryPlane, MembershipManifestV1, PeerHelloV1, StateSnapshotAttestationV1,
};
use kerosene_discovery::{
    ChallengeStore, DiscoveryError, HelloExchangeRequest, PeerAuthenticator, PersistentPeerStore,
};
use kerosene_identity_core::NodeIdentity;
use kerosene_membership::{MembershipError, MembershipVerifier};
use kerosene_sync::{
    Lifecycle, LifecycleState, LifecycleStore, StateSnapshot, StateSynchronizer, SyncError,
    VerifiedStateBinding,
};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;

#[derive(Clone)]
pub struct NodeService {
    inner: Arc<NodeServiceInner>,
}

struct NodeServiceInner {
    identity: Arc<NodeIdentity>,
    endpoint: String,
    plane: DiscoveryPlane,
    challenges: Arc<ChallengeStore>,
    authenticator: PeerAuthenticator,
    membership: Arc<RwLock<MembershipVerifier>>,
    peer_store: Arc<PersistentPeerStore>,
    lifecycle: Mutex<Lifecycle>,
    lifecycle_store: LifecycleStore,
    active_peers: RwLock<HashMap<String, u64>>,
    peer_live_window_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Readiness {
    pub live: bool,
    pub local_ready: bool,
    pub member_ready: bool,
    pub quorum_ready: bool,
    pub financial_ready: bool,
    pub plane: DiscoveryPlane,
    pub lifecycle: LifecycleState,
    pub operational_state: &'static str,
    pub verified_members: usize,
    pub live_members: usize,
    pub required_threshold: usize,
    pub manifest_hash: Option<String>,
}

impl NodeService {
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
    ) -> Result<Self, String> {
        kerosene_discovery::validate_onion_endpoint(&endpoint)
            .map_err(|error| error.to_string())?;
        let membership = Arc::new(RwLock::new(membership));
        let challenges = Arc::new(ChallengeStore::new(challenge_ttl_ms));
        let authenticator = PeerAuthenticator::new(
            identity.network_id(),
            plane,
            challenge_ttl_ms,
            challenges.clone(),
            membership.clone(),
        );
        let mut lifecycle = lifecycle_store.load().map_err(|error| error.to_string())?;
        bootstrap_local_lifecycle(&mut lifecycle).map_err(|error| error.to_string())?;
        let current_manifest_hash = membership.read().current_hash();
        if lifecycle.verified_state().is_some_and(|binding| {
            current_manifest_hash.as_deref() != Some(&binding.membership_manifest_hash)
        }) {
            lifecycle.require_state_revalidation();
        }
        lifecycle_store
            .save(&lifecycle)
            .map_err(|error| error.to_string())?;
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
            }),
        })
    }

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
        let lifecycle = self.inner.lifecycle.lock().state();
        let state_verified = matches!(
            lifecycle,
            LifecycleState::StateVerified | LifecycleState::Eligible | LifecycleState::Active
        );
        let current_manifest_hash = membership.current_hash();
        let state_bound_to_membership =
            self.inner
                .lifecycle
                .lock()
                .verified_state()
                .is_some_and(|binding| {
                    current_manifest_hash.as_deref() == Some(&binding.membership_manifest_hash)
                });
        let financial_ready =
            quorum && lifecycle == LifecycleState::Active && state_bound_to_membership;
        Readiness {
            live: true,
            local_ready: lifecycle != LifecycleState::Created,
            member_ready: local_member,
            quorum_ready: quorum,
            financial_ready,
            plane: self.inner.plane,
            lifecycle,
            operational_state: if financial_ready {
                "ACTIVE"
            } else if state_verified {
                "ELIGIBLE_WAITING_FOR_QUORUM"
            } else {
                "ACTIVE_LOCAL_WAITING_FOR_PEERS"
            },
            verified_members: membership.member_count(),
            live_members,
            required_threshold: threshold,
            manifest_hash: membership.current_hash(),
        }
    }

    pub fn issue_challenge(&self, now_epoch_ms: u64) -> String {
        self.inner.challenges.issue(now_epoch_ms)
    }

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

    pub fn accept_membership(&self, manifest: MembershipManifestV1) -> Result<(), MembershipError> {
        let manifest_hash = canonical_hash(&manifest);
        if self.inner.membership.read().current_hash().as_deref() == Some(manifest_hash.as_str()) {
            return Ok(());
        }
        let previous_hash = self.inner.membership.read().current_hash();
        let mut candidate = self.inner.membership.read().clone();
        candidate.accept(manifest.clone())?;
        if previous_hash.is_some() {
            let mut lifecycle = self.inner.lifecycle.lock();
            lifecycle.require_state_revalidation();
            self.inner
                .lifecycle_store
                .save(&lifecycle)
                .map_err(|_| MembershipError::Persistence)?;
        }
        self.inner
            .peer_store
            .append_manifest(&manifest)
            .map_err(|_| MembershipError::Persistence)?;
        *self.inner.membership.write() = candidate;
        self.activate_if_quorum(now_epoch_ms());
        Ok(())
    }

    pub fn current_manifest(&self) -> Option<MembershipManifestV1> {
        self.inner.membership.read().current().cloned()
    }

    pub fn authenticated_peers(
        &self,
    ) -> Result<Vec<kerosene_discovery::EndpointRecord>, DiscoveryError> {
        self.inner
            .peer_store
            .authenticated_endpoints(self.inner.plane)
    }

    pub async fn synchronize_state(
        &self,
        synchronizer: &dyn StateSynchronizer,
    ) -> Result<StateSnapshot, SyncError> {
        let snapshot = synchronizer.synchronize().await?;
        self.verify_state_snapshot(&snapshot)?;
        Ok(snapshot)
    }

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

    pub fn verify_attested_state_snapshot(
        &self,
        attestation: &StateSnapshotAttestationV1,
        bytes: Vec<u8>,
    ) -> Result<(), String> {
        let membership = self.inner.membership.read();
        membership
            .verify_state_snapshot_attestation(attestation)
            .map_err(|error| error.to_string())?;
        let snapshot = StateSnapshot {
            epoch: attestation.snapshot_epoch,
            bytes,
            state_root: attestation.state_root.clone(),
        };
        snapshot.verify().map_err(|error| error.to_string())?;
        let mut lifecycle = self.inner.lifecycle.lock();
        lifecycle
            .bind_verified_state(VerifiedStateBinding {
                membership_manifest_hash: attestation.membership_manifest_hash.clone(),
                snapshot_epoch: attestation.snapshot_epoch,
                state_root: attestation.state_root.clone(),
            })
            .map_err(|error| error.to_string())?;
        if lifecycle.state() == LifecycleState::StateVerified {
            lifecycle
                .advance(LifecycleState::Eligible)
                .map_err(|error| error.to_string())?;
        }
        self.inner
            .lifecycle_store
            .save(&lifecycle)
            .map_err(|error| error.to_string())?;
        drop(lifecycle);
        drop(membership);
        self.activate_if_quorum(now_epoch_ms());
        Ok(())
    }

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

    fn activate_if_quorum(&self, now_epoch_ms: u64) {
        let readiness = self.readiness(now_epoch_ms);
        let mut lifecycle = self.inner.lifecycle.lock();
        if readiness.quorum_ready && lifecycle.state() == LifecycleState::Eligible {
            let _ = lifecycle.advance(LifecycleState::Active);
            let _ = self.inner.lifecycle_store.save(&lifecycle);
        }
    }

    fn expire_peers(&self, now_epoch_ms: u64) {
        self.inner.active_peers.write().retain(|_, last_seen| {
            now_epoch_ms.saturating_sub(*last_seen) <= self.inner.peer_live_window_ms
        });
    }
}

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

pub fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
