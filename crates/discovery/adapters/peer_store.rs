use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use kerosene_contracts::{DiscoveryPlane, MembershipManifestV1};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::domain::{
    validate_onion_endpoint, AuthenticatedPeer, DiscoveryError, DiscoverySource, EndpointRecord,
    StoredPeer, SuccessfulConnection,
};

/// JSON store filename for authenticated peer identities.
pub const PEERS_DB: &str = "peers.db";
/// JSON store filename for known peer endpoints and their provenance.
pub const ENDPOINTS_DB: &str = "endpoints.db";
/// JSON store filename for endpoints with a completed connection.
pub const SUCCESSFUL_CONNECTIONS_DB: &str = "successful-connections.db";
/// JSON store filename for received membership manifests.
pub const MEMBERSHIP_MANIFESTS_DB: &str = "membership-manifests.db";

/// JSON-backed peer store that serializes writes and atomically replaces files.
pub struct PersistentPeerStore {
    root: PathBuf,
    write_lock: Mutex<()>,
}

impl PersistentPeerStore {
    /// Opens the store directory and initializes each missing JSON database.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, DiscoveryError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        let store = Self {
            root,
            write_lock: Mutex::new(()),
        };
        store.ensure_file::<StoredPeer>(PEERS_DB)?;
        store.ensure_file::<EndpointRecord>(ENDPOINTS_DB)?;
        store.ensure_file::<SuccessfulConnection>(SUCCESSFUL_CONNECTIONS_DB)?;
        store.ensure_file::<MembershipManifestV1>(MEMBERSHIP_MANIFESTS_DB)?;
        Ok(store)
    }

    /// Upserts authenticated identity and its endpoint provenance.
    pub fn upsert_authenticated(&self, peer: AuthenticatedPeer) -> Result<(), DiscoveryError> {
        let _guard = self.write_lock.lock();
        let mut peers: Vec<StoredPeer> = self.read(PEERS_DB)?;
        peers.retain(|saved| saved.member_id != peer.member_id);
        peers.push(StoredPeer {
            member_id: peer.member_id.clone(),
            plane: peer.plane,
            root_public_key: peer.root_public_key,
            endpoint: peer.endpoint.clone(),
            authenticated_at_epoch_ms: peer.authenticated_at_epoch_ms,
            last_success_epoch_ms: None,
        });
        self.write(PEERS_DB, &peers)?;

        let mut endpoints: Vec<EndpointRecord> = self.read(ENDPOINTS_DB)?;
        endpoints.retain(|saved| {
            saved.member_id != peer.member_id || saved.source != DiscoverySource::AuthenticatedPeer
        });
        endpoints.push(EndpointRecord {
            member_id: peer.member_id,
            endpoint: peer.endpoint,
            source: DiscoverySource::AuthenticatedPeer,
            observed_at_epoch_ms: peer.authenticated_at_epoch_ms,
        });
        self.write(ENDPOINTS_DB, &endpoints)
    }

    /// Records a successful connection and updates the peer's last-success time.
    pub fn record_success(
        &self,
        member_id: &str,
        endpoint: &str,
        now_epoch_ms: u64,
    ) -> Result<(), DiscoveryError> {
        validate_onion_endpoint(endpoint)?;
        let _guard = self.write_lock.lock();
        let mut successes: Vec<SuccessfulConnection> = self.read(SUCCESSFUL_CONNECTIONS_DB)?;
        successes.retain(|saved| saved.member_id != member_id || saved.endpoint != endpoint);
        successes.push(SuccessfulConnection {
            member_id: member_id.into(),
            endpoint: endpoint.into(),
            connected_at_epoch_ms: now_epoch_ms,
        });
        self.write(SUCCESSFUL_CONNECTIONS_DB, &successes)?;

        let mut peers: Vec<StoredPeer> = self.read(PEERS_DB)?;
        for peer in &mut peers {
            if peer.member_id == member_id && peer.endpoint == endpoint {
                peer.last_success_epoch_ms = Some(now_epoch_ms);
            }
        }
        self.write(PEERS_DB, &peers)
    }

    /// Appends a verified membership manifest to the local history.
    pub fn append_manifest(&self, manifest: &MembershipManifestV1) -> Result<(), DiscoveryError> {
        let _guard = self.write_lock.lock();
        let mut manifests: Vec<MembershipManifestV1> = self.read(MEMBERSHIP_MANIFESTS_DB)?;
        manifests.push(manifest.clone());
        self.write(MEMBERSHIP_MANIFESTS_DB, &manifests)
    }

    /// Returns all membership manifests persisted by this store.
    pub fn manifests(&self) -> Result<Vec<MembershipManifestV1>, DiscoveryError> {
        self.read(MEMBERSHIP_MANIFESTS_DB)
    }

    /// Counts authenticated peers belonging to the requested discovery plane.
    pub fn authenticated_count(&self, plane: DiscoveryPlane) -> Result<usize, DiscoveryError> {
        let peers: Vec<StoredPeer> = self.read(PEERS_DB)?;
        Ok(peers.iter().filter(|peer| peer.plane == plane).count())
    }

    /// Lists endpoints belonging to authenticated peers on the requested plane.
    pub fn authenticated_endpoints(
        &self,
        plane: DiscoveryPlane,
    ) -> Result<Vec<EndpointRecord>, DiscoveryError> {
        let peers: Vec<StoredPeer> = self.read(PEERS_DB)?;
        Ok(peers
            .into_iter()
            .filter(|peer| peer.plane == plane)
            .map(|peer| EndpointRecord {
                member_id: peer.member_id,
                endpoint: peer.endpoint,
                source: DiscoverySource::AuthenticatedPeer,
                observed_at_epoch_ms: peer.authenticated_at_epoch_ms,
            })
            .collect())
    }

    /// Merges endpoint sources by reliability and removes duplicate endpoints.
    ///
    /// Previously successful connections come first (newest first), followed by
    /// the accepted manifest, genesis endpoints, mirrors, and authenticated
    /// suggestions. Every candidate is validated as an HTTPS v3 onion endpoint.
    pub fn ordered_candidates(
        &self,
        plane: DiscoveryPlane,
        current_manifest: Option<&MembershipManifestV1>,
        genesis: &[EndpointRecord],
        mirrors: &[EndpointRecord],
        authenticated_suggestions: &[EndpointRecord],
    ) -> Result<Vec<EndpointRecord>, DiscoveryError> {
        let successes: Vec<SuccessfulConnection> = self.read(SUCCESSFUL_CONNECTIONS_DB)?;
        let peers: Vec<StoredPeer> = self.read(PEERS_DB)?;
        let mut candidates = Vec::new();

        let mut successes = successes;
        successes.sort_by_key(|item| std::cmp::Reverse(item.connected_at_epoch_ms));
        for success in successes {
            if let Some(peer) = peers
                .iter()
                .find(|peer| peer.member_id == success.member_id && peer.plane == plane)
            {
                candidates.push(EndpointRecord {
                    member_id: peer.member_id.clone(),
                    endpoint: success.endpoint,
                    source: DiscoverySource::PreviousConnection,
                    observed_at_epoch_ms: success.connected_at_epoch_ms,
                });
            }
        }
        if let Some(manifest) = current_manifest {
            candidates.extend(manifest.members.iter().map(|member| EndpointRecord {
                member_id: member.member_id.clone(),
                endpoint: member.endpoint.clone(),
                source: DiscoverySource::CurrentManifest,
                observed_at_epoch_ms: manifest.epoch,
            }));
        }
        candidates.extend_from_slice(genesis);
        candidates.extend_from_slice(mirrors);
        candidates.extend_from_slice(authenticated_suggestions);
        deduplicate_valid(candidates)
    }

    /// Creates a missing JSON database as an empty array.
    fn ensure_file<T: Serialize>(&self, name: &str) -> Result<(), DiscoveryError> {
        let path = self.root.join(name);
        if !path.exists() {
            self.write(name, &Vec::<T>::new())?;
        }
        Ok(())
    }

    /// Reads and deserializes one JSON array from the peer-store directory.
    fn read<T: for<'de> Deserialize<'de>>(&self, name: &str) -> Result<Vec<T>, DiscoveryError> {
        let bytes = fs::read(self.root.join(name))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Serializes values to a temporary file and renames it into place.
    fn write<T: Serialize>(&self, name: &str, values: &[T]) -> Result<(), DiscoveryError> {
        let path = self.root.join(name);
        let temporary = self.root.join(format!("{name}.tmp"));
        let bytes = serde_json::to_vec(values)?;
        fs::write(&temporary, bytes)?;
        fs::rename(temporary, path)?;
        Ok(())
    }
}

/// Validates and deduplicates candidates while preserving their first-seen order.
fn deduplicate_valid(
    candidates: Vec<EndpointRecord>,
) -> Result<Vec<EndpointRecord>, DiscoveryError> {
    let mut seen = HashSet::new();
    let mut ordered = Vec::new();
    for candidate in candidates {
        validate_onion_endpoint(&candidate.endpoint)?;
        if seen.insert(candidate.endpoint.clone()) {
            ordered.push(candidate);
        }
    }
    Ok(ordered)
}

/// Returns the four JSON database paths used by [PersistentPeerStore].
pub fn db_files(root: &Path) -> [PathBuf; 4] {
    [
        root.join(PEERS_DB),
        root.join(ENDPOINTS_DB),
        root.join(SUCCESSFUL_CONNECTIONS_DB),
        root.join(MEMBERSHIP_MANIFESTS_DB),
    ]
}
