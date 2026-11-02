use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{
    pkcs8::{DecodePublicKey, EncodePublicKey},
    Signature, Signer, SigningKey, VerifyingKey,
};
use kerosene_contracts::{canonical_json_bytes, canonical_json_hash, release::*};
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{BankEndpoint, BankTransport};

#[derive(Debug, Error)]
pub enum ObserverError {
    #[error("observer configuration is invalid")]
    Configuration,
    #[error("release target or report is invalid")]
    InvalidReport,
    #[error("Bank read is unavailable or exceeded the bounded timeout")]
    BankUnavailable,
    #[error("Bank evidence is invalid, synthetic, expired or mismatched")]
    InvalidBankEvidence,
    #[error("Bank observation is not compatible")]
    Incompatible,
    #[error("target sequence was already signed or is older than the durable sequence")]
    Replay,
    #[error("release observations are unknown")]
    NotFound,
    #[error("release observations have expired")]
    Expired,
    #[error("observer persistence failed")]
    Persistence,
    #[error("observer is busy")]
    Busy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Reservation {
    sequence: u64,
    release_digest: String,
    report_digest: String,
}

#[derive(Clone)]
pub struct ReleaseObserver {
    inner: Arc<Inner>,
}

struct Inner {
    observer_id: String,
    network_id: String,
    key: SigningKey,
    banks: BTreeMap<String, BankEndpoint>,
    transport: BankTransport,
    db: sled::Db,
    // Bound total concurrent remote reads. Persist/sign operations share a lock.
    inflight: tokio::sync::Semaphore,
    signing: Mutex<()>,
}

impl ReleaseObserver {
    pub fn open(
        observer_id: String,
        network_id: String,
        key: SigningKey,
        banks: Vec<BankEndpoint>,
        transport: BankTransport,
        state_path: &Path,
    ) -> Result<Self, ObserverError> {
        if !valid_identifier(&observer_id)
            || !valid_identifier(&network_id)
            || banks.is_empty()
            || banks.len() > MAX_OBSERVERS
        {
            return Err(ObserverError::Configuration);
        }
        let mut sources = BTreeMap::new();
        let mut source_keys = BTreeSet::new();
        for bank in banks {
            bank.validate()?;
            let key_bytes = verify_key(&bank.public_key_der_base64)?.to_bytes();
            if !source_keys.insert(key_bytes) {
                return Err(ObserverError::Configuration);
            }
            if sources.insert(bank.observer_id.clone(), bank).is_some() {
                return Err(ObserverError::Configuration);
            }
        }
        if !sources.contains_key(&observer_id) {
            return Err(ObserverError::Configuration);
        }
        prepare_state_directory(state_path)?;
        let db = sled::open(state_path).map_err(|_| ObserverError::Persistence)?;
        // Fail startup on corrupt anti-replay state. Never reset it implicitly.
        if let Some(state) = db
            .get(format!("sequence:{network_id}"))
            .map_err(|_| ObserverError::Persistence)?
        {
            let reservation: Reservation =
                serde_json::from_slice(&state).map_err(|_| ObserverError::Persistence)?;
            if reservation.sequence == 0
                || reservation.sequence > MAX_SEQUENCE
                || !valid_digest(&reservation.release_digest)
                || !valid_digest(&reservation.report_digest)
            {
                return Err(ObserverError::Persistence);
            }
        }
        Ok(Self {
            inner: Arc::new(Inner {
                observer_id,
                network_id,
                key,
                banks: sources,
                transport,
                db,
                inflight: tokio::sync::Semaphore::new(4),
                signing: Mutex::new(()),
            }),
        })
    }

    pub fn discovery(&self) -> ObserverDiscoveryV1 {
        ObserverDiscoveryV1 {
            schema: "kerosene.release-observer-discovery/v1".into(),
            observer_id: self.inner.observer_id.clone(),
            network_id: self.inner.network_id.clone(),
            public_key_der_base64: public_der(&self.inner.key),
            bank_observers: self.inner.banks.keys().cloned().collect(),
            report_schema: REPORT_SCHEMA.into(),
            max_report_lifetime_seconds: MAX_REPORT_LIFETIME_SECS,
            commit_certificate: CommitCertificateAvailability::Unavailable,
        }
    }

    /// Verify every observation against a fresh challenge-bound mTLS Bank read.
    /// Successful reads are persisted for the unsigned retrieval endpoint.
    pub async fn verify(
        &self,
        request: &ReleaseObserverRequestV1,
    ) -> Result<ReleaseObservationsV1, ObserverError> {
        validate_report_for_read(
            request,
            &self.inner.network_id,
            &self.inner.observer_id,
            Utc::now(),
        )?;
        let _permit = self
            .inner
            .inflight
            .try_acquire()
            .map_err(|_| ObserverError::Busy)?;
        let operation = async {
            let mut observations = Vec::new();
            for candidate in &request.report.observations {
                let bank = self
                    .inner
                    .banks
                    .get(&candidate.observer_id)
                    .ok_or(ObserverError::InvalidReport)?;
                let mut bytes = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut bytes);
                let challenge = hex::encode(bytes);
                let read = self
                    .inner
                    .transport
                    .read(
                        bank,
                        &request.report.release_lock_canonical_digest,
                        &challenge,
                    )
                    .await?;
                validate_bank_read(
                    &read,
                    bank,
                    &request.report,
                    candidate,
                    &challenge,
                    Utc::now(),
                )?;
                let payload = SignedReleaseObservationPayloadV1 {
                    schema: OBSERVATION_SCHEMA.into(),
                    release_id: request.report.release_id.clone(),
                    network_id: request.report.network_id.clone(),
                    target_sequence: request.report.target_sequence,
                    release_lock_canonical_digest: request
                        .report
                        .release_lock_canonical_digest
                        .clone(),
                    issued_at: timestamp(Utc::now()),
                    expires_at: read.expires_at.clone(),
                    observation: read.observation.clone(),
                    bank_read: read,
                    commit_certificate: CommitCertificateAvailability::Unavailable,
                };
                let signature = sign_payload(&self.inner.key, &self.inner.observer_id, &payload);
                observations.push(payload.signed(vec![signature]));
            }
            Ok::<_, ObserverError>(ReleaseObservationsV1 {
                schema: READS_SCHEMA.into(),
                observations,
            })
        };
        let reads = tokio::time::timeout(Duration::from_secs(10), operation)
            .await
            .map_err(|_| ObserverError::BankUnavailable)??;
        // Recheck after network IO: never emit evidence after the report expires.
        validate_report_for_read(
            request,
            &self.inner.network_id,
            &self.inner.observer_id,
            Utc::now(),
        )?;
        if reads
            .observations
            .iter()
            .any(|read| parse_time(&read.expires_at).map_or(true, |expiry| expiry <= Utc::now()))
        {
            return Err(ObserverError::Expired);
        }
        let encoded = serde_json::to_vec(&reads).map_err(|_| ObserverError::Persistence)?;
        // One cached target per network bounds storage. High-water mark is separate.
        self.inner
            .db
            .insert(format!("reads:{}", self.inner.network_id), encoded)
            .map_err(|_| ObserverError::Persistence)?;
        self.inner
            .db
            .flush()
            .map_err(|_| ObserverError::Persistence)?;
        Ok(reads)
    }

    /// The entire v2 document is signed only after durable sequence reservation.
    /// A crash after reservation burns the sequence; retries never re-sign it.
    pub async fn sign(
        &self,
        request: &ReleaseObserverRequestV1,
    ) -> Result<BankObserverReportV2, ObserverError> {
        self.check_sequence(request.report.target_sequence)?;
        validate_report(
            request,
            &self.inner.network_id,
            &self.inner.observer_id,
            Utc::now(),
        )?;
        self.verify(request).await?;
        let _lock = self.inner.signing.lock();
        self.check_sequence(request.report.target_sequence)?;
        validate_report(
            request,
            &self.inner.network_id,
            &self.inner.observer_id,
            Utc::now(),
        )?;
        let reservation = Reservation {
            sequence: request.report.target_sequence,
            release_digest: request.report.release_lock_canonical_digest.clone(),
            report_digest: format!("sha256:{}", canonical_json_hash(&request.report)),
        };
        self.inner
            .db
            .insert(
                format!("sequence:{}", self.inner.network_id),
                serde_json::to_vec(&reservation).map_err(|_| ObserverError::Persistence)?,
            )
            .map_err(|_| ObserverError::Persistence)?;
        self.inner
            .db
            .flush()
            .map_err(|_| ObserverError::Persistence)?;
        let signature = sign_payload(&self.inner.key, &self.inner.observer_id, &request.report);
        Ok(request.report.clone().signed(vec![signature]))
    }

    pub fn observations(&self, digest: &str) -> Result<ReleaseObservationsV1, ObserverError> {
        if !valid_digest(digest) {
            return Err(ObserverError::InvalidReport);
        }
        let bytes = self
            .inner
            .db
            .get(format!("reads:{}", self.inner.network_id))
            .map_err(|_| ObserverError::Persistence)?
            .ok_or(ObserverError::NotFound)?;
        let reads: ReleaseObservationsV1 =
            serde_json::from_slice(&bytes).map_err(|_| ObserverError::Persistence)?;
        if reads.observations.is_empty()
            || reads
                .observations
                .iter()
                .any(|read| read.release_lock_canonical_digest != digest)
        {
            return Err(ObserverError::NotFound);
        }
        if reads
            .observations
            .iter()
            .any(|read| parse_time(&read.expires_at).map_or(true, |t| t <= Utc::now()))
        {
            return Err(ObserverError::Expired);
        }
        Ok(reads)
    }

    fn check_sequence(&self, sequence: u64) -> Result<(), ObserverError> {
        if let Some(bytes) = self
            .inner
            .db
            .get(format!("sequence:{}", self.inner.network_id))
            .map_err(|_| ObserverError::Persistence)?
        {
            let state: Reservation =
                serde_json::from_slice(&bytes).map_err(|_| ObserverError::Persistence)?;
            if sequence <= state.sequence {
                return Err(ObserverError::Replay);
            }
        }
        Ok(())
    }
}

fn prepare_state_directory(path: &Path) -> Result<(), ObserverError> {
    if !path.is_absolute() {
        return Err(ObserverError::Persistence);
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(ObserverError::Persistence);
        }
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(ObserverError::Persistence),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ObserverError::Persistence),
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        match std::fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(ObserverError::Persistence),
        }
        let meta = std::fs::symlink_metadata(path).map_err(|_| ObserverError::Persistence)?;
        if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
            return Err(ObserverError::Persistence);
        }
    }
    #[cfg(not(unix))]
    return Err(ObserverError::Persistence);
    Ok(())
}

#[cfg(all(test, unix))]
mod state_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn observer_state_requires_a_private_real_directory_and_never_repairs_unsafe_permissions() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state");
        prepare_state_directory(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(prepare_state_directory(&path).is_err());
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(prepare_state_directory(&link).is_err());
        assert!(prepare_state_directory(Path::new("relative-state")).is_err());
        assert!(prepare_state_directory(&root.path().join("state/../other")).is_err());
    }
}

pub fn timestamp(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Secs, true)
}
fn parse_time(value: &str) -> Result<DateTime<Utc>, ObserverError> {
    DateTime::parse_from_rfc3339(value)
        .map(|v| v.with_timezone(&Utc))
        .map_err(|_| ObserverError::InvalidReport)
}

pub fn validate_report(
    request: &ReleaseObserverRequestV1,
    network: &str,
    local: &str,
    now: DateTime<Utc>,
) -> Result<(), ObserverError> {
    validate_report_identity(request, network, local, now, true)
}

fn validate_report_for_read(
    request: &ReleaseObserverRequestV1,
    network: &str,
    local: &str,
    now: DateTime<Utc>,
) -> Result<(), ObserverError> {
    validate_report_identity(request, network, local, now, false)
}

fn validate_report_identity(
    request: &ReleaseObserverRequestV1,
    network: &str,
    local: &str,
    now: DateTime<Utc>,
    require_local_compatible: bool,
) -> Result<(), ObserverError> {
    let report = &request.report;
    let lock = &request.release_lock;
    let digest = canonical_release_digest(lock).map_err(|_| ObserverError::InvalidReport)?;
    let supported_lock = matches!(
        (
            lock.get("schema").and_then(|v| v.as_str()),
            lock.get("schemaVersion").and_then(|v| v.as_u64())
        ),
        (Some("kerosene.release-lock/v1"), Some(1))
            | (Some("kerosene.release-lock/v2"), Some(2))
            | (Some("kerosene.release-lock/v3"), Some(3))
    );
    if !supported_lock
        || report.schema != REPORT_SCHEMA
        || !valid_identifier(&report.release_id)
        || !valid_identifier(&report.network_id)
        || report.network_id != network
        || report.target_sequence == 0
        || report.target_sequence > MAX_SEQUENCE
        || lock.get("releaseId").and_then(|v| v.as_str()) != Some(report.release_id.as_str())
        || lock
            .get("network")
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            != Some(network)
        || lock
            .get("network")
            .and_then(|v| v.get("plane"))
            .and_then(|v| v.as_str())
            != Some("bank")
        || lock.get("sequence").and_then(|v| v.as_u64()) != Some(report.target_sequence)
        || report.release_lock_canonical_digest != digest
        || report.observations.is_empty()
        || report.observations.len() > MAX_OBSERVERS
    {
        return Err(ObserverError::InvalidReport);
    }
    let issued = parse_time(&report.issued_at)?;
    let expires = parse_time(&report.expires_at)?;
    if issued > now + chrono::Duration::seconds(MAX_CLOCK_SKEW_SECS)
        || expires <= now
        || expires <= issued
        || expires - issued > chrono::Duration::seconds(MAX_REPORT_LIFETIME_SECS)
    {
        return Err(ObserverError::Expired);
    }
    let mut seen = BTreeSet::new();
    let mut local_compatible = false;
    for observation in &report.observations {
        let observed = parse_time(&observation.observed_at)?;
        if !valid_identifier(&observation.observer_id)
            || !seen.insert(observation.observer_id.as_str())
            || !valid_digest(&observation.release_digest)
            || observation.observed_sequence > MAX_SEQUENCE
            || observed > issued + chrono::Duration::seconds(MAX_CLOCK_SKEW_SECS)
            || observed < issued - chrono::Duration::seconds(MAX_OBSERVATION_AGE_SECS)
        {
            return Err(ObserverError::InvalidReport);
        }
        if observation.status == Compatibility::Compatible {
            if observation.observed_sequence != report.target_sequence
                || observation.release_digest != digest
            {
                return Err(ObserverError::InvalidReport);
            }
            local_compatible |= observation.observer_id == local;
        }
    }
    if !seen.contains(local) {
        return Err(ObserverError::InvalidReport);
    }
    if require_local_compatible && !local_compatible {
        return Err(ObserverError::Incompatible);
    }
    Ok(())
}

fn validate_bank_read(
    read: &BankReleaseReadV1,
    bank: &BankEndpoint,
    report: &BankObserverReportPayloadV2,
    candidate: &BankObservationV2,
    challenge: &str,
    now: DateTime<Utc>,
) -> Result<(), ObserverError> {
    let issued = parse_time(&read.issued_at).map_err(|_| ObserverError::InvalidBankEvidence)?;
    let expires = parse_time(&read.expires_at).map_err(|_| ObserverError::InvalidBankEvidence)?;
    let observed = parse_time(&read.observation.observed_at)
        .map_err(|_| ObserverError::InvalidBankEvidence)?;
    if read.schema != BANK_READ_SCHEMA
        || read.source != BankReadSource::BankRuntime
        || read.challenge != challenge
        || read.release_id != report.release_id
        || read.network_id != report.network_id
        || read.target_sequence != report.target_sequence
        || read.release_lock_canonical_digest != report.release_lock_canonical_digest
        || read.observation.observer_id != bank.observer_id
        || read.observation.status != candidate.status
        || read.observation.observed_sequence != candidate.observed_sequence
        || read.observation.release_digest != candidate.release_digest
        || read.signatures.len() != 1
        || issued > now + chrono::Duration::seconds(5)
        || issued < now - chrono::Duration::seconds(MAX_BANK_READ_LIFETIME_SECS)
        || expires <= now
        || expires <= issued
        || expires - issued > chrono::Duration::seconds(MAX_BANK_READ_LIFETIME_SECS)
        || observed > issued + chrono::Duration::seconds(5)
        || observed < issued - chrono::Duration::seconds(MAX_OBSERVATION_AGE_SECS)
    {
        return Err(ObserverError::InvalidBankEvidence);
    }
    verify_signature(
        &read.payload(),
        &read.signatures[0],
        &bank.observer_id,
        &bank.public_key_der_base64,
    )
}

pub fn public_der(key: &SigningKey) -> String {
    STANDARD.encode(
        key.verifying_key()
            .to_public_key_der()
            .expect("Ed25519 SPKI encoding")
            .as_bytes(),
    )
}
pub fn verify_key(encoded: &str) -> Result<VerifyingKey, ObserverError> {
    let der = STANDARD
        .decode(encoded)
        .map_err(|_| ObserverError::Configuration)?;
    VerifyingKey::from_public_key_der(&der).map_err(|_| ObserverError::Configuration)
}
pub fn sign_payload<T: Serialize>(
    key: &SigningKey,
    member_id: &str,
    payload: &T,
) -> ReleaseSignatureV1 {
    ReleaseSignatureV1 {
        member_id: member_id.into(),
        public_key_der_base64: public_der(key),
        signature_base64: STANDARD.encode(key.sign(&canonical_json_bytes(payload)).to_bytes()),
    }
}
pub fn verify_signature<T: Serialize>(
    payload: &T,
    signature: &ReleaseSignatureV1,
    member: &str,
    trusted_der: &str,
) -> Result<(), ObserverError> {
    if signature.member_id != member || signature.public_key_der_base64 != trusted_der {
        return Err(ObserverError::InvalidBankEvidence);
    }
    let key = verify_key(trusted_der).map_err(|_| ObserverError::InvalidBankEvidence)?;
    let bytes = STANDARD
        .decode(&signature.signature_base64)
        .map_err(|_| ObserverError::InvalidBankEvidence)?;
    let sig = Signature::from_slice(&bytes).map_err(|_| ObserverError::InvalidBankEvidence)?;
    key.verify_strict(&canonical_json_bytes(payload), &sig)
        .map_err(|_| ObserverError::InvalidBankEvidence)
}
