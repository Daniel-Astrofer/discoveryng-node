use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use kerosene_contracts::{canonical_json_bytes, release::*};
use kerosene_release_observer::*;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::{
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
    RootCertStore, ServerConfig,
};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
};

#[derive(Clone)]
struct BankState {
    request: ReleaseObserverRequestV1,
    mode: Arc<AtomicU8>,
    key: SigningKey,
}

async fn read(
    State(state): State<BankState>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    assert_eq!(
        query["releaseDigest"],
        state.request.report.release_lock_canonical_digest
    );
    let now = Utc::now();
    let mode = state.mode.load(Ordering::SeqCst);
    if mode == 8 {
        return (
            StatusCode::TEMPORARY_REDIRECT,
            [("location", "https://untrusted.invalid")],
        )
            .into_response();
    }
    if mode == 9 {
        return Json(serde_json::json!({"padding":"x".repeat(MAX_BODY_BYTES)})).into_response();
    }
    let mut payload = BankReleaseReadPayloadV1 {
        schema: BANK_READ_SCHEMA.into(),
        release_id: state.request.report.release_id.clone(),
        network_id: state.request.report.network_id.clone(),
        target_sequence: state.request.report.target_sequence,
        release_lock_canonical_digest: state.request.report.release_lock_canonical_digest.clone(),
        issued_at: timestamp(now),
        expires_at: timestamp(now + Duration::seconds(45)),
        challenge: query["challenge"].clone(),
        source: BankReadSource::BankRuntime,
        observation: state.request.report.observations[0].clone(),
    };
    payload.observation.observed_at = timestamp(now);
    match mode {
        1 => payload.source = BankReadSource::Synthetic,
        2 => payload.challenge = "0".repeat(64),
        3 => payload.expires_at = timestamp(now - Duration::seconds(1)),
        4 => payload.observation.status = Compatibility::Incompatible,
        5 => payload.release_lock_canonical_digest = format!("sha256:{}", "f".repeat(64)),
        6 => payload.expires_at = timestamp(now + Duration::seconds(61)),
        7 => payload.observation.observed_at = timestamp(now - Duration::seconds(901)),
        10 => {
            payload.observation.status = Compatibility::Unknown;
            payload.observation.observed_sequence = 0;
        }
        _ => {}
    }
    let signature = sign_payload(&state.key, "bank-001", &payload);
    Json(payload.signed(vec![signature])).into_response()
}

fn request() -> ReleaseObserverRequestV1 {
    let lock = serde_json::json!({"schema":"kerosene.release-lock/v3","schemaVersion":3,"releaseId":"release-001","network":{"id":"bank-main","plane":"bank"},"sequence":42,"authorization":{"bft":{"networkId":"governance-main","epoch":1,"threshold":3,"members":4}}});
    let digest = canonical_release_digest(&lock).unwrap();
    let now = Utc::now();
    ReleaseObserverRequestV1 {
        release_lock: lock,
        report: BankObserverReportPayloadV2 {
            schema: REPORT_SCHEMA.into(),
            release_id: "release-001".into(),
            network_id: "bank-main".into(),
            target_sequence: 42,
            release_lock_canonical_digest: digest.clone(),
            issued_at: timestamp(now),
            expires_at: timestamp(now + Duration::seconds(300)),
            observations: vec![BankObservationV2 {
                observer_id: "bank-001".into(),
                status: Compatibility::Compatible,
                observed_sequence: 42,
                release_digest: digest,
                observed_at: timestamp(now),
            }],
        },
    }
}

struct Fixture {
    bank: BankEndpoint,
    identity: Vec<u8>,
    ca: Vec<u8>,
    mode: Arc<AtomicU8>,
    handle: axum_server::Handle<std::net::SocketAddr>,
    state_dir: tempfile::TempDir,
    request: ReleaseObserverRequestV1,
}

impl Fixture {
    async fn start() -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let server_key = KeyPair::generate().unwrap();
        let mut server_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();
        let client_key = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::new(vec![]).unwrap();
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .unwrap();
        let identity = format!("{}{}", client_cert.pem(), client_key.serialize_pem()).into_bytes();
        let mut roots = RootCertStore::empty();
        roots.add(ca_cert.der().clone()).unwrap();
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server_cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )
            .unwrap();
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let mode = Arc::new(AtomicU8::new(0));
        let request = request();
        let bank_key = SigningKey::from_bytes(&[8; 32]);
        let api = Router::new()
            .route("/v1/releases/observation", get(read))
            .with_state(BankState {
                request: request.clone(),
                mode: mode.clone(),
                key: bank_key.clone(),
            });
        let handle = axum_server::Handle::new();
        let server = axum_server::from_tcp_rustls(listener, tls)
            .unwrap()
            .handle(handle.clone());
        tokio::spawn(async move {
            server.serve(api.into_make_service()).await.unwrap();
        });
        handle.listening().await.unwrap();
        Self {
            bank: BankEndpoint {
                observer_id: "bank-001".into(),
                endpoint: format!("https://localhost:{}", address.port()),
                public_key_der_base64: public_der(&bank_key),
            },
            identity,
            ca: ca_cert.pem().into_bytes(),
            mode,
            handle,
            state_dir: tempfile::tempdir().unwrap(),
            request,
        }
    }
    fn observer(&self) -> ReleaseObserver {
        self.with_bank(self.bank.clone())
    }
    fn with_bank(&self, bank: BankEndpoint) -> ReleaseObserver {
        ReleaseObserver::open(
            "bank-001".into(),
            "bank-main".into(),
            SigningKey::from_bytes(&[7; 32]),
            vec![bank],
            BankTransport::new_mtls(&self.identity, &self.ca, None).unwrap(),
            &self.state_dir.path().join("observer"),
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.handle.shutdown();
    }
}

#[tokio::test]
async fn real_mtls_read_signature_full_report_deploy_verifier_and_restart_replay() {
    let fixture = Fixture::start().await;
    let observer = fixture.observer();
    let reads = observer.verify(&fixture.request).await.unwrap();
    assert_eq!(reads.observations.len(), 1);
    let signed = &reads.observations[0];
    assert_eq!(
        signed.commit_certificate,
        CommitCertificateAvailability::Unavailable
    );
    verify_signature(
        &signed.payload(),
        &signed.signatures[0],
        "bank-001",
        &public_der(&SigningKey::from_bytes(&[7; 32])),
    )
    .unwrap();
    assert_eq!(
        observer
            .observations(&fixture.request.report.release_lock_canonical_digest)
            .unwrap(),
        reads
    );
    let report = observer.sign(&fixture.request).await.unwrap();
    verify_signature(
        &report.payload(),
        &report.signatures[0],
        "bank-001",
        &report.signatures[0].public_key_der_base64,
    )
    .unwrap();
    // OpenSSL is the exact Ed25519 verification primitive used by deploy.
    let dir = tempfile::tempdir().unwrap();
    let payload_path = dir.path().join("payload");
    let sig_path = dir.path().join("sig");
    let key_path = dir.path().join("pub.der");
    use base64::{engine::general_purpose::STANDARD, Engine};
    std::fs::write(&payload_path, canonical_json_bytes(&report.payload())).unwrap();
    std::fs::write(
        &sig_path,
        STANDARD
            .decode(&report.signatures[0].signature_base64)
            .unwrap(),
    )
    .unwrap();
    std::fs::write(
        &key_path,
        STANDARD
            .decode(&report.signatures[0].public_key_der_base64)
            .unwrap(),
    )
    .unwrap();
    assert!(std::process::Command::new("openssl")
        .args(["pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey"])
        .arg(key_path)
        .arg("-sigfile")
        .arg(sig_path)
        .arg("-in")
        .arg(payload_path)
        .status()
        .unwrap()
        .success());
    drop(observer);
    let restarted = fixture.observer();
    assert!(restarted
        .observations(&fixture.request.report.release_lock_canonical_digest)
        .is_ok());
    assert!(matches!(
        restarted.sign(&fixture.request).await,
        Err(ObserverError::Replay)
    ));
    let mut older = fixture.request.clone();
    older.report.target_sequence -= 1;
    assert!(matches!(
        restarted.sign(&older).await,
        Err(ObserverError::Replay)
    ));
    let mut conflict = fixture.request.clone();
    conflict.report.release_lock_canonical_digest = format!("sha256:{}", "a".repeat(64));
    assert!(matches!(
        restarted.sign(&conflict).await,
        Err(ObserverError::Replay)
    ));
}

#[tokio::test]
async fn synthetic_replayed_expired_mismatched_and_incompatible_bank_evidence_never_counts() {
    let fixture = Fixture::start().await;
    let observer = fixture.observer();
    for mode in 1..=7 {
        fixture.mode.store(mode, Ordering::SeqCst);
        assert!(
            matches!(
                observer.sign(&fixture.request).await,
                Err(ObserverError::InvalidBankEvidence)
            ),
            "mode {mode}"
        );
    }
    for mode in [8, 9] {
        fixture.mode.store(mode, Ordering::SeqCst);
        assert!(
            matches!(
                observer.sign(&fixture.request).await,
                Err(ObserverError::BankUnavailable)
            ),
            "transport mode {mode}"
        );
    }
    assert!(matches!(
        observer.observations(&fixture.request.report.release_lock_canonical_digest),
        Err(ObserverError::NotFound)
    ));
    fixture.mode.store(0, Ordering::SeqCst);
    // Failed checks never reserve/burn a sequence.
    assert!(observer.sign(&fixture.request).await.is_ok());
}

#[tokio::test]
async fn missing_client_certificate_and_wrong_bank_key_are_rejected() {
    let fixture = Fixture::start().await;
    let ca = reqwest::Certificate::from_pem(&fixture.ca).unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(ca)
        .build()
        .unwrap();
    let result = client
        .get(format!("{}/v1/releases/observation", fixture.bank.endpoint))
        .send()
        .await;
    assert!(result.is_err(), "listener must require client certificate");
    let mut wrong = fixture.bank.clone();
    wrong.public_key_der_base64 = public_der(&SigningKey::from_bytes(&[9; 32]));
    let observer = fixture.with_bank(wrong);
    assert!(matches!(
        observer.sign(&fixture.request).await,
        Err(ObserverError::InvalidBankEvidence)
    ));
}

#[tokio::test]
async fn simultaneous_signing_reserves_only_once() {
    let fixture = Fixture::start().await;
    let observer = fixture.observer();
    let (a, b) = tokio::join!(
        observer.sign(&fixture.request),
        observer.sign(&fixture.request)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(matches!(a, Err(ObserverError::Replay)) || matches!(b, Err(ObserverError::Replay)));
}

#[tokio::test]
async fn incompatible_and_unknown_are_visible_but_never_authorize_an_update() {
    let fixture = Fixture::start().await;
    let observer = fixture.observer();
    for (mode, status, sequence) in [
        (4, Compatibility::Incompatible, 42),
        (10, Compatibility::Unknown, 0),
    ] {
        fixture.mode.store(mode, Ordering::SeqCst);
        let mut request = fixture.request.clone();
        request.report.observations[0].status = status.clone();
        request.report.observations[0].observed_sequence = sequence;
        let reads = observer.verify(&request).await.unwrap();
        assert_eq!(reads.observations[0].observation.status, status);
        assert_eq!(
            observer
                .observations(&request.report.release_lock_canonical_digest)
                .unwrap(),
            reads
        );
        assert!(matches!(
            observer.sign(&request).await,
            Err(ObserverError::Incompatible)
        ));
    }
    fixture.mode.store(0, Ordering::SeqCst);
    assert!(
        observer.sign(&fixture.request).await.is_ok(),
        "negative reads must not consume the signing sequence"
    );
}

#[test]
fn malformed_targets_duplicates_time_gates_and_float_canonicalization_fail() {
    let request = request();
    let now = Utc::now();
    validate_report(&request, "bank-main", "bank-001", now).unwrap();
    let mut bad = request.clone();
    bad.report
        .observations
        .push(bad.report.observations[0].clone());
    assert!(validate_report(&bad, "bank-main", "bank-001", now).is_err());
    let mut bad = request.clone();
    bad.report.expires_at = timestamp(now + Duration::hours(2));
    assert!(validate_report(&bad, "bank-main", "bank-001", now).is_err());
    let mut bad = request.clone();
    bad.report.observations[0].observed_at = timestamp(now - Duration::minutes(16));
    assert!(validate_report(&bad, "bank-main", "bank-001", now).is_err());
    let mut bad = request.clone();
    bad.release_lock["sequence"] = serde_json::json!(43);
    assert!(validate_report(&bad, "bank-main", "bank-001", now).is_err());
    assert!(canonical_release_digest(&serde_json::json!({"float":1.2})).is_err());
    let mut bad = request.clone();
    bad.report.observations[0].status = Compatibility::Unknown;
    assert!(matches!(
        validate_report(&bad, "bank-main", "bank-001", now),
        Err(ObserverError::Incompatible)
    ));
}
