//! Explicit disposable Node/Core wire qualification, never release authorization.
use std::{path::PathBuf, process::ExitCode};

use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use kerosene_contracts::release::*;
use kerosene_release_observer::{
    timestamp, BankEndpoint, BankTransport, ObserverError, ReleaseObserver,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LabConfiguration {
    bank: BankEndpoint,
    network_id: String,
    release_lock: serde_json::Value,
    identity_pem: PathBuf,
    ca_pem: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    match probe().await {
        Ok(()) => {
            println!("Node/Core mTLS read and independent signature verified; unknown target cannot authorize signing");
            ExitCode::SUCCESS
        }
        Err(error) => {
            // No configuration, endpoints, certificate bytes or credentials in output.
            eprintln!("Node/Core disposable probe failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn probe() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut args = std::env::args_os().skip(1);
    let path = args
        .next()
        .ok_or("one disposable configuration path required")?;
    if args.next().is_some() {
        return Err("one disposable configuration path required".into());
    }
    let configuration: LabConfiguration =
        decode_release_json(&std::fs::read(path)?).map_err(|_| "invalid probe configuration")?;
    let endpoint = url::Url::parse(&configuration.bank.endpoint)?;
    if !matches!(
        endpoint.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]")
    ) {
        return Err("disposable probe requires a loopback Core endpoint".into());
    }
    let transport = BankTransport::new_mtls(
        &std::fs::read(&configuration.identity_pem)?,
        &std::fs::read(&configuration.ca_pem)?,
        None,
    )?;
    let state = tempfile::tempdir()?;
    let observer = ReleaseObserver::open(
        configuration.bank.observer_id.clone(),
        configuration.network_id.clone(),
        SigningKey::generate(&mut rand::rngs::OsRng),
        vec![configuration.bank.clone()],
        transport,
        &state.path().join("observer-state"),
    )?;
    let now = Utc::now();
    let lock = configuration.release_lock;
    let digest = canonical_release_digest(&lock)?;
    let request = ReleaseObserverRequestV1 {
        report: BankObserverReportPayloadV2 {
            schema: REPORT_SCHEMA.into(),
            release_id: lock["releaseId"]
                .as_str()
                .ok_or("missing release id")?
                .into(),
            network_id: configuration.network_id,
            target_sequence: lock["sequence"].as_u64().ok_or("missing target sequence")?,
            release_lock_canonical_digest: digest.clone(),
            issued_at: timestamp(now),
            expires_at: timestamp(now + Duration::seconds(60)),
            observations: vec![BankObservationV2 {
                observer_id: configuration.bank.observer_id,
                status: Compatibility::Unknown,
                observed_sequence: 0,
                release_digest: digest.clone(),
                observed_at: timestamp(now),
            }],
        },
        release_lock: lock,
    };
    // The real production path queries Core with a random challenge and checks
    // both target bindings and its independently pinned Bank signature.
    let reads = observer.verify(&request).await?;
    if reads.observations.len() != 1
        || reads.observations[0].observation.status != Compatibility::Unknown
        || reads.observations[0].bank_read.source != BankReadSource::BankRuntime
        || reads.observations[0].commit_certificate != CommitCertificateAvailability::Unavailable
        || observer.observations(&digest)? != reads
    {
        return Err("unexpected cached evidence".into());
    }
    if !matches!(
        observer.sign(&request).await,
        Err(ObserverError::Incompatible)
    ) {
        return Err("unknown target was not rejected for signing".into());
    }
    Ok(())
}
