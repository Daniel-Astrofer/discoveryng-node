use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use kerosene_contracts::{
    member_id, CanonicalSignable, DiscoveryPlane, GenesisTrustBundleV1, ManifestMember,
    ManifestSignature, MembershipManifestV1, MembershipPhase, TrustMember, TrustPlane,
    DISCOVERY_CONTRACT_VERSION,
};
use kerosene_discovery::{DiscoveryError, HelloExchangeRequest, PersistentPeerStore};
use kerosene_identity_core::NodeIdentity;
use kerosene_membership::MembershipVerifier;
use kerosene_node::NodeService;
use kerosene_sync::{LifecycleStore, StateSnapshot};
use sha2::{Digest, Sha256};

const NETWORK: &str = "kerosene-test";

fn onion(character: char) -> String {
    format!("https://{}.onion", character.to_string().repeat(56))
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn trust(key: &SigningKey) -> TrustMember {
    TrustMember {
        member_id: member_id(NETWORK, key.verifying_key().as_bytes()),
        root_public_key: hex::encode(key.verifying_key().as_bytes()),
    }
}

fn bundle(bank: &[SigningKey], vault: &[SigningKey]) -> GenesisTrustBundleV1 {
    GenesisTrustBundleV1 {
        contract_version: DISCOVERY_CONTRACT_VERSION.into(),
        network_id: NETWORK.into(),
        bank: TrustPlane {
            threshold: 2,
            members: bank.iter().map(trust).collect(),
        },
        vault: TrustPlane {
            threshold: 2,
            members: vault.iter().map(trust).collect(),
        },
        created_at_epoch_ms: 1,
    }
}

fn service(
    bundle: &GenesisTrustBundleV1,
    plane: DiscoveryPlane,
    seed: u8,
    endpoint: String,
) -> (NodeService, tempfile::TempDir) {
    let root = tempfile::tempdir().unwrap();
    let identity = Arc::new(NodeIdentity::from_secret(NETWORK, plane, [seed; 32]));
    let membership = MembershipVerifier::new(bundle, plane).unwrap();
    let peer_store = Arc::new(PersistentPeerStore::open(root.path()).unwrap());
    let service = NodeService::new(
        identity,
        endpoint,
        plane,
        membership,
        peer_store,
        LifecycleStore::new(root.path().join("lifecycle.db")),
        30_000,
        90_000,
    )
    .unwrap();
    (service, root)
}

fn initial_manifest(
    plane: DiscoveryPlane,
    keys: &[SigningKey],
    endpoint_character: char,
) -> MembershipManifestV1 {
    let mut manifest = MembershipManifestV1 {
        contract_version: DISCOVERY_CONTRACT_VERSION.into(),
        network_id: NETWORK.into(),
        plane,
        epoch: 1,
        phase: MembershipPhase::Stable,
        previous_manifest_hash: "0".repeat(64),
        threshold: 2,
        members: keys
            .iter()
            .enumerate()
            .map(|(index, key)| ManifestMember {
                member_id: member_id(NETWORK, key.verifying_key().as_bytes()),
                root_public_key: hex::encode(key.verifying_key().as_bytes()),
                endpoint: onion(char::from_u32(endpoint_character as u32 + index as u32).unwrap()),
            })
            .collect(),
        next_epoch: None,
        signatures: vec![],
    };
    manifest.signatures = keys[..2]
        .iter()
        .map(|key| ManifestSignature {
            signer_id: member_id(NETWORK, key.verifying_key().as_bytes()),
            signature: hex::encode(key.sign(&manifest.signing_bytes()).to_bytes()),
        })
        .collect();
    manifest
}

fn snapshot(epoch: u64) -> StateSnapshot {
    let bytes = format!("verified-state-{epoch}").into_bytes();
    StateSnapshot {
        epoch,
        state_root: hex::encode(Sha256::digest(&bytes)),
        bytes,
    }
}

fn kfe_checkpoint(service: &NodeService, now: u64) -> kerosene_node::KfeLedgerCheckpoint {
    let mut checkpoint = kerosene_node::KfeLedgerCheckpoint {
        network: NETWORK.into(),
        challenge: service.issue_ledger_challenge(now).unwrap(),
        generated_at_ms: now,
        expires_at_ms: now + 120_000,
        ledger_root: "b".repeat(64),
        balances_count: 2,
        postings_count: 3,
        signature: String::new(),
    };
    checkpoint.signature = hex::encode(
        key(7)
            .sign(checkpoint.signing_message().as_bytes())
            .to_bytes(),
    );
    checkpoint
}

#[test]
fn authoritative_kfe_checkpoint_completes_sync_and_expires_without_erasing_source() {
    let bank = [key(1), key(2), key(3)];
    let vault = [key(4), key(5), key(6)];
    let (service, root) = service(&bundle(&bank, &vault), DiscoveryPlane::Vault, 4, onion('d'));
    let public = hex::encode(key(7).verifying_key().as_bytes());
    service.configure_kfe_ledger_source(Some(&public)).unwrap();
    let now = kerosene_node::now_epoch_ms();
    let remote = NodeIdentity::from_secret(NETWORK, DiscoveryPlane::Vault, [5; 32]);
    service
        .exchange_hello(
            &HelloExchangeRequest {
                hello: remote.sign_hello(service.issue_challenge(now), onion('e'), now),
                response_challenge: "a".repeat(64),
            },
            now,
        )
        .unwrap();
    service
        .accept_membership(initial_manifest(DiscoveryPlane::Vault, &vault, 'd'))
        .unwrap();
    assert!(!service.readiness(now).financial_ready);
    let lifecycle_path = root.path().join("lifecycle.db");
    let saved_lifecycle = std::fs::read(&lifecycle_path).unwrap();
    std::fs::remove_file(&lifecycle_path).unwrap();
    std::fs::create_dir(&lifecycle_path).unwrap();
    assert!(service
        .accept_kfe_checkpoint(kfe_checkpoint(&service, now), now)
        .is_err());
    assert!(service.readiness(now).ledger_source.is_none());
    assert!(!service.readiness(now).financial_ready);
    std::fs::remove_dir(&lifecycle_path).unwrap();
    std::fs::write(&lifecycle_path, saved_lifecycle).unwrap();
    let proof = kfe_checkpoint(&service, now);
    service.accept_kfe_checkpoint(proof.clone(), now).unwrap();
    assert!(service.readiness(now).financial_ready);
    assert_eq!(service.readiness(now).ledger_source.unwrap().source, "KFE");
    assert!(
        service.accept_kfe_checkpoint(proof, now).is_err(),
        "one-use nonce must reject replay"
    );
    assert!(!service.readiness(now + 120_001).financial_ready);
    assert!(service
        .readiness(now + 120_001)
        .financial_blockers
        .contains(&"KFE_LEDGER_CHECKPOINT_UNAVAILABLE_OR_STALE"));
    assert!(service.readiness(now + 120_001).ledger_source.is_some());

    // Reconstruct the service from a persisted ACTIVE lifecycle. It still needs
    // a fresh KFE proof; persisted cursor alone cannot authorize operations.
    drop(service);
    let peers = Arc::new(PersistentPeerStore::open(root.path()).unwrap());
    let restored = NodeService::new(
        Arc::new(NodeIdentity::from_secret(
            NETWORK,
            DiscoveryPlane::Vault,
            [4; 32],
        )),
        onion('d'),
        DiscoveryPlane::Vault,
        MembershipVerifier::restore(
            &bundle(&bank, &vault),
            DiscoveryPlane::Vault,
            peers.manifests().unwrap(),
        )
        .unwrap(),
        peers,
        LifecycleStore::new(root.path().join("lifecycle.db")),
        30_000,
        90_000,
    )
    .unwrap();
    restored.configure_kfe_ledger_source(Some(&public)).unwrap();
    assert!(!restored.readiness(now).financial_ready);
    assert!(restored.readiness(now).ledger_source.is_none());
}

#[test]
fn invalid_kfe_proof_cannot_consume_a_valid_nonce_or_activate_the_node() {
    let bank = [key(1), key(2), key(3)];
    let vault = [key(4), key(5), key(6)];
    let (service, _root) = service(&bundle(&bank, &vault), DiscoveryPlane::Vault, 4, onion('d'));
    service
        .configure_kfe_ledger_source(Some(&hex::encode(key(7).verifying_key().as_bytes())))
        .unwrap();
    let now = kerosene_node::now_epoch_ms();
    let valid = kfe_checkpoint(&service, now);
    let mut forged = valid.clone();
    forged.ledger_root = "c".repeat(64);
    assert!(service.accept_kfe_checkpoint(forged, now).is_err());
    assert!(service.readiness(now).ledger_source.is_none());
    // Valid signatures do not skip peer authentication and membership stages.
    assert!(service.accept_kfe_checkpoint(valid, now).is_err());
    assert!(!service.readiness(now).financial_ready);
}

#[test]
fn one_core_and_one_vault_are_locally_ready_but_not_cross_plane_quorum() {
    let bank = [key(1), key(2), key(3)];
    let vault = [key(4), key(5), key(6)];
    let bundle = bundle(&bank, &vault);
    let (core, _core_root) = service(&bundle, DiscoveryPlane::Bank, 1, onion('a'));
    let (vault_node, _vault_root) = service(&bundle, DiscoveryPlane::Vault, 4, onion('d'));

    let core_ready = core.readiness(10_000);
    let vault_ready = vault_node.readiness(10_000);
    assert!(core_ready.local_ready && core_ready.member_ready);
    assert!(vault_ready.local_ready && vault_ready.member_ready);
    assert!(!core_ready.quorum_ready);
    assert!(!vault_ready.quorum_ready);
    assert!(!vault_ready.financial_ready);

    let challenge = vault_node.issue_challenge(10_000);
    let cross_plane = NodeIdentity::from_secret(NETWORK, DiscoveryPlane::Bank, [1; 32]).sign_hello(
        challenge,
        onion('a'),
        10_000,
    );
    assert!(matches!(
        vault_node.exchange_hello(
            &HelloExchangeRequest {
                hello: cross_plane,
                response_challenge: "f".repeat(64),
            },
            10_000
        ),
        Err(DiscoveryError::ScopeMismatch)
    ));
}

#[test]
fn vault_becomes_financially_ready_only_after_live_threshold_and_verified_manifest() {
    let bank = [key(1), key(2), key(3)];
    let vault = [key(4), key(5), key(6)];
    let bundle = bundle(&bank, &vault);
    let (service, _root) = service(&bundle, DiscoveryPlane::Vault, 4, onion('d'));
    let now = kerosene_node::now_epoch_ms();

    let remote = NodeIdentity::from_secret(NETWORK, DiscoveryPlane::Vault, [5; 32]);
    let request = HelloExchangeRequest {
        hello: remote.sign_hello(service.issue_challenge(now), onion('e'), now),
        response_challenge: "a".repeat(64),
    };
    service.exchange_hello(&request, now).unwrap();
    assert!(service.readiness(now).quorum_ready);
    assert!(!service.readiness(now).financial_ready);

    service
        .accept_membership(initial_manifest(DiscoveryPlane::Vault, &vault, 'd'))
        .unwrap();
    assert!(!service.readiness(now).financial_ready);
    service.verify_state_snapshot(&snapshot(1)).unwrap();
    let ready = service.readiness(now);
    assert!(ready.quorum_ready);
    assert!(ready.financial_ready);
    assert_eq!(ready.operational_state, "ACTIVE");

    let expired = service.readiness(now + 90_001);
    assert!(!expired.quorum_ready);
    assert!(!expired.financial_ready);
}

#[test]
fn restart_preserves_manifests_but_not_liveness_authority() {
    let bank = [key(1), key(2), key(3)];
    let vault = [key(4), key(5), key(6)];
    let bundle = bundle(&bank, &vault);
    let root = tempfile::tempdir().unwrap();
    let manifest = initial_manifest(DiscoveryPlane::Vault, &vault, 'd');
    let store = Arc::new(PersistentPeerStore::open(root.path()).unwrap());
    let identity = Arc::new(NodeIdentity::from_secret(
        NETWORK,
        DiscoveryPlane::Vault,
        [4; 32],
    ));
    let service = NodeService::new(
        identity.clone(),
        onion('d'),
        DiscoveryPlane::Vault,
        MembershipVerifier::new(&bundle, DiscoveryPlane::Vault).unwrap(),
        store,
        LifecycleStore::new(root.path().join("lifecycle.db")),
        30_000,
        90_000,
    )
    .unwrap();
    service.accept_membership(manifest).unwrap();
    drop(service);

    let store = Arc::new(PersistentPeerStore::open(root.path()).unwrap());
    let verifier =
        MembershipVerifier::restore(&bundle, DiscoveryPlane::Vault, store.manifests().unwrap())
            .unwrap();
    let restarted = NodeService::new(
        identity,
        onion('d'),
        DiscoveryPlane::Vault,
        verifier,
        store,
        LifecycleStore::new(root.path().join("lifecycle.db")),
        30_000,
        90_000,
    )
    .unwrap();
    let ready = restarted.readiness(10_000);
    assert!(ready.member_ready);
    assert!(ready.manifest_hash.is_some());
    assert!(!ready.quorum_ready);
    assert!(!ready.financial_ready);
}

#[test]
fn three_nodes_form_same_plane_quorum_through_authenticated_handshakes() {
    let bank = [key(1), key(2), key(3)];
    let vault = [key(4), key(5), key(6)];
    let bundle = bundle(&bank, &vault);
    let (first, _first_root) = service(&bundle, DiscoveryPlane::Vault, 4, onion('d'));
    let (second, _second_root) = service(&bundle, DiscoveryPlane::Vault, 5, onion('e'));
    let (third, _third_root) = service(&bundle, DiscoveryPlane::Vault, 6, onion('f'));
    let identities = [
        NodeIdentity::from_secret(NETWORK, DiscoveryPlane::Vault, [4; 32]),
        NodeIdentity::from_secret(NETWORK, DiscoveryPlane::Vault, [5; 32]),
        NodeIdentity::from_secret(NETWORK, DiscoveryPlane::Vault, [6; 32]),
    ];
    let services = [&first, &second, &third];
    let now = kerosene_node::now_epoch_ms();

    for index in 0..services.len() {
        let remote = (index + 1) % services.len();
        let request = HelloExchangeRequest {
            hello: identities[remote].sign_hello(
                services[index].issue_challenge(now),
                onion(char::from_u32('d' as u32 + remote as u32).unwrap()),
                now,
            ),
            response_challenge: format!("{index:064x}"),
        };
        services[index].exchange_hello(&request, now).unwrap();
        services[index]
            .accept_membership(initial_manifest(DiscoveryPlane::Vault, &vault, 'd'))
            .unwrap();
        services[index].verify_state_snapshot(&snapshot(1)).unwrap();
        let ready = services[index].readiness(now);
        assert!(ready.quorum_ready, "{ready:?}");
        assert!(ready.financial_ready, "{ready:?}");
        assert_eq!(ready.live_members, 2);
    }
}

#[test]
fn self_connection_is_rejected_and_manifest_delivery_is_idempotent() {
    let bank = [key(1), key(2), key(3)];
    let vault = [key(4), key(5), key(6)];
    let bundle = bundle(&bank, &vault);
    let (service, _root) = service(&bundle, DiscoveryPlane::Vault, 4, onion('d'));
    let identity = NodeIdentity::from_secret(NETWORK, DiscoveryPlane::Vault, [4; 32]);
    let now = 60_000;
    let request = HelloExchangeRequest {
        hello: identity.sign_hello(service.issue_challenge(now), onion('d'), now),
        response_challenge: "a".repeat(64),
    };
    assert!(matches!(
        service.exchange_hello(&request, now),
        Err(DiscoveryError::SelfConnection)
    ));

    let manifest = initial_manifest(DiscoveryPlane::Vault, &vault, 'd');
    service.accept_membership(manifest.clone()).unwrap();
    service.accept_membership(manifest).unwrap();
}
