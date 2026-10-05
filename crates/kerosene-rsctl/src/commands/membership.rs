use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use kerosene_contracts::{
    canonical_hash, member_id, CanonicalSignable, GenesisTrustBundleV1, ManifestMember,
    ManifestSignature, MembershipManifestV1, MembershipPhase, DISCOVERY_CONTRACT_VERSION,
};
use kerosene_membership::MembershipVerifier;
use serde::Serialize;
use serde_json::{json, Value};

use crate::cli::MembershipCommand;
use crate::client::ensure_private_file;

/// Executes the selected membership manifest operation and returns its JSON result.
///
/// Creation and signing write files with private permissions; verification uses
/// genesis trust; publishing requires HTTPS and optional Tor SOCKS5H routing.
///
/// # Errors
/// Returns file, serialization, signature, trust-validation, transport, or
/// argument validation errors.
pub async fn membership(command: MembershipCommand) -> Result<Value> {
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

/// Reads and deserializes a JSON file into the requested contract or option type.
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&fs::read(path).with_context(|| format!("read {}", path.display()))?)
        .with_context(|| format!("parse {}", path.display()))
}

/// Reads a lowercase hexadecimal 32-byte identity seed from a protected file.
pub fn read_secret(path: &Path) -> Result<[u8; 32]> {
    ensure_private_file(path)?;
    let bytes = hex::decode(fs::read_to_string(path)?.trim())?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("identity key must contain 32 bytes"))
}

/// Serializes a value as pretty JSON and writes it with owner-only permissions on Unix.
pub fn write_private_json(path: &Path, value: &impl Serialize) -> Result<()> {
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
