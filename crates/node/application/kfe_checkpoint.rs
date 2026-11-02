//! KFE is authoritative; a Node verifies fresh attestations without mutating balances.
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KfeLedgerCheckpoint {
    pub network: String,
    pub challenge: String,
    pub generated_at_ms: u64,
    pub expires_at_ms: u64,
    pub ledger_root: String,
    pub balances_count: u64,
    pub postings_count: u64,
    pub signature: String,
}

impl KfeLedgerCheckpoint {
    /// Versioned, domain-separated wire message shared with the KFE signer.
    pub fn signing_message(&self) -> String {
        format!(
            "KEROSENE_KFE_LEDGER_V1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.network,
            self.challenge,
            self.generated_at_ms,
            self.expires_at_ms,
            self.ledger_root,
            self.balances_count,
            self.postings_count
        )
    }

    pub fn verify(&self, network: &str, key: &VerifyingKey, now: u64) -> Result<(), String> {
        if self.network != network
            || self.network.is_empty()
            || !self
                .network
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || !is_hex(&self.challenge, 64)
            || !is_hex(&self.ledger_root, 64)
            || self.generated_at_ms > now.saturating_add(5_000)
            || self.expires_at_ms <= now
            || self.expires_at_ms <= self.generated_at_ms
            || self.expires_at_ms - self.generated_at_ms > 120_000
        {
            return Err("invalid or expired KFE ledger checkpoint scope".into());
        }
        let bytes = hex::decode(&self.signature).map_err(|_| "invalid checkpoint signature")?;
        let signature =
            Signature::from_slice(&bytes).map_err(|_| "invalid checkpoint signature")?;
        key.verify_strict(self.signing_message().as_bytes(), &signature)
            .map_err(|_| "unauthorized KFE ledger checkpoint".into())
    }
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    const SIGNATURE: &str = "1acbe1e4fd55193bf315e193f4bc1b929fe19410b17f3e22e5688bbd749253fc701d67bb5238bed42f5fa24c6f1c3c82a25dbe83837fb57babf8b5843b266405";

    #[test]
    fn cross_language_signature_and_fail_closed_validation() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let proof = KfeLedgerCheckpoint {
            network: "kerosene-test".into(),
            challenge: "a".repeat(64),
            generated_at_ms: 1_000_000,
            expires_at_ms: 1_120_000,
            ledger_root: "b".repeat(64),
            balances_count: 2,
            postings_count: 3,
            signature: SIGNATURE.into(),
        };
        proof.verify("kerosene-test", &key, 1_000_000).unwrap();
        assert!(proof.verify("other", &key, 1_000_000).is_err());
        assert!(proof.verify("kerosene-test", &key, 1_120_000).is_err());
        assert!(proof.verify("kerosene-test", &key, 900_000).is_err());
        let mut changed = proof.clone();
        changed.postings_count += 1;
        assert!(changed.verify("kerosene-test", &key, 1_000_000).is_err());
        changed = proof;
        changed.expires_at_ms += 1;
        assert!(changed.verify("kerosene-test", &key, 1_000_000).is_err());
    }
}
