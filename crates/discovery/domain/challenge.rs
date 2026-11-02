use std::collections::HashMap;

use parking_lot::Mutex;
use rand::RngCore;

use super::error::DiscoveryError;

/// In-memory, single-use challenge store with a bounded validity interval.
#[derive(Debug)]
pub struct ChallengeStore {
    ttl_ms: u64,
    pending: Mutex<HashMap<String, u64>>,
}

impl ChallengeStore {
    /// Creates a challenge store; zero TTL is raised to one millisecond.
    pub fn new(ttl_ms: u64) -> Self {
        Self {
            ttl_ms: ttl_ms.max(1),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Generates and records a random 32-byte hex challenge until its deadline.
    pub fn issue(&self, now_epoch_ms: u64) -> String {
        let mut bytes = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let challenge = hex::encode(bytes);
        self.pending
            .lock()
            .insert(challenge.clone(), now_epoch_ms.saturating_add(self.ttl_ms));
        challenge
    }

    /// Limits outstanding challenges on authenticated service ingress endpoints.
    pub fn issue_bounded(&self, now_epoch_ms: u64, limit: usize) -> Result<String, DiscoveryError> {
        let mut pending = self.pending.lock();
        pending.retain(|_, expires| *expires >= now_epoch_ms);
        if pending.len() >= limit {
            return Err(DiscoveryError::ChallengeRejected);
        }
        let mut bytes = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let challenge = hex::encode(bytes);
        pending.insert(challenge.clone(), now_epoch_ms.saturating_add(self.ttl_ms));
        Ok(challenge)
    }

    /// Consumes a live challenge once and removes expired pending challenges.
    pub fn consume(&self, challenge: &str, now_epoch_ms: u64) -> Result<(), DiscoveryError> {
        let mut pending = self.pending.lock();
        pending.retain(|_, expires_at| *expires_at >= now_epoch_ms);
        match pending.remove(challenge) {
            Some(expires_at) if expires_at >= now_epoch_ms => Ok(()),
            _ => Err(DiscoveryError::ChallengeRejected),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_challenges_expire_and_are_consumed_once() {
        let store = ChallengeStore::new(10);
        let challenge = store.issue_bounded(0, 1).unwrap();
        assert!(store.issue_bounded(0, 1).is_err());
        store.consume(&challenge, 0).unwrap();
        assert!(store.consume(&challenge, 0).is_err());
        store.issue_bounded(1, 1).unwrap();
        assert!(store.issue_bounded(12, 1).is_ok());
    }
}
