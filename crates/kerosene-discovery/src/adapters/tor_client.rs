use kerosene_contracts::{MembershipManifestV1, PeerHelloV1};
use kerosene_identity_core::NodeIdentity;
use serde::{Deserialize, Serialize};

use crate::domain::{validate_onion_endpoint, DiscoveryError};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Challenge value returned by the remote discovery endpoint.
pub struct ChallengeResponse {
    /// Hex-encoded, single-use challenge issued for the handshake.
    pub challenge: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Request body used to submit a signed hello and the reciprocal challenge.
pub struct HelloExchangeRequest {
    /// Local peer hello signed for the challenge issued by the remote peer.
    pub hello: PeerHelloV1,
    /// Challenge issued by the local node for the remote peer to answer.
    pub response_challenge: String,
}

/// HTTPS client routed through Tor and configured for mutual TLS.
pub struct TorHandshakeClient {
    client: reqwest::Client,
}

impl TorHandshakeClient {
    /// Builds a Tor-only HTTPS client with client identity and trusted CA.
    pub fn new_mtls(
        socks_proxy: &str,
        client_identity_pem: &[u8],
        ca_pem: &[u8],
    ) -> Result<Self, DiscoveryError> {
        if !socks_proxy.starts_with("socks5h://") {
            return Err(DiscoveryError::Transport(
                "Tor proxy must use socks5h remote resolution".into(),
            ));
        }
        let proxy = reqwest::Proxy::all(socks_proxy)
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?;
        let identity = reqwest::Identity::from_pem(client_identity_pem)
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?;
        let ca = reqwest::Certificate::from_pem(ca_pem)
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?;
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .https_only(true)
            .identity(identity)
            .add_root_certificate(ca)
            .build()
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?;
        Ok(Self { client })
    }

    /// Performs the challenge/hello exchange with a remote onion peer.
    pub async fn exchange(
        &self,
        endpoint: &str,
        local_identity: &NodeIdentity,
        local_endpoint: &str,
        response_challenge: String,
        now_epoch_ms: u64,
    ) -> Result<PeerHelloV1, DiscoveryError> {
        validate_onion_endpoint(endpoint)?;
        validate_onion_endpoint(local_endpoint)?;
        let challenge: ChallengeResponse = self
            .client
            .get(format!("{endpoint}/v1/discovery/challenge"))
            .send()
            .await
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?
            .error_for_status()
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?
            .json()
            .await
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?;
        let request = HelloExchangeRequest {
            hello: local_identity.sign_hello(challenge.challenge, local_endpoint, now_epoch_ms),
            response_challenge,
        };
        self.client
            .post(format!("{endpoint}/v1/discovery/hello"))
            .json(&request)
            .send()
            .await
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?
            .error_for_status()
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?
            .json()
            .await
            .map_err(|error| DiscoveryError::Transport(error.to_string()))
    }

    /// Fetches the remote peer's current membership manifest over the Tor client.
    pub async fn fetch_manifest(
        &self,
        endpoint: &str,
    ) -> Result<MembershipManifestV1, DiscoveryError> {
        validate_onion_endpoint(endpoint)?;
        self.client
            .get(format!("{endpoint}/v1/membership/current"))
            .send()
            .await
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?
            .error_for_status()
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?
            .json()
            .await
            .map_err(|error| DiscoveryError::Transport(error.to_string()))
    }
}
