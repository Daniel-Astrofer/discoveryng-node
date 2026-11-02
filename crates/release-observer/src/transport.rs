use std::time::Duration;

use kerosene_contracts::release::{
    decode_release_json, valid_identifier, BankReleaseReadV1, MAX_BODY_BYTES,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{verify_key, ObserverError};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BankEndpoint {
    pub observer_id: String,
    /// HTTPS base URL. A Bank listener, never a caller-provided URL.
    pub endpoint: String,
    pub public_key_der_base64: String,
}

/// Only this concrete authenticated transport can supply successful reads.
/// There is deliberately no fake adapter or local compatible fallback.
#[derive(Clone)]
pub struct BankTransport {
    client: reqwest::Client,
}

impl BankTransport {
    pub fn new_mtls(
        identity_pem: &[u8],
        ca_pem: &[u8],
        socks_proxy: Option<&str>,
    ) -> Result<Self, ObserverError> {
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .identity(
                reqwest::Identity::from_pem(identity_pem)
                    .map_err(|_| ObserverError::Configuration)?,
            )
            .add_root_certificate(
                reqwest::Certificate::from_pem(ca_pem).map_err(|_| ObserverError::Configuration)?,
            )
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .no_proxy();
        if let Some(proxy) = socks_proxy {
            if !proxy.starts_with("socks5h://") {
                return Err(ObserverError::Configuration);
            }
            builder = builder
                .proxy(reqwest::Proxy::all(proxy).map_err(|_| ObserverError::Configuration)?);
        }
        Ok(Self {
            client: builder.build().map_err(|_| ObserverError::Configuration)?,
        })
    }

    pub async fn read(
        &self,
        bank: &BankEndpoint,
        digest: &str,
        challenge: &str,
    ) -> Result<BankReleaseReadV1, ObserverError> {
        let mut url = bank.url()?;
        url.set_path("/v1/releases/observation");
        url.query_pairs_mut()
            .append_pair("releaseDigest", digest)
            .append_pair("challenge", challenge);
        let mut response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| ObserverError::BankUnavailable)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|n| n > MAX_BODY_BYTES as u64)
        {
            return Err(ObserverError::BankUnavailable);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ObserverError::BankUnavailable)?
        {
            if body.len() + chunk.len() > MAX_BODY_BYTES {
                return Err(ObserverError::BankUnavailable);
            }
            body.extend_from_slice(&chunk);
        }
        decode_release_json(&body).map_err(|_| ObserverError::InvalidBankEvidence)
    }
}

impl BankEndpoint {
    pub fn validate(&self) -> Result<(), ObserverError> {
        self.url()?;
        if !valid_identifier(&self.observer_id) {
            return Err(ObserverError::Configuration);
        }
        verify_key(&self.public_key_der_base64)?;
        Ok(())
    }

    fn url(&self) -> Result<Url, ObserverError> {
        let url = Url::parse(&self.endpoint).map_err(|_| ObserverError::Configuration)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !matches!(url.path(), "" | "/")
        {
            return Err(ObserverError::Configuration);
        }
        Ok(url)
    }
}
