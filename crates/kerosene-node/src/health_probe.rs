//! Local credential-file-only readiness probe; it never constructs NodeService.
use std::io::Read;
use std::net::SocketAddr;
use std::time::Duration;

fn bounded_file(name: &str, maximum: u64) -> Result<Vec<u8>, ()> {
    let path = std::env::var(name).map_err(|_| ())?;
    if !std::path::Path::new(&path).is_absolute()
        || !std::fs::metadata(&path).map_err(|_| ())?.is_file()
    {
        return Err(());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| ())?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(());
    }
    Ok(bytes)
}

fn target(hostname: &str, port: u16) -> Result<(reqwest::Url, String, SocketAddr), ()> {
    let hostname = hostname.trim();
    let endpoint = format!("https://{hostname}:{port}");
    kerosene_discovery::validate_onion_endpoint(&endpoint).map_err(|_| ())?;
    let url = reqwest::Url::parse(&(endpoint + "/ready-local")).map_err(|_| ())?;
    Ok((
        url,
        hostname.to_owned(),
        SocketAddr::from(([127, 0, 0, 1], port)),
    ))
}

fn locally_ready(body: &[u8]) -> Result<(), ()> {
    #[derive(serde::Deserialize)]
    struct LocalReadiness {
        local_ready: bool,
    }
    let readiness: LocalReadiness = serde_json::from_slice(body).map_err(|_| ())?;
    readiness.local_ready.then_some(()).ok_or(())
}

pub async fn run() -> Result<(), ()> {
    let hostname = String::from_utf8(bounded_file("KEROSENE_NODE_ONION_HOSTNAME_PATH", 256)?)
        .map_err(|_| ())?;
    let port = std::env::var("KEROSENE_NODE_ONION_PORT")
        .map_err(|_| ())?
        .parse::<u16>()
        .map_err(|_| ())?;
    if port == 0 {
        return Err(());
    }
    let (url, host, address) = target(&hostname, port)?;
    let identity = bounded_file("KEROSENE_TLS_CLIENT_IDENTITY_PEM", 131_072)?;
    let certificates = reqwest::Certificate::from_pem_bundle(&bounded_file(
        "KEROSENE_TLS_CLIENT_CA_PATH",
        65_536,
    )?)
    .map_err(|_| ())?;
    if certificates.is_empty() {
        return Err(());
    }
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false)
        .identity(reqwest::Identity::from_pem(&identity).map_err(|_| ())?)
        .resolve(&host, address)
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(4));
    for certificate in certificates {
        builder = builder.add_root_certificate(certificate);
    }
    let mut response = builder
        .build()
        .map_err(|_| ())?
        .get(url)
        .send()
        .await
        .map_err(|_| ())?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if body.len() + chunk.len() > 16_384 {
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    locally_ready(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_is_only_a_v3_onion_resolved_to_loopback() {
        for hostname in [
            "localhost",
            "127.0.0.1",
            "short.onion",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0.onion",
        ] {
            assert!(target(hostname, 8800).is_err());
        }
        let hostname = format!("{}.onion", "a".repeat(56));
        let (url, host, address) = target(&hostname, 8800).unwrap();
        assert_eq!(url.path(), "/ready-local");
        assert_eq!(host, hostname);
        assert_eq!(address, "127.0.0.1:8800".parse().unwrap());
    }

    #[test]
    fn readiness_requires_a_boolean_true() {
        assert!(locally_ready(br#"{"local_ready":true,"financial_ready":false}"#).is_ok());
        for body in [
            br#"{"local_ready":false}"#.as_slice(),
            br#"{"local_ready":"true"}"#,
            br#"{}"#,
            b"invalid",
            br#"{"local_ready":true,"local_ready":true}"#,
        ] {
            assert!(locally_ready(body).is_err());
        }
    }
}
