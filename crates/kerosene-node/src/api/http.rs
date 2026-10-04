//! HTTP translation boundary for node discovery and readiness.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use kerosene_contracts::{canonical_hash, MembershipManifestV1, PeerHelloV1};
use kerosene_discovery::{ChallengeResponse, HelloExchangeRequest};
use serde::Serialize;

use crate::{now_epoch_ms, NodeService, NodeServiceError, Readiness};

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

impl NodeService {
    /// Builds the protocol boundary. Business state transitions remain in the
    /// application service and are never implemented in handlers.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/live", get(live))
            .route("/ready-local", get(ready_local))
            .route("/ready-member", get(ready_member))
            .route("/ready-quorum", get(ready_quorum))
            .route("/ready-financial", get(ready_financial))
            .route("/v1/readiness", get(readiness))
            .route("/v1/discovery/challenge", get(challenge))
            .route("/v1/discovery/peers", get(peers))
            .route("/v1/discovery/hello", post(hello))
            .route("/v1/membership/current", get(current_manifest))
            .route("/v1/membership", post(accept_manifest))
            .with_state(self.clone())
    }
}

async fn live() -> Json<serde_json::Value> {
    Json(serde_json::json!({"live": true}))
}

async fn ready_local(State(service): State<NodeService>) -> (StatusCode, Json<Readiness>) {
    readiness_status(service.readiness(now_epoch_ms()), |ready| ready.local_ready)
}

async fn ready_member(State(service): State<NodeService>) -> (StatusCode, Json<Readiness>) {
    readiness_status(service.readiness(now_epoch_ms()), |ready| {
        ready.member_ready
    })
}

async fn ready_quorum(State(service): State<NodeService>) -> (StatusCode, Json<Readiness>) {
    readiness_status(service.readiness(now_epoch_ms()), |ready| {
        ready.quorum_ready
    })
}

async fn ready_financial(State(service): State<NodeService>) -> (StatusCode, Json<Readiness>) {
    readiness_status(service.readiness(now_epoch_ms()), |ready| {
        ready.financial_ready
    })
}

async fn readiness(State(service): State<NodeService>) -> Json<Readiness> {
    Json(service.readiness(now_epoch_ms()))
}

async fn challenge(State(service): State<NodeService>) -> Json<ChallengeResponse> {
    Json(ChallengeResponse {
        challenge: service.issue_challenge(now_epoch_ms()),
    })
}

async fn peers(
    State(service): State<NodeService>,
) -> Result<Json<Vec<kerosene_discovery::EndpointRecord>>, StatusCode> {
    service
        .authenticated_peers()
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn hello(
    State(service): State<NodeService>,
    Json(request): Json<HelloExchangeRequest>,
) -> Result<Json<PeerHelloV1>, (StatusCode, Json<ErrorBody>)> {
    service
        .exchange_hello(&request, now_epoch_ms())
        .map(Json)
        .map_err(|error| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorBody {
                    error: error.to_string(),
                }),
            )
        })
}

async fn current_manifest(
    State(service): State<NodeService>,
) -> Result<Json<MembershipManifestV1>, StatusCode> {
    service
        .current_manifest()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn accept_manifest(
    State(service): State<NodeService>,
    Json(manifest): Json<MembershipManifestV1>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    let hash = canonical_hash(&manifest);
    service
        .accept_membership(manifest)
        .map(|()| Json(serde_json::json!({"accepted": true, "manifest_hash": hash})))
        .map_err(|error| {
            let status = match error {
                NodeServiceError::Membership(_) => StatusCode::UNPROCESSABLE_ENTITY,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (
                status,
                Json(ErrorBody {
                    error: error.to_string(),
                }),
            )
        })
}

fn readiness_status(
    readiness: Readiness,
    predicate: impl FnOnce(&Readiness) -> bool,
) -> (StatusCode, Json<Readiness>) {
    let status = if predicate(&readiness) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(readiness))
}
