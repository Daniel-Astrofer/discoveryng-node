//! Observer routes mounted only on the runtime's mandatory mTLS listener.
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, FromRequest, Query, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use kerosene_contracts::release::{
    decode_release_json, BankObserverReportV2, ObserverDiscoveryV1, ReleaseObservationsV1,
    ReleaseObserverRequestV1, MAX_BODY_BYTES,
};
use kerosene_release_observer::{ObserverError, ReleaseObserver};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

type ObserverState = Arc<Option<ReleaseObserver>>;
type ApiError = (StatusCode, Json<ErrorBody>);
struct StrictRequest(ReleaseObserverRequestV1);
impl<S: Send + Sync> FromRequest<S> for StrictRequest {
    type Rejection = Response;
    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        if !request
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';')
                    .next()
                    .is_some_and(|mime| mime.trim() == "application/json")
            })
        {
            return Err((
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                Json(ErrorBody {
                    code: "report_invalid",
                }),
            )
                .into_response());
        }
        let bytes = Bytes::from_request(request, state)
            .await
            .map_err(IntoResponse::into_response)?;
        decode_release_json(&bytes).map(Self).map_err(|_| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorBody {
                    code: "report_invalid",
                }),
            )
                .into_response()
        })
    }
}
#[derive(Serialize)]
pub struct ErrorBody {
    code: &'static str,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadQuery {
    release_digest: String,
}

pub fn router(observer: Option<ReleaseObserver>) -> Router {
    Router::new()
        .route("/v1/release-observer/discover", get(discover))
        .route("/v1/release-observer/verify", post(verify))
        .route("/v1/release-observer/sign", post(sign))
        .route("/v1/releases/observations", get(observations))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(Arc::new(observer))
}
fn configured(state: &ObserverState) -> Result<&ReleaseObserver, ApiError> {
    state.as_ref().as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorBody {
            code: "observer_unconfigured",
        }),
    ))
}
async fn discover(
    State(state): State<ObserverState>,
) -> Result<Json<ObserverDiscoveryV1>, ApiError> {
    Ok(Json(configured(&state)?.discovery()))
}
async fn verify(
    State(state): State<ObserverState>,
    StrictRequest(request): StrictRequest,
) -> Result<Json<ReleaseObservationsV1>, ApiError> {
    configured(&state)?
        .verify(&request)
        .await
        .map(Json)
        .map_err(api_error)
}
async fn sign(
    State(state): State<ObserverState>,
    StrictRequest(request): StrictRequest,
) -> Result<Json<BankObserverReportV2>, ApiError> {
    configured(&state)?
        .sign(&request)
        .await
        .map(Json)
        .map_err(api_error)
}
async fn observations(
    State(state): State<ObserverState>,
    Query(query): Query<ReadQuery>,
) -> Result<Json<ReleaseObservationsV1>, ApiError> {
    configured(&state)?
        .observations(&query.release_digest)
        .map(Json)
        .map_err(api_error)
}
fn api_error(error: ObserverError) -> ApiError {
    let (status, code) = match error {
        ObserverError::Replay => (StatusCode::CONFLICT, "sequence_replay"),
        ObserverError::NotFound => (StatusCode::NOT_FOUND, "observations_unknown"),
        ObserverError::Expired => (StatusCode::GONE, "evidence_expired"),
        ObserverError::BankUnavailable => (StatusCode::BAD_GATEWAY, "bank_unavailable"),
        ObserverError::InvalidBankEvidence => {
            (StatusCode::UNPROCESSABLE_ENTITY, "bank_evidence_invalid")
        }
        ObserverError::InvalidReport => (StatusCode::UNPROCESSABLE_ENTITY, "report_invalid"),
        ObserverError::Incompatible => (StatusCode::UNPROCESSABLE_ENTITY, "bank_incompatible"),
        ObserverError::Busy => (StatusCode::TOO_MANY_REQUESTS, "observer_busy"),
        ObserverError::Persistence => (
            StatusCode::SERVICE_UNAVAILABLE,
            "observer_persistence_failed",
        ),
        ObserverError::Configuration => (StatusCode::SERVICE_UNAVAILABLE, "observer_unconfigured"),
    };
    (status, Json(ErrorBody { code }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    #[tokio::test]
    async fn absence_is_explicit_and_caller_status_is_never_accepted() {
        let api = router(None);
        let response = api
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/release-observer/discover")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let response = api
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/release-observer/sign")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"compatible":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}
