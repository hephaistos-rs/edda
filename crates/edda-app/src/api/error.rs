//! The single service-error → HTTP mapping (plan.local.md §14.2). Every
//! `/api/v1` handler returns `Result<T, ServiceError>`; axum's blanket
//! `IntoResponse for Result` plus this impl turn that into a status +
//! `{ "error": { "code": "<stable_slug>", "message": "<human>" } }` body.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::services::ServiceError;

#[derive(Serialize)]
pub(crate) struct ApiErrorBody {
    pub(crate) error: ApiErrorDetail,
}

#[derive(Serialize)]
pub(crate) struct ApiErrorDetail {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        // The `Db`/`Git` detail is for us, not the caller — log it here,
        // return only "internal error" on the wire (`client_message`).
        if self.http_status() >= 500 {
            tracing::error!(error = %self, "request failed with an internal service error");
        }
        let status =
            StatusCode::from_u16(self.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = ApiErrorBody {
            error: ApiErrorDetail {
                code: self.code(),
                message: self.client_message(),
            },
        };
        (status, Json(body)).into_response()
    }
}
