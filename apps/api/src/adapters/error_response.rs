use axum::{
    Json,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use uuid::Uuid;

use crate::error::AppError;

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
    request_id: String,
}

impl IntoResponse for AppError {
    /// 把应用错误转换为标准化 HTTP 错误响应，并附带 request_id 便于排查。
    fn into_response(self) -> Response {
        let request_id = Uuid::new_v4().to_string();
        let status = self.status_code();
        if status.is_server_error() {
            // Keep internal details in server logs while returning a sanitized payload to clients.
            tracing::error!(%request_id, error = ?self, "request failed");
        }
        let mut response = (status, Json(ErrorBody {
            error: self.public_message(),
            request_id,
        }))
        .into_response();

        if matches!(self, AppError::MfaRequired) {
            response.headers_mut().insert(
                "X-Mfa-Required",
                axum::http::HeaderValue::from_static("true"),
            );
        }

        response
    }
}
