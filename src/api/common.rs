use axum::{
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
};

/// CORS 中间件：允许跨域请求
pub async fn cors_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> impl IntoResponse {
    let cors_headers = [
        (
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        ),
        (
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, PUT, DELETE, POST, OPTIONS"),
        ),
        (
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Content-Type, Authorization"),
        ),
    ];

    if request.method() == axum::http::Method::OPTIONS {
        let mut response = (StatusCode::NO_CONTENT, ()).into_response();
        for (k, v) in cors_headers {
            response.headers_mut().insert(k, v);
        }
        response.headers_mut().insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("86400"),
        );
        return response;
    }

    let mut response = next.run(request).await;
    for (k, v) in cors_headers {
        response.headers_mut().insert(k, v);
    }
    response
}

/// 认证检查：如果设置了密码，则要求 Authorization header 匹配
pub fn check_auth(headers: &axum::http::HeaderMap, pwd: &str) -> Result<(), StatusCode> {
    if !pwd.is_empty() {
        if let Some(auth_val) = headers.get("Authorization") {
            if let Ok(auth_str) = auth_val.to_str() {
                if auth_str == pwd || auth_str == format!("Bearer {}", pwd) {
                    return Ok(());
                }
            }
        }
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}
