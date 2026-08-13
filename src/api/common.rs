use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

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

/// 路由鉴权中间件：在进入 handler 和解析请求参数前完成认证。
pub async fn auth_middleware(
    State(password): State<Arc<str>>,
    request: Request,
    next: Next,
) -> Response {
    match check_auth(request.headers(), password.as_ref()) {
        Ok(()) => next.run(request).await,
        Err(status) => status.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::{auth_middleware, cors_middleware};
    use axum::{Router, http::StatusCode, middleware, routing::get};
    use std::sync::Arc;
    use std::time::Duration;

    fn test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }

    async fn spawn_test_server(password: &str) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route("/protected", get(|| async { StatusCode::OK }))
            .route_layer(middleware::from_fn_with_state(
                Arc::<str>::from(password),
                auth_middleware,
            ))
            .layer(middleware::from_fn(cors_middleware));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (format!("http://{address}"), server)
    }

    #[tokio::test]
    async fn route_auth_rejects_missing_credentials_and_accepts_bearer() {
        let (base_url, server) = spawn_test_server("secret").await;
        let client = test_client();

        let unauthorized = client
            .get(format!("{base_url}/protected"))
            .send()
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let authorized = client
            .get(format!("{base_url}/protected"))
            .bearer_auth("secret")
            .send()
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::OK);

        server.abort();
    }

    #[tokio::test]
    async fn cors_preflight_bypasses_auth_and_unknown_routes_stay_not_found() {
        let (base_url, server) = spawn_test_server("secret").await;
        let client = test_client();

        let preflight = client
            .request(reqwest::Method::OPTIONS, format!("{base_url}/protected"))
            .send()
            .await
            .unwrap();
        assert_eq!(preflight.status(), StatusCode::NO_CONTENT);

        let not_found = client
            .get(format!("{base_url}/missing"))
            .send()
            .await
            .unwrap();
        assert_eq!(not_found.status(), StatusCode::NOT_FOUND);

        server.abort();
    }

    #[tokio::test]
    async fn empty_password_keeps_routes_open() {
        let (base_url, server) = spawn_test_server("").await;
        let client = test_client();

        let response = client
            .get(format!("{base_url}/protected"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        server.abort();
    }
}
