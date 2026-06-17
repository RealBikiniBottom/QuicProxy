//! 静态文件服务 — SPA fallback
//!
//! 为 persist-server 提供 Flutter Web 等 SPA 构建产物的静态文件服务。

use axum::{
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct StaticFilesState {
    pub web_dir: PathBuf,
}

/// SPA fallback 静态文件服务器（axum handler）
/// - 路径 / → index.html
/// - 路径 /xxx.yyy → web_dir/xxx.yyy
/// - 其他路径 → 先尝试精确文件 / <path>.html，失败则 fallback 到 index.html
pub async fn serve_static(
    State(state): State<StaticFilesState>,
    request: axum::extract::Request,
) -> Response {
    serve_static_from(&state.web_dir, request).await
}

/// SPA fallback 核心逻辑，接受 web_dir 引用（不依赖 axum State 类型）
pub async fn serve_static_from(web_dir: &PathBuf, request: axum::extract::Request) -> Response {
    if request.method() != axum::http::Method::GET {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    let path = request.uri().path();
    let path = path.trim_start_matches('/');

    let file_path = if path.is_empty() {
        web_dir.join("index.html")
    } else {
        let candidate = web_dir.join(path);
        let has_ext = Path::new(path)
            .extension()
            .map(|e| !e.is_empty())
            .unwrap_or(false);

        if has_ext {
            if candidate.exists() {
                candidate
            } else {
                return StatusCode::NOT_FOUND.into_response();
            }
        } else {
            if candidate.exists() && candidate.is_file() {
                candidate
            } else {
                let html_path = web_dir.join(format!("{}.html", path));
                if html_path.exists() {
                    html_path
                } else {
                    web_dir.join("index.html")
                }
            }
        }
    };

    // 安全检查：防止 ../ 路径遍历
    {
        let Ok(root) = web_dir.canonicalize() else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        let Ok(canonical) = file_path.canonicalize() else {
            return StatusCode::FORBIDDEN.into_response();
        };
        if !canonical.starts_with(&root) {
            return StatusCode::FORBIDDEN.into_response();
        }
    }

    match tokio::fs::read(&file_path).await {
        Ok(data) => {
            let mime = mime_for_path(&file_path);
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime)
                .header(
                    header::CACHE_CONTROL,
                    if is_hashed_asset(&file_path) {
                        "public, max-age=31536000, immutable"
                    } else {
                        "no-cache"
                    },
                )
                .body(axum::body::Body::from(data))
                .unwrap()
        }
        Err(_) => {
            let has_ext = Path::new(path).extension().map(|_| true).unwrap_or(false);
            if has_ext {
                match tokio::fs::read(web_dir.join("index.html")).await {
                    Ok(data) => Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                        .body(axum::body::Body::from(data))
                        .unwrap(),
                    Err(_) => StatusCode::NOT_FOUND.into_response(),
                }
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }
    }
}

fn mime_for_path(path: &PathBuf) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("wasm") => "application/wasm",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("otf") => "font/otf",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("txt") => "text/plain; charset=utf-8",
        Some("map") => "application/json; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Flutter Web 构建产物的文件名通常包含 hash（如 main.dart.12345678.js）
fn is_hashed_asset(path: &PathBuf) -> bool {
    path.file_stem()
        .and_then(|s| s.to_str())
        .map(|stem| {
            let parts: Vec<&str> = stem.rsplitn(2, '.').collect();
            if parts.len() == 2 {
                parts[0].len() >= 8 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
            } else {
                false
            }
        })
        .unwrap_or(false)
}
