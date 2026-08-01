//! 静态文件服务
//!
//! 使用 `tower-http` 提供成熟的静态资源服务，并为 SPA 应用保留
//! `index.html` fallback 能力。

use anyhow::{Context, Result, ensure};
use axum::{Router, routing::get_service};
use std::path::{Path, PathBuf};
use tower_http::services::{ServeDir, ServeFile};

/// 构建 SPA 静态文件路由。
///
/// - 优先使用 `ServeDir` 直接服务构建产物目录
/// - 未命中静态资源时 fallback 到 `index.html`
pub fn spa_router(web_dir: impl Into<PathBuf>) -> Result<Router> {
    let web_dir = web_dir.into();
    let index_file = validate_web_dir(&web_dir)?;

    let static_service =
        get_service(ServeDir::new(&web_dir).not_found_service(ServeFile::new(index_file)));

    Ok(Router::new().fallback_service(static_service))
}

fn validate_web_dir(web_dir: &Path) -> Result<PathBuf> {
    ensure!(
        web_dir.is_dir(),
        "web_dir does not exist or is not a directory: {}",
        web_dir.display()
    );

    let index_file = web_dir.join("index.html");
    ensure!(
        index_file.is_file(),
        "web_dir is missing index.html: {}",
        index_file.display()
    );

    index_file.canonicalize().with_context(|| {
        format!(
            "Failed to resolve index.html path: {}",
            index_file.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::validate_web_dir;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn validate_web_dir_accepts_directory_with_index() {
        let dir = tempdir().unwrap();
        let index_path = dir.path().join("index.html");
        fs::write(&index_path, "<!doctype html>").unwrap();

        let resolved = validate_web_dir(dir.path()).unwrap();

        assert_eq!(resolved, index_path.canonicalize().unwrap());
    }

    #[test]
    fn validate_web_dir_rejects_directory_without_index() {
        let dir = tempdir().unwrap();
        let err = validate_web_dir(dir.path()).unwrap_err();

        assert!(err.to_string().contains("missing index.html"));
    }
}
