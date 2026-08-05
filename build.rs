use chrono::{TimeZone, Utc};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    let build_date = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|epoch| epoch.parse::<i64>().ok())
        .and_then(|epoch| Utc.timestamp_opt(epoch, 0).single())
        .unwrap_or_else(Utc::now)
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    println!("cargo:rustc-env=QUICPROXY_BUILD_DATE={build_date}");
}
