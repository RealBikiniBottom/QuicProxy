//! Shared ShadowQuic config builders for integration tests.
//!
//! Both `tests/shadowquic_test.rs` (TCP / JLS / reuse / path-state) and
//! `tests/shadowquic_udp_test.rs` (udp_mod coverage) boot the same two-proxy
//! chain, so the full config JSON is built here instead of being pasted in
//! every test. Fixed tags: server inbound `sq_in`, client inbound `socks_in`,
//! client shadowquic outbound `sq_out`.

use serde_json::{Value, json};

fn dns_server(server_name: &str, outbound: &str) -> Value {
    json!({
        "default_server": server_name,
        "servers": {
            server_name: {
                "type": "udp",
                "address": "8.8.8.8",
                "port": 53,
                "outbound": outbound,
            }
        }
    })
}

/// Server-side (inbound) config: TLS-enabled shadowquic listener + direct outbound.
pub fn server_config(username: &str, password: &str) -> Value {
    json!({
        "inbounds": {
            "sq_in": {
                "type": "shadowquic",
                "address": "127.0.0.1",
                "port": 0,
                "username": username,
                "password": password,
                "tls": { "enable": true }
            }
        },
        "dns": dns_server("local_dns", "direct_out"),
        "outbounds": {
            "default_server": "direct_out",
            "servers": {
                "direct_out": { "type": "direct" }
            }
        },
        "router": { "default_mode": "proxy" }
    })
}

/// Server-side config using JLS credentials instead of plain username/password.
pub fn jls_server_config(jls_username: &str, jls_password: &str) -> Value {
    json!({
        "inbounds": {
            "sq_in": {
                "type": "shadowquic",
                "address": "127.0.0.1",
                "port": 0,
                "tls": {
                    "enable_jls": true,
                    "jls_username": jls_username,
                    "jls_password": jls_password
                }
            }
        },
        "dns": dns_server("local_dns", "direct_out"),
        "outbounds": {
            "default_server": "direct_out",
            "servers": {
                "direct_out": { "type": "direct" }
            }
        },
        "router": { "default_mode": "proxy" }
    })
}

/// Client-side config: SOCKS5 inbound whose default outbound is the shadowquic
/// client pointed at `proxy_port`. `udp_mod` selects the UDP transport mode
/// ("stream" default / "datagram"); `None` leaves it unset.
pub fn client_config(
    username: &str,
    password: &str,
    proxy_port: u16,
    udp_mod: Option<&str>,
) -> Value {
    let mut sq_out = json!({
        "type": "shadowquic",
        "address": "127.0.0.1",
        "port": proxy_port,
        "username": username,
        "password": password,
        "tls": {
            "enable": true,
            "insecure": true,
            "sni": "localhost"
        }
    });

    if let Some(mode) = udp_mod {
        sq_out["udp_mod"] = json!(mode);
    }

    json!({
        "inbounds": {
            "socks_in": {
                "type": "socks5",
                "address": "127.0.0.1",
                "port": 0
            }
        },
        "dns": dns_server("local_dns", "sq_out"),
        "outbounds": {
            "default_server": "sq_out",
            "servers": {
                "sq_out": sq_out
            }
        },
        "router": { "default_mode": "proxy" }
    })
}

/// Client-side config with JLS authentication against the peer on `proxy_port`.
pub fn jls_client_config(jls_username: &str, jls_password: &str, proxy_port: u16) -> Value {
    json!({
        "inbounds": {
            "socks_in": {
                "type": "socks5",
                "address": "127.0.0.1",
                "port": 0
            }
        },
        "dns": dns_server("local_dns", "sq_out"),
        "outbounds": {
            "default_server": "sq_out",
            "servers": {
                "sq_out": {
                    "type": "shadowquic",
                    "address": "127.0.0.1",
                    "port": proxy_port,
                    "tls": {
                        "enable_jls": true,
                        "sni": "localhost",
                        "jls_username": jls_username,
                        "jls_password": jls_password
                    }
                }
            }
        },
        "router": { "default_mode": "proxy" }
    })
}
