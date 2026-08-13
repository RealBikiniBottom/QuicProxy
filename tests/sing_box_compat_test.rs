//! Cross-implementation tests for the VMess and Shadowsocks outbounds.
//!
//! The sibling sing-box checkout is used as the protocol server. Override its
//! location with `SING_BOX_DIR` when the repositories are not siblings.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::json;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::LazyLock;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const VMESS_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const START_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const LARGE_IO_TIMEOUT: Duration = Duration::from_secs(180);
const LARGE_BLOCK_SIZE: usize = 10 * 1024 * 1024;
const LARGE_BLOCK_COUNT: usize = 10;
const CONCURRENT_IO_TIMEOUT: Duration = Duration::from_secs(60);
const CONCURRENT_REQUESTS: usize = 32;
const CONCURRENT_PAYLOAD_SIZE: usize = 256 * 1024;

fn compat_log_level() -> String {
    std::env::var("COMPAT_LOG_LEVEL").unwrap_or_else(|_| "warn".to_string())
}

static SING_BOX_BINARY: LazyLock<PathBuf> = LazyLock::new(|| {
    if let Some(binary) = std::env::var_os("SING_BOX_BIN").map(PathBuf::from) {
        assert!(
            binary.is_file(),
            "sing-box binary not found at {}",
            binary.display()
        );
        return binary;
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = std::env::var_os("SING_BOX_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            manifest
                .parent()
                .expect("quicproxy must have a parent directory")
                .join("sing-box")
        });
    assert!(
        source.join("go.mod").is_file(),
        "sing-box source not found at {}; set SING_BOX_DIR to override",
        source.display()
    );

    let output_dir = manifest.join("target/sing-box-compat");
    std::fs::create_dir_all(&output_dir).expect("create sing-box test output directory");
    let binary = output_dir.join("sing-box");
    let result = Command::new("go")
        .current_dir(&source)
        .args(["build", "-trimpath", "-tags", "with_quic", "-o"])
        .arg(&binary)
        .arg("./cmd/sing-box")
        .output()
        .unwrap_or_else(|e| panic!("failed to execute Go compiler: {e}"));
    assert!(
        result.status.success(),
        "failed to build sing-box from {}:\n{}",
        source.display(),
        String::from_utf8_lossy(&result.stderr)
    );
    binary
});

struct ChildGuard {
    child: Child,
    _config: NamedTempFile,
}

impl ChildGuard {
    fn spawn(mut command: Command, config: NamedTempFile) -> Self {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let child = command.spawn().expect("spawn compatibility-test process");
        Self {
            child,
            _config: config,
        }
    }

    fn assert_running(&mut self, name: &str) {
        if let Some(status) = self.child.try_wait().expect("inspect child status") {
            panic!("{name} exited early with {status}");
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve TCP port")
        .local_addr()
        .unwrap()
        .port()
}

fn write_config(config: serde_json::Value) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("create compatibility-test config");
    serde_json::to_writer(&mut file, &config).expect("write compatibility-test config");
    file.flush().expect("flush compatibility-test config");
    file
}

fn spawn_sing_box(config: serde_json::Value) -> ChildGuard {
    let config = write_config(config);
    let mut command = Command::new(&*SING_BOX_BINARY);
    command.arg("run").arg("-c").arg(config.path());
    ChildGuard::spawn(command, config)
}

fn spawn_quicproxy(config: serde_json::Value) -> ChildGuard {
    let config = write_config(config);
    let mut command = Command::new(env!("CARGO_BIN_EXE_quicproxy"));
    command.arg("--config").arg(config.path()).env(
        "RUST_LOG",
        std::env::var("COMPAT_RUST_LOG").unwrap_or_else(|_| "quicproxy=warn".to_string()),
    );
    ChildGuard::spawn(command, config)
}

async fn wait_for_tcp(port: u16, child: &mut ChildGuard, name: &str) {
    let deadline = tokio::time::Instant::now() + START_TIMEOUT;
    loop {
        child.assert_running(name);
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{name} did not listen on port {port}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn spawn_tcp_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind TCP echo");
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    (address, task)
}

async fn spawn_tcp_send_then_close(payload: Vec<u8>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind TCP close test server");
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept TCP close test");
        stream
            .write_all(&payload)
            .await
            .expect("write TCP close test payload");
        stream.shutdown().await.expect("close TCP test stream");
    });
    (address, task)
}

async fn spawn_udp_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP echo");
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut data = [0; 65535];
        while let Ok((length, peer)) = socket.recv_from(&mut data).await {
            let _ = socket.send_to(&data[..length], peer).await;
        }
    });
    (address, task)
}

async fn read_socks_reply(stream: &mut TcpStream) -> SocketAddr {
    let mut header = [0; 4];
    stream
        .read_exact(&mut header)
        .await
        .expect("read SOCKS5 reply");
    assert_eq!(header[0], 5);
    assert_eq!(header[1], 0, "SOCKS5 request failed with {}", header[1]);
    match header[3] {
        1 => {
            let mut address = [0; 6];
            stream.read_exact(&mut address).await.unwrap();
            SocketAddr::new(
                Ipv4Addr::new(address[0], address[1], address[2], address[3]).into(),
                u16::from_be_bytes([address[4], address[5]]),
            )
        }
        atyp => panic!("unexpected SOCKS5 reply address type {atyp}"),
    }
}

async fn socks_connect(port: u16, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to SOCKS5");
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);

    let SocketAddr::V4(target) = target else {
        panic!("compatibility tests require IPv4");
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    read_socks_reply(&mut stream).await;
    stream
}

async fn assert_tcp_echo(socks_port: u16, target: SocketAddr, payload: &[u8]) {
    let mut stream = socks_connect(socks_port, target).await;
    stream.write_all(payload).await.expect("write TCP payload");
    let mut echoed = vec![0; payload.len()];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut echoed))
        .await
        .expect("TCP echo timed out")
        .expect("read TCP echo");
    assert_eq!(echoed, payload);
}

async fn assert_large_tcp_echo(socks_port: u16, target: SocketAddr) {
    let stream = socks_connect(socks_port, target).await;
    let (mut reader, mut writer) = stream.into_split();
    let mut payload = vec![0; LARGE_BLOCK_SIZE];
    let mut echoed = vec![0; LARGE_BLOCK_SIZE];

    for round in 0..LARGE_BLOCK_COUNT {
        for (offset, byte) in payload.iter_mut().enumerate() {
            *byte = ((offset.wrapping_mul(31) + round * 17) % 251) as u8;
        }

        tokio::time::timeout(LARGE_IO_TIMEOUT, async {
            tokio::try_join!(writer.write_all(&payload), reader.read_exact(&mut echoed))
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "TCP echo timed out in large block {}/{}",
                round + 1,
                LARGE_BLOCK_COUNT
            )
        })
        .expect("transfer large TCP echo block");
        assert_eq!(
            echoed,
            payload,
            "large TCP echo mismatch in block {}/{}",
            round + 1,
            LARGE_BLOCK_COUNT
        );
    }

    writer.shutdown().await.expect("shutdown large TCP stream");
}

async fn assert_concurrent_tcp_echo(socks_port: u16, target: SocketAddr) {
    let mut requests = tokio::task::JoinSet::new();
    for request_id in 0..CONCURRENT_REQUESTS {
        requests.spawn(async move {
            let payload = (0..CONCURRENT_PAYLOAD_SIZE)
                .map(|offset| ((offset.wrapping_mul(31) + request_id * 17) % 251) as u8)
                .collect::<Vec<_>>();
            assert_tcp_echo(socks_port, target, &payload).await;
        });
    }

    tokio::time::timeout(CONCURRENT_IO_TIMEOUT, async {
        while let Some(result) = requests.join_next().await {
            result.expect("concurrent proxy request task failed");
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{} concurrent proxy requests timed out after {:?}",
            CONCURRENT_REQUESTS, CONCURRENT_IO_TIMEOUT
        )
    });
}

async fn assert_remote_close_is_clean(socks_port: u16, target: SocketAddr, expected: &[u8]) {
    let mut stream = socks_connect(socks_port, target).await;
    let mut received = Vec::new();
    tokio::time::timeout(IO_TIMEOUT, stream.read_to_end(&mut received))
        .await
        .expect("remote close timed out")
        .expect("remote close should be reported as a clean EOF");
    assert_eq!(received, expected);
}

async fn assert_udp_echo(socks_port: u16, target: SocketAddr, payload: &[u8]) {
    let mut control = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .expect("connect to SOCKS5");
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    control.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .expect("write UDP ASSOCIATE");
    let relay = read_socks_reply(&mut control).await;

    let SocketAddr::V4(target) = target else {
        panic!("compatibility tests require IPv4");
    };
    let mut packet = vec![0, 0, 0, 1];
    packet.extend_from_slice(&target.ip().octets());
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&packet, relay).await.unwrap();
    let mut response = [0; 65535];
    let (length, _) = tokio::time::timeout(IO_TIMEOUT, socket.recv_from(&mut response))
        .await
        .expect("UDP echo timed out")
        .expect("read UDP echo");
    assert!(length >= 10, "short SOCKS5 UDP response");
    assert_eq!(&response[10..length], payload);
}

fn sing_box_vmess_config(port: u16) -> serde_json::Value {
    let log_level = compat_log_level();
    json!({
        "log": { "level": log_level },
        "inbounds": [{
            "type": "vmess",
            "tag": "vmess-in",
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{ "name": "compat", "uuid": VMESS_UUID, "alterId": 0 }]
        }],
        "outbounds": [{ "type": "direct", "tag": "direct" }]
    })
}

fn sing_box_shadowsocks_config(port: u16, method: &str, password: &str) -> serde_json::Value {
    let log_level = compat_log_level();
    json!({
        "log": { "level": log_level },
        "inbounds": [{
            "type": "shadowsocks",
            "tag": "ss-in",
            "listen": "127.0.0.1",
            "listen_port": port,
            "method": method,
            "password": password
        }],
        "outbounds": [{ "type": "direct", "tag": "direct" }]
    })
}

fn quicproxy_outbound_config(
    socks_port: u16,
    server_port: u16,
    protocol: &str,
    method: &str,
    password: Option<&str>,
) -> serde_json::Value {
    let log_level = compat_log_level();
    let outbound = match protocol {
        "vmess" => json!({
            "type": "vmess",
            "address": "127.0.0.1",
            "port": server_port,
            "uuid": VMESS_UUID,
            "username": "0",
            "udp_mod": method
        }),
        "shadowsocks" => json!({
            "type": "shadowsocks",
            "address": "127.0.0.1",
            "port": server_port,
            "password": password.expect("Shadowsocks requires a password"),
            "udp_mod": method
        }),
        _ => unreachable!(),
    };
    json!({
        "inbounds": {
            "socks-in": { "type": "socks5", "address": "127.0.0.1", "port": socks_port }
        },
        "outbounds": {
            "final_outbound": "compat-out",
            "servers": {
                "compat-out": outbound,
                "direct-out": { "type": "direct" }
            }
        },
        "dns": {
            "default_server": "local-dns",
            "servers": {
                "local-dns": {
                    "type": "udp", "address": "127.0.0.1", "port": 53,
                    "outbound": "direct-out"
                }
            }
        },
        "router": { "default_mode": "proxy" },
        "log": { "level": log_level }
    })
}

async fn check_vmess(security: &str, tcp_echo: SocketAddr, udp_echo: Option<SocketAddr>) {
    let server_port = free_tcp_port();
    let mut server = spawn_sing_box(sing_box_vmess_config(server_port));
    wait_for_tcp(server_port, &mut server, "sing-box VMess server").await;

    let socks_port = free_tcp_port();
    let mut client = spawn_quicproxy(quicproxy_outbound_config(
        socks_port,
        server_port,
        "vmess",
        security,
        None,
    ));
    wait_for_tcp(socks_port, &mut client, "quicproxy VMess outbound").await;
    assert_tcp_echo(socks_port, tcp_echo, security.as_bytes()).await;
    if let Some(udp_echo) = udp_echo {
        assert_udp_echo(socks_port, udp_echo, b"vmess-udp-sing-box").await;
    }
}

async fn check_shadowsocks(
    method: &str,
    password: &str,
    tcp_echo: SocketAddr,
    udp_echo: SocketAddr,
) {
    let server_port = free_tcp_port();
    let mut server = spawn_sing_box(sing_box_shadowsocks_config(server_port, method, password));
    wait_for_tcp(server_port, &mut server, "sing-box Shadowsocks server").await;

    let socks_port = free_tcp_port();
    let mut client = spawn_quicproxy(quicproxy_outbound_config(
        socks_port,
        server_port,
        "shadowsocks",
        method,
        Some(password),
    ));
    wait_for_tcp(socks_port, &mut client, "quicproxy Shadowsocks outbound").await;
    assert_tcp_echo(socks_port, tcp_echo, method.as_bytes()).await;
    assert_udp_echo(socks_port, udp_echo, method.as_bytes()).await;
}

async fn check_vmess_stress(
    tcp_echo: SocketAddr,
    closing_target: SocketAddr,
    closing_payload: &[u8],
) {
    let server_port = free_tcp_port();
    let mut server = spawn_sing_box(sing_box_vmess_config(server_port));
    wait_for_tcp(server_port, &mut server, "sing-box VMess stress server").await;

    let socks_port = free_tcp_port();
    let mut client = spawn_quicproxy(quicproxy_outbound_config(
        socks_port,
        server_port,
        "vmess",
        "aes-128-gcm",
        None,
    ));
    wait_for_tcp(socks_port, &mut client, "quicproxy VMess stress outbound").await;

    assert_large_tcp_echo(socks_port, tcp_echo).await;
    assert_concurrent_tcp_echo(socks_port, tcp_echo).await;
    assert_remote_close_is_clean(socks_port, closing_target, closing_payload).await;
}

async fn check_shadowsocks_stress(tcp_echo: SocketAddr) {
    let server_port = free_tcp_port();
    let mut server = spawn_sing_box(sing_box_shadowsocks_config(
        server_port,
        "aes-256-gcm",
        "sing-box-compat-password",
    ));
    wait_for_tcp(
        server_port,
        &mut server,
        "sing-box Shadowsocks stress server",
    )
    .await;

    let socks_port = free_tcp_port();
    let mut client = spawn_quicproxy(quicproxy_outbound_config(
        socks_port,
        server_port,
        "shadowsocks",
        "aes-256-gcm",
        Some("sing-box-compat-password"),
    ));
    wait_for_tcp(
        socks_port,
        &mut client,
        "quicproxy Shadowsocks stress outbound",
    )
    .await;

    assert_large_tcp_echo(socks_port, tcp_echo).await;
    assert_concurrent_tcp_echo(socks_port, tcp_echo).await;
}

#[tokio::test]
async fn vmess_outbound_is_compatible_with_sing_box() {
    let (tcp_echo, tcp_task) = spawn_tcp_echo().await;
    let (udp_echo, udp_task) = spawn_udp_echo().await;

    for security in ["auto", "aes-128-gcm", "chacha20-poly1305", "none"] {
        check_vmess(security, tcp_echo, Some(udp_echo)).await;
    }

    tcp_task.abort();
    udp_task.abort();
}

#[tokio::test]
async fn shadowsocks_outbound_is_compatible_with_sing_box() {
    let (tcp_echo, tcp_task) = spawn_tcp_echo().await;
    let (udp_echo, udp_task) = spawn_udp_echo().await;
    let key_128 = BASE64.encode([1u8; 16]);
    let key_256 = BASE64.encode([2u8; 32]);

    for method in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"] {
        check_shadowsocks(method, "sing-box-compat-password", tcp_echo, udp_echo).await;
    }
    check_shadowsocks("2022-blake3-aes-128-gcm", &key_128, tcp_echo, udp_echo).await;
    for method in ["2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"] {
        check_shadowsocks(method, &key_256, tcp_echo, udp_echo).await;
    }

    tcp_task.abort();
    udp_task.abort();
}

#[tokio::test]
async fn vmess_outbound_handles_large_and_concurrent_requests_with_sing_box() {
    let (tcp_echo, tcp_task) = spawn_tcp_echo().await;
    let closing_payload = (0..64 * 1024)
        .map(|offset| ((offset * 31) % 251) as u8)
        .collect::<Vec<_>>();
    let (closing_target, closing_task) = spawn_tcp_send_then_close(closing_payload.clone()).await;

    check_vmess_stress(tcp_echo, closing_target, &closing_payload).await;

    tcp_task.abort();
    closing_task.await.unwrap();
}

#[tokio::test]
async fn shadowsocks_outbound_handles_large_and_concurrent_requests_with_sing_box() {
    let (tcp_echo, tcp_task) = spawn_tcp_echo().await;

    check_shadowsocks_stress(tcp_echo).await;

    tcp_task.abort();
}
