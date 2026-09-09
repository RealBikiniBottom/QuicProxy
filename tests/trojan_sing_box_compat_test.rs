//! Cross-implementation tests for the Trojan outbound's stream transports.
//!
//! The sibling sing-box checkout is used as the protocol server. Override its
//! location with `SING_BOX_DIR`, or point `SING_BOX_BIN` directly at a prebuilt
//! `sing-box` binary. Every scenario asserts both TCP and UDP end to end
//! through a quicproxy SOCKS5 inbound:
//!
//! * plain trojan over TLS (wire-format baseline),
//! * trojan over the `ws` transport on a bare TCP connection,
//! * trojan over the `ws` transport on top of TLS (`wss`).

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

const PASSWORD: &str = "trojan-sing-box-compat-password";
const WS_PATH: &str = "/trojan-ws";
const START_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const LARGE_IO_TIMEOUT: Duration = Duration::from_secs(60);
const LARGE_BLOCK_SIZE: usize = 1024 * 1024;
const LARGE_BLOCK_COUNT: usize = 4;

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
        .args(["build", "-trimpath", "-o"])
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

/// A multi-megabyte TCP echo whose content spans many websocket frames.
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
            tokio::try_join!(
                writer.write_all(&payload),
                reader.read_exact(&mut echoed)
            )
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

/// Generate a self-signed certificate for `localhost`, returning (cert, key)
/// PEM paths valid for the process lifetime.
fn generate_tls_files() -> (PathBuf, PathBuf) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let mut cert_file = NamedTempFile::new().unwrap();
    cert_file
        .write_all(certified.cert.pem().as_bytes())
        .unwrap();
    let (_, cert_path) = cert_file.keep().unwrap();
    let mut key_file = NamedTempFile::new().unwrap();
    key_file
        .write_all(certified.signing_key.serialize_pem().as_bytes())
        .unwrap();
    let (_, key_path) = key_file.keep().unwrap();
    (cert_path, key_path)
}

/// sing-box trojan inbound. `transport` and `tls` are optional.
fn sing_box_trojan_config(
    port: u16,
    transport: Option<serde_json::Value>,
    tls: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut inbound = json!({
        "type": "trojan",
        "tag": "trojan-in",
        "listen": "127.0.0.1",
        "listen_port": port,
        "users": [{ "name": "compat", "password": PASSWORD }]
    });
    if let Some(transport) = transport {
        inbound["transport"] = transport;
    }
    if let Some(tls) = tls {
        inbound["tls"] = tls;
    }
    json!({
        "log": { "level": compat_log_level() },
        "inbounds": [inbound],
        "outbounds": [{ "type": "direct", "tag": "direct" }]
    })
}

/// quicproxy client config: SOCKS5 inbound in front of a trojan outbound.
fn quicproxy_trojan_config(
    socks_port: u16,
    server_port: u16,
    tls: serde_json::Value,
    transport: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut outbound = json!({
        "type": "trojan",
        "address": "127.0.0.1",
        "port": server_port,
        "password": PASSWORD,
        "tls": tls
    });
    if let Some(transport) = transport {
        outbound["transport"] = transport;
    }
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
        "log": { "level": compat_log_level() }
    })
}

async fn check_trojan(
    tls: serde_json::Value,
    transport: Option<serde_json::Value>,
    server_tls: Option<serde_json::Value>,
    tcp_echo: SocketAddr,
    udp_echo: SocketAddr,
    label: &str,
) {
    let server_port = free_tcp_port();
    let mut server = spawn_sing_box(sing_box_trojan_config(server_port, transport.clone(), server_tls));
    wait_for_tcp(server_port, &mut server, &format!("sing-box {label} server")).await;

    let socks_port = free_tcp_port();
    let mut client = spawn_quicproxy(quicproxy_trojan_config(
        socks_port,
        server_port,
        tls,
        transport,
    ));
    wait_for_tcp(
        socks_port,
        &mut client,
        &format!("quicproxy {label} outbound"),
    )
    .await;

    assert_tcp_echo(socks_port, tcp_echo, label.as_bytes()).await;
    assert_udp_echo(socks_port, udp_echo, label.as_bytes()).await;
    assert_large_tcp_echo(socks_port, tcp_echo).await;
}

#[tokio::test]
async fn trojan_tls_outbound_is_compatible_with_sing_box() {
    let (tcp_echo, tcp_task) = spawn_tcp_echo().await;
    let (udp_echo, udp_task) = spawn_udp_echo().await;
    let (cert_path, key_path) = generate_tls_files();

    let server_tls = json!({
        "enabled": true,
        "certificate_path": cert_path.to_str().unwrap(),
        "key_path": key_path.to_str().unwrap()
    });
    check_trojan(
        json!({ "enable": true, "insecure": true, "server_name": "localhost" }),
        None,
        Some(server_tls),
        tcp_echo,
        udp_echo,
        "trojan-tls",
    )
    .await;

    tcp_task.abort();
    udp_task.abort();
}

#[tokio::test]
async fn trojan_ws_outbound_is_compatible_with_sing_box() {
    let (tcp_echo, tcp_task) = spawn_tcp_echo().await;
    let (udp_echo, udp_task) = spawn_udp_echo().await;

    let ws_transport = json!({ "type": "ws", "path": WS_PATH });
    check_trojan(
        json!({ "enable": false }),
        Some(ws_transport),
        None,
        tcp_echo,
        udp_echo,
        "trojan-ws",
    )
    .await;

    tcp_task.abort();
    udp_task.abort();
}

#[tokio::test]
async fn trojan_ws_over_tls_outbound_is_compatible_with_sing_box() {
    let (tcp_echo, tcp_task) = spawn_tcp_echo().await;
    let (udp_echo, udp_task) = spawn_udp_echo().await;
    let (cert_path, key_path) = generate_tls_files();

    let ws_transport = json!({ "type": "ws", "path": WS_PATH });
    let server_tls = json!({
        "enabled": true,
        "certificate_path": cert_path.to_str().unwrap(),
        "key_path": key_path.to_str().unwrap()
    });
    check_trojan(
        json!({ "enable": true, "insecure": true, "server_name": "localhost" }),
        Some(ws_transport),
        Some(server_tls),
        tcp_echo,
        udp_echo,
        "trojan-wss",
    )
    .await;

    tcp_task.abort();
    udp_task.abort();
}
