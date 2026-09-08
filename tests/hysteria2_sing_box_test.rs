//! Cross-implementation tests for the Hysteria2 outbound.
//!
//! A sibling sing-box checkout is used as the protocol server (its
//! `hysteria2` inbound, built with `with_quic`). Override the binary with
//! `SING_BOX_BIN`, or the source location with `SING_BOX_DIR` when the
//! repositories are not siblings. The quicproxy under test runs as a real
//! binary with a SOCKS5 inbound and a `hysteria2` outbound pointed at
//! sing-box's hy2 server.

use rcgen::generate_simple_self_signed;
use serde_json::json;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const HY2_PASSWORD: &str = "sing-box-compat-hy2-password";
const START_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const LARGE_IO_TIMEOUT: Duration = Duration::from_secs(240);
const LARGE_BLOCK_SIZE: usize = 10 * 1024 * 1024;
const LARGE_BLOCK_COUNT: usize = 10;
const CONCURRENT_IO_TIMEOUT: Duration = Duration::from_secs(120);
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
    _cert: Option<NamedTempFile>,
    _key: Option<NamedTempFile>,
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
            _cert: None,
            _key: None,
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

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("reserve UDP port")
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

fn spawn_quicproxy(config: serde_json::Value) -> ChildGuard {
    let config = write_config(config);
    let mut command = Command::new(env!("CARGO_BIN_EXE_quicproxy"));
    command.arg("--config").arg(config.path()).env(
        "RUST_LOG",
        std::env::var("COMPAT_RUST_LOG").unwrap_or_else(|_| "quicproxy=warn".to_string()),
    );
    ChildGuard::spawn(command, config)
}

fn generate_tls() -> (NamedTempFile, NamedTempFile) {
    let cert = generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate hy2 test certificate");
    let mut cert_file = NamedTempFile::new().expect("create cert file");
    cert_file
        .write_all(cert.cert.pem().as_bytes())
        .expect("write cert file");
    cert_file.flush().unwrap();
    let mut key_file = NamedTempFile::new().expect("create key file");
    key_file
        .write_all(cert.signing_key.serialize_pem().as_bytes())
        .expect("write key file");
    key_file.flush().unwrap();
    (cert_file, key_file)
}

/// Wait until `child` is still running long enough to be listening on its
/// UDP port. There is no TCP port to probe for a QUIC listener, so wait a
/// short grace period while asserting the process did not exit.
async fn wait_until_quic_ready(child: &mut ChildGuard, name: &str) {
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        child.assert_running(name);
        if Instant::now() > deadline {
            panic!("{name} did not become ready in time");
        }
        tokio::time::sleep(Duration::from_millis(1500)).await;
        child.assert_running(name);
        // A 1.5s uptime without exiting is enough for QUIC server setup.
        if Instant::now() >= deadline {
            panic!("{name} did not become ready in time");
        }
        return;
    }
}

async fn wait_for_tcp(port: u16, child: &mut ChildGuard, name: &str) {
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        child.assert_running(name);
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{name} did not listen on port {port}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn spawn_tcp_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind TCP echo");
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
        // The hy2 TCPRequest is fused into the client's first write, so the
        // server waits for one request byte before replying and closing.
        let mut byte = [0u8; 1];
        stream
            .read_exact(&mut byte)
            .await
            .expect("read TCP close test trigger");
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
    stream.write_all(b"x").await.expect("trigger remote close");
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
    // The relay prefixes responses with RSV/FRAG/ATYP/ADDR/PORT; match only
    // the payload portion.
    assert!(response[..length].ends_with(payload));
}

fn sing_box_hysteria2_config(
    port: u16,
    password: &str,
    cert: &NamedTempFile,
    key: &NamedTempFile,
) -> serde_json::Value {
    let log_level = compat_log_level();
    json!({
        "log": { "level": log_level },
        "inbounds": [{
            "type": "hysteria2",
            "tag": "hy2-in",
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{ "name": "compat", "password": password }],
            "ignore_client_bandwidth": true,
            "tls": {
                "enabled": true,
                "certificate_path": cert.path(),
                "key_path": key.path()
            }
        }],
        "outbounds": [{ "type": "direct", "tag": "direct" }]
    })
}

fn quicproxy_hysteria2_config(
    socks_port: u16,
    server_port: u16,
    password: &str,
) -> serde_json::Value {
    let log_level = compat_log_level();
    json!({
        "inbounds": {
            "socks-in": { "type": "socks5", "address": "127.0.0.1", "port": socks_port }
        },
        "outbounds": {
            "final_outbound": "compat-out",
            "servers": {
                "compat-out": {
                    "type": "hysteria2",
                    "address": "127.0.0.1",
                    "port": server_port,
                    "password": password,
                    "tls": { "insecure": true }
                },
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

async fn start_hy2_pair(
    server_password: &str,
    client_password: &str,
) -> (ChildGuard, ChildGuard, u16, u16) {
    let (cert, key) = generate_tls();
    let server_port = free_udp_port();
    let server_config = write_config(sing_box_hysteria2_config(
        server_port,
        server_password,
        &cert,
        &key,
    ));
    let mut command = Command::new(&*SING_BOX_BINARY);
    command.arg("run").arg("-c").arg(server_config.path());
    let child = command
        .spawn()
        .expect("spawn sing-box hy2 server");
    let mut server = ChildGuard {
        child,
        _config: server_config,
        _cert: Some(cert),
        _key: Some(key),
    };
    wait_until_quic_ready(&mut server, "sing-box Hysteria2 server").await;

    let socks_port = free_tcp_port();
    let mut client = spawn_quicproxy(quicproxy_hysteria2_config(
        socks_port,
        server_port,
        client_password,
    ));
    wait_for_tcp(socks_port, &mut client, "quicproxy Hysteria2 outbound").await;
    (server, client, server_port, socks_port)
}

#[tokio::test]
async fn hysteria2_outbound_is_compatible_with_sing_box() {
    let (tcp_echo, tcp_task) = spawn_tcp_echo().await;
    let (udp_echo, udp_task) = spawn_udp_echo().await;

    let (_server, _client, _server_port, socks_port) =
        start_hy2_pair(HY2_PASSWORD, HY2_PASSWORD).await;

    assert_tcp_echo(socks_port, tcp_echo, b"hysteria2-tcp-sing-box").await;
    assert_udp_echo(socks_port, udp_echo, b"hysteria2-udp-sing-box").await;

    tcp_task.abort();
    udp_task.abort();
}

#[tokio::test]
async fn hysteria2_outbound_handles_large_and_concurrent_requests_with_sing_box() {
    let (tcp_echo, tcp_task) = spawn_tcp_echo().await;
    let closing_payload = (0..64 * 1024)
        .map(|offset| ((offset * 31) % 251) as u8)
        .collect::<Vec<_>>();
    let (closing_target, closing_task) = spawn_tcp_send_then_close(closing_payload.clone()).await;

    let (_server, _client, _server_port, socks_port) =
        start_hy2_pair(HY2_PASSWORD, HY2_PASSWORD).await;

    assert_large_tcp_echo(socks_port, tcp_echo).await;
    assert_concurrent_tcp_echo(socks_port, tcp_echo).await;
    assert_remote_close_is_clean(socks_port, closing_target, &closing_payload).await;

    tcp_task.abort();
    closing_task.await.unwrap();
}

#[tokio::test]
async fn hysteria2_outbound_rejects_a_wrong_password_without_hanging() {
    let (_server, _client, _server_port, socks_port) =
        start_hy2_pair(HY2_PASSWORD, "definitely-wrong").await;

    // Wrong credentials: the SOCKS connect is reported optimistically and
    // the failure surfaces when traffic flows. A write must be rejected with
    // a reset/EOF (never echoed) and must not hang.
    let target = spawn_tcp_echo().await;
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .expect("connect to SOCKS5");
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await.unwrap();

    let (target_addr, task) = target;
    let SocketAddr::V4(addr) = target_addr else {
        panic!("IPv4 required");
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&addr.ip().octets());
    request.extend_from_slice(&addr.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut reply))
        .await
        .expect("timed out reading SOCKS connect reply")
        .unwrap();

    let start = Instant::now();
    stream.write_all(b"no-echo").await.expect("write probe");
    let outcome = tokio::time::timeout(Duration::from_secs(20), async {
        let mut buf = [0u8; 256];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break, // clean EOF
                Ok(n) => {
                    assert_ne!(&buf[..n], b"no-echo", "data must not echo");
                }
                Err(_) => break, // connection reset
            }
        }
    })
    .await;

    assert!(
        outcome.is_ok(),
        "wrong-password connection hung for 20s instead of failing"
    );
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "wrong-password connection took too long to fail"
    );
    task.abort();
}
