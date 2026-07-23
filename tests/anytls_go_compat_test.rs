//! Cross-implementation compatibility tests against the sibling anytls-go source tree.
//! Override its location with `ANYTLS_GO_DIR` when the repositories are not siblings.

use serde_json::json;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const PASSWORD: &str = "anytls-go-compat-password";
const START_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

struct GoBinaries {
    server: PathBuf,
    client: PathBuf,
}

static GO_BINARIES: LazyLock<GoBinaries> = LazyLock::new(|| {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let go_source = std::env::var_os("ANYTLS_GO_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            manifest
                .parent()
                .expect("quicproxy must have a parent directory")
                .join("anytls-go")
        });
    assert!(
        go_source.join("go.mod").is_file(),
        "anytls-go source not found at {}; set ANYTLS_GO_DIR to override",
        go_source.display()
    );

    let output_dir = manifest.join("target/anytls-go-compat");
    std::fs::create_dir_all(&output_dir).expect("create anytls-go test output directory");
    let server = output_dir.join("anytls-server");
    let client = output_dir.join("anytls-client");
    build_go_binary(&go_source, "./cmd/server", &server);
    build_go_binary(&go_source, "./cmd/client", &client);
    GoBinaries { server, client }
});

fn build_go_binary(source: &Path, package: &str, output: &Path) {
    let result = Command::new("go")
        .current_dir(source)
        .args(["build", "-trimpath", "-o"])
        .arg(output)
        .arg(package)
        .output()
        .unwrap_or_else(|e| panic!("failed to execute Go compiler: {e}"));
    assert!(
        result.status.success(),
        "failed to build {package} from {}:\n{}",
        source.display(),
        String::from_utf8_lossy(&result.stderr)
    );
}

struct ChildGuard {
    child: Child,
    _config: Option<NamedTempFile>,
}

impl ChildGuard {
    fn spawn(mut command: Command, config: Option<NamedTempFile>) -> Self {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
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
    let mut file = NamedTempFile::new().expect("create quicproxy config");
    serde_json::to_writer(&mut file, &config).expect("write quicproxy config");
    file.flush().expect("flush quicproxy config");
    file
}

fn custom_padding_scheme() -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("create custom padding scheme");
    file.write_all(b"stop=4\n0=24-24\n1=80-120\n2=128-256,c\n3=64-96\n")
        .expect("write custom padding scheme");
    file.flush().expect("flush custom padding scheme");
    file
}

fn spawn_go_server(port: u16, padding_scheme: Option<&Path>) -> ChildGuard {
    let mut command = Command::new(&GO_BINARIES.server);
    command
        .args(["-l", &format!("127.0.0.1:{port}"), "-p", PASSWORD])
        .env("LOG_LEVEL", "warn");
    if let Some(path) = padding_scheme {
        command.arg("-padding-scheme").arg(path);
    }
    ChildGuard::spawn(command, None)
}

fn spawn_go_client(socks_port: u16, server_port: u16) -> ChildGuard {
    let mut command = Command::new(&GO_BINARIES.client);
    command
        .args([
            "-l",
            &format!("127.0.0.1:{socks_port}"),
            "-s",
            &format!("127.0.0.1:{server_port}"),
            "-p",
            PASSWORD,
            "-m",
            "1",
        ])
        .env("LOG_LEVEL", "warn");
    ChildGuard::spawn(command, None)
}

fn spawn_rust_proxy(config: serde_json::Value) -> ChildGuard {
    let config = write_config(config);
    let mut command = Command::new(env!("CARGO_BIN_EXE_quicproxy"));
    command
        .arg("--config")
        .arg(config.path())
        .env("RUST_LOG", "quicproxy=warn");
    ChildGuard::spawn(command, Some(config))
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
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    (addr, task)
}

async fn spawn_udp_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP echo");
    let addr = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut data = [0; 65535];
        while let Ok((length, peer)) = socket.recv_from(&mut data).await {
            let _ = socket.send_to(&data[..length], peer).await;
        }
    });
    (addr, task)
}

async fn spawn_counting_relay(
    target: SocketAddr,
) -> (u16, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind counting relay");
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let count = connections.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                if let Ok(mut outbound) = TcpStream::connect(target).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    (port, connections, task)
}

async fn socks_connect(port: u16, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to SOCKS5");
    stream
        .write_all(&[5, 1, 0])
        .await
        .expect("write SOCKS5 greeting");
    let mut greeting = [0; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .expect("read SOCKS5 greeting");
    assert_eq!(greeting, [5, 0]);

    let SocketAddr::V4(target) = target else {
        panic!("compatibility tests require IPv4");
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream
        .write_all(&request)
        .await
        .expect("write SOCKS5 CONNECT");
    read_socks_reply(&mut stream).await;
    stream
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

async fn assert_tcp_echo(socks_port: u16, target: SocketAddr, payload: &[u8]) {
    let mut stream = socks_connect(socks_port, target).await;
    stream.write_all(payload).await.expect("write TCP payload");
    let mut echoed = vec![0; payload.len()];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut echoed))
        .await
        .expect("TCP echo timed out")
        .expect("read TCP echo");
    assert_eq!(echoed, payload);
    stream.shutdown().await.expect("shutdown TCP stream");
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

    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind SOCKS5 UDP client");
    socket
        .send_to(&packet, relay)
        .await
        .expect("send UDP packet");
    let mut response = [0; 65535];
    let (length, _) = tokio::time::timeout(IO_TIMEOUT, socket.recv_from(&mut response))
        .await
        .expect("UDP echo timed out")
        .expect("read UDP echo");
    assert!(length >= 10, "short SOCKS5 UDP response");
    assert_eq!(&response[10..length], payload);
}

fn rust_outbound_config(socks_port: u16, anytls_port: u16) -> serde_json::Value {
    json!({
        "inbounds": {
            "socks_in": {
                "type": "socks5",
                "address": "127.0.0.1",
                "port": socks_port
            }
        },
        "outbounds": {
            "final_outbound": "anytls_out",
            "servers": {
                "anytls_out": {
                    "type": "anytls",
                    "address": "127.0.0.1",
                    "port": anytls_port,
                    "password": PASSWORD,
                    "tls": {
                        "enable": true,
                        "insecure": true,
                        "server_name": "127.0.0.1"
                    }
                },
                "direct_out": { "type": "direct" }
            }
        },
        "dns": {
            "default_server": "local_dns",
            "servers": {
                "local_dns": {
                    "type": "udp",
                    "address": "127.0.0.1",
                    "port": 53,
                    "outbound": "direct_out"
                }
            }
        },
        "router": { "default_mode": "proxy" },
        "log": { "level": "warn" }
    })
}

fn rust_inbound_config(anytls_port: u16) -> serde_json::Value {
    json!({
        "inbounds": {
            "anytls_in": {
                "type": "anytls",
                "address": "127.0.0.1",
                "port": anytls_port,
                "password": PASSWORD,
                "tls": { "enable": true }
            }
        },
        "outbounds": {
            "final_outbound": "direct_out",
            "servers": {
                "direct_out": { "type": "direct" }
            }
        },
        "dns": {
            "default_server": "local_dns",
            "servers": {
                "local_dns": {
                    "type": "udp",
                    "address": "127.0.0.1",
                    "port": 53,
                    "outbound": "direct_out"
                }
            }
        },
        "router": { "default_mode": "direct" },
        "log": { "level": "warn" }
    })
}

#[tokio::test]
async fn rust_outbound_is_compatible_with_go_server() {
    let (tcp_echo, tcp_task) = spawn_tcp_echo().await;
    let (udp_echo, udp_task) = spawn_udp_echo().await;

    let go_port = free_tcp_port();
    let padding_scheme = custom_padding_scheme();
    let mut go_server = spawn_go_server(go_port, Some(padding_scheme.path()));
    wait_for_tcp(go_port, &mut go_server, "anytls-go server").await;

    let (relay_port, connection_count, relay_task) =
        spawn_counting_relay(SocketAddr::from(([127, 0, 0, 1], go_port))).await;
    let socks_port = free_tcp_port();
    let mut rust = spawn_rust_proxy(rust_outbound_config(socks_port, relay_port));
    wait_for_tcp(socks_port, &mut rust, "Rust anytls outbound").await;

    assert_tcp_echo(socks_port, tcp_echo, b"rust-outbound-go-server-1").await;
    assert_tcp_echo(socks_port, tcp_echo, b"rust-outbound-go-server-2").await;
    assert_udp_echo(socks_port, udp_echo, b"rust-outbound-go-server-udp").await;
    assert_eq!(
        connection_count.load(Ordering::SeqCst),
        1,
        "Rust mux should reuse one TLS session for sequential TCP and UDP streams"
    );

    tcp_task.abort();
    udp_task.abort();
    relay_task.abort();
}

#[tokio::test]
async fn go_client_is_compatible_with_rust_inbound() {
    let (tcp_echo, tcp_task) = spawn_tcp_echo().await;
    let (udp_echo, udp_task) = spawn_udp_echo().await;

    let anytls_port = free_tcp_port();
    let mut rust = spawn_rust_proxy(rust_inbound_config(anytls_port));
    wait_for_tcp(anytls_port, &mut rust, "Rust anytls inbound").await;

    let socks_port = free_tcp_port();
    let mut go_client = spawn_go_client(socks_port, anytls_port);
    wait_for_tcp(socks_port, &mut go_client, "anytls-go client").await;

    assert_tcp_echo(socks_port, tcp_echo, b"go-client-rust-inbound-1").await;
    assert_tcp_echo(socks_port, tcp_echo, b"go-client-rust-inbound-2").await;
    assert_udp_echo(socks_port, udp_echo, b"go-client-rust-inbound-udp").await;

    tcp_task.abort();
    udp_task.abort();
}
