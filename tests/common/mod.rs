#![allow(dead_code)]

use quicproxy::bootstrap;
use quicproxy::config::Config;
use std::fs::File;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::oneshot;
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio::task::JoinHandle;

pub struct ProxyInstance {
    pub addr: SocketAddr,
    pub port: u16,
    pub protocol: String,
    _handle: JoinHandle<()>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl Drop for ProxyInstance {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

pub struct Watchdog {
    done: Arc<AtomicBool>,
}

impl Watchdog {
    pub fn new(name: &str, timeout: Duration) -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let done_clone = done.clone();
        let name_clone = name.to_string();

        std::thread::spawn(move || {
            std::thread::sleep(timeout);
            if !done_clone.load(Ordering::SeqCst) {
                eprintln!(
                    "WATCHDOG: Test '{}' timed out after {:?}",
                    name_clone, timeout
                );
                std::process::abort();
            }
        });

        Self { done }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.done.store(true, Ordering::SeqCst);
    }
}

pub struct TestContext {
    pub mock_server_http_addr: SocketAddr,
    pub mock_server_tcp_addr: SocketAddr,
    pub mock_server_udp_addr: SocketAddr,
    pub mock_server_dns_addr: SocketAddr,

    // We can hold multiple proxies.
    // But for backward compatibility with existing tests, we can keep the "main" one accessible or just store them in a list/map.
    // Let's store them in a vector.
    pub proxies: Vec<ProxyInstance>,

    _mock_handles: Vec<JoinHandle<()>>,
    pub default_timeout: Duration,
    // Keep log guard to prevent logs from being dropped
    _log_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
    // Proxy bootstrap uses process-global registries, so test contexts in the
    // same integration-test binary must not run concurrently.
    _test_guard: OwnedMutexGuard<()>,
}

static TEST_CONTEXT_LOCK: LazyLock<Arc<Mutex<()>>> = LazyLock::new(|| Arc::new(Mutex::new(())));

impl TestContext {
    pub async fn new() -> Self {
        let test_guard = TEST_CONTEXT_LOCK.clone().lock_owned().await;
        bootstrap::shutdown_app().await;
        let mut handles = Vec::new();

        let (tx_http, rx_http) = oneshot::channel();
        let h_http = tokio::spawn(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx_http.send(listener.local_addr().unwrap()).unwrap();
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0; 1024];
                    let n = match socket.read(&mut buf).await {
                        Ok(n) if n == 0 => return,
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    let request = String::from_utf8_lossy(&buf[..n]);
                    if request.contains("GET") {
                        let response = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nHello World!";
                        let _ = socket.write_all(response.as_bytes()).await;
                        let _ = socket.flush().await;
                    }
                });
            }
        });
        handles.push(h_http);
        let mock_server_http_addr = rx_http.await.unwrap();

        let (tx_tcp, rx_tcp) = oneshot::channel();
        let h_tcp = tokio::spawn(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx_tcp.send(listener.local_addr().unwrap()).unwrap();
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut rd, mut wr) = socket.split();
                    let _ = tokio::io::copy(&mut rd, &mut wr).await;
                });
            }
        });
        handles.push(h_tcp);
        let mock_server_tcp_addr = rx_tcp.await.unwrap();

        let (tx_udp, rx_udp) = oneshot::channel();
        let h_udp = tokio::spawn(async move {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            tx_udp.send(socket.local_addr().unwrap()).unwrap();
            let mut buf = [0u8; 2048];
            loop {
                if let Ok((len, addr)) = socket.recv_from(&mut buf).await {
                    let _ = socket.send_to(&buf[..len], addr).await;
                }
            }
        });
        handles.push(h_udp);
        let mock_server_udp_addr = rx_udp.await.unwrap();

        let (tx_dns, rx_dns) = oneshot::channel();
        let h_dns = tokio::spawn(async move {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            tx_dns.send(socket.local_addr().unwrap()).unwrap();
            let mut buf = [0u8; 2048];
            loop {
                if let Ok((len, addr)) = socket.recv_from(&mut buf).await {
                    if len < 12 {
                        continue;
                    }

                    let mut response = buf[..len].to_vec();
                    response[2] |= 0x80; // QR: response
                    response[3] |= 0x80; // RA: recursion available
                    response[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT
                    response.extend_from_slice(&[
                        0xc0, 0x0c, // compressed query name
                        0x00, 0x01, // A
                        0x00, 0x01, // IN
                        0x00, 0x00, 0x00, 0x3c, // TTL: 60 seconds
                        0x00, 0x04, // RDLENGTH
                        203, 0, 113, 1, // TEST-NET-3 address
                    ]);
                    let _ = socket.send_to(&response, addr).await;
                }
            }
        });
        handles.push(h_dns);
        let mock_server_dns_addr = rx_dns.await.unwrap();

        println!(
            "Mock Servers: HTTP={}, TCP={}, UDP={}, DNS={}",
            mock_server_http_addr, mock_server_tcp_addr, mock_server_udp_addr, mock_server_dns_addr
        );

        Self {
            mock_server_http_addr,
            mock_server_tcp_addr,
            mock_server_udp_addr,
            mock_server_dns_addr,
            proxies: Vec::new(),
            _mock_handles: handles,
            default_timeout: Duration::from_secs(5),
            _log_guard: None,
            _test_guard: test_guard,
        }
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.default_timeout = timeout;
    }

    pub fn generate_tls_files() -> (PathBuf, PathBuf) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = certified.cert.pem();
        let key_pem = certified.signing_key.serialize_pem();

        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(cert_pem.as_bytes()).unwrap();
        let (_, cert_path) = cert_file.keep().unwrap();

        let mut key_file = NamedTempFile::new().unwrap();
        key_file.write_all(key_pem.as_bytes()).unwrap();
        let (_, key_path) = key_file.keep().unwrap();

        (cert_path, key_path)
    }

    pub async fn start_proxy(
        &mut self,
        config_json: serde_json::Value,
        inbound_name: &str,
    ) -> usize {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut port = listener.local_addr().unwrap().port();
        drop(listener);

        // Modify config with the port
        let mut config_json = config_json;
        let mut protocol_type = "mix".to_string();
        let is_quic_transport;

        if let Some(inbound) = config_json
            .get_mut("inbounds")
            .and_then(|i| i.get_mut(inbound_name))
        {
            inbound["port"] = serde_json::json!(port);
            inbound["address"] = serde_json::json!("127.0.0.1");
            if let Some(t) = inbound.get("type") {
                if let Some(s) = t.as_str() {
                    protocol_type = s.to_string();
                }
            }
            is_quic_transport = inbound
                .get("transport")
                .and_then(|v| v.get("type"))
                .and_then(|v| v.as_str())
                .map(|v| v.eq_ignore_ascii_case("quic"))
                .unwrap_or(false);

            if protocol_type == "shadowquic" || (protocol_type == "trojan" && is_quic_transport) {
                let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                port = socket.local_addr().unwrap().port();
                inbound["port"] = serde_json::json!(port);
            }
        } else {
            panic!("Inbound '{}' not found in config", inbound_name);
        }

        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        write!(temp_file, "{}", config_json.to_string()).expect("Failed to write config");
        let (_file, path) = temp_file.keep().unwrap();

        let config = Config::load(Some(path.clone())).expect("Failed to load config");
        let _ = std::fs::remove_file(path);

        let (tx, rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let shutdown_signal = async move {
                let _ = rx.await;
                Ok(())
            };
            if let Err(e) = bootstrap::run_with_signal(config, shutdown_signal).await {
                eprintln!("Proxy error: {:#}", e);
            }
        });

        let start_time = tokio::time::Instant::now();
        let timeout = Duration::from_secs(20);
        let proxy_ready = async {
            loop {
                let ready = if protocol_type == "shadowquic"
                    || (protocol_type == "trojan" && is_quic_transport)
                {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    true
                } else if protocol_type == "trojan" {
                    match tokio::net::TcpStream::connect(SocketAddr::new(
                        "127.0.0.1".parse().unwrap(),
                        port,
                    ))
                    .await
                    {
                        Ok(_) => {
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            true
                        }
                        Err(_) => false,
                    }
                } else {
                    tokio::net::TcpStream::connect(SocketAddr::new(
                        "127.0.0.1".parse().unwrap(),
                        port,
                    ))
                    .await
                    .is_ok()
                };

                if ready {
                    println!("Proxy on port {} is ready.", port);
                    break;
                }

                if start_time.elapsed() > timeout {
                    panic!("Proxy on port {} did not start in time", port);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };

        if let Err(_) = tokio::time::timeout(Duration::from_secs(30), proxy_ready).await {
            panic!(
                "start_proxy timed out after 30s for inbound '{}'",
                inbound_name
            );
        }

        let instance = ProxyInstance {
            addr: SocketAddr::new("127.0.0.1".parse().unwrap(), port),
            port,
            protocol: protocol_type,
            _handle: handle,
            shutdown_tx: Some(tx),
        };

        self.proxies.push(instance);
        self.proxies.len() - 1
    }

    pub async fn start_proxy_with_config_file(&mut self, config_path: &Path, inbound_name: &str) {
        let file = File::open(config_path).expect("Failed to open config file");
        let reader = std::io::BufReader::new(file);
        let config_json: serde_json::Value =
            serde_json::from_reader(reader).expect("Failed to parse config json");
        self.start_proxy(config_json, inbound_name).await;
    }

    pub fn last_proxy(&self) -> &ProxyInstance {
        match self.proxies.last() {
            Some(p) => p,
            None => {
                eprintln!("No proxy started");
                std::process::exit(1);
            }
        }
    }

    pub async fn test_http_get(&self) {
        let test_fut = async {
            let proxy = self.last_proxy();
            let proxy_scheme = match proxy.protocol.as_str() {
                "socks5" => "socks5",
                _ => "http",
            };
            let proxy_url = format!("{}://{}", proxy_scheme, proxy.addr);
            println!("Testing HTTP GET with proxy: {}", proxy_url);

            let client = reqwest::Client::builder()
                .proxy(reqwest::Proxy::all(&proxy_url).unwrap())
                .build()
                .unwrap();

            let target_url = format!("http://{}", self.mock_server_http_addr);
            let resp = client
                .get(&target_url)
                .send()
                .await
                .expect("Request failed");

            assert_eq!(resp.status(), 200);
            let body = resp.text().await.unwrap();
            assert_eq!(body, "Hello World!");
        };

        if let Err(_) = tokio::time::timeout(self.default_timeout, test_fut).await {
            panic!("HTTP GET Test timed out after {:?}", self.default_timeout);
        }
    }

    pub async fn test_tcp_echo(&self) {
        let proxy = self.last_proxy();
        println!("Testing TCP Echo with proxy: {:?}", proxy.addr);

        // Timeout for test
        let test_fut = async {
            if proxy.protocol == "socks5" {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut stream = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();

                // SOCKS5 Handshake
                // 1. Client greeting
                stream.write_all(&[5, 1, 0]).await.unwrap(); // Ver 5, 1 method, No auth (0)
                let mut buf = [0u8; 2];
                stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, [5, 0]); // Ver 5, Method 0

                // 2. Client connection request
                // CMD 1 (Connect), RSV 0, ATYP 1 (IPv4)
                let mut req = vec![5, 1, 0, 1];
                // Address
                let ip_octets = match self.mock_server_tcp_addr.ip() {
                    std::net::IpAddr::V4(ip) => ip.octets(),
                    _ => panic!("IPv6 not supported in this simple test"),
                };
                req.extend_from_slice(&ip_octets);
                // Port
                req.extend_from_slice(&self.mock_server_tcp_addr.port().to_be_bytes());

                stream.write_all(&req).await.unwrap();

                // 3. Server response
                let mut resp_head = [0u8; 4];
                stream.read_exact(&mut resp_head).await.unwrap();
                assert_eq!(resp_head[0], 5);
                if resp_head[1] != 0 {
                    panic!("Socks5 connection failed with error: {}", resp_head[1]);
                }

                // Read address/port (ignore)
                let addr_type = resp_head[3];
                match addr_type {
                    1 => {
                        let mut buf = [0u8; 4 + 2];
                        stream.read_exact(&mut buf).await.unwrap();
                    } // IPv4
                    3 => {
                        let mut len = [0u8; 1];
                        stream.read_exact(&mut len).await.unwrap();
                        let mut buf = vec![0u8; len[0] as usize + 2];
                        stream.read_exact(&mut buf).await.unwrap();
                    } // Domain
                    4 => {
                        let mut buf = [0u8; 16 + 2];
                        stream.read_exact(&mut buf).await.unwrap();
                    } // IPv6
                    _ => panic!("Unknown address type"),
                }

                // 4. Send data
                let msg = b"Hello TCP";
                stream.write_all(msg).await.unwrap();
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], msg);

                // 5. Close
                stream.shutdown().await.unwrap();
                drop(stream);
            } else {
                println!(
                    "Skipping TCP test for non-socks5 protocol (TODO: implement HTTP CONNECT)"
                );
            }
        };

        if let Err(_) = tokio::time::timeout(self.default_timeout, test_fut).await {
            panic!("TCP Echo Test timed out after {:?}", self.default_timeout);
        }
    }

    pub async fn test_udp_echo(&self) {
        let test_fut = async {
            let proxy = self.last_proxy();
            if proxy.protocol == "socks5" {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut stream = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();

                // SOCKS5 Handshake
                stream.write_all(&[5, 1, 0]).await.unwrap();
                let mut buf = [0u8; 2];
                stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, [5, 0]);

                // UDP Associate
                // CMD 3 (UDP Associate)
                let mut req = vec![5, 3, 0, 1];
                req.extend_from_slice(&[0, 0, 0, 0]); // 0.0.0.0
                req.extend_from_slice(&[0, 0]); // Port 0

                stream.write_all(&req).await.unwrap();

                // Server response
                let mut resp_head = [0u8; 4];
                stream.read_exact(&mut resp_head).await.unwrap();
                assert_eq!(resp_head[1], 0); // Success

                let addr_type = resp_head[3];
                let relay_addr = match addr_type {
                    1 => {
                        let mut buf = [0u8; 4];
                        stream.read_exact(&mut buf).await.unwrap();
                        std::net::IpAddr::V4(std::net::Ipv4Addr::from(buf))
                    }
                    // Skip others for now
                    _ => panic!("Unsupported address type for UDP relay"),
                };
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await.unwrap();
                let relay_port = u16::from_be_bytes(port_buf);
                let relay_socket_addr = SocketAddr::new(relay_addr, relay_port);

                // Now send UDP packet to relay_socket_addr
                // Header: RSV(2) FRAG(1) ATYP(1) DST.ADDR(4/16) DST.PORT(2) DATA
                let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

                let mut packet = vec![0u8, 0u8, 0u8, 1]; // RSV, FRAG, ATYP=IPv4
                let ip_octets = match self.mock_server_udp_addr.ip() {
                    std::net::IpAddr::V4(ip) => ip.octets(),
                    _ => panic!("IPv6 not supported"),
                };
                packet.extend_from_slice(&ip_octets);
                packet.extend_from_slice(&self.mock_server_udp_addr.port().to_be_bytes());
                let msg = b"Hello UDP";
                packet.extend_from_slice(msg);

                udp_socket
                    .send_to(&packet, relay_socket_addr)
                    .await
                    .unwrap();

                let mut recv_buf = [0u8; 2048];
                let (len, _src) = udp_socket.recv_from(&mut recv_buf).await.unwrap();

                // Parse response header
                // RSV(2) FRAG(1) ATYP(1) ...
                let header_len = 3 + 1 + 4 + 2; // For IPv4
                let data = &recv_buf[header_len..len];
                assert_eq!(data, msg);

                // 5. Close
                stream.shutdown().await.unwrap();
                drop(stream);
            } else {
                println!("Skipping UDP test for non-socks5 protocol");
            }
        };

        if let Err(_) = tokio::time::timeout(self.default_timeout, test_fut).await {
            panic!("UDP Echo Test timed out after {:?}", self.default_timeout);
        }
    }

    pub async fn test_udp_timeout(&self) {
        let test_fut = async {
            let proxy = self.last_proxy();
            if proxy.protocol == "socks5" {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut stream = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();

                // SOCKS5 Handshake
                stream.write_all(&[5, 1, 0]).await.unwrap();
                let mut buf = [0u8; 2];
                stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, [5, 0]);

                // UDP Associate
                // CMD 3 (UDP Associate)
                let mut req = vec![5, 3, 0, 1];
                req.extend_from_slice(&[0, 0, 0, 0]); // 0.0.0.0
                req.extend_from_slice(&[0, 0]); // Port 0

                stream.write_all(&req).await.unwrap();

                // Server response
                let mut resp_head = [0u8; 4];
                stream.read_exact(&mut resp_head).await.unwrap();
                assert_eq!(resp_head[1], 0); // Success

                let addr_type = resp_head[3];
                let relay_addr = match addr_type {
                    1 => {
                        let mut buf = [0u8; 4];
                        stream.read_exact(&mut buf).await.unwrap();
                        std::net::IpAddr::V4(std::net::Ipv4Addr::from(buf))
                    }
                    _ => panic!("Unsupported address type for UDP relay"),
                };
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await.unwrap();
                let relay_port = u16::from_be_bytes(port_buf);
                let relay_socket_addr = SocketAddr::new(relay_addr, relay_port);

                let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

                let mut packet = vec![0u8, 0u8, 0u8, 1]; // RSV, FRAG, ATYP=IPv4
                let ip_octets = match self.mock_server_udp_addr.ip() {
                    std::net::IpAddr::V4(ip) => ip.octets(),
                    _ => panic!("IPv6 not supported"),
                };
                packet.extend_from_slice(&ip_octets);
                packet.extend_from_slice(&self.mock_server_udp_addr.port().to_be_bytes());
                let msg = b"Hello UDP Timeout Test";
                packet.extend_from_slice(msg);

                // Send first packet
                udp_socket
                    .send_to(&packet, relay_socket_addr)
                    .await
                    .unwrap();

                let mut recv_buf = [0u8; 2048];
                let (len, _src) = tokio::time::timeout(
                    Duration::from_secs(5),
                    udp_socket.recv_from(&mut recv_buf),
                )
                .await
                .expect("Timeout waiting for first UDP response")
                .unwrap();
                let header_len = 3 + 1 + 4 + 2; // For IPv4
                let data = &recv_buf[header_len..len];
                assert_eq!(data, msg);

                // Wait for timeout (e.g. 5 seconds)
                println!("Waiting for UDP session timeout...");
                tokio::time::sleep(Duration::from_secs(5)).await;

                // Send packet again after timeout
                udp_socket
                    .send_to(&packet, relay_socket_addr)
                    .await
                    .unwrap();

                // It should succeed because the proxy should transparently create a new session
                let recv_res = tokio::time::timeout(
                    Duration::from_secs(5),
                    udp_socket.recv_from(&mut recv_buf),
                )
                .await;

                assert!(
                    recv_res.is_ok(),
                    "UDP session should transparently re-establish and receive response"
                );

                println!("UDP session timeout and re-establishment verified successfully.");

                // 5. Close
                stream.shutdown().await.unwrap();
                drop(stream);
            } else {
                println!("Skipping UDP timeout test for non-socks5 protocol");
            }
        };

        if let Err(_) = tokio::time::timeout(Duration::from_secs(15), test_fut).await {
            panic!("UDP Timeout Test timed out after 15s");
        }
    }

    /// Create a SOCKS5 UDP association and return the relay address and the TCP control stream
    pub async fn create_socks5_udp_association(&self) -> (SocketAddr, tokio::net::TcpStream) {
        let proxy = self.last_proxy();
        assert_eq!(
            proxy.protocol, "socks5",
            "UDP association only works with SOCKS5 proxy"
        );

        Self::create_socks5_udp_association_for_proxy(proxy.addr).await
    }

    /// Static version of create_socks5_udp_association for use in concurrent tests
    pub async fn create_socks5_udp_association_for_proxy(
        proxy_addr: SocketAddr,
    ) -> (SocketAddr, tokio::net::TcpStream) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();

        // SOCKS5 Handshake
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [5, 0]);

        // UDP Associate
        let mut req = vec![5, 3, 0, 1];
        req.extend_from_slice(&[0, 0, 0, 0]); // 0.0.0.0
        req.extend_from_slice(&[0, 0]); // Port 0

        stream.write_all(&req).await.unwrap();

        // Server response
        let mut resp_head = [0u8; 4];
        stream.read_exact(&mut resp_head).await.unwrap();
        assert_eq!(resp_head[1], 0); // Success

        let addr_type = resp_head[3];
        let relay_addr = match addr_type {
            1 => {
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await.unwrap();
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(buf))
            }
            _ => panic!("Unsupported address type for UDP relay"),
        };
        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).await.unwrap();
        let relay_port = u16::from_be_bytes(port_buf);
        let relay_socket_addr = SocketAddr::new(relay_addr, relay_port);

        (relay_socket_addr, stream)
    }

    /// Send a UDP packet through SOCKS5 relay
    pub async fn send_socks5_udp_packet(
        &self,
        udp_socket: &UdpSocket,
        relay_addr: SocketAddr,
        dest_addr: SocketAddr,
        data: &[u8],
    ) {
        Self::send_socks5_udp_packet_static(udp_socket, relay_addr, dest_addr, data).await;
    }

    /// Static version of send_socks5_udp_packet for use in concurrent tests
    pub async fn send_socks5_udp_packet_static(
        udp_socket: &UdpSocket,
        relay_addr: SocketAddr,
        dest_addr: SocketAddr,
        data: &[u8],
    ) {
        // SOCKS5 UDP Header: RSV(2) FRAG(1) ATYP(1) DST.ADDR(4/16) DST.PORT(2) DATA
        let mut packet = vec![0u8, 0u8, 0u8]; // RSV, FRAG

        match dest_addr.ip() {
            std::net::IpAddr::V4(ip) => {
                packet.push(1); // ATYP=IPv4
                packet.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                packet.push(4); // ATYP=IPv6
                packet.extend_from_slice(&ip.octets());
            }
        }
        packet.extend_from_slice(&dest_addr.port().to_be_bytes());
        packet.extend_from_slice(data);

        udp_socket.send_to(&packet, relay_addr).await.unwrap();
    }

    /// Receive and parse a UDP packet from SOCKS5 relay, returns the data payload
    pub async fn recv_socks5_udp_packet(&self, udp_socket: &UdpSocket, buf: &mut [u8]) -> Vec<u8> {
        Self::recv_socks5_udp_packet_static(udp_socket, buf).await
    }

    /// Static version of recv_socks5_udp_packet for use in concurrent tests
    pub async fn recv_socks5_udp_packet_static(udp_socket: &UdpSocket, buf: &mut [u8]) -> Vec<u8> {
        let (len, _) = udp_socket.recv_from(buf).await.unwrap();

        // SOCKS5 UDP Header: RSV(2) FRAG(1) ATYP(1) DST.ADDR(4/16) DST.PORT(2) DATA
        let mut offset = 3; // Skip RSV and FRAG
        let atyp = buf[offset];
        offset += 1;

        match atyp {
            1 => offset += 4,  // IPv4
            4 => offset += 16, // IPv6
            3 => {
                let domain_len = buf[offset] as usize;
                offset += 1 + domain_len; // Domain name
            }
            _ => panic!("Unsupported ATYP: {}", atyp),
        }
        offset += 2; // Skip port

        buf[offset..len].to_vec()
    }
}
