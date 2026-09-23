# Self-Hosted Node Setup

[简体中文](./server.md) | [English](./server_en.md)

Deploy a QuicProxy node on a VPS and generate a subscription link for clients.

---

## One-Click Setup

```bash
curl -fsSL https://raw.githubusercontent.com/RealBikiniBottom/QuicProxy/master/server_install.sh | sudo bash
```

The script interactively asks which protocols to enable, then completes the installation automatically.

## Supported Protocols

Inbound protocols you can choose during installation:

| Protocol                    | Transport | Best For                    |
| --------------------------- | --------- | --------------------------- |
| **shadowquic** (QUIC + JLS) | UDP       | Lowest latency, ideal for gaming and video |
| **anytls** (insecure TLS)   | TCP       | TLS camouflage, better against blocking     |
| **trojan** (TLS)            | TCP       | Standard Trojan, broadly compatible         |

---

## After Installation

The script automatically:

1. Downloads the latest `quicproxy` binary
2. Generates random credentials
3. Detects the port and public IP automatically
4. Writes the server configuration to `server.json5` (including `observe` / `api` / `subscription`)
5. Registers and starts a `systemd` service
6. Prints the subscription link (Core API subscription + direct nodes) and a QR code

```bash
# Show the subscription link
cat /opt/quicproxy/subscription.txt

# Service management
systemctl status   quicproxy
systemctl restart  quicproxy
journalctl -u quicproxy -f
```

---

## Subscription

The script enables the core API and observe, then prints a Core API subscription URL:

```
http://<public-ip>:<api-port>/sub?username=<user>&password=<password>
```

Import this URL directly in the client (the script also renders a QR code through the Core API). Node links are generated dynamically by each inbound, and the `subscription-userinfo` response header reports the user's used traffic in real time. Traffic and time are unlimited by default, while consumption keeps being counted.

---

## Server Configuration File

After installation, the configuration is generated at `/opt/quicproxy/server.json5`. You can edit it manually and restart the service:

```bash
vim /opt/quicproxy/server.json5
systemctl restart quicproxy
```

Key settings include inbound usernames and passwords, ports, and TLS/SNI options. See the configuration documentation for more details.

---

## Directory Structure

```text
/opt/quicproxy/
├── quicproxy            # Binary
├── server.json5         # Core configuration
├── subscription.txt     # Subscription link
└── .core_api            # Core API password and port
```

---

## Uninstall

```bash
systemctl stop quicproxy
systemctl disable quicproxy
rm -f /etc/systemd/system/quicproxy.service
systemctl daemon-reload
rm -rf /opt/quicproxy
```
