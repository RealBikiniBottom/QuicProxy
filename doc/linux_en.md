# Linux Client Installation

[简体中文](./linux.md) | [English](./linux_en.md)

Install QuicProxy on a local Linux device with one command and manage proxies through the Web UI.

> Supports **systemd** and **init.d** (SysV), with automatic CPU architecture detection (x64 / arm64 / arm32).
> Supports common distributions such as Ubuntu, Debian, and OpenWrt.

---

## One-Click Installation

```bash
curl -fsSL https://raw.githubusercontent.com/RealBikiniBottom/QuicProxy/master/linux_install.sh | sudo bash
```

After installation, the terminal prints a randomly generated API password and the management panel address. Open that web address in your browser and you can start using it right away.

## Management Commands

**systemd (Ubuntu / Debian / CentOS 7+):**

```bash
systemctl status   quicproxy    # Show status
systemctl restart  quicproxy    # Restart
systemctl stop     quicproxy    # Stop
journalctl -u quicproxy -f      # View logs
```

**init.d (OpenWrt / older Linux systems):**

```bash
service quicproxy status        # Show status
service quicproxy restart       # Restart
service quicproxy stop          # Stop
```

---

## API Examples

```bash
PASS="your-password"
BASE="http://127.0.0.1:8080"

# Health check
curl ${BASE}/api/health -H "Authorization: ${PASS}"

# Push core configuration
curl -X PUT ${BASE}/api/core/config \
  -H "Authorization: ${PASS}" \
  -H "Content-Type: application/json" \
  -d '{"config":"{...core config JSON...}"}'

# Start the core
curl -X POST ${BASE}/api/core/start -H "Authorization: ${PASS}"

# Check core status
curl ${BASE}/api/core/status -H "Authorization: ${PASS}"
```

After the core starts, the following endpoints are automatically reverse-proxied to the core:

| Endpoint           | Description              |
| ------------------ | ------------------------ |
| `GET /observe`     | Proxy status statistics  |
| `GET /outbounds`   | Outbound node list       |
| `PUT /selector`    | Switch selected node     |
| `GET /connections` | Current connection list  |
| `GET /traffic`     | Traffic statistics       |

---

## Directory Structure

```text
/opt/quicproxy/
├── quicproxy            # Binary
├── config.json          # Management config
├── persist.json         # Persistent data kept across restarts
└── web/                 # Flutter Web assets (optional)
```

---

## Uninstall

```bash
# systemd
systemctl stop quicproxy
systemctl disable quicproxy
rm -f /etc/systemd/system/quicproxy.service
systemctl daemon-reload

# init.d
service quicproxy stop
rm -f /etc/init.d/quicproxy

# Remove files
rm -rf /opt/quicproxy
```

---

## Supported Architectures

| Architecture      | Typical Devices             |
| ----------------- | --------------------------- |
| x86_64 / amd64    | Most PCs / VPS instances    |
| aarch64 / arm64   | Raspberry Pi 4/5, ARM VPS   |
| armv7l / arm      | Raspberry Pi 3, older ARM devices |
