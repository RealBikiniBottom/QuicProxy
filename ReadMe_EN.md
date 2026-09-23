<div align="center">
    <img src="./assets/logo.png" alt="logo" width="250" />
  <br>
  <sup>A high-performance, low-memory, zero-latency, secure, and easy-to-use open source game accelerator</sup>
</div>

<p align="center">
  <a href="./ReadMe.md">简体中文</a> | <strong>English</strong>
</p>

# Download And Start Right Away

|    Platform    | Download                                                                                                                    | Notes                                                             |
| :------------: | --------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| 🖥️ **Windows** | [⬇ Download Installer](https://github.com/RealBikiniBottom/QuicProxy/releases/latest/download/QuicProxy-Windows-Setup.exe) | `.exe` installer                                                  |
| 📱 **Android** | [⬇ Download APK](https://github.com/RealBikiniBottom/QuicProxy/releases/latest/download/QuicProxy-Android.apk)             | `.apk` app                                                        |
|   📱 **iOS**   | [⬇ App Store](https://apps.apple.com/us/app/quicproxy/id6775813506?l=zh-Hans-CN)                                           | Available only for Apple IDs outside mainland China               |
|  🐧 **Linux**  | [Installation Guide](./doc/linux_en.md) and [Set Up Your Own Node](#set-up-your-own-node-in-3-steps)                        | Works on Linux with or without a GUI                              |
| 🛜 **Router**  | See the [Installation Guide](./doc/linux_en.md)                                                                             | Includes a [Web Panel](https://github.com/spongebob888/quicboard) |
|  🍎 **macOS**  | _Coming soon_                                                                                                               |                                                                   |

## Easy To Use (Out Of The Box)

Thanks to JLS, you do not need to buy a domain name or generate certificates yourself. It is beginner-friendly and requires almost no manual configuration:

> 1. Download
> 2. Install
> 3. Import the subscription
> 4. Start

Just 4 steps to use our recommended best practice setup:

> - Accurate domestic and international traffic routing
> - No DNS query leaks
> - Automatic best node selection

## Set Up Your Own Node In 3 Steps

Run the following command on a Linux server for a one-click installation:

```bash
curl -fsSL https://raw.githubusercontent.com/RealBikiniBottom/QuicProxy/master/server_install.sh | sudo bash
```

The script finishes automatically and prints a [subscription link](https://github.com/RealBikiniBottom/QuicProxy/discussions/2). Copy and paste it into the client to start using it. For a detailed walkthrough, see [this guide](./doc/server_en.md).

## Supported Protocols

Inbound:

- Socks5
- HTTP
- Tun
- Shadowquic
- AnyTLS
- AnyTLS-JLS
- Trojan

Outbound:

- Shadowquic (recommended)
- Socks5
- AnyTLS
- AnyTLS-JLS
- Trojan
- Shadowsocks
- Vmess
- Hysteria2

## Zero Latency Throughout

For a proxied TCP connection:

- Other TCP-based solutions (such as Trojan) must first establish TCP (three-way handshake, costing 1.5 RTT), then establish TLS (costing another 1 RTT).

- Other QUIC-based solutions (such as Hysteria2) can send stream requests over an existing connection without extra RTT, but if that connection breaks, they still need 1 RTT to recover.

- Our approach uses QUIC Connection Early Data, so even after a connection is interrupted, traffic can resume without paying any RTT for recovery.

**Highly available on unstable networks**, especially in environments where the network changes frequently, such as on high-speed rail when the device keeps switching base stations. Shadowquic switches smoothly and users barely notice reconnects.

## Advanced Congestion Control

> Waiting for upstream adaptation

Powered by BBRv3 for faster startup latency, a more stable congestion window, and better performance on mobile networks where signal quality changes frequently.

## UDP Friendly

Full Cone with UDP Extension solves long-standing issues like slow QUIC proxy traffic. UDP packets stay encrypted and unordered, which better matches how UDP is meant to work and makes it more suitable for gaming.

## Low Memory Usage

QuicProxy focuses on doing one thing and doing it well. It removes unnecessary features and goes back to fundamentals. The codebase was written from scratch and carefully tuned to balance performance, memory, power consumption, security, and usability.

Even with TUN enabled, memory usage in heavy daily use is usually still below 20 MB, staying well under Apple's 50 MB limit whenever possible.

## Friendly For Service Operators

Released under the permissive MIT license, so you can modify it freely and even keep your own changes closed source if that fits your use case.

A backend API for user management is provided for free, available for trojan / anytls / shadowquic inbounds:

- `GET /users`: list every user with traffic usage
- `POST /users`: add or update a user, body `{"username":"alice","password":"secret"}`
- `DELETE /users?username=alice`: remove a user and close its connections
- `GET /users/stats?username=alice&clear=true`: fetch one user's usage; `clear=true` atomically reads and zeroes the counters (omit `username` for all users)

These endpoints are served by the core API (`api` config) and use the same `Authorization: <password>` auth. Users can be seeded through the top-level `users` list or an inbound's `users`; runtime additions and traffic counters persist to the observe cache.

The core API also distributes subscriptions. Node links are generated dynamically by each inbound, so there is nothing to maintain by hand:

- `GET /sub?username=alice&password=secret`: a public endpoint (no API password) that returns the user's sq / anytls / trojan nodes and reports their used traffic through the `subscription-userinfo` response header. Traffic and time are unlimited by default (`total=0; expire=0`), while consumption keeps being counted
- `GET /qr?text=<url>`: renders text as a terminal QR code (half-block glyphs that merge two module rows per line so the code fits an 80-column terminal) and requires the API password

The `subscription` config supplies the public host and metadata:

```json5
"subscription": {
  "host": "1.2.3.4",             // public address embedded in node links; string or array
  "name": "MyNode",              // optional node name prefix
  "update_interval": 24,         // optional profile-update-interval header (hours)
  "web_page_url": "https://..."  // optional profile-web-page-url header
}
```

`host` may also be an array to publish several addresses at once (IPv6 nodes lead, and every node name is suffixed with `-IPv4` / `-IPv6`):

```json5
"subscription": {
  "host": ["2001:db8::1", "1.2.3.4"]
}
```

We guarantee that none of our projects will include ads that redirect your users to competing providers such as airports, VPNs, VPS services, or IP proxy sellers.

## Donations

[GitHub Issues](https://github.com/RealBikiniBottom/QuicProxy/issues) are only for bug reports and must include detailed reproduction steps. If you are not sure whether something is a bug, have suggestions, or need usage help, please use the [Discussions](https://github.com/RealBikiniBottom/QuicProxy/discussions) section instead.

QuicProxy is completely free software. We do not take responsibility for any issues that arise, and QuicProxy itself does not provide nodes or subscriptions.

To keep the project healthy, we accept voluntary donations. Paying supporters get more direct attention from the developer, access to a private group chat, and a direct line for feature requests.
