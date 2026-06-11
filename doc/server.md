# 自建节点

在 VPS 上搭建 QuicProxy 节点，生成订阅链接供客户端使用。

---

## 一键搭建

```bash
curl -fsSL https://raw.githubusercontent.com/RealBikiniBottom/QuicProxy/main/server_install.sh | sudo bash
```

脚本会交互式询问需要启用的协议，然后自动完成安装。

## 支持的协议

安装过程中可选择启用的入站协议：

| 协议                        | 传输层 | 适用场景                |
| --------------------------- | ------ | ----------------------- |
| **shadowquic** (QUIC + JLS) | UDP    | 延迟最低，适合游戏/视频 |
| **anytls** (insecure TLS)   | TCP    | 伪装 TLS，抗封锁        |
| **trojan** (TLS)            | TCP    | 标准 Trojan，通用性强   |

---

## 安装后

脚本自动完成：

1. 下载最新 quicproxy 二进制
2. 生成随机凭据
3. 自动检测端口和公网 IP
4. 写入服务端配置 (`server.json5`)
5. 注册 systemd 服务并启动
6. 输出订阅链接

```bash
# 查看订阅链接
cat /opt/quicproxy/subscription.txt

# 服务管理
systemctl status   quicproxy
systemctl restart  quicproxy
journalctl -u quicproxy -f
```

---

## 服务端配置文件

安装后在 `/opt/quicproxy/server.json5` 自动生成配置，可手动编辑后重启：

```bash
vim /opt/quicproxy/server.json5
systemctl restart quicproxy
```

关键配置项：入站的用户名密码、端口、TLS/SNI 设置。详见配置文档。

---

## 目录结构

```
/opt/quicproxy/
├── quicproxy            # 二进制
├── server.json5         # 核心配置
└── subscription.txt     # 订阅链接
```

---

## 卸载

```bash
systemctl stop quicproxy
systemctl disable quicproxy
rm -f /etc/systemd/system/quicproxy.service
systemctl daemon-reload
rm -rf /opt/quicproxy
```
