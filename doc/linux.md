# Linux 客户端安装

在本地 Linux 设备上一键安装 QuicProxy，通过 Web UI 管理代理。

> 支持 **systemd** 和 **init.d** (SysV)，自动检测 CPU 架构 (x64 / arm64 / arm32)。
> 支持各种常见发行版：Ubuntu、Debian、OpenWrt 等

---

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/RealBikiniBottom/QuicProxy/main/linux_install.sh | sudo bash
```

安装完成后终端会打印随机生成的 API 密码和管理面板地址。打开浏览器输入 web 地址，就可以直接使用了。

## 管理命令

**systemd (Ubuntu / Debian / CentOS 7+):**

```bash
systemctl status   quicproxy    # 查看状态
systemctl restart  quicproxy    # 重启
systemctl stop     quicproxy    # 停止
journalctl -u quicproxy -f      # 查看日志
```

**init.d (OpenWrt / 旧版 Linux):**

```bash
service quicproxy status        # 查看状态
service quicproxy restart       # 重启
service quicproxy stop          # 停止
```

---

## API 操作示例

```bash
PASS="your-password"
BASE="http://127.0.0.1:8080"

# 健康检查
curl ${BASE}/api/health -H "Authorization: ${PASS}"

# 下发核心配置
curl -X PUT ${BASE}/api/core/config \
  -H "Authorization: ${PASS}" \
  -H "Content-Type: application/json" \
  -d '{"config":"{...核心配置 JSON...}"}'

# 启动核心
curl -X POST ${BASE}/api/core/start -H "Authorization: ${PASS}"

# 查看核心状态
curl ${BASE}/api/core/status -H "Authorization: ${PASS}"
```

核心启动后，以下端点自动反向代理到核心：

| 端点               | 说明         |
| ------------------ | ------------ |
| `GET /observe`     | 代理状态统计 |
| `GET /outbounds`   | 出站节点列表 |
| `PUT /selector`    | 切换节点     |
| `GET /connections` | 当前连接列表 |
| `GET /traffic`     | 流量统计     |

---

## 目录结构

```
/opt/quicproxy/
├── quicproxy            # 二进制
├── config.json          # 管理配置
├── persist.json         # 持久化数据（跨重启保留）
└── web/                 # Flutter Web 产物（可选）
```

---

## 卸载

```bash
# systemd
systemctl stop quicproxy
systemctl disable quicproxy
rm -f /etc/systemd/system/quicproxy.service
systemctl daemon-reload

# init.d
service quicproxy stop
rm -f /etc/init.d/quicproxy

# 删除文件
rm -rf /opt/quicproxy
```

---

## 架构支持

| 架构            | 典型设备              |
| --------------- | --------------------- |
| x86_64 / amd64  | 大多数 PC / VPS       |
| aarch64 / arm64 | 树莓派 4/5、ARM VPS   |
| armv7l / arm    | 树莓派 3、老 ARM 设备 |
