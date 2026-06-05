#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

REPO="RealBikiniBottom/QuicProxy"
INSTALL_DIR="/opt/quicproxy"
CONFIG_PATH="${INSTALL_DIR}/server.json5"
BIN_PATH="${INSTALL_DIR}/quicproxy"
SERVICE_NAME="quicproxy"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
GITHUB_API="https://api.github.com/repos/${REPO}/releases/latest"
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/quicproxy-core-linux-x64.tar.gz"

TMPDIR=""

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()  { echo -e "\n${BLUE}==>${NC} ${CYAN}$*${NC}"; }

cleanup() {
  if [[ -n "${TMPDIR}" ]] && [[ -d "${TMPDIR}" ]]; then
    rm -rf "${TMPDIR}"
  fi
}
trap cleanup EXIT

check_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    log_error "请使用 root 权限运行此脚本"
    log_info "用法: sudo bash linux_install.sh"
    exit 1
  fi
}

check_deps() {
  local missing=()
  for cmd in curl tar mktemp; do
    if ! command -v "$cmd" &>/dev/null; then
      missing+=("$cmd")
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    log_error "缺少依赖: ${missing[*]}"
    log_info "请先安装: apt install -y curl tar   (Debian/Ubuntu)"
    log_info "或:        yum install -y curl tar   (CentOS/RHEL)"
    exit 1
  fi
}

stop_existing_process() {
  log_step "停止已有进程..."

  local stopped=false

  if [[ -f "$SERVICE_FILE" ]]; then
    log_info "发现 systemd 服务, 正在停止..."
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    stopped=true
  elif systemctl list-unit-files --type=service 2>/dev/null | grep -q "^${SERVICE_NAME}\." 2>/dev/null; then
    log_info "systemd 服务已存在, 正在停止..."
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    stopped=true
  fi

  local pids
  pids=$(pgrep -f "quicproxy" 2>/dev/null || true)
  if [[ -n "$pids" ]]; then
    log_info "发现运行中的 quicproxy 进程 (PID: $(echo $pids | tr '\n' ' ')), 正在终止..."
    for pid in $pids; do
      kill "$pid" 2>/dev/null || true
    done
    stopped=true
  fi

  if [[ "$stopped" == true ]]; then
    sleep 2

    pids=$(pgrep -f "quicproxy" 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
      log_warn "进程未退出, 强制终止..."
      for pid in $pids; do
        kill -9 "$pid" 2>/dev/null || true
      done
      sleep 1
    fi
    log_info "已有进程已全部停止"
  else
    log_info "未检测到运行中的 quicproxy 进程 (首次安装)"
  fi
}

detect_latest_version() {
  log_step "检测最新版本..."

  local api_response
  api_response=$(curl -sfL --connect-timeout 10 --max-time 30 "$GITHUB_API" 2>/dev/null) || {
    log_error "无法访问 GitHub API, 请检查网络连接"
    log_info "你也可以手动指定版本: VERSION=v1.0.0 sudo bash linux_install.sh"
    exit 1
  }

  TAG_NAME=$(echo "$api_response" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

  if [[ -z "$TAG_NAME" ]]; then
    log_error "解析 GitHub API 响应失败"
    exit 1
  fi

  log_info "最新版本: ${TAG_NAME}"
}

download_and_extract() {
  log_step "下载并解压..."

  local tarball="${TMPDIR}/quicproxy.tar.gz"

  log_info "正在下载 quicproxy-core (${TAG_NAME})..."
  curl -fSL --connect-timeout 10 --max-time 300 -o "$tarball" "$DOWNLOAD_URL" || {
    log_error "下载失败"
    exit 1
  }

  log_info "校验文件..."
  if ! tar tzf "$tarball" &>/dev/null; then
    log_error "下载的文件损坏, 请重试"
    exit 1
  fi

  if [[ -d "$INSTALL_DIR" ]]; then
    local old_version
    old_version=$("$BIN_PATH" --version 2>/dev/null || echo "unknown")

    if [[ -f "$BIN_PATH" ]]; then
      log_info "备份旧版本 (${old_version})..."
      cp "$BIN_PATH" "${BIN_PATH}.bak.$(date +%s)" 2>/dev/null || true
    fi

    log_info "覆盖安装到 ${INSTALL_DIR} ..."
  else
    mkdir -p "$INSTALL_DIR"
    log_info "首次安装到 ${INSTALL_DIR} ..."
  fi

  tar xzf "$tarball" -C "$INSTALL_DIR" --overwrite || {
    log_error "解压失败"
    exit 1
  }

  chmod +x "$BIN_PATH"

  local installed_version
  installed_version=$("$BIN_PATH" --version 2>/dev/null || echo "unknown")
  log_info "安装完成: ${installed_version}"
}

generate_credentials() {
  if [[ -f "$CONFIG_PATH" ]]; then
    log_info "检测到已有配置文件, 尝试复用凭据..."

    local existing_user existing_pass
    existing_user=$(grep -o '"jls_username": *"[^"]*"' "$CONFIG_PATH" 2>/dev/null | head -1 | sed 's/.*"jls_username": *"\([^"]*\)".*/\1/' || true)
    existing_pass=$(grep -o '"jls_password": *"[^"]*"' "$CONFIG_PATH" 2>/dev/null | head -1 | sed 's/.*"jls_password": *"\([^"]*\)".*/\1/' || true)

    if [[ -n "$existing_user" ]] && [[ -n "$existing_pass" ]]; then
      USERNAME="$existing_user"
      PASSWORD="$existing_pass"
      log_info "已复用现有凭据 (用户名: ${USERNAME})"
      return
    fi

    log_warn "无法解析已有凭据, 将生成新的"
  fi

  USERNAME=$(openssl rand -hex 6 2>/dev/null || cat /dev/urandom 2>/dev/null | tr -dc 'a-z0-9' | head -c 12)
  PASSWORD=$(openssl rand -hex 16 2>/dev/null || cat /dev/urandom 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 32)
  log_info "已生成随机用户名: ${USERNAME}"
  log_info "已生成随机密码: ${PASSWORD}"
}

detect_available_port() {
  log_step "检测可用端口..."

  local preferred=443
  local fallback_ports=(13431 8443 4443 54321)

  if [[ -n "${PORT:-}" ]]; then
    SHADOWQUIC_PORT="$PORT"
    log_info "使用手动指定的端口: ${SHADOWQUIC_PORT}"
    return
  fi

  check_udp_port_free() {
    local port=$1
    if command -v ss &>/dev/null; then
      ss -uln 2>/dev/null | grep -q ":${port} " && return 1 || return 0
    elif command -v netstat &>/dev/null; then
      netstat -uln 2>/dev/null | grep -q ":${port} " && return 1 || return 0
    fi
    return 0
  }

  if check_udp_port_free "$preferred"; then
    SHADOWQUIC_PORT="$preferred"
    log_info "UDP ${preferred} 端口可用, 优先使用"
    return
  fi

  log_warn "UDP ${preferred} 端口已被占用"

  for port in "${fallback_ports[@]}"; do
    if check_udp_port_free "$port"; then
      SHADOWQUIC_PORT="$port"
      log_info "使用备用端口: UDP ${port}"
      return
    fi
    log_warn "UDP ${port} 端口已被占用"
  done

  log_error "所有候选端口均被占用, 请手动指定: PORT=12345 sudo bash linux_install.sh"
  exit 1
}

detect_server_ip() {
  log_step "检测公网 IP..."

  if [[ -n "${SERVER_IP:-}" ]]; then
    log_info "使用手动指定的公网 IP: ${SERVER_IP}"
    return
  fi

  local ip=""

  local http_services=(
    "https://api.ipify.org"
    "https://ifconfig.me"
    "https://icanhazip.com"
    "https://checkip.amazonaws.com"
    "https://ipinfo.io/ip"
    "https://api.ip.sb/ip"
    "https://ip.seeip.org"
  )

  for svc in "${http_services[@]}"; do
    ip=$(curl -sf4 --connect-timeout 5 --max-time 10 "$svc" 2>/dev/null | tr -d '[:space:]' || true)
    if [[ -n "$ip" ]] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      SERVER_IP="$ip"
      log_info "检测到服务器公网 IP: ${SERVER_IP} (来源: ${svc})"
      return
    fi
  done

  if command -v dig &>/dev/null; then
    ip=$(dig +short +timeout=5 myip.opendns.com @resolver1.opendns.com 2>/dev/null | tr -d '[:space:]' || true)
    if [[ -n "$ip" ]] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      SERVER_IP="$ip"
      log_info "检测到服务器公网 IP: ${SERVER_IP} (来源: DNS/OpenDNS)"
      return
    fi

    ip=$(dig +short +timeout=5 whoami.akamai.net @ns1-1.akamaitech.net 2>/dev/null | tr -d '[:space:]' || true)
    if [[ -n "$ip" ]] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      SERVER_IP="$ip"
      log_info "检测到服务器公网 IP: ${SERVER_IP} (来源: DNS/Akamai)"
      return
    fi
  fi

  if command -v nslookup &>/dev/null; then
    ip=$(nslookup myip.opendns.com resolver1.opendns.com 2>/dev/null | grep -A1 "Name:" | grep "Address:" | tail -1 | awk '{print $2}' | tr -d '[:space:]' || true)
    if [[ -n "$ip" ]] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      SERVER_IP="$ip"
      log_info "检测到服务器公网 IP: ${SERVER_IP} (来源: nslookup/OpenDNS)"
      return
    fi
  fi

  log_error "无法自动检测公网 IP, 请确认服务器能访问外网"
  log_info "将直接退出, 避免生成无效的订阅链接"
  log_info "如果你的服务器有固定公网 IP, 可用以下方式手动指定:"
  log_info "  SERVER_IP=1.2.3.4 sudo bash linux_install.sh"
  exit 1
}

write_server_config() {
  log_step "生成服务端配置文件..."

  local sni="www.apple.com"
  local idle_timeout=500

  cat > "$CONFIG_PATH" << JSON5EOF
{
  "inbounds": {
    "shadowquic_inbound": {
      "type": "shadowquic",
      "address": "0.0.0.0",
      "port": ${SHADOWQUIC_PORT},
      "idle_timeout": ${idle_timeout},
      "gso": true,
      "tls": {
        "enable_jls": true,
        "jls_username": "${USERNAME}",
        "jls_password": "${PASSWORD}",
        "zero_rtt": true,
        "sni": "${sni}"
      }
    }
  },
  "outbounds": {
    "default_server": "direct",
    "servers": {
      "direct": {
        "type": "direct",
      }
    }
  },
  "cache": {
    "all_cache": {
      "memory_size": 1000,
      "path": "${INSTALL_DIR}/server_cache.db"
    }
  },
  "router": {
    "default_mode": "rule"
  },
  "dns": {
    "default_server": "local_dns",
    "servers": {
      "local_dns": {
        "type": "udp",
        "address": "1.1.1.1",
        "port": 53,
        "timeout": 10,
        "outbound": "direct",
        "strategy": "ipv4_only",
        "cache": "all_cache"
      }
    }
  },
  "log": {
    "level": "warn",
    "color": false
  }
}
JSON5EOF

  log_info "配置文件已保存到: ${CONFIG_PATH}"
}

install_systemd_service() {
  log_step "安装 systemd 服务..."

  cat > "$SERVICE_FILE" << UNITEOF
[Unit]
Description=QuicProxy Server
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BIN_PATH} -c ${CONFIG_PATH}
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity
LimitNPROC=infinity
TasksMax=infinity

[Install]
WantedBy=multi-user.target
UNITEOF

  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  systemctl start "${SERVICE_NAME}"

  sleep 2

  if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
    log_info "✓ 服务运行中"
  else
    log_warn "服务可能未正常启动, 请检查: journalctl -u ${SERVICE_NAME} -f"
  fi
}

generate_subscription_url() {
  log_step "生成订阅链接..."

  local host="${SERVER_IP}"
  local port="${SHADOWQUIC_PORT}"
  local sni="www.apple.com"
  local tag="QuicProxy-$(hostname 2>/dev/null || echo 'Server')"
  local encoded_tag
  encoded_tag=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${tag}', safe=''))" 2>/dev/null || echo "${tag}")

  local sub_url="sq://${USERNAME}:${PASSWORD}@${host}:${port}?sni=${sni}&zero_rtt=true&idle_timeout=500#${encoded_tag}"

  echo ""
  echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
  echo -e "${CYAN}  安装完成! 以下是你的订阅信息:${NC}"
  echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
  echo ""
  echo -e "  ${YELLOW}订阅链接:${NC}"
  echo ""
  echo -e "  ${GREEN}${sub_url}${NC}"
  echo ""
  echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
  echo ""
  echo -e "  ${YELLOW}用户名:${NC} ${USERNAME}"
  echo -e "  ${YELLOW}密码:  ${NC} ${PASSWORD}"
  echo -e "  ${YELLOW}端口:  ${NC} ${port}"
  echo -e "  ${YELLOW}SNI:   ${NC} ${sni}"
  echo ""
  echo -e "  ${YELLOW}管理命令:${NC}"
  echo -e "    systemctl status   ${SERVICE_NAME}    # 查看状态"
  echo -e "    systemctl restart  ${SERVICE_NAME}    # 重启服务"
  echo -e "    systemctl stop     ${SERVICE_NAME}    # 停止服务"
  echo -e "    journalctl -u ${SERVICE_NAME} -f      # 查看日志"
  echo -e "    ${BIN_PATH} -c ${CONFIG_PATH}         # 手动运行"
  echo ""
}

print_banner() {
  echo -e "${BLUE}"
  echo "  ╔══════════════════════════════════════════╗"
  echo "  ║        QuicProxy Server Installer        ║"
  echo "  ╚══════════════════════════════════════════╝"
  echo -e "${NC}"
}

main() {
  TMPDIR=$(mktemp -d)

  print_banner

  check_root
  check_deps

  log_info "安装目录: ${INSTALL_DIR}"

  stop_existing_process

  if [[ -n "${VERSION:-}" ]]; then
    TAG_NAME="$VERSION"
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/quicproxy-core-linux-x64.tar.gz"
    log_info "使用指定版本: ${VERSION}"
  else
    detect_latest_version
  fi

  download_and_extract
  generate_credentials
  detect_available_port
  detect_server_ip
  write_server_config
  install_systemd_service
  generate_subscription_url

  log_info "安装成功! 🎉"
}

main "$@"
