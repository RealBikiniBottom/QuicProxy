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
    log_info "用法: sudo bash server_install.sh"
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
    log_info "你也可以手动指定版本: VERSION=v1.0.0 sudo bash server_install.sh"
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
    log_info "覆盖安装到 ${INSTALL_DIR} ..."
  else
    mkdir -p "$INSTALL_DIR"
    log_info "首次安装到 ${INSTALL_DIR} ..."
  fi

  tar xzf "$tarball" -C "$INSTALL_DIR" --overwrite || {
    log_error "解压失败"
    exit 1
  }

  rm -f "${BIN_PATH}.bak."* 2>/dev/null || true
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

prompt_install_options() {
  log_step "选择要安装的入站协议"

  local choose_anytls="${INSTALL_ANYTLS:-yes}"
  local choose_shadowquic="${INSTALL_SHADOWQUIC:-yes}"
  local choose_trojan="${INSTALL_TROJAN:-yes}"

  if [[ -t 0 ]]; then
    echo ""
    echo -e "  ${GREEN}QuicProxy 支持三种入站协议:${NC}"
    echo ""
    echo -e "  ${CYAN}1) shadowquic (QUIC + JLS)${NC} — 基于 QUIC 的隧道，延迟更低"
    echo -e "  ${CYAN}2) anytls (TCP / insecure TLS)${NC}  — 基于 TLS 的伪装隧道，抗封锁更好"
    echo -e "  ${CYAN}3) trojan (TLS)${NC} — 标准 Trojan 协议，通用性更强"
    echo ""

    echo -ne "  ${YELLOW}安装 shadowquic (QUIC + JLS)? [Y/n]: ${NC}"
    read -r input
    if [[ -n "$input" ]]; then
      input=$(echo "$input" | tr '[:upper:]' '[:lower:]')
      case "$input" in
        n|no|0|false) choose_shadowquic="no" ;;
        *)            choose_shadowquic="yes" ;;
      esac
    fi

    echo -ne "  ${YELLOW}安装 anytls (TCP / insecure TLS)? [Y/n]: ${NC}"
    read -r input
    if [[ -n "$input" ]]; then
      input=$(echo "$input" | tr '[:upper:]' '[:lower:]')
      case "$input" in
        n|no|0|false) choose_anytls="no" ;;
        *)            choose_anytls="yes" ;;
      esac
    fi

    echo -ne "  ${YELLOW}安装 trojan (TLS)? [Y/n]: ${NC}"
    read -r input
    if [[ -n "$input" ]]; then
      input=$(echo "$input" | tr '[:upper:]' '[:lower:]')
      case "$input" in
        n|no|0|false) choose_trojan="no" ;;
        *)            choose_trojan="yes" ;;
      esac
    fi

    echo ""
  fi

  if [[ "$choose_anytls" == "no" ]] && [[ "$choose_shadowquic" == "no" ]] && [[ "$choose_trojan" == "no" ]]; then
    log_error "至少需要选择一种协议"
    exit 1
  fi

  ENABLE_SHADOWQUIC="$choose_shadowquic"
  ENABLE_ANYTLS="$choose_anytls"
  ENABLE_TROJAN="$choose_trojan"

  local parts=()
  [[ "$choose_shadowquic" == "yes" ]] && parts+=("shadowquic")
  [[ "$choose_anytls" == "yes" ]] && parts+=("anytls")
  [[ "$choose_trojan" == "yes" ]] && parts+=("trojan")
  log_info "已选择: ${parts[*]}"
}

check_udp_port_free() {
  local port=$1
  if command -v ss &>/dev/null; then
    ss -uln 2>/dev/null | grep -q ":${port} " && return 1 || return 0
  elif command -v netstat &>/dev/null; then
    netstat -uln 2>/dev/null | grep -q ":${port} " && return 1 || return 0
  fi
  return 0
}

check_tcp_port_free() {
  local port=$1
  if command -v ss &>/dev/null; then
    ss -tln 2>/dev/null | grep -q ":${port} " && return 1 || return 0
  elif command -v netstat &>/dev/null; then
    netstat -tln 2>/dev/null | grep -q ":${port} " && return 1 || return 0
  fi
  return 0
}

find_free_tcp_port() {
  # 在候选端口列表中找到首个空闲 TCP 端口，并避开已分配的端口
  local exclude_a="${1:-}"
  local exclude_b="${2:-}"
  local candidates=(443 8443 5443)
  for port in "${candidates[@]}"; do
    [[ "$port" == "$exclude_a" ]] && continue
    [[ "$port" == "$exclude_b" ]] && continue
    if check_tcp_port_free "$port"; then
      echo "$port"
      return 0
    fi
  done
  # 候选耗尽后，从基准端口向后偏移寻找
  local base="${exclude_a:-443}"
  for offset in 1 2 3 11 21 31 41 51 101 201; do
    local candidate=$((base + offset))
    [[ "$candidate" == "$exclude_a" ]] && continue
    [[ "$candidate" == "$exclude_b" ]] && continue
    if check_tcp_port_free "$candidate"; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

find_free_udp_port() {
  local candidates=(443 8443 5443)
  for port in "${candidates[@]}"; do
    if check_udp_port_free "$port"; then
      echo "$port"
      return 0
    fi
  done
  return 1
}

detect_available_port() {
  log_step "检测可用端口..."

  SQ_PORT=""
  ANYTLS_PORT=""
  TROJAN_PORT=""

  if [[ -n "${PORT:-}" ]]; then
    # 手动指定端口时，shadowquic 用 UDP，可与一个 TCP 协议共用；
    # anytls / trojan 均为 TCP，若都启用则必须分配不同端口
    if [[ "${ENABLE_SHADOWQUIC:-}" == "yes" ]]; then
      SQ_PORT="$PORT"
      log_info "shadowquic(UDP) → ${SQ_PORT} (手动指定)"
    fi
    if [[ "${ENABLE_ANYTLS:-}" == "yes" ]]; then
      ANYTLS_PORT="$PORT"
      log_info "anytls(TCP) → ${ANYTLS_PORT} (手动指定)"
    fi
    if [[ "${ENABLE_TROJAN:-}" == "yes" ]]; then
      if [[ "${ENABLE_ANYTLS:-}" == "yes" ]]; then
        # 必须为 trojan 另找一个 TCP 端口，避免与 anytls 冲突
        local trojan_port
        trojan_port=$(find_free_tcp_port "$ANYTLS_PORT") || {
          log_error "无法为 trojan 找到空闲 TCP 端口 (anytls 已占用 ${ANYTLS_PORT})"
          exit 1
        }
        TROJAN_PORT="$trojan_port"
        log_info "trojan(TCP) → ${TROJAN_PORT} (anytls 与 trojan 不能共用 TCP 端口)"
      else
        TROJAN_PORT="$PORT"
        log_info "trojan(TCP) → ${TROJAN_PORT} (手动指定)"
      fi
    fi
  else
    # 自动检测：UDP 与 TCP 互不冲突，但 anytls / trojan 必须各自占用不同 TCP 端口
    if [[ "${ENABLE_SHADOWQUIC:-}" == "yes" ]]; then
      local sq_port
      sq_port=$(find_free_udp_port) || {
        log_error "未找到空闲 UDP 端口, 请手动指定: PORT=12345 sudo bash server_install.sh"
        exit 1
      }
      SQ_PORT="$sq_port"
      log_info "shadowquic(UDP) → ${SQ_PORT}"
    fi

    if [[ "${ENABLE_ANYTLS:-}" == "yes" ]]; then
      local anytls_port
      anytls_port=$(find_free_tcp_port) || {
        log_error "未找到空闲 TCP 端口给 anytls, 请手动指定: PORT=12345 sudo bash server_install.sh"
        exit 1
      }
      ANYTLS_PORT="$anytls_port"
      log_info "anytls(TCP) → ${ANYTLS_PORT}"
    fi

    if [[ "${ENABLE_TROJAN:-}" == "yes" ]]; then
      local trojan_port
      trojan_port=$(find_free_tcp_port "$ANYTLS_PORT") || {
        log_error "未找到空闲 TCP 端口给 trojan, 请手动指定: PORT=12345 sudo bash server_install.sh"
        exit 1
      }
      TROJAN_PORT="$trojan_port"
      log_info "trojan(TCP) → ${TROJAN_PORT}"
    fi
  fi
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
  log_info "  SERVER_IP=1.2.3.4 sudo bash server_install.sh"
  exit 1
}

detect_server_country() {
  log_step "检测服务器国家..."

  if [[ -n "${SERVER_COUNTRY:-}" ]]; then
    log_info "使用手动指定的国家代码: ${SERVER_COUNTRY}"
    return
  fi

  local country=""

  # 优先用 ipinfo.io（有免费额度），备选 ip-api.com
  country=$(curl -sf4 --connect-timeout 5 --max-time 10 "https://ipinfo.io/${SERVER_IP}/country" 2>/dev/null | tr -d '[:space:]' || true)
  if [[ -z "$country" ]]; then
    country=$(curl -sf4 --connect-timeout 5 --max-time 10 "http://ip-api.com/line/${SERVER_IP}?fields=countryCode" 2>/dev/null | tr -d '[:space:]' || true)
  fi

  if [[ -n "$country" ]] && [[ "$country" =~ ^[A-Z]{2}$ ]]; then
    SERVER_COUNTRY="$country"
    log_info "检测到服务器国家: ${SERVER_COUNTRY}"
    return
  fi

  log_warn "无法自动检测国家代码, 使用 Unknown"
  SERVER_COUNTRY="UN"
}

write_server_config() {
  log_step "生成服务端配置文件..."

  local sni="www.apple.com"

  local sq_enabled=false
  local anytls_enabled=false
  local trojan_enabled=false
  [[ "${ENABLE_SHADOWQUIC:-yes}" == "yes" ]] && sq_enabled=true
  [[ "${ENABLE_ANYTLS:-yes}" == "yes" ]] && anytls_enabled=true
  [[ "${ENABLE_TROJAN:-yes}" == "yes" ]] && trojan_enabled=true

  local port="${SQ_PORT}"

  # 计算启用的协议列表，用于逗号控制
  local enabled=()
  $sq_enabled && enabled+=("sq")
  $anytls_enabled && enabled+=("anytls")
  $trojan_enabled && enabled+=("trojan")
  local total=${#enabled[@]}
  local count=0

  cat > "$CONFIG_PATH" << JSON5EOF
{
  "inbounds": {
JSON5EOF

  if $sq_enabled; then
    count=$((count + 1))
    local trailing=""
    [[ $count -lt $total ]] && trailing=","
    cat >> "$CONFIG_PATH" << JSON5EOF
    "shadowquic_inbound": {
      "type": "shadowquic",
      "address": "0.0.0.0",
      "port": ${port},
      "tls": {
        "enable_jls": true,
        "jls_username": "${USERNAME}",
        "jls_password": "${PASSWORD}",
        "zero_rtt": true,
        "sni": "${sni}"
      }
    }${trailing}
JSON5EOF
  fi

  if $anytls_enabled; then
    count=$((count + 1))
    local trailing=""
    [[ $count -lt $total ]] && trailing=","
    cat >> "$CONFIG_PATH" << JSON5EOF
    "anytls_inbound": {
      "type": "anytls",
      "address": "0.0.0.0",
      "port": ${ANYTLS_PORT},
      "password": "${PASSWORD}",
      "tls": {
        "enable": true,
        "insecure": true,
        "sni": "${sni}"
      }
    }${trailing}
JSON5EOF
  fi

  if $trojan_enabled; then
    count=$((count + 1))
    local trailing=""
    [[ $count -lt $total ]] && trailing=","
    cat >> "$CONFIG_PATH" << JSON5EOF
    "trojan_inbound": {
      "type": "trojan",
      "address": "0.0.0.0",
      "port": ${TROJAN_PORT},
      "password": "${PASSWORD}",
      "transport": {
        "type": "tcp"
      },
      "tls": {
        "enable": true,
        "insecure": true
      }
    }${trailing}
JSON5EOF
  fi

  cat >> "$CONFIG_PATH" << JSON5EOF
  },
  "outbounds": {
    "default_server": "direct",
    "servers": {
      "direct": {
        "type": "direct"
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
  local sni="www.apple.com"

  local anytls_enabled=false
  local sq_enabled=false
  local trojan_enabled=false
  [[ "${ENABLE_ANYTLS:-yes}" == "yes" ]] && anytls_enabled=true
  [[ "${ENABLE_SHADOWQUIC:-yes}" == "yes" ]] && sq_enabled=true
  [[ "${ENABLE_TROJAN:-yes}" == "yes" ]] && trojan_enabled=true

  local node_num=1
  local sq_url=""
  local anytls_url=""
  local trojan_url=""

  if $sq_enabled; then
    local sq_tag
    sq_tag=$(printf "%s-%02d" "${SERVER_COUNTRY}" "${node_num}")
    node_num=$((node_num + 1))
    local encoded_tag
    encoded_tag=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${sq_tag}', safe=''))" 2>/dev/null || echo "${sq_tag}")
    sq_url="sq://${USERNAME}:${PASSWORD}@${host}:${SQ_PORT}?sni=${sni}&zero_rtt=true#${encoded_tag}"
  fi

  if $anytls_enabled; then
    local anytls_tag
    anytls_tag=$(printf "%s-%02d" "${SERVER_COUNTRY}" "${node_num}")
    node_num=$((node_num + 1))
    local anytls_encoded_tag
    anytls_encoded_tag=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${anytls_tag}', safe=''))" 2>/dev/null || echo "${anytls_tag}")
    anytls_url="anytls://${PASSWORD}@${host}:${ANYTLS_PORT}?sni=${sni}&insecure=true#${anytls_encoded_tag}"
  fi

  if $trojan_enabled; then
    local trojan_tag
    trojan_tag=$(printf "%s-%02d" "${SERVER_COUNTRY}" "${node_num}")
    node_num=$((node_num + 1))
    local trojan_encoded_tag
    trojan_encoded_tag=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${trojan_tag}', safe=''))" 2>/dev/null || echo "${trojan_tag}")
    trojan_url="trojan://${PASSWORD}@${host}:${TROJAN_PORT}?sni=${sni}&type=tcp&insecure=true#${trojan_encoded_tag}"
  fi

  # 将订阅写入文件，方便之后查看、systemd 日志也会引用这个路径
  {
    if $sq_enabled; then
      echo "$sq_url"
    fi
    if $anytls_enabled; then
      echo "$anytls_url"
    fi
    if $trojan_enabled; then
      echo "$trojan_url"
    fi
  } > "${INSTALL_DIR}/subscription.txt"

  # 突出显示订阅链接
  local BOLD='\033[1m'
  local WHITE='\033[1;37m'

  echo ""
  echo -e "  ${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "  ${YELLOW}║${NC}  ${BOLD}${WHITE}📋 订 阅 链 接${NC}                                              ${YELLOW}║${NC}"
  echo -e "  ${YELLOW}║${NC}  ${CYAN}请复制下面单独一整行链接，或复制备份文件内容${NC}                ${YELLOW}║${NC}"
  echo -e "  ${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"

  if $sq_enabled; then
    echo -e "${GREEN}${BOLD}${sq_url}${NC}"
  fi

  if $anytls_enabled; then
    echo -e "${GREEN}${BOLD}${anytls_url}${NC}"
  fi

  if $trojan_enabled; then
    echo -e "${GREEN}${BOLD}${trojan_url}${NC}"
  fi

  echo ""

  log_info "以上订阅链接已备份到 ${INSTALL_DIR}/subscription.txt"
  log_info "可以随时用 cat ${INSTALL_DIR}/subscription.txt 查看"
  echo ""
  echo -e "  ${YELLOW}管理命令:${NC}"
  echo -e "    systemctl status   ${SERVICE_NAME}    # 查看状态"
  echo -e "    systemctl restart  ${SERVICE_NAME}    # 重启服务"
  echo -e "    systemctl stop     ${SERVICE_NAME}    # 停止服务"
  echo -e "    journalctl -u ${SERVICE_NAME} -f      # 查看日志"
  echo -e "    cat ${INSTALL_DIR}/subscription.txt   # 查看订阅"
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

  prompt_install_options

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
  detect_server_country
  write_server_config
  install_systemd_service
  generate_subscription_url

  log_info "安装成功! 🎉"
}

main "$@"
