#!/bin/bash
set -euo pipefail

# ────────────────────────────────────────────────────────────
# QuicProxy Client Installer — 一键安装客户端（管理模式）
#
# 用法:
#   curl -fsSL https://raw.githubusercontent.com/.../linux_install.sh | sudo bash -s -- --password mypass
#
# 特性:
#   - 自动检测 CPU 架构 (x86_64 / aarch64 / armv7l)
#   - 同时支持 systemd 和 init.d (SysV)
#   - 以 --manage 模式运行，暴露管理 API + 反向代理
#   - 可选的 Web UI (通过 --web-dir 指定 Flutter Web 产物目录)
# ────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── 默认值 ──
REPO="RealBikiniBottom/QuicProxy"
GITHUB_API="https://api.github.com/repos/${REPO}/releases/latest"
INSTALL_DIR="/opt/quicproxy"
BIN_PATH="${INSTALL_DIR}/quicproxy"
CONFIG_PATH="${INSTALL_DIR}/config.json"
PERSIST_PATH="${INSTALL_DIR}/persist.json"
SERVICE_NAME="quicproxy"
SYSTEMD_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
INITD_FILE="/etc/init.d/${SERVICE_NAME}"

# 用户可覆盖
PASSWORD="${PASSWORD:-}"
PORT="${PORT:-8080}"
WEB_DIR="${WEB_DIR:-}"
VERSION="${VERSION:-}"
WORK_DIR="${WORK_DIR:-${INSTALL_DIR}}"
HOST="${HOST:-0.0.0.0}"

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

# ──────────────────────────────────────────────
# 基础检查
# ──────────────────────────────────────────────

check_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    log_error "请使用 root 权限运行此脚本"
    log_info "用法: curl ... | sudo bash"
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
    log_info "Debian/Ubuntu: apt install -y curl tar"
    log_info "CentOS/RHEL:    yum install -y curl tar"
    log_info "OpenWrt:        opkg install curl tar"
    exit 1
  fi
}

# ──────────────────────────────────────────────
# 架构检测与二进制选择
# ──────────────────────────────────────────────

detect_arch() {
  log_step "检测 CPU 架构..."

  local machine
  machine=$(uname -m)

  case "$machine" in
    x86_64|amd64)
      ARCH="x64"
      ARCH_TARGET="linux-x64"
      ;;
    aarch64|arm64)
      ARCH="arm64"
      ARCH_TARGET="linux-arm64"
      ;;
    armv7l|armv6l|arm)
      ARCH="arm32"
      ARCH_TARGET="linux-arm32"
      ;;
    *)
      log_error "不支持的 CPU 架构: ${machine}"
      log_info "支持的架构: x86_64, aarch64, armv7l"
      exit 1
      ;;
  esac

  log_info "检测到架构: ${machine} → ${ARCH}"
}

detect_latest_version() {
  log_step "检测最新版本..."

  if [[ -n "${VERSION}" ]]; then
    TAG_NAME="$VERSION"
    log_info "使用指定版本: ${TAG_NAME}"
    return
  fi

  local api_response
  api_response=$(curl -sfL --connect-timeout 10 --max-time 30 "$GITHUB_API" 2>/dev/null) || {
    log_error "无法访问 GitHub API, 请检查网络连接"
    log_info "可用 VERSION=v1.0.0 手动指定版本"
    exit 1
  }

  TAG_NAME=$(echo "$api_response" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

  if [[ -z "$TAG_NAME" ]]; then
    log_error "解析 GitHub API 响应失败"
    exit 1
  fi

  log_info "最新版本: ${TAG_NAME}"
}

# ──────────────────────────────────────────────
# 下载与安装
# ──────────────────────────────────────────────

download_and_install() {
  log_step "下载 QuicProxy (${ARCH_TARGET})..."

  local download_url
  if [[ -n "${VERSION:-}" ]]; then
    download_url="https://github.com/${REPO}/releases/download/${VERSION}/quicproxy-core-${ARCH_TARGET}.tar.gz"
  else
    download_url="https://github.com/${REPO}/releases/latest/download/quicproxy-core-${ARCH_TARGET}.tar.gz"
  fi

  local tarball="${TMPDIR}/quicproxy.tar.gz"

  log_info "下载地址: ${download_url}"
  curl -fSL --connect-timeout 10 --max-time 300 -o "$tarball" "$download_url" || {
    log_error "下载失败, 请检查网络或版本号"
    log_info "如果 release 中还没有 ${ARCH_TARGET} 产物，请联系开发者"
    exit 1
  }

  log_info "校验文件..."
  if ! tar tzf "$tarball" &>/dev/null; then
    log_error "下载的文件损坏, 请重试"
    exit 1
  fi

  # 备份旧版本
  if [[ -f "$BIN_PATH" ]]; then
    local old_version
    old_version=$("$BIN_PATH" --version 2>/dev/null || echo "unknown")
    log_info "备份旧版本 (${old_version})..."
    cp "$BIN_PATH" "${BIN_PATH}.bak.$(date +%s)" 2>/dev/null || true
  fi

  mkdir -p "$INSTALL_DIR"
  tar xzf "$tarball" -C "$INSTALL_DIR" --overwrite || {
    log_error "解压失败"
    exit 1
  }
  chmod +x "$BIN_PATH"

  local installed_version
  installed_version=$("$BIN_PATH" --version 2>/dev/null || echo "unknown")
  log_info "安装完成: ${installed_version}"
}

# ──────────────────────────────────────────────
# 生成管理配置
# ──────────────────────────────────────────────

generate_manage_config() {
  log_step "生成管理配置..."

  if [[ -z "$PASSWORD" ]]; then
    PASSWORD=$(openssl rand -hex 12 2>/dev/null || cat /dev/urandom 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 24)
    log_info "已生成随机 API 密码: ${PASSWORD}"
    log_info "请保管好此密码! 可在 ${CONFIG_PATH} 中修改"
  fi

  cat > "$CONFIG_PATH" << JSONEOF
{
  "manage": true,
  "host": "${HOST}",
  "port": ${PORT},
  "password": "${PASSWORD}",
  "work_dir": "${WORK_DIR}",
  "persist_file": "persist.json"
}
JSONEOF

  log_info "配置已保存: ${CONFIG_PATH}"
}

# ──────────────────────────────────────────────
# 停止已有进程
# ──────────────────────────────────────────────

stop_existing() {
  log_step "停止已有进程..."

  local stopped=false

  # systemd
  if [[ -f "$SYSTEMD_FILE" ]]; then
    log_info "发现 systemd 服务, 正在停止..."
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    stopped=true
  fi

  # init.d
  if [[ -f "$INITD_FILE" ]]; then
    log_info "发现 init.d 服务, 正在停止..."
    "$INITD_FILE" stop 2>/dev/null || true
    update-rc.d -f "${SERVICE_NAME}" remove 2>/dev/null || true
    chkconfig --del "${SERVICE_NAME}" 2>/dev/null || true
    stopped=true
  fi

  # 强制杀残留进程
  local pids
  pids=$(pgrep -f "quicproxy" 2>/dev/null || true)
  if [[ -n "$pids" ]]; then
    log_info "终止残留进程 (PID: $(echo $pids | tr '\n' ' '))..."
    for pid in $pids; do
      kill "$pid" 2>/dev/null || true
    done
    sleep 2
    pids=$(pgrep -f "quicproxy" 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
      for pid in $pids; do
        kill -9 "$pid" 2>/dev/null || true
      done
    fi
    stopped=true
  fi

  if [[ "$stopped" == true ]]; then
    log_info "已有进程已全部停止"
  else
    log_info "未检测到运行中的进程 (首次安装)"
  fi
}

# ──────────────────────────────────────────────
# 服务安装：systemd
# ──────────────────────────────────────────────

install_systemd() {
  log_step "安装 systemd 服务..."

  local exec_start="${BIN_PATH} --manage"
  [[ -n "$PASSWORD" ]] && exec_start="${exec_start} --password \"${PASSWORD}\""
  [[ -n "$PORT" ]] && exec_start="${exec_start} --port ${PORT}"
  [[ -n "$HOST" ]] && exec_start="${exec_start} --host ${HOST}"
  [[ -n "$WORK_DIR" ]] && exec_start="${exec_start} --work-dir ${WORK_DIR}"
  [[ -f "${WORK_DIR}/persist.json" ]] && exec_start="${exec_start} --persist-file ${WORK_DIR}/persist.json"

  # Web UI 可选
  if [[ -n "$WEB_DIR" ]] && [[ -d "$WEB_DIR" ]]; then
    exec_start="${exec_start} --web-dir ${WEB_DIR}"
  fi

  cat > "$SYSTEMD_FILE" << UNITEOF
[Unit]
Description=QuicProxy Client (Manage Mode)
After=network.target

[Service]
Type=simple
WorkingDirectory=${WORK_DIR}
ExecStart=${exec_start}
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
UNITEOF

  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  systemctl start "${SERVICE_NAME}"

  sleep 2
  if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
    log_info "systemd 服务运行中 ✓"
    return 0
  else
    log_warn "systemd 服务可能未正常启动, 查看日志: journalctl -u ${SERVICE_NAME} -f"
    return 1
  fi
}

# ──────────────────────────────────────────────
# 服务安装：init.d (SysV)
# ──────────────────────────────────────────────

install_initd() {
  log_step "安装 init.d 服务..."

  local exec_start="${BIN_PATH} --manage"
  [[ -n "$PASSWORD" ]] && exec_start="${exec_start} --password \"${PASSWORD}\""
  [[ -n "$PORT" ]] && exec_start="${exec_start} --port ${PORT}"
  [[ -n "$HOST" ]] && exec_start="${exec_start} --host ${HOST}"
  [[ -n "$WORK_DIR" ]] && exec_start="${exec_start} --work-dir ${WORK_DIR}"
  [[ -f "${WORK_DIR}/persist.json" ]] && exec_start="${exec_start} --persist-file ${WORK_DIR}/persist.json"

  if [[ -n "$WEB_DIR" ]] && [[ -d "$WEB_DIR" ]]; then
    exec_start="${exec_start} --web-dir ${WEB_DIR}"
  fi

  cat > "$INITD_FILE" << INITEOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          ${SERVICE_NAME}
# Required-Start:    \$network \$remote_fs
# Required-Stop:     \$network \$remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: QuicProxy Client Service
# Description:       QuicProxy 客户端管理模式
### END INIT INFO

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
NAME="${SERVICE_NAME}"
DESC="QuicProxy Client"
DAEMON="${BIN_PATH}"
DAEMON_ARGS="--manage --password ${PASSWORD} --port ${PORT} --host ${HOST} --work-dir ${WORK_DIR}"
PIDFILE="/var/run/\${NAME}.pid"

test -x \${DAEMON} || exit 0

case "\$1" in
  start)
    echo -n "Starting \${DESC}: \${NAME}"
    start-stop-daemon --start --quiet --oknodo --background \\
      --make-pidfile --pidfile \${PIDFILE} \\
      --chdir "${WORK_DIR}" \\
      --exec \${DAEMON} -- \${DAEMON_ARGS}
    echo "."
    ;;
  stop)
    echo -n "Stopping \${DESC}: \${NAME}"
    start-stop-daemon --stop --quiet --oknodo --pidfile \${PIDFILE}
    rm -f \${PIDFILE}
    echo "."
    ;;
  restart|force-reload)
    \$0 stop
    sleep 2
    \$0 start
    ;;
  status)
    if start-stop-daemon --status --pidfile \${PIDFILE} 2>/dev/null; then
      echo "\${NAME} is running"
    else
      echo "\${NAME} is not running"
      exit 3
    fi
    ;;
  *)
    echo "Usage: \$0 {start|stop|restart|status}"
    exit 1
    ;;
esac

exit 0
INITEOF

  chmod +x "$INITD_FILE"

  # 注册到启动项 (根据发行版)
  if command -v update-rc.d &>/dev/null; then
    update-rc.d "${SERVICE_NAME}" defaults 2>/dev/null || true
    update-rc.d "${SERVICE_NAME}" enable 2>/dev/null || true
  elif command -v chkconfig &>/dev/null; then
    chkconfig --add "${SERVICE_NAME}" 2>/dev/null || true
    chkconfig "${SERVICE_NAME}" on 2>/dev/null || true
  elif command -v rc-update &>/dev/null; then
    # Alpine / OpenRC
    rc-update add "${SERVICE_NAME}" default 2>/dev/null || true
  fi

  # 启动服务
  "$INITD_FILE" start 2>/dev/null || true

  sleep 2
  if "$INITD_FILE" status &>/dev/null; then
    log_info "init.d 服务运行中 ✓"
    return 0
  else
    log_warn "init.d 服务可能未正常启动"
    return 1
  fi
}

# ──────────────────────────────────────────────
# 检测与安装服务
# ──────────────────────────────────────────────

detect_and_install_service() {
  log_step "检测 init 系统并安装服务..."

  # 优先 systemd，其次 init.d
  if command -v systemctl &>/dev/null; then
    log_info "检测到 systemd"
    install_systemd
  elif [[ -d "/etc/init.d" ]] || command -v update-rc.d &>/dev/null || command -v chkconfig &>/dev/null || command -v rc-update &>/dev/null; then
    log_info "检测到 init.d / SysV"
    install_initd
  else
    log_error "未检测到支持的 init 系统 (systemd / init.d)"
    log_info "你可以手动运行:"
    log_info "  ${BIN_PATH} --manage --password ${PASSWORD} --port ${PORT}"
    exit 1
  fi
}

# ──────────────────────────────────────────────
# 打印完成信息
# ──────────────────────────────────────────────

print_success() {
  echo ""
  echo -e "  ${GREEN}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "  ${GREEN}║        QuicProxy Client 安装完成!                 ║${NC}"
  echo -e "  ${GREEN}╚══════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "  ${CYAN}管理面板:${NC} http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo "YOUR_IP"):${PORT}"
  echo -e "  ${CYAN}API 密码:${NC}  ${PASSWORD}"
  echo -e "  ${CYAN}配置文件:${NC} ${CONFIG_PATH}"
  echo -e "  ${CYAN}持久化数据:${NC} ${PERSIST_PATH}"
  echo ""

  if [[ -d "${WEB_DIR:-}" ]]; then
    echo -e "  ${CYAN}Web UI:${NC}   已启用 (${WEB_DIR})"
  else
    echo -e "  ${YELLOW}Web UI:${NC}   未启用。如需 Web 管理界面，请设置 WEB_DIR 重新安装"
    echo -e "              WEB_DIR=/path/to/web 重新运行本脚本"
  fi

  echo ""
  echo -e "  ${YELLOW}管理命令:${NC}"

  if command -v systemctl &>/dev/null; then
    echo -e "    systemctl status   ${SERVICE_NAME}    # 查看状态"
    echo -e "    systemctl restart  ${SERVICE_NAME}    # 重启"
    echo -e "    systemctl stop     ${SERVICE_NAME}    # 停止"
    echo -e "    journalctl -u ${SERVICE_NAME} -f      # 查看日志"
  else
    echo -e "    service ${SERVICE_NAME} status        # 查看状态"
    echo -e "    service ${SERVICE_NAME} restart       # 重启"
    echo -e "    service ${SERVICE_NAME} stop          # 停止"
  fi
  echo ""
  echo -e "  ${GREEN}API 端点:${NC}"
  echo -e "    POST /api/core/config   — 下发核心配置 JSON"
  echo -e "    POST /api/core/start    — 启动核心"
  echo -e "    POST /api/core/stop     — 停止核心"
  echo -e "    POST /api/core/restart  — 重启核心"
  echo -e "    GET  /api/core/status   — 查看核心状态"
  echo -e "    GET  /api/core/logs     — 查看核心日志"
  echo -e "    GET  /api/health        — 健康检查"
  echo -e "    GET  /observe           — 代理状态 (反向代理到核心)"
  echo -e "    GET  /outbounds         — 出站列表 (反向代理到核心)"
  echo -e "    PUT  /selector          — 切换节点 (反向代理到核心)"
  echo ""
}

print_banner() {
  echo -e "${BLUE}"
  echo "  ╔══════════════════════════════════════════════╗"
  echo "  ║      QuicProxy Client Installer              ║"
  echo "  ║      一键安装客户端 (管理模式)               ║"
  echo "  ╚══════════════════════════════════════════════╝"
  echo -e "${NC}"
}

# ──────────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────────

main() {
  TMPDIR=$(mktemp -d)

  print_banner

  check_root
  check_deps
  detect_arch
  detect_latest_version

  log_info "安装目录: ${INSTALL_DIR}"
  log_info "架构:      ${ARCH_TARGET}"
  log_info "端口:      ${PORT}"

  stop_existing
  download_and_install
  generate_manage_config
  detect_and_install_service
  print_success

  log_info "${GREEN}安装成功!${NC} 🎉"
}

# 解析参数
while [[ $# -gt 0 ]]; do
  case "$1" in
    --password)
      PASSWORD="$2"; shift 2 ;;
    --port)
      PORT="$2"; shift 2 ;;
    --host)
      HOST="$2"; shift 2 ;;
    --web-dir)
      WEB_DIR="$2"; shift 2 ;;
    --work-dir)
      WORK_DIR="$2"; shift 2 ;;
    --version)
      VERSION="$2"; shift 2 ;;
    *)
      log_error "未知参数: $1"
      echo "用法: sudo bash linux_install.sh [--password PASS] [--port 8080] [--web-dir /path] [--version v1.0.0]"
      exit 1
      ;;
  esac
done

main
