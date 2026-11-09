#!/bin/bash
set -euo pipefail

# ────────────────────────────────────────────────────────────
# QuicProxy Client Installer — 一键安装客户端（管理模式）
#
# 用法:
#   curl -fsSL https://raw.githubusercontent.com/RealBikiniBottom/QuicProxy/master/linux_install.sh | sudo bash -s -- --password mypass
#   # raw.githubusercontent.com 访问不畅时可经 jsDelivr 拉取脚本:
#   curl -fsSL https://cdn.jsdelivr.net/gh/RealBikiniBottom/QuicProxy@master/linux_install.sh | sudo bash -s -- --web-ui with
#
# 特性:
#   - 自动检测 CPU 架构 (x86_64 / aarch64 / armv7l)
#   - 同时支持 systemd 和 init.d (SysV)
#   - 以 --manage 模式运行，暴露管理 API + 反向代理
#   - 支持用户选择安装带 Web UI 或不带 Web UI 的版本
#   - 无论是否带 Web UI，都统一通过 systemd / init.d 管理
#   - 支持通过 --web-dir 指定已有的 Flutter Web 产物目录
#   - 下载源: 官网 CDN (web.quicproxy.org) 优先，失败自动回退 GitHub Releases（--mirror 可指定）
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
CORE_DIR="${INSTALL_DIR}/core"
DEFAULT_WEB_DIR="${INSTALL_DIR}/web"
BIN_PATH="${CORE_DIR}/quicproxy"
CONFIG_PATH="${INSTALL_DIR}/config.json"
SERVICE_NAME="quicproxy"
SYSTEMD_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
INITD_FILE="/etc/init.d/${SERVICE_NAME}"
WEB_ASSET_NAME="QuicProxy-Web-Full.zip"

# 发布流程会把最新版安装包同步到官网 (static/assets → /assets/)，经 Cloudflare 加速。
# 官网只保留最新版，因此指定 --version 时不使用该源。
# 网站仓库是私有的，jsDelivr 无法分发安装包，只用于分发本脚本和查询最新版本号。
CDN_ASSET_BASE="${CDN_ASSET_BASE:-https://web.quicproxy.org/assets}"
JSDELIVR_DATA_API="https://data.jsdelivr.com/v1/packages/gh/${REPO}/resolved?specifier=latest"

# 用户可覆盖
PASSWORD="${PASSWORD:-}"
PORT="${PORT:-8080}"
WEB_DIR="${WEB_DIR:-}"
WEB_UI_MODE="${WEB_UI_MODE:-ask}"
VERSION="${VERSION:-}"
MIRROR="${MIRROR:-auto}"   # auto: 官网 CDN 优先，失败回退 GitHub; cdn: 只用官网 CDN; github: 只用 GitHub
WORK_DIR="${WORK_DIR:-${INSTALL_DIR}}"
HOST="${HOST:-::}"
PERSIST_PATH="${WORK_DIR}/persist.json"

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

has_zip_extractor() {
  command -v unzip &>/dev/null || command -v bsdtar &>/dev/null
}

build_release_download_url() {
  local asset_name="$1"

  if [[ -n "${TAG_NAME:-}" ]]; then
    echo "https://github.com/${REPO}/releases/download/${TAG_NAME}/${asset_name}"
  else
    echo "https://github.com/${REPO}/releases/latest/download/${asset_name}"
  fi
}

build_cdn_download_url() {
  local asset_name="$1"
  # 官网只有最新版；用户指定了版本就跳过
  [[ -z "${VERSION:-}" ]] || return 1
  echo "${CDN_ASSET_BASE}/${asset_name}"
}

# 按 MIRROR 输出候选下载地址，每行一个，按优先级排序
build_download_urls() {
  local asset_name="$1"
  local cdn_url=""
  cdn_url=$(build_cdn_download_url "$asset_name" || true)
  local gh_url
  gh_url=$(build_release_download_url "$asset_name")

  case "$MIRROR" in
    cdn)
      [[ -n "$cdn_url" ]] && echo "$cdn_url"
      ;;
    github)
      echo "$gh_url"
      ;;
    *)
      [[ -n "$cdn_url" ]] && echo "$cdn_url"
      echo "$gh_url"
      ;;
  esac
}

# download_with_fallback <输出文件> <校验函数> <超时秒> <url...>
# 依次尝试每个地址，下载成功且校验通过即返回 0
download_with_fallback() {
  local output="$1"
  local verify_fn="$2"
  local max_time="$3"
  shift 3

  local url
  for url in "$@"; do
    log_info "下载: ${url}"
    rm -f "$output"
    if curl -fSL --connect-timeout 10 --max-time "$max_time" --retry 2 --retry-delay 1 \
        -o "$output" "$url"; then
      if "$verify_fn" "$output"; then
        return 0
      fi
      log_warn "文件校验失败，换下一个下载源"
    else
      log_warn "下载失败，换下一个下载源"
    fi
  done
  return 1
}

verify_tarball() {
  tar tzf "$1" &>/dev/null
}

verify_zip() {
  if command -v unzip &>/dev/null; then
    unzip -tq "$1" &>/dev/null
  else
    bsdtar -tf "$1" &>/dev/null
  fi
}

normalize_mirror() {
  case "$MIRROR" in
    auto|cdn|github) ;;
    jsdelivr|web) MIRROR="cdn" ;;
    gh) MIRROR="github" ;;
    *)
      log_error "无效的下载源: ${MIRROR}"
      log_info "支持的值: auto, cdn, github"
      exit 1
      ;;
  esac
}

extract_zip_to_dir() {
  local zip_file="$1"
  local dest_dir="$2"

  mkdir -p "$dest_dir"

  if command -v unzip &>/dev/null; then
    unzip -oq "$zip_file" -d "$dest_dir"
  elif command -v bsdtar &>/dev/null; then
    bsdtar -xf "$zip_file" -C "$dest_dir"
  else
    return 1
  fi
}

normalize_web_ui_mode() {
  case "${WEB_UI_MODE}" in
    ask|with|without)
      ;;
    true|yes|y|1)
      WEB_UI_MODE="with"
      ;;
    false|no|n|0)
      WEB_UI_MODE="without"
      ;;
    *)
      log_error "无效的 WEB_UI_MODE: ${WEB_UI_MODE}"
      log_info "支持的值: ask, with, without"
      exit 1
      ;;
  esac
}

prompt_web_ui_mode() {
  if [[ "$WEB_UI_MODE" != "ask" ]]; then
    return
  fi

  if [[ -n "$WEB_DIR" ]]; then
    WEB_UI_MODE="with"
    return
  fi

  log_step "选择安装模式..."
  echo "  1) 带 Web UI（下载并启用内置 Web 管理界面）"
  echo "  2) 不带 Web UI（仅安装 Core 管理服务）"

  if [[ -r /dev/tty ]]; then
    local choice=""
    while true; do
      read -r -p "请选择 [1/2] (默认 1): " choice </dev/tty
      choice="${choice:-1}"
      case "$choice" in
        1)
          WEB_UI_MODE="with"
          break
          ;;
        2)
          WEB_UI_MODE="without"
          break
          ;;
        *)
          log_warn "请输入 1 或 2"
          ;;
      esac
    done
  else
    WEB_UI_MODE="without"
    log_warn "当前不是交互式终端，默认安装不带 Web UI 的版本"
    log_warn "如需带 Web UI，请显式传入: --web-ui with"
  fi
}

check_existing_installation() {
  log_step "检查已有安装..."

  local current_bin=""
  if [[ -f "$BIN_PATH" ]]; then
    current_bin="$BIN_PATH"
  elif [[ -f "${INSTALL_DIR}/quicproxy" ]]; then
    current_bin="${INSTALL_DIR}/quicproxy"
  fi

  if [[ -z "$current_bin" ]]; then
    log_info "未检测到已有安装，将执行全新安装"
    return
  fi

  local current_version
  current_version=$("$current_bin" --version 2>/dev/null || echo "unknown")

  log_info "检测到已安装版本: ${current_version}"
  log_info "目标安装版本: ${TAG_NAME}"
  log_info "将执行覆盖安装并自动更新现有文件"
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

  TAG_NAME=""

  # 1) GitHub API（未登录每小时 60 次限额，可能被限流）
  if [[ "$MIRROR" != "cdn" ]]; then
    local api_response
    if api_response=$(curl -sfL --connect-timeout 10 --max-time 20 "$GITHUB_API" 2>/dev/null); then
      TAG_NAME=$(echo "$api_response" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    fi
  fi

  # 2) jsDelivr 数据接口（返回去掉 v 前缀的版本号）
  if [[ -z "$TAG_NAME" ]] && [[ "$MIRROR" != "github" ]]; then
    local cdn_response cdn_version
    if cdn_response=$(curl -sfL --connect-timeout 10 --max-time 20 "$JSDELIVR_DATA_API" 2>/dev/null); then
      cdn_version=$(echo "$cdn_response" | grep -o '"version": *"[^"]*"' | head -1 | sed 's/.*"version": *"\([^"]*\)".*/\1/')
      [[ -n "$cdn_version" ]] && TAG_NAME="v${cdn_version#v}"
    fi
  fi

  # 3) github.com 的 releases/latest 跳转（不走 API 限额）
  if [[ -z "$TAG_NAME" ]]; then
    local location
    location=$(curl -sI --connect-timeout 10 --max-time 20 "https://github.com/${REPO}/releases/latest" 2>/dev/null \
      | tr -d '\r' | awk 'tolower($1)=="location:" {print $2}' | tail -1)
    [[ "$location" == */releases/tag/* ]] && TAG_NAME="${location##*/}"
  fi

  if [[ -z "$TAG_NAME" ]]; then
    log_error "无法获取最新版本 (GitHub / jsDelivr 均不可达)，请检查网络"
    log_info "可用 --version v1.0.0 手动指定版本"
    exit 1
  fi

  log_info "最新版本: ${TAG_NAME}"
}

# ──────────────────────────────────────────────
# 下载与安装
# ──────────────────────────────────────────────

download_and_install() {
  log_step "下载 QuicProxy (${ARCH_TARGET})..."

  local asset_name="quicproxy-core-${ARCH_TARGET}.tar.gz"
  local tarball="${TMPDIR}/quicproxy.tar.gz"
  local urls=()
  mapfile -t urls < <(build_download_urls "$asset_name")

  if ! download_with_fallback "$tarball" verify_tarball 300 "${urls[@]}"; then
    log_error "所有下载源均失败, 请检查网络或版本号"
    log_info "如果 release 中还没有 ${ARCH_TARGET} 产物，请联系开发者"
    exit 1
  fi

  # 备份旧版本
  local current_bin=""
  if [[ -f "$BIN_PATH" ]]; then
    current_bin="$BIN_PATH"
  elif [[ -f "${INSTALL_DIR}/quicproxy" ]]; then
    current_bin="${INSTALL_DIR}/quicproxy"
  fi

  if [[ -n "$current_bin" ]]; then
    local old_version
    old_version=$("$current_bin" --version 2>/dev/null || echo "unknown")
    log_info "备份旧版本 (${old_version})..."
    cp "$current_bin" "${current_bin}.bak.$(date +%s)" 2>/dev/null || true
  fi

  mkdir -p "$INSTALL_DIR" "$CORE_DIR"
  tar xzf "$tarball" -C "$CORE_DIR" --overwrite || {
    log_error "解压失败"
    exit 1
  }
  chmod +x "$BIN_PATH"

  local installed_version
  installed_version=$("$BIN_PATH" --version 2>/dev/null || echo "unknown")
  log_info "安装完成: ${installed_version}"
}

setup_web_ui() {
  if [[ "$WEB_UI_MODE" == "without" ]]; then
    log_info "已选择不安装 Web UI"
    return
  fi

  if [[ -n "$WEB_DIR" ]]; then
    if [[ -d "$WEB_DIR" ]]; then
      log_info "使用指定的 Web UI 目录: ${WEB_DIR}"
      return
    fi
    log_error "指定的 Web UI 目录不存在: ${WEB_DIR}"
    exit 1
  fi

  log_step "安装 Web UI..."

  if ! has_zip_extractor; then
    log_error "未找到 unzip 或 bsdtar，无法自动解压 Web UI"
    exit 1
  fi

  mkdir -p "$INSTALL_DIR"

  local web_zip="${TMPDIR}/${WEB_ASSET_NAME}"
  local web_staging_dir="${TMPDIR}/web"
  local urls=()
  mapfile -t urls < <(build_download_urls "$WEB_ASSET_NAME")

  if ! download_with_fallback "$web_zip" verify_zip 600 "${urls[@]}"; then
    log_error "Web UI 下载失败，无法继续安装"
    exit 1
  fi

  rm -rf "$web_staging_dir"
  if ! extract_zip_to_dir "$web_zip" "$web_staging_dir"; then
    log_error "Web UI 解压失败，无法继续安装"
    exit 1
  fi

  if [[ ! -f "${web_staging_dir}/index.html" ]]; then
    log_error "Web UI 内容不完整，未发现 index.html"
    exit 1
  fi

  rm -rf "$DEFAULT_WEB_DIR"
  if ! mv "$web_staging_dir" "$DEFAULT_WEB_DIR"; then
    log_error "无法将 Web UI 安装到 ${DEFAULT_WEB_DIR}"
    exit 1
  fi
  WEB_DIR="$DEFAULT_WEB_DIR"

  log_info "Web UI 已安装到: ${WEB_DIR}"
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
  [[ -f "${PERSIST_PATH}" ]] && exec_start="${exec_start} --persist-file ${PERSIST_PATH}"

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

  local daemon_args="--manage --password ${PASSWORD} --port ${PORT} --host ${HOST} --work-dir ${WORK_DIR}"
  [[ -f "${PERSIST_PATH}" ]] && daemon_args="${daemon_args} --persist-file ${PERSIST_PATH}"

  if [[ -n "$WEB_DIR" ]] && [[ -d "$WEB_DIR" ]]; then
    daemon_args="${daemon_args} --web-dir ${WEB_DIR}"
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
DAEMON_ARGS="${daemon_args}"
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
  echo -e "  ${CYAN}Core 目录:${NC} ${CORE_DIR}"
  echo -e "  ${CYAN}配置文件:${NC} ${CONFIG_PATH}"
  echo -e "  ${CYAN}持久化数据:${NC} ${PERSIST_PATH}"
  echo -e "  ${CYAN}安装模式:${NC} ${WEB_UI_MODE}"
  echo ""

  if [[ -d "${WEB_DIR:-}" ]]; then
    echo -e "  ${CYAN}Web UI:${NC}   已启用 (${WEB_DIR})"
  elif [[ "${WEB_UI_MODE}" == "without" ]]; then
    echo -e "  ${YELLOW}Web UI:${NC}   未启用（已按选择安装为不带 Web UI）"
  else
    echo -e "  ${YELLOW}Web UI:${NC}   未启用（本次选择了带 Web UI，但下载或解压未成功）"
    echo -e "              可使用 --web-ui with 或 --web-dir /path/to/web 重新运行本脚本"
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

refresh_runtime_paths() {
  PERSIST_PATH="${WORK_DIR}/persist.json"
}

# ──────────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────────

main() {
  TMPDIR=$(mktemp -d)
  refresh_runtime_paths

  print_banner

  check_root
  check_deps
  normalize_web_ui_mode
  normalize_mirror
  prompt_web_ui_mode
  detect_arch
  detect_latest_version
  check_existing_installation

  log_info "安装目录: ${INSTALL_DIR}"
  log_info "Core 目录: ${CORE_DIR}"
  log_info "架构:      ${ARCH_TARGET}"
  log_info "端口:      ${PORT}"
  log_info "下载源:    ${MIRROR}"

  stop_existing
  download_and_install
  setup_web_ui
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
    --web-ui)
      WEB_UI_MODE="$2"; shift 2 ;;
    --web-dir)
      WEB_DIR="$2"; shift 2 ;;
    --work-dir)
      WORK_DIR="$2"; shift 2 ;;
    --version)
      VERSION="$2"; shift 2 ;;
    --mirror)
      MIRROR="$2"; shift 2 ;;
    *)
      log_error "未知参数: $1"
      echo "用法: sudo bash linux_install.sh [--password PASS] [--port 8080] [--host ::] [--web-ui ask|with|without] [--web-dir /path] [--work-dir /path] [--version v1.0.0] [--mirror auto|cdn|github]"
      exit 1
      ;;
  esac
done

main
