#!/usr/bin/env bash
set -e

XRAY_BIN="/usr/local/bin/xray"
XRAY_DIR="/etc/xray"
CONF="$XRAY_DIR/config.json"
WEB_DIR="/opt/xray-web"
WEB_PORT=12789
ACME_HOME="$HOME/.acme.sh"

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; PLAIN='\033[0m'

log() { echo -e "${GREEN}[+]${PLAIN} $1"; }
warn() { echo -e "${YELLOW}[!]${PLAIN} $1"; }
err() { echo -e "${RED}[x]${PLAIN} $1"; exit 1; }

check_root() { [[ $EUID -eq 0 ]] || err "请使用 root 运行"; }

rand_port() { shuf -i20000-60000 -n1; }

install_base() {
  log "安装依赖"
  apt update -y
  apt install -y curl wget unzip socat cron jq python3
}

install_xray() {
  log "安装 Xray"
  bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)
  mkdir -p "$XRAY_DIR"
}

install_acme() {
  log "安装 acme.sh"
  curl https://get.acme.sh | sh
}

issue_cert() {
  read -rp "请输入域名(已解析到本机): " DOMAIN
  read -rp "邮箱(可随意): " EMAIL
  $ACME_HOME/acme.sh --register-account -m "$EMAIL"
  $ACME_HOME/acme.sh --issue --standalone -d "$DOMAIN"
  mkdir -p "$XRAY_DIR/cert"
  $ACME_HOME/acme.sh --install-cert -d "$DOMAIN" \
    --key-file "$XRAY_DIR/cert/key.pem" \
    --fullchain-file "$XRAY_DIR/cert/cert.pem"
}

make_config() {
  log "生成 Xray 配置（含 TLS fallback + 防扫）"

  PORT_TLS=$(rand_port)
  PORT_WS=$(rand_port)
  PORT_GRPC=$(rand_port)
  PORT_REALIT_
