#!/usr/bin/env bash
# =============================================================
# Xray Lite Ultimate 一键部署脚本
# 特性：Reality / TUIC v5 / TLS Fallback / WS / gRPC / 订阅链接
# =============================================================
set -e

### 基础变量
XRAY_BIN="/usr/local/bin/xray"
XRAY_DIR="/etc/xray"
CONF="$XRAY_DIR/config.json"
WEB_DIR="/opt/xray-web"
WEB_PORT=12789
ACME_HOME="$HOME/.acme.sh"

# 颜色定义
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; PLAIN='\033[0m'
# 工具函数
log() { echo -e "${GREEN}[+]${PLAIN} $1"; }
warn() { echo -e "${YELLOW}[!]${PLAIN} $1"; }
err() { echo -e "${RED}[x]${PLAIN} $1"; exit 1; }
check_root() { [[ $EUID -eq 0 ]] || err "请使用 root 运行"; }
rand_port() { shuf -i20000-60000 -n1; }

# ------------------------------------
# 核心函数: 生成 Reality 密钥
# ------------------------------------
gen_reality_key() {
  log "生成 Reality 密钥对..."
  # 确保 xray 命令可用
  if ! command -v xray &>/dev/null; then
      err "Xray 尚未安装或不在 PATH 中，无法生成 Reality 密钥。"
  fi
  
  # 生成 X25519 密钥对
  local keys=$($XRAY_BIN x25519)
  REALITY_PRIVATE=$(echo "$keys" | grep Private | awk '{print $3}')
  REALITY_PUBLIC=$(echo "$keys" | grep Public | awk '{print $3}')
  
  # 生成 Short ID (8位 hex)
  REALITY_SID=$(tr -dc a-f0-9 </dev/urandom | head -c8)
}

# ------------------------------------
# 核心函数: 安装 / 依赖
# ------------------------------------
install_base() {
  log "安装基础依赖：curl, wget, unzip, cron, socat, jq, python3..."
  apt update -y > /dev/null
  apt install -y curl wget unzip cron socat jq python3 python3-pip qrencode > /dev/null
}

install_xray() {
  if command -v xray >/dev/null 2>&1; then
      log "Xray 已存在，跳过安装。"
  else
      log "安装 Xray..."
      bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)
  fi
  mkdir -p "$XRAY_DIR/cert"
}

install_acme() {
  if [ -d "$ACME_HOME" ]; then
      log "acme.sh 已存在，跳过安装。"
  else
      log "安装 acme.sh..."
      curl https://get.acme.sh | sh
  fi
}

issue_cert() {
  if [ -f "$XRAY_DIR/cert/cert.pem" ]; then
    warn "证书已存在，跳过申请。如需更新，请手动删除 $XRAY_DIR/cert/。"
    DOMAIN=$(grep 'serverName' "$CONF" | head -n 1 | awk -F'"' '{print $4}')
    return
  fi

  read -rp "请输入域名(必须已解析到本机IP): " DOMAIN
  read -rp "邮箱(acme.sh注册，可随意): " EMAIL
  
  if [ -z "$DOMAIN" ]; then
      err "域名不能为空！"
  fi

  log "注册 acme.sh 账户..."
  $ACME_HOME/acme.sh --register-account -m "$EMAIL" || warn "acme.sh 注册失败或已注册。"
  
  log "申请证书..."
  $ACME_HOME/acme.sh --issue --standalone -d "$DOMAIN" --keylength 2048 --log || err "证书申请失败！请检查域名解析和端口占用。"
  
  log "安装证书到 Xray 目录..."
  $ACME_HOME/acme.sh --install-cert -d "$DOMAIN" \
    --key-file "$XRAY_DIR/cert/key.pem" \
    --fullchain-file "$XRAY_DIR/cert/cert.pem"
}

# ------------------------------------
# 核心函数: 配置生成 (ALL-IN-ONE)
# ------------------------------------
make_config() {
  log "正在生成 Xray 配置和随机参数..."

  # 随机化参数
  PORT_REALITY=$(rand_port)
  PORT_TLS=$(rand_port)
  PORT_WS=$(rand_port)
  PORT_GRPC=$(rand_port)
  PORT_TUIC=$(rand_port)

  UUID=$(cat /proc/sys/kernel/random/uuid)
  
  WS_PATH="/$(tr -dc a-z0-9 </dev/urandom | head -c10)"
  GRPC_SVC="grpc$(tr -dc a-z0-9 </dev/urandom | head -c8)"
  
  # Reality 参数
  REALITY_SNI="www.cloudflare.com" # 伪装 SNI
  REALITY_DEST="www.cloudflare.com:443" # 目标网站
  gen_reality_key
  
  # TUIC 参数 (使用 UUID 作为密码)
  TUIC_PASS="$UUID"

  # 1. 生成 Xray 配置 (config.json)
  cat > "$CONF" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [

    // ===== Reality（主力，抗封最强）=====
    {
      "port": $PORT_REALITY,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "$UUID" }],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$REALITY_DEST",
          "xver": 0,
          "serverNames": ["$REALITY_SNI"],
          "privateKey": "$REALITY_PRIVATE",
          "shortIds": ["$REALITY_SID"]
        }
      }
    },

    // ===== VLESS + TLS + fallback（伪装/防扫）=====
    {
      "port": $PORT_TLS,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "$UUID", "flow": "xtls-rprx-vision" }],
        "decryption": "none"
      },
      "streamSettings": {
        "security": "tls",
        "tlsSettings": {
          "serverName": "$DOMAIN",
          "minVersion": "1.3",
          "certificates": [{
            "certificateFile": "$XRAY_DIR/cert/cert.pem",
            "keyFile": "$XRAY_DIR/cert/key.pem"
          }],
          "fallbacks": [
            { "dest": 80 }, // 非TLS/SNI 命中
            { "alpn": "h2", "dest": $WEB_PORT, "xver": 1 } // HTTP/2 命中 Web 管理页
          ]
        }
      }
    },

    // ===== WS（备用 / CDN）=====
    {
      "port": $PORT_WS,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "$UUID" }],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$WS_PATH"
        }
      }
    },

    // ===== gRPC（备用 / CDN）=====
    {
      "port": $PORT_GRPC,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "$UUID" }],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "$GRPC_SVC"
        }
      }
    },

    // ===== TUIC v5（UDP / QUIC）=====
    {
      "port": $PORT_TUIC,
      "protocol": "tuic",
      "settings": {
        "clients": [{ "uuid": "$UUID", "password": "$TUIC_PASS" }],
        "congestion_control": "bbr",
        "udp_relay_mode": "native",
        "zero_rtt_handshake": true,
        "heartbeat": 10000
      },
      "streamSettings": {
        "security": "tls",
        "tlsSettings": {
          "alpn": ["h3"],
          "certificates": [{
            "certificateFile": "$XRAY_DIR/cert/cert.pem",
            "keyFile": "$XRAY_DIR/cert/key.pem"
          }]
        }
      }
    }
  ],
  // IPv6 支持 (Reality 和 TUIC5 不做重复配置，因为它们不需要域名/证书，只需在主 inbounds 绑定 IPv6)
  // 此处仅添加一个 VLESS-TLS 的 IPv6 监听示例，实际效果依赖于 systemd 和内核配置
  "inboundsIPv6": [
    {
      "port": $PORT_TLS,
      "listen": "::",
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "$UUID", "flow": "xtls-rprx-vision" }],
        "decryption": "none"
      },
      "streamSettings": {
        "security": "tls",
        "tlsSettings": {
          "serverName": "$DOMAIN",
          "minVersion": "1.3",
          "certificates": [{
            "certificateFile": "$XRAY_DIR/cert/cert.pem",
            "keyFile": "$XRAY_DIR/cert/key.pem"
          }]
        }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom" }
  ]
}
EOF

  # 2. 生成节点分享链接
  local SERVER_IP=$(curl -s ipv4.icanhazip.com)
  
  # Reality 链接
  VLESS_REALITY_LINK="vless://${UUID}@${SERVER_IP}:${PORT_REALITY}?encryption=none&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${REALITY_SID}&type=tcp#REALITY"
  
  # TLS Vision 链接
  VLESS_TLS_LINK="vless://${UUID}@${DOMAIN}:${PORT_TLS}?encryption=none&security=tls&sni=${DOMAIN}&fp=chrome&type=tcp#VLESS-TLS"
  
  # WS 链接
  VLESS_WS_LINK="vless://${UUID}@${DOMAIN}:${PORT_WS}?encryption=none&security=none&type=ws&path=${WS_PATH}&host=${DOMAIN}#VLESS-WS"
  
  # gRPC 链接
  VLESS_GRPC_LINK="vless://${UUID}@${DOMAIN}:${PORT_GRPC}?encryption=none&security=tls&type=grpc&serviceName=${GRPC_SVC}&sni=${DOMAIN}#VLESS-gRPC"
  
  # TUIC v5 链接 (注意：客户端支持情况)
  # 使用 tuic://uuid:password@domain:port?alpn=h3&congestion_control=bbr#tag 格式
  TUIC_LINK="tuic://${UUID}:${TUIC_PASS}@${DOMAIN}:${PORT_TUIC}?alpn=h3&congestion_control=bbr&zero_rtt=true#TUIC-v5"

  # 3. 生成 Base64 订阅链接 (所有链接用换行符分隔)
  ALL_LINKS="${VLESS_REALITY_LINK}\n${VLESS_TLS_LINK}\n${VLESS_WS_LINK}\n${VLESS_GRPC_LINK}\n${TUIC_LINK}"
  SUBSCRIPTION_B64=$(echo -e "$ALL_LINKS" | base64 -w 0)

  # 4. 生成 info.txt
  cat > "$XRAY_DIR/info.txt" <<EOF
====================================
      Xray Lite 节点信息
====================================
UUID: $UUID
域名: $DOMAIN
IP: $SERVER_IP

--- Reality (主力/免证书) ---
端口: $PORT_REALITY
SNI: $REALITY_SNI
PublicKey: $REALITY_PUBLIC
ShortID: $REALITY_SID

--- VLESS + TLS Vision (Fallback) ---
端口: $PORT_TLS

--- TUIC v5 (高性能 UDP) ---
端口: $PORT_TUIC
密码: $TUIC_PASS

--- VLESS + WS (CDN) ---
端口: $PORT_WS
路径: $WS_PATH

--- VLESS + gRPC (CDN) ---
端口: $PORT_GRPC
服务名: $GRPC_SVC

====================================
      分享链接 (可直接导入)
====================================
Reality 链接:
$VLESS_REALITY_LINK

TLS-Vision 链接:
$VLESS_TLS_LINK

TUIC v5 链接:
$TUIC_LINK

====================================
      Base64 订阅链接 (全节点)
====================================
订阅链接 (复制此行导入):
$SUBSCRIPTION_B64
====================================
EOF
}

# ------------------------------------
# 核心函数: 服务管理 / 防扫 / Web
# ------------------------------------
install_service() {
  log "配置 systemd 和 iptables 防扫规则..."
  # 写入 systemd 文件
  cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target

[Service]
ExecStart=$XRAY_BIN run -config $CONF
Restart=always
# 给予 Xray 绑定低端口的权限（可选，如果不用 443 就不需要）
AmbientCapabilities=CAP_NET_BIND_SERVICE
# Reality / WS / gRPC / TUIC 需要 IPv4 + IPv6
ExecStartPre=-/sbin/ip -6 route add local ::/0 dev lo
LimitNOFILE=51200

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable xray
  systemctl restart xray
  
  # 配置 iptables 防扫
  log "配置 iptables 防扫规则..."
  # 清除旧的规则 (可选)
  iptables -D INPUT -p tcp --dport $PORT_TLS -m string --string "GET /" --algo bm -j DROP 2>/dev/null || true
  iptables -D INPUT -p tcp --dport $PORT_REALITY -j DROP 2>/dev/null || true
  iptables -D INPUT -p udp --dport $PORT_TUIC -j ACCEPT 2>/dev/null || true
  
  # 1. 阻断 HTTP 探测 TLS / Reality 端口
  iptables -A INPUT -p tcp --dport $PORT_TLS -m string --string "GET /" --algo bm -j DROP
  # 2. Reality 端口，不走任何非 Reality 的流量 (扫端口的直接丢弃，可选)
  # iptables -A INPUT -p tcp --dport $PORT_REALITY -j DROP 
  # 3. TUIC 必须放行 UDP
  iptables -A INPUT -p udp --dport $PORT_TUIC -j ACCEPT
}

install_web() {
  log "安装轻量 Web 管理页 (Python $WEB_PORT)..."
  mkdir -p "$WEB_DIR"
  
  # 写入 index.html (读取 info.txt 内容)
  cat > "$WEB_DIR/index.html" <<EOF
<!DOCTYPE html><html><body>
<h2>Xray Lite Panel</h2>
<p>管理页端口: ${WEB_PORT} (请勿暴露给外网)</p>
<pre id="info"></pre>
<script>
fetch('/info').then(r=>r.text()).then(t=>info.innerText=t)
</script>
</body></html>
EOF

  # 写入 Python 简易服务器
  cat > "$WEB_DIR/server.py" <<EOF
from http.server import BaseHTTPRequestHandler,HTTPServer
import os
import sys

class H(BaseHTTPRequestHandler):
  def do_GET(self):
    if self.path=='/info':
      self.send_response(200);self.end_headers()
      try:
          self.wfile.write(open(os.path.join('$XRAY_DIR','info.txt'),'rb').read())
      except FileNotFoundError:
          self.wfile.write(b"Node Info Not Found.")
    elif self.path=='/':
      self.send_response(200);self.end_headers()
      self.wfile.write(open(os.path.join('$WEB_DIR','index.html'),'rb').read())
    else:
      self.send_response(404);self.end_headers()

log("Starting web server on port $WEB_PORT...")
try:
    HTTPServer(('0.0.0.0',$WEB_PORT),H).serve_forever()
except Exception as e:
    log("Web Server Error: " + str(e))
    sys.exit(1)
EOF
  # 使用 nohup 后台运行 Python
  pkill -f "python3 $WEB_DIR/server.py" || true
  nohup python3 "$WEB_DIR/server.py" >/dev/null 2>&1 &
}

# ------------------------------------
# 菜单 / 主逻辑
# ------------------------------------
show_menu() {
  clear
  echo "=========================================="
  echo "      👑 Xray Lite Ultimate 一键脚本 👑     "
  echo "=========================================="
  echo " 1. 全新安装 (Reality/TLS/TUIC/WS/gRPC)"
  echo " 2. 重新生成入站 (更新链接/端口/密钥)"
  echo " 3. 查看节点信息 (info.txt / 订阅链接)"
  echo " 4. 查看 Xray 状态"
  echo " 5. 卸载全部"
  echo " 0. 退出"
  echo "=========================================="
}

uninstall() {
  log "停止并移除服务..."
  pkill -f "python3 $WEB_DIR/server.py" || true
  systemctl stop xray || true
  systemctl disable xray || true
  
  log "清理文件..."
  rm -rf "$XRAY_DIR" "$WEB_DIR" /etc/systemd/system/xray.service
  
  log "清理 iptables 规则 (需手动)"
  warn "请手动清理 iptables 规则，例如："
  warn "iptables -D INPUT -p udp --dport $PORT_TUIC -j ACCEPT"
  
  systemctl daemon-reload
  log "已完全卸载"
}

check_root
while true; do
  show_menu
  read -rp "请选择: " n
  case $n in
    1) 
      install_base
      install_xray
      install_acme
      issue_cert # 申请证书，设置 DOMAIN 变量
      make_config
      install_service
      install_web
      log "安装完成！请查看下方或 Web 面板获取链接。"
      cat "$XRAY_DIR/info.txt"
      ;;
    2) 
      if [ ! -f "$XRAY_DIR/cert/cert.pem" ]; then
          err "证书文件不存在，请先执行安装 (1)！"
      fi
      make_config
      install_service
      install_web
      log "已重新生成配置和链接，服务已重启。"
      cat "$XRAY_DIR/info.txt"
      ;;
    3) 
      if [ ! -f "$XRAY_DIR/info.txt" ]; then
          err "节点信息文件不存在，请先执行安装 (1)！"
      fi
      cat "$XRAY_DIR/info.txt"
      ;;
    4) 
      systemctl status xray --no-pager
      ;;
    5) 
      uninstall
      ;;
    0) exit 0;;
    *) echo -e "${RED}选项无效${PLAIN}";;
  esac
  read -rp "按回车键继续..."
done