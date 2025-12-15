#!/usr/bin/env bash
# =============================================================
# VPS Xray Lite 一键部署脚本
# 特性：TLS(acme.sh) / Reality / WS / gRPC / 多入站
#      随机端口 / 防扫 / 轻量 Web 管理页
# 适用：Debian 10+/Ubuntu 20+
# =============================================================
set -e

### 基础变量
XRAY_BIN="/usr/local/bin/xray"
XRAY_DIR="/etc/xray"
CONF="$XRAY_DIR/config.json"
WEB_DIR="/opt/xray-web"
WEB_PORT=12789
ACME_HOME="$HOME/.acme.sh"

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; PLAIN='\033[0m'

log(){ echo -e "${GREEN}[+]${PLAIN} $1"; }
warn(){ echo -e "${YELLOW}[!]${PLAIN} $1"; }
err(){ echo -e "${RED}[x]${PLAIN} $1"; exit 1; }

check_root(){ [[ $EUID -eq 0 ]] || err "请使用 root 运行"; }

rand_port(){ shuf -i20000-60000 -n1; }

install_base(){
  log "安装依赖"
  apt update -y
  apt install -y curl wget unzip socat cron jq
}

install_xray(){
  log "安装 Xray"
  bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)
  mkdir -p "$XRAY_DIR"
}

install_acme(){
  log "安装 acme.sh"
  curl https://get.acme.sh | sh
}

issue_cert(){
  read -rp "请输入域名(已解析到本机): " DOMAIN
  read -rp "邮箱(可随意): " EMAIL
  $ACME_HOME/acme.sh --register-account -m "$EMAIL"
  $ACME_HOME/acme.sh --issue --standalone -d "$DOMAIN"
  mkdir -p "$XRAY_DIR/cert"
  $ACME_HOME/acme.sh --install-cert -d "$DOMAIN" \
    --key-file       "$XRAY_DIR/cert/key.pem" \
    --fullchain-file "$XRAY_DIR/cert/cert.pem"
}

make_config(){
  log "生成 Xray 配置（含 TLS fallback + 防扫）"

  PORT_TLS=$(rand_port)
  PORT_WS=$(rand_port)
  PORT_GRPC=$(rand_port)

  UUID=$(cat /proc/sys/kernel/random/uuid)
  WS_PATH="/$(tr -dc a-z0-9 </dev/urandom | head -c8)"
  GRPC_SVC="grpc$(tr -dc a-z0-9 </dev/urandom | head -c6)"

  cat > "$CONF" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {
      "port": $PORT_TLS,
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "$UUID","flow": "xtls-rprx-vision"}],
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
            {"dest": 80},
            {"alpn": "h2", "dest": 8080}
          ]
        }
      }
    },
    {
      "port": $PORT_WS,
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "$UUID"}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {"path": "$WS_PATH"}
      }
    },
    {
      "port": $PORT_GRPC,
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "$UUID"}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {"serviceName": "$GRPC_SVC"}
      }
    }
  ],
  "outbounds": [{"protocol": "freedom"}]
}
EOF

  cat > "$XRAY_DIR/info.txt" <<EOF
===== 节点信息 =====
协议: VLESS + REALITY
地址: $DOMAIN
端口: $PORT_REALITY
UUID: $UUID
SNI: $REALITY_SNI
PublicKey: $REALITY_PUBLIC
ShortID: $REALITY_SID

VLESS+REALITY 链接:
vless://$UUID@$DOMAIN:$PORT_REALITY?encryption=none&security=reality&sni=$REALITY_SNI&fp=chrome&pbk=$REALITY_PUBLIC&sid=$REALITY_SID&type=tcp#VLESS-REALITY

--- 其他入站 ---
TLS端口: $PORT_TLS
WS端口:  $PORT_WS
WS路径:  $WS_PATH
gRPC端口:$PORT_GRPC
gRPC服务:$GRPC_SVC
EOF
}
EOF

  cat > "$XRAY_DIR/info.txt" <<EOF
TLS端口: $PORT_TLS
WS端口:  $PORT_WS
WS路径:  $WS_PATH
gRPC端口:$PORT_GRPC
gRPC服务:$GRPC_SVC
UUID:    $UUID
EOF
}

install_service(){
  log "配置 systemd"
  cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target

[Service]
ExecStart=$XRAY_BIN -config $CONF
Restart=always

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable xray
  systemctl restart xray
}

install_web(){
  log "安装轻量 Web 管理页"
  mkdir -p "$WEB_DIR"
  cat > "$WEB_DIR/index.html" <<EOF
<!DOCTYPE html><html><body>
<h2>Xray Lite Panel</h2>
<pre id="info"></pre>
<script>
fetch('/info').then(r=>r.text()).then(t=>info.innerText=t)
</script>
</body></html>
EOF

  cat > "$WEB_DIR/server.py" <<EOF
from http.server import BaseHTTPRequestHandler,HTTPServer
class H(BaseHTTPRequestHandler):
  def do_GET(self):
    if self.path=='/info':
      self.send_response(200);self.end_headers()
      self.wfile.write(open('/etc/xray/info.txt','rb').read())
    else:
      self.send_response(200);self.end_headers()
      self.wfile.write(open('index.html','rb').read())
HTTPServer(('0.0.0.0',$WEB_PORT),H).serve_forever()
EOF

  nohup python3 "$WEB_DIR/server.py" >/dev/null 2>&1 &
}

show_menu(){
  clear
  echo "==== VPS Xray Lite 一键脚本 ===="
  echo "1. 全新安装"
  echo "2. 重新生成入站"
  echo "3. 查看节点信息"
  echo "4. 卸载"
  echo "0. 退出"
}

uninstall(){
  systemctl stop xray || true
  rm -rf "$XRAY_DIR" "$WEB_DIR" /etc/systemd/system/xray.service
  systemctl daemon-reload
  log "已卸载"
}

check_root
while true; do
  show_menu
  read -rp "选择: " n
  case $n in
    1) install_base; install_xray; install_acme; issue_cert; make_config; install_service; install_web; log "完成";;
    2) make_config; systemctl restart xray; log "已重新生成";;
    3) cat "$XRAY_DIR/info.txt";;
    4) uninstall;;
    0) exit 0;;
  esac
  read -rp "回车继续..."
done


# =========================
# 下一步扩展：TUIC v5 + fallback 防扫（已集成示例）
# 说明：以下为可直接合并到 make_config() 的示例片段
# =========================

# ---- TUIC v5 入站（UDP，QUIC）示例 ----
# 依赖：Xray v1.8+（含 tuic 协议）
# 端口需放行 UDP
#
# {
#   "port": $PORT_TUIC5,
#   "protocol": "tuic",
#   "settings": {
#     "clients": [{"uuid": "$UUID"}],
#     "congestion_control": "bbr",
#     "udp_relay_mode": "native",
#     "zero_rtt_handshake": true,
#     "heartbeat": 10000
#   },
#   "streamSettings": {
#     "security": "tls",
#     "tlsSettings": {
#       "alpn": ["h3"],
#       "certificates": [{
#         "certificateFile": "$XRAY_DIR/cert/cert.pem",
#         "keyFile": "$XRAY_DIR/cert/key.pem"
#       }]
#     }
#   }
# }

# ---- TLS fallback + 防扫 ----
# 思路：真实 TLS 站点 + fallback 到 80/WEB，未知 SNI 直接丢弃
# 在 vless+tls 入站的 tlsSettings 中加入 fallbacks
#
# "tlsSettings": {
#   "serverName": "$DOMAIN",
#   "minVersion": "1.3",
#   "certificates": [{
#     "certificateFile": "$XRAY_DIR/cert/cert.pem",
#     "keyFile": "$XRAY_DIR/cert/key.pem"
#   }],
#   "fallbacks": [
#     {"dest": 80},
#     {"alpn": "h2", "dest": 8080},
#     {"path": "/", "dest": 80}
#   ]
# }
#
# 防扫建议：
# 1) Reality / TLS 使用随机高端口
# 2) WS/gRPC 随机 path/serviceName
# 3) 配合 iptables：
#    iptables -A INPUT -p tcp --dport $PORT_TLS -m string --string "GET" --algo bm -j DROP
# 4) 仅允许 Cloudflare / 自有 IP 访问管理 Web
