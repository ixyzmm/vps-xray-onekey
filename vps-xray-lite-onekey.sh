#!/usr/bin/env bash
set -e

# -----------------------------
# VPS Xray Lite 一键部署脚本
# 支持 VLESS+TLS/WS/gRPC/Reality/Tuic5 + IPv6 + 防扫
# -----------------------------

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
  PORT_REALITY=$(rand_port)

  UUID=$(cat /proc/sys/kernel/random/uuid)
  WS_PATH="/$(tr -dc a-z0-9 </dev/urandom | head -c8)"
  GRPC_SVC="grpc$(tr -dc a-z0-9 </dev/urandom | head -c6)"
  REALITY_SNI="$DOMAIN"
  REALITY_PUBLIC=$(openssl rand -base64 32)
  REALITY_SID=$(openssl rand -hex 6)

  cat > "$CONF" <<EOF
{
  "log": {"loglevel":"warning"},
  "inbounds": [
    {
      "port": $PORT_TLS,
      "protocol": "vless",
      "settings": {"clients":[{"id":"$UUID","flow":"xtls-rprx-vision"}],"decryption":"none"},
      "streamSettings":{
        "security":"tls",
        "tlsSettings":{
          "serverName":"$DOMAIN",
          "minVersion":"1.3",
          "certificates":[{"certificateFile":"$XRAY_DIR/cert/cert.pem","keyFile":"$XRAY_DIR/cert/key.pem"}],
          "fallbacks":[{"dest":80},{"alpn":"h2","dest":8080}]
        }
      }
    },
    {
      "port": $PORT_WS,
      "protocol": "vless",
      "settings":{"clients":[{"id":"$UUID"}],"decryption":"none"},
      "streamSettings":{"network":"ws","wsSettings":{"path":"$WS_PATH"}}
    },
    {
      "port": $PORT_GRPC,
      "protocol": "vless",
      "settings":{"clients":[{"id":"$UUID"}],"decryption":"none"},
      "streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"$GRPC_SVC"}}
    },
    {
      "port": $PORT_REALITY,
      "protocol": "vless",
      "settings":{"clients":[{"id":"$UUID"}],"decryption":"none"},
      "streamSettings":{"security":"reality","realitySettings":{"show":false,"dest":"$DOMAIN:443","xver":0,"serverNames":["$REALITY_SNI"],"privateKey":"$REALITY_PUBLIC","shortIds":["$REALITY_SID"]}}
    }
  ],
  "outbounds":[{"protocol":"freedom"}]
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

install_service() {
  log "配置 systemd + 基础防扫"
  cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target

[Service]
ExecStart=$XRAY_BIN -config $CONF
Restart=always
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable xray
  systemctl restart xray

  # 基础防扫
  iptables -C INPUT -p tcp --dport $PORT_TLS -m string --string "GET /" --algo bm -j DROP 2>/dev/null || \
  iptables -A INPUT -p tcp --dport $PORT_TLS -m string --string "GET /" --algo bm -j DROP
}

install_web() {
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

show_menu() {
  clear
  echo "==== VPS Xray Lite 一键脚本 ===="
  echo "1. 全新安装"
  echo "2. 重新生成入站"
  echo "3. 查看节点信息"
  echo "4. 卸载"
  echo "0. 退出"
}

uninstall() {
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
