#!/usr/bin/env bash
# LinkSec·AutoTest AI v3.8.0-beta.1 — Ubuntu 22.04/24.04 原生测试版安装
# 测试前端 18080 / 后端 127.0.0.1:15000，与正式版 80/5000 同机共存。
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "请以 root 运行：sudo bash deploy-ubuntu/install-test.sh" >&2
  exit 1
fi

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR=/opt/linksec-test
WEB_DIR=/var/www/linksec-test
DATA_DIR=/var/lib/linksec-test
SERVICE_USER=linksec-test

echo "[1/8] 安装 Ubuntu 基础依赖…"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  python3 python3-venv python3-pip nginx rsync curl nmap masscan nikto hydra \
  whatweb gobuster smbclient dnsutils net-tools
# 不同 Ubuntu 版本的软件包可用性不同，以下工具尽力安装；缺失时平台自动跳过对应阶段。
for pkg in enum4linux nuclei; do
  apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1 || \
    echo "[提示] Ubuntu 源中无 $pkg，已跳过（不影响其余功能）"
done

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# 保留数据目录；应用代码覆盖更新
echo "[2/8] 安装测试版到 $APP_DIR…"
mkdir -p "$APP_DIR" "$WEB_DIR" "$DATA_DIR"
rsync -a --delete --exclude data/ --exclude __pycache__/ "$SRC_DIR/backend/" "$APP_DIR/backend/"
rsync -a --delete "$SRC_DIR/frontend/public/" "$WEB_DIR/"

python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/backend/requirements.txt"

chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR" "$DATA_DIR"
chmod -R a+rX "$WEB_DIR"

# 独立测试环境变量；首次安装创建，后续不覆盖 API Key。
echo "[3/8] 写入测试环境配置…"
if [[ ! -f /etc/linksec-test.env ]]; then
  cat >/etc/linksec-test.env <<'EOF'
ANTHROPIC_API_KEY=
LINKSEC_CORS_ORIGINS=
LINKSEC_SSRF_ALLOW_PRIVATE=
EOF
  chmod 600 /etc/linksec-test.env
fi

install -m 0644 "$SRC_DIR/deploy-ubuntu/linksec-test.service" /etc/systemd/system/linksec-test.service
install -m 0644 "$SRC_DIR/deploy-ubuntu/nginx-linksec-test.conf" /etc/nginx/sites-available/linksec-test.conf
ln -sfn /etc/nginx/sites-available/linksec-test.conf /etc/nginx/sites-enabled/linksec-test.conf

echo "[4/8] 校验 Nginx 配置…"
nginx -t

echo "[5/8] 启动测试后端（15000）…"
systemctl daemon-reload
systemctl enable --now linksec-test.service

echo "[6/8] 重载 Nginx（18080）…"
systemctl enable --now nginx
systemctl reload nginx

# 如果 UFW 已启用则放行测试前端端口。
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
  ufw allow 18080/tcp comment 'LinkSec beta test frontend' >/dev/null
fi

echo "[7/8] 健康检查…"
for _ in $(seq 1 30); do
  curl -fsS http://127.0.0.1:15000/api/health >/dev/null && break
  sleep 1
done
curl -fsS http://127.0.0.1:15000/api/health || {
  systemctl status --no-pager linksec-test.service || true
  exit 1
}

echo "[8/8] 安装完成"
echo "测试前端：http://<Ubuntu服务器IP>:18080"
echo "测试后端：127.0.0.1:15000（仅本机监听）"
echo "正式版端口 80/5000 未修改，可同机共存。"
echo "环境配置：sudo nano /etc/linksec-test.env"
