#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# LinkSec·AutoTest AI — 客户端更新脚本（v3.3.1 私有部署源）
#
# 功能：读取部署源 latest.json → 版本比对 → 下载 → SHA256 校验 → 备份 → 解压 → 回滚
#
# 用法：
#   ./update.sh                 # 检查并更新到最新版
#   ./update.sh --check         # 仅检查新版本
#   ./update.sh --force         # 强制重新安装当前版本
#   ./update.sh --rollback      # 回滚到上一次备份
#
# 环境变量：
#   LINKSEC_UPDATE_URL  部署源地址（默认 https://134.175.131.134:8443）
#   LINKSEC_INSTALL_DIR 安装目录（默认脚本所在目录的上级目录，即包含 linksec/ 的位置）
# ─────────────────────────────────────────────────────────────────────────────
set -u
BASE_URL="${LINKSEC_UPDATE_URL:-https://134.175.131.134:8443}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="${LINKSEC_INSTALL_DIR:-$(dirname "$SCRIPT_DIR")}"
APP_DIR="$INSTALL_DIR/linksec"
VERSION_FILE="$INSTALL_DIR/.linksec_version"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

log() { echo "[update] $*"; }
die() { echo "[update] 错误：$*" >&2; exit 1; }

json_get() { python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))"; }

case "${1:-}" in
  --check) CHECK_ONLY=1 ;;
  --force) FORCE=1 ;;
  --rollback) ROLLBACK=1 ;;
  *) CHECK_ONLY=0; FORCE=0 ;;
esac

# ── 回滚 ─────────────────────────────────────────────────────────────────────
if [ "${ROLLBACK:-0}" = "1" ]; then
  LATEST_BAK=$(ls -d "$INSTALL_DIR"/linksec.bak.* 2>/dev/null | sort | tail -1)
  [ -z "$LATEST_BAK" ] && die "没有可用备份"
  rm -rf "$APP_DIR"
  mv "$LATEST_BAK" "$APP_DIR"
  log "已回滚到 $(basename "$LATEST_BAK")"
  exit 0
fi

# ── 获取远端版本清单 ────────────────────────────────────────────────────────
log "获取版本清单：$BASE_URL/latest.json"
MANIFEST=$(curl -sk -m 15 "$BASE_URL/latest.json") || die "无法连接部署源"
REMOTE_VER=$(echo "$MANIFEST" | json_get version)
REMOTE_FILE=$(echo "$MANIFEST" | json_get file)
REMOTE_SHA=$(echo "$MANIFEST" | json_get sha256)
[ -n "$REMOTE_VER" ] && [ -n "$REMOTE_FILE" ] || die "latest.json 格式错误"

LOCAL_VER=$(cat "$VERSION_FILE" 2>/dev/null || echo "未安装")

if [ "$LOCAL_VER" = "$REMOTE_VER" ] && [ "${FORCE:-0}" = "0" ]; then
  log "已是最新版本：$REMOTE_VER（本地 $LOCAL_VER）"
  exit 0
fi

if [ "${CHECK_ONLY:-0}" = "1" ]; then
  log "发现新版本：$REMOTE_VER（本地 $LOCAL_VER）"
  echo "$MANIFEST" | python3 -c "import sys,json; d=json.load(sys.stdin); print('  文件:',d['file'],'| 大小:',d['size'],'B | 更新:',d.get('updated_at'),'| 说明:',d.get('note',''))"
  exit 0
fi

# ── 下载并校验 ──────────────────────────────────────────────────────────────
URL=$(echo "$MANIFEST" | json_get url)
[ -n "$URL" ] || URL="$BASE_URL/$REMOTE_FILE"
log "下载 $URL"
curl -sk -m 300 -o "$TMP_DIR/$REMOTE_FILE" "$URL" || die "下载失败"

ACTUAL_SHA=$(sha256sum "$TMP_DIR/$REMOTE_FILE" | cut -d' ' -f1)
if [ "$ACTUAL_SHA" != "$REMOTE_SHA" ]; then
  die "SHA256 校验失败：期望 $REMOTE_SHA，实际 $ACTUAL_SHA"
fi
log "SHA256 校验通过"

# ── 备份旧版本 → 解压新版本 → 写入版本号 ────────────────────────────────────
STAMP=$(date +%Y%m%d%H%M%S)
HAD_OLD=0
if [ -d "$APP_DIR" ]; then
  mv "$APP_DIR" "$INSTALL_DIR/linksec.bak.$STAMP"
  HAD_OLD=1
  log "已备份旧版本 → linksec.bak.$STAMP"
fi

mkdir -p "$APP_DIR"
if ! unzip -qo "$TMP_DIR/$REMOTE_FILE" -d "$APP_DIR"; then
  # 解压失败：恢复备份
  rm -rf "$APP_DIR"
  [ "$HAD_OLD" = "1" ] && mv "$INSTALL_DIR/linksec.bak.$STAMP" "$APP_DIR"
  die "解压失败，已回滚"
fi
# 解压后可能存在双层目录（包内为 linksec/...），自动抬升一层
if [ -d "$APP_DIR/linksec" ]; then
  rm -rf "$APP_DIR.new"
  mv "$APP_DIR/linksec" "$APP_DIR.new"
  rm -rf "$APP_DIR"
  mv "$APP_DIR.new" "$APP_DIR"
fi

echo "$REMOTE_VER" > "$VERSION_FILE"
log "更新完成：$LOCAL_VER → $REMOTE_VER"
log "安装目录：$APP_DIR"
[ "$HAD_OLD" = "1" ] && log "旧版本保留在 linksec.bak.$STAMP，可执行 ./update.sh --rollback 回滚"
log "提示：如使用 Docker 部署，请在安装目录执行 sudo docker compose up -d --build；Kali 直接部署请重启后端进程。"
