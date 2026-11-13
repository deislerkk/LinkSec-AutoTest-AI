# -*- coding: utf-8 -*-
"""
LinkSec·AutoTest AI — latest.json 版本清单生成脚本（v3.3.1 私有部署源）

用法（在部署包目录执行）：
    python3 gen_latest.py \
        --dir /srv/linksec-deploy \
        --version v3.3.1 \
        --file LinkSec_AutoTest_AI_v3.3.1.zip \
        --base-url https://134.175.131.134:8443 \
        --note "补齐功能 + 私有部署源"

生成 latest.json（客户端 update.sh 读取）：
{
  "product": "LinkSec·AutoTest AI",
  "version": "v3.3.1",
  "updated_at": "2026-11-13T12:00:00+08:00",
  "file": "LinkSec_AutoTest_AI_v3.3.1.zip",
  "url": "https://134.175.131.134:8443/LinkSec_AutoTest_AI_v3.3.1.zip",
  "sha256": "...",
  "size": 12345,
  "note": "..."
}
"""
import argparse
import datetime
import hashlib
import json
import os


def sha256(path, blocksize=1 << 20):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(blocksize), b''):
            h.update(block)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description='生成 LinkSec 部署源 latest.json')
    ap.add_argument('--dir', default='.', help='部署包所在目录')
    ap.add_argument('--version', required=True, help='版本标记，如 v3.3.1')
    ap.add_argument('--file', required=True, help='主部署包文件名（.zip）')
    ap.add_argument('--base-url', default='https://134.175.131.134:8443',
                    help='下载基础地址（部署源服务器）')
    ap.add_argument('--note', default='', help='版本说明')
    ap.add_argument('--changelog', default='CHANGELOG.md', help='变更日志文件名')
    args = ap.parse_args()

    fp = os.path.join(args.dir, args.file)
    if not os.path.isfile(fp):
        raise SystemExit(f'错误：找不到部署包 {fp}')

    tz8 = datetime.timezone(datetime.timedelta(hours=8))
    manifest = {
        'product': 'LinkSec·AutoTest AI',
        'version': args.version,
        'updated_at': datetime.datetime.now(tz8).isoformat(timespec='seconds'),
        'file': args.file,
        'url': f"{args.base_url.rstrip('/')}/{args.file}",
        'sha256': sha256(fp),
        'size': os.path.getsize(fp),
        'note': args.note,
    }
    cl = os.path.join(args.dir, args.changelog)
    if os.path.isfile(cl):
        manifest['changelog_url'] = f"{args.base_url.rstrip('/')}/{args.changelog}"

    out = os.path.join(args.dir, 'latest.json')
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print(f'已生成 {out}')
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
