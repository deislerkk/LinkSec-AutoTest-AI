# LinkSec·AutoTest AI — 私有部署源搭建说明（v3.3.1）

在自有公网服务器（如 134.175.131.134）上搭建**长期源码部署源**，取代对境外公共源的依赖，实现「一键更新」。

## 目录结构

```
deploy-server/
├── README.md            # 本说明
├── gen_latest.py        # 服务端：生成 latest.json 版本清单
├── nginx-deploy.conf    # 服务端：Nginx 只读静态托管配置
└── update.sh            # 客户端：下载/校验/备份/回滚更新脚本
（latest.json 由 gen_latest.py 在服务器端生成，不在部署包内分发）
```

## 一、服务端搭建（一次性，约 5 分钟）

```bash
# 1. 创建部署包目录并放入部署包 + 变更日志
sudo mkdir -p /srv/linksec-deploy
sudo cp LinkSec_AutoTest_AI_v3.3.1.zip CHANGELOG.md /srv/linksec-deploy/

# 2. 生成版本清单
sudo python3 gen_latest.py --dir /srv/linksec-deploy \
    --version v3.3.1 \
    --file LinkSec_AutoTest_AI_v3.3.1.zip \
    --base-url https://134.175.131.134:8443 \
    --note "私有部署源上线"

# 3. 部署 Nginx 配置（只读托管，8443 端口）
sudo cp nginx-deploy.conf /etc/nginx/conf.d/linksec-deploy.conf
# 按文件内注释配置证书路径后：
sudo nginx -t && sudo nginx -s reload

# 4. 验证
curl -sk https://134.175.131.134:8443/latest.json
```

每次发布新版本：上传新 zip + 更新 CHANGELOG.md → 重新运行 `gen_latest.py`（覆盖 latest.json）即可，**无需重启 Nginx**。

> 说明：使用 8443 独立端口，规避云商对未备案域名 80/443 的拦截；Nginx 配置只放行
> `latest.json / CHANGELOG.md / LinkSec_AutoTest_AI_*.zip` 三类文件，其余路径一律拒绝。
> 若新版本文件名采用新命名，需同步扩展配置中的正则。

## 二、客户端更新（Kali / 任意 Linux）

```bash
# 检查新版本
./update.sh --check

# 更新到最新版（自动备份旧版本，SHA256 校验失败或解压失败自动回滚）
./update.sh

# 强制重装 / 回滚
./update.sh --force
./update.sh --rollback
```

环境变量可覆盖：`LINKSEC_UPDATE_URL`（部署源地址）、`LINKSEC_INSTALL_DIR`（安装目录）。

更新完成后按原部署方式重启：
- Docker：`cd <安装目录> && sudo docker compose up -d --build`
- Kali 直接部署：重启 gunicorn/systemd 服务

## 三、安全建议

1. 部署源与业务应用分离（独立端口/目录），互不影响。
2. Nginx 仅开放 GET、禁目录浏览、单独访问日志审计。
3. 证书有效期监控（自签证书建议用内部 CA 或按年续签）。
4. 部署包发布前在服务器本地核对 SHA256，防止被篡改。
5. 云服务器安全组仅放行 8443（与业务端口），其余端口按需最小化开放。
