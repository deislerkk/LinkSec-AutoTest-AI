# Ubuntu 测试版部署（v3.8.0-beta.1）

本测试版适配 Ubuntu 22.04/24.04，并与正式版 v3.7.0 同机共存：

| 实例 | 前端 | 后端 | 数据/容器/服务 |
|------|------|------|----------------|
| 正式版 v3.7.0 | 80 | 5000 | `linksec-*` |
| 测试版 v3.8.0-beta.1 | **18080** | **127.0.0.1:15000** | `linksec-test-*` / `linksec-test.service` |

## 方式一：Docker Compose（推荐）

```bash
cp .env.test.example .env.test
# 按需填写 ANTHROPIC_API_KEY
sudo docker compose -f docker-compose.test.yml --env-file .env.test up -d --build
sudo docker compose -f docker-compose.test.yml ps
curl http://127.0.0.1:18080/api/health
```

停止/删除测试栈（不影响正式版）：

```bash
sudo docker compose -f docker-compose.test.yml down
# 如需连测试数据卷一并删除：
sudo docker compose -f docker-compose.test.yml down -v
```

访问：`http://<Ubuntu服务器IP>:18080`

## 方式二：Ubuntu 原生 systemd + Nginx

```bash
sudo bash deploy-ubuntu/install-test.sh
systemctl status linksec-test.service
curl http://127.0.0.1:15000/api/health
```

文件位置：

- 应用：`/opt/linksec-test`
- 前端：`/var/www/linksec-test`
- 数据库：`/var/lib/linksec-test/linksec-test.db`
- 环境变量：`/etc/linksec-test.env`
- systemd：`/etc/systemd/system/linksec-test.service`
- Nginx：`/etc/nginx/sites-enabled/linksec-test.conf`

运维命令：

```bash
sudo journalctl -u linksec-test -f
sudo systemctl restart linksec-test
sudo systemctl stop linksec-test       # 不影响正式版
```

## 防冲突检查

```bash
ss -lntp | grep -E ':(80|5000|18080|15000)\b'
docker ps --format 'table {{.Names}}\t{{.Ports}}'
systemctl status linksec-test --no-pager
```

预期：测试前端占用 18080，测试后端仅本机 15000；正式版端口保持不变。

## 字体与显示

测试版 UI 已提高桌面阅读字号：正文 15px、导航 13.5px、表格 12.5px、输入框 13.5px、页面标题 24px；1024px 以下自动切换紧凑布局，避免字体放大造成横向溢出。
