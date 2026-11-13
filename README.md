# LinkSec·AutoTest AI
## 自动化渗透测试平台 — Kali Linux 部署指南

> **重要声明**：本平台仅供授权渗透测试使用。请确保已取得目标系统的书面授权，非法扫描可能违反法律法规。

---

## 一、项目结构

```
linksec/
├── backend/
│   ├── app.py              # Flask REST API
│   ├── scanner.py          # 真实扫描引擎（对接 Kali 工具链）
│   ├── ai_analyst.py       # Claude AI 分析模块
│   ├── requirements.txt
│   └── Dockerfile          # 基于 kalilinux/kali-rolling 镜像
├── frontend/
│   ├── public/index.html   # 全中文单页前端
│   └── Dockerfile
├── docker/
│   ├── nginx.conf          # Docker 部署配置
│   └── nginx-local.conf    # Kali 本机直接部署配置
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## 二、方式一：直接在 Kali Linux 上部署（推荐）

### 前置要求
- Kali Linux 2023.x 或更新版本
- Python 3.10+
- root 权限（nmap SYN 扫描需要）

### 步骤

```bash
# 1. 安装工具链（Kali 通常已自带大部分）
sudo apt update && sudo apt install -y \
    nmap masscan nikto hydra enum4linux whatweb \
    gobuster smbclient curl nuclei python3-pip nginx

# 2. 更新 nuclei 模板
nuclei -update-templates

# 3. 安装 Python 依赖
cd linksec/backend
pip3 install -r requirements.txt --break-system-packages

# 4. 配置环境变量（可选）
cp ../.env.example ../.env
# 编辑 .env 填入 ANTHROPIC_API_KEY

# 5. 启动后端（需要 root 以使用原始套接字）
sudo python3 app.py
# 或生产模式：
sudo gunicorn --bind 0.0.0.0:5000 --workers 2 --threads 4 --timeout 600 app:app

# 6. 部署前端
sudo cp frontend/public/index.html /var/www/linksec/
sudo cp docker/nginx-local.conf /etc/nginx/conf.d/linksec.conf
sudo nginx -s reload

# 7. 访问平台
# http://localhost
```

---

## 三、方式二：Docker 部署

### 前置要求
- Docker 20.x+
- Docker Compose 2.x+
- 运行 Docker 的宿主机需要 root/sudo

```bash
# 1. 复制环境变量
cp .env.example .env
# 可选：填入 ANTHROPIC_API_KEY

# 2. 构建并启动（首次构建约 5-10 分钟，需拉取 Kali 镜像）
sudo docker compose up -d --build

# 3. 访问
# http://localhost
```

> **注意**：Docker 容器使用 `network_mode: host` 和 `NET_RAW` 能力，
> 确保 nmap SYN 扫描可以正常工作。

---

## 四、工具链说明

| 工具 | 作用 | 扫描阶段 |
|------|------|---------|
| `nmap` | 主机发现、端口扫描、服务识别、NSE 漏洞脚本 | discovery / port_scan / vuln_scan |
| `masscan` | 大规模高速端口扫描 | port_scan（激进模式） |
| `nikto` | Web 服务器漏洞扫描 | web_scan |
| `whatweb` | Web 应用指纹识别 | web_scan |
| `gobuster` | 目录 / 子域名枚举 | web_scan |
| `nuclei` | 基于模板的漏洞扫描（CVE / 配置问题） | vuln_scan |
| `enum4linux` | SMB / NetBIOS 服务枚举 | service_enum |
| `hydra` | 多协议弱口令爆破（SSH/FTP/RDP…） | brute_force（激进模式） |
| `smbclient` | SMB 连接测试 | service_enum |

平台启动时自动检测工具可用性，未安装的工具对应阶段会自动跳过。

---

## 五、扫描配置说明

| 配置 | 阶段 | 说明 |
|------|------|------|
| 🔍 快速侦察 | 主机发现 + 端口扫描 | 快速了解目标暴露面 |
| ⚔️ 全面渗透 | 全阶段（除爆破）| 推荐日常使用 |
| 💀 激进模式 | 全阶段含弱口令爆破 | 完整渗透测试 |
| 🕵️ 隐匿模式 | 低速慢扫，规避检测 | 对抗 IDS 场景 |
| 🌐 Web应用审计 | 专注 HTTP/HTTPS 服务 | Web 应用专项 |

---

## 六、AI 分析配置

| 模式 | 配置 | 说明 |
|------|------|------|
| 模拟模式（默认） | 无需配置 | 内置预设分析，无需联网 |
| 真实 AI 模式 | `ANTHROPIC_API_KEY=sk-ant-…` | 调用 Claude claude-sonnet-4，实时分析攻击链 |

---

## 七、API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/api/health` | 健康检查 + 工具可用性 |
| GET  | `/api/dashboard` | 面板统计（含工具状态） |
| GET  | `/api/scans` | 扫描任务列表 |
| POST | `/api/scans` | 创建扫描 `{target, profile}` |
| GET  | `/api/scans/:id` | 扫描详情 |
| POST | `/api/scans/:id/stop` | 停止扫描 |
| GET  | `/api/scans/:id/stream` | SSE 实时日志 |
| GET  | `/api/vulnerabilities` | 漏洞列表（支持 severity/scan_id 过滤） |
| POST | `/api/ai/analyze` | AI 分析 `{prompt, context}` |
| POST | `/api/ai/report/:id` | 生成渗透报告 |

---

## 八、v3.3 扩展功能（补齐）

> v3.3 在 v3.2.1 基础上补齐以下能力，代码位于 `backend/ext_v3.py` 及新增模块。
> 未包含任何目标域名/网站拦截（如政府域名保护）功能。

### 8.1 功能总览

| 模块 | 说明 | 关键接口 |
|------|------|---------|
| 资产管理 | 域名/IP/端口/服务统一归档、自动去重、合并、CSV/JSON 导入导出、扫描覆盖跟踪、漏洞关联 | `/api/assets*` |
| 平台 RBAC | 多用户、角色（admin/operator/viewer）、登录令牌、按资源鉴权 | `/api/auth/*` `/api/users` `/api/roles` |
| 人机协同审批 | 高危操作（C2 指令/WebShell 执行/终端命令/技能执行/Payload 生成）审批模式，决策留痕、通过后自动执行 | `/api/approvals*` |
| 机器人接入 | 企业微信/钉钉/飞书/Slack/Telegram/QQ/通用 Webhook 通道管理、测试发送、群发 | `/api/bots/*` |
| SQLite 持久化 | 全量存储快照落盘（默认 `backend/data/linksec.db`），启动恢复 + 定时自动保存 | `/api/storage/info` |
| 漏洞状态流转 | detected→confirmed→exploited→remediated 状态机 | `POST /api/vulnerabilities/:id/status` |
| 攻击链增强 | 图谱数据（nodes/edges）、步骤追加与回放数据 | `/api/chains/:id/graph` `/api/chains/:id/steps` |
| AI 多智能体编排 | single / deep / plan-execute / supervisor 四种编排模式 | `POST /api/ai/orchestrate` |
| 报告导出 | 渗透报告 Markdown / HTML 文件下载 | `GET /api/ai/report/:id/export` |

### 8.2 登录与权限

- 首次启动自动创建默认管理员：`admin / admin123`，登录后请立即修改密码。
- 角色权限：`admin` 全部权限；`operator` 安全运营读写；`viewer` 只读。
- 所有 `/api/*` 接口（除 `/api/health` 与 `/api/auth/login`）默认要求登录
  （`Authorization: Bearer <token>` 或 SSE 用 `?token=`）。
- 如需关闭登录保护：`PUT /api/settings` 设置 `{"auth_enabled": false}`。

### 8.3 人机协同审批

- 默认关闭；开启：`PUT /api/settings` 设置 `{"approval_mode": true}`。
- 开启后，非 admin 角色执行高危操作会被拦截并生成审批单（202 返回 `approval_id`）。
- 审批人在「审批中心」批准后，系统以审批人身份自动回放执行原请求，结果回写审批单；
  拒绝则操作不执行。全部决策写入审计日志。

### 8.4 SQLite 持久化

- 路径由环境变量 `LINKSEC_DB` 指定（默认 `backend/data/linksec.db`）。
- 所有内存存储（扫描、漏洞、项目、攻击链、C2、WebShell、知识库、技能包、任务、
  审计、通知、资产、用户、角色、审批单、机器人通道）每 10 秒自动快照落盘，
  重启后自动恢复。
- Docker 部署建议为 `backend` 挂载持久卷以保存 `data/` 目录。

---

## 八点五、v3.4 Token 用量统计（按单个任务 / 单次对话）

- 维度：**单个任务**（AI 分析任务、扫描任务 AI 阶段与报告、技能执行、攻击链分析）与**单次对话**（/api/ai/analyze 与 /api/ai/orchestrate 按 conversation_id 聚合），非全局汇总。
- 计数：模拟模式为启发式估算（CJK 字符 1:1、英文单词 ×1.3），真实 AI 模式使用 API 返回的精确 usage。
- 接口：`GET /api/ai/tokens?scope=conversation|task`（按单个对话/任务聚合列表）、`GET /api/ai/tokens/<id>`（单条明细）、`GET /api/ai/tokens/stats`（维度统计）。
- 前端：「AI 分析」页单次调用后展示本次输入/输出/合计 Token；「Token 用量」页按对话/任务双维度查看，点击行查看逐条明细。

---

## 九、迭代与版本标记约定

| 标记形式 | 含义 |
|----------|------|
| `vX.Y.Z` | 完整迭代：后端接口 / 功能 / 部署 / 文档变更 |
| `vX.Y.Z-UI<n>` | **纯 UI / 前端迭代**（特殊标记号）：仅界面与演示页，不改后端与部署 |

每次迭代记录见 [CHANGELOG.md](CHANGELOG.md)。交付文件名与页面内版本号同步携带标记号。

---

## 十、私有部署源（v3.3.1）

可在自有公网服务器搭建长期源码部署源，取代境外公共源下载依赖：

- 服务端：`deploy-server/gen_latest.py` 生成 `latest.json` 版本清单；`deploy-server/nginx-deploy.conf` 提供 8443 只读静态托管（仅放行清单/日志/部署包）
- 客户端：`deploy-server/update.sh --check|--force|--rollback` 实现版本比对、SHA256 校验、自动备份与失败回滚

详细步骤见 [deploy-server/README.md](deploy-server/README.md)。

---

*LinkSec·AutoTest AI v3.4.0 — 仅供合法授权渗透测试使用*
