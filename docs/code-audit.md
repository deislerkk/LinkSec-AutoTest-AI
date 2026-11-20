# 代码审计报告（v3.6.0-UI5）

审计日期：2026-11-20 · 范围：backend/*.py、frontend/public/index.html、docker/*、docker-compose.yml、deploy-server/*

## 一、总览

| 严重度 | 数量 | 结论 |
|--------|------|------|
| 高危 High | 3 | 存储型 XSS、SSRF、命令执行边界缺失 |
| 中危 Medium | 4 | 无 TLS、CORS 全开、默认口令、viewer 读权限过宽 |
| 低危 Low | 4 | 依赖版本旧、改密后旧 token 有效、root 运行、token 入日志 |
| 代码质量 | 4 | 未使用 import、未使用变量等 |

静态分析：全部 `.py` 通过 `py_compile`；pyflakes 报 4 处未使用项；无 eval/pickle、无硬编码密钥、安全随机数用 `secrets`（合格）。

## 二、高危（建议优先修复）

### H1 · 存储型 XSS（前端）
- 位置：`frontend/public/index.html` 所有列表/详情渲染。
- 问题：项目名、漏洞名、主机、资产值、组件名、扫描目标等用户可控字段经 `${...}` 直接拼进 `innerHTML`，全程无转义。
- 危害：任意 operator 写入 `<img src=x onerror=...>` 即可执行脚本，窃取他人 localStorage 中的 Bearer Token（越权到 admin），或劫持界面。
- 修复：新增 `esc()` 转义函数，对所有插值统一 `esc()` 包裹；或改 `textContent`/DOM 构建。

### H2 · SSRF（机器人 webhook）
- 位置：`backend/bots.py send_to_channel`、`backend/app.py send_notification`。
- 问题：webhook URL 服务端直接 `urlopen`，未校验协议与目标地址。
- 危害：可指向 `http://169.254.169.254/`（云元数据）、`http://127.0.0.1:5000` 等内网地址，探测/攻击内部服务或泄露元数据。
- 修复：仅允许 `https`（内网自建场景可配置白名单）；解析后拒绝私网/回环/链路本地 IP。

### H3 · 命令执行边界缺失
- 位置：`backend/app.py webshell_exec`（无任何拦截）、`terminal_exec`/`terminal_stream`（拦截清单可绕过，如 `rm -rf  /`、`rm -rf /*`）。
- 说明：终端/WebShell 是产品功能，本身即"命令执行"，但当前边界依赖"登录 + 审批"，且默认口令 + 公网暴露会放大为 RCE-as-a-service。
- 修复：容器以最小权限运行（非 root + 仅 NET_RAW capability）；审批模式默认开启；文档明确"仅内网受控环境"；删除可绕过的伪拦截清单，改为真实的允许/拒绝策略或标注为管理员可信功能。

## 三、中危

| 编号 | 位置 | 问题 | 建议 |
|------|------|------|------|
| M1 | `docker/nginx*.conf` | 仅 listen 80，无 TLS；登录凭证明文传输 | 加 HTTPS（正式证书或自签），或强制内网部署 |
| M2 | `backend/app.py` `CORS(app)` | 默认允许所有来源跨域 | 限制 `origins` 为实际前端地址 |
| M3 | `backend/rbac.py` | 默认 admin/admin123；auth_enabled 可被关闭后全裸奔 | 已有强制改密（保留）；文档警示勿关闭 auth 于公网 |
| M4 | 鉴权门 GET 全放行 | viewer 可读 /api/users（含 last_login）、/api/audit 全量、/api/assets 导出 | 按需收紧 viewer 可读范围 |

## 四、低危 / 代码质量

| 编号 | 位置 | 问题 | 建议 |
|------|------|------|------|
| L1 | `requirements.txt` | anthropic==0.28.0、gunicorn==22.0.0、flask-cors==4.0.1 版本旧 | 升级到当前稳定版并核对 breaking changes |
| L2 | `rbac.change_password` | 改密后既有 token 不失效 | 改密时吊销该用户全部 token |
| L3 | `backend/Dockerfile` | 后端以 root 运行（nmap 需要） | 非 root 用户 + `setcap cap_net_raw+ep` 替代 |
| L4 | SSE 鉴权 | scans stream 用 `?token=` 传递，token 会进 access 日志 | 短期令牌或日志脱敏 |
| Q1 | app.py / approvals.py / scanner.py | 未使用 import（os/time）与未使用变量 | 清理 |

## 五、结论

- 架构与功能设计合理，治理框架（RBAC/审批/审计/持久化）在同类中较完整，v3.5 已修复一批 P0。
- 剩余主要风险集中在**前端 XSS 与 SSRF 两个高危**，以及**终端命令执行的产品边界**（属设计内，但需运维约束）。
- 建议下一完整迭代 `v3.7.0` 落地：H1（esc 转义）、H2（SSRF 校验）、H3（最小权限+审批默认开）、M1/M2（TLS+CORS）、L2（token 吊销）。
