# LinkSec·AutoTest AI — 迭代记录（CHANGELOG）

## 版本标记约定

| 标记形式 | 含义 | 示例 |
|----------|------|------|
| `vX.Y.Z` | **完整迭代**：涉及后端接口 / 功能逻辑 / 部署方式 / 文档的变更 | v3.3.0 |
| `vX.Y.Z-UI<n>` | **纯 UI / 前端界面迭代**：仅界面、演示页、样式调整，不改变后端接口与部署方式（特殊标记号） | v3.3.0-UI1、v3.3.0-UI2 |

规则：

1. 每次迭代必须在本文档追加一条记录（日期、标记号、变更范围、变更摘要）。
2. 纯 UI / 前端迭代一律使用 `-UI<n>` 后缀，`<n>` 从 1 递增，不占用主版本号。
3. 交付文件名同步携带标记号，例如 `产品_v3.3.0-UI1_功能演示demo.html`。
4. 页面内 logo / 关于 / 平台信息处同步显示当前标记号。

---

## 迭代记录

### v3.6.0-UI5（2026-11-16）· 纯 UI 迭代 🎨

- 变更范围：前端界面（开机动画背景升级，不涉及后端接口与部署）
- 内容：开机层背景升级为「深绿网格+粒子」风格——深绿径向渐变底色 + 绿色细网格（中心渐隐、呼吸微光）+ canvas 自绘漂浮粒子数据流（70 颗粒子上浮漂移）；六边形 LS 字标、居中日志排版、分段进度条与音效保持不变
- 交付物：`LinkSec_AutoTest_AI_v3.6.0-UI5.zip`、`LinkSec_AutoTest_AI_v3.6.0-UI5_功能演示demo.html`

### v3.6.0-UI4（2026-11-16）· 纯 UI 迭代 🎨

- 变更范围：前端界面（开机动画音效，不涉及后端接口与部署）
- 内容：为莱茵风开机动画补充配套音效（Web Audio API 全合成，零外部音频文件，单文件离线可用）：
  - 打字滴答声（逐字符）· 自检行完成提示音 · 节点确认音 · 自检成功上行琶音 · ACCESS GRANTED 低音和弦 · 验证失败提示音
  - 新增「点击/ENTER 启动」闸门（符合浏览器自动播放策略，也是开屏交互惯例）；右上角 🔊/🔇 静音开关
- 交付物：`LinkSec_AutoTest_AI_v3.6.0-UI4.zip`、`LinkSec_AutoTest_AI_v3.6.0-UI4_功能演示demo.html`

### v3.6.0-UI3（2026-11-16）· 纯 UI 迭代 🎨

- 变更范围：前端界面（登录界面替换，不涉及后端接口与部署）
- 内容：**登录界面替换为「莱茵生命风」开机/身份验证动画**（自绘 CSS/SVG，无视频素材）：
  - 开机动画：六边形徽标 + 逐行打字自检 + 分段进度条 + 扫描线 CRT 质感
  - IDENTITY VERIFICATION 三确认节点：① 授权声明确认 → ② 环境自检（真实调用 /api/health 展示版本与工具链可用数，非伪造进度）→ ③ 身份认证（终端风凭证输入，接真实 POST /api/auth/login）
  - ACCESS GRANTED 欢迎页（用户+角色+令牌签发）→ 退场动画进入工作台
  - 支持点击节点或 ENTER 推进；退出登录后重新进入开机流程
- 说明：视觉风格参考社区流行风格，全部元素为原创绘制（六边形徽标/文案/动画），未使用任何第三方素材
- 交付物：`LinkSec_AutoTest_AI_v3.6.0-UI3.zip`、`LinkSec_AutoTest_AI_v3.6.0-UI3_功能演示demo.html`

### v3.6.0-UI2（2026-11-16）· 纯 UI 迭代 🎨

- 变更范围：前端界面（不涉及后端接口与部署）
- 内容：组件能力全面入 UI——总览面板新增「组件」统计卡片（6 卡布局）；底部状态栏新增组件计数；组件管理页新增类型筛选 Tab 与关键词搜索、点击行打开组件详情弹窗（主机实例+关联漏洞+类型/来源）；登录框新增版本徽标
- 交付物：`LinkSec_AutoTest_AI_v3.6.0-UI2.zip`、`LinkSec_AutoTest_AI_v3.6.0-UI2_功能演示demo.html`

### v3.6.0（2026-11-16）· 完整迭代 🚀

- 变更范围：后端 + 前端 + 文档
- 内容：**组件管理**——目标主机软件组件台账（Web服务器/中间件/框架/数据库/组件库/操作系统/网络设备），补全「资产 → 组件 → 漏洞/CVE」关键中间层：
  - 新增 `backend/components.py`：组件台账（名称+版本自动去重）、主机实例关联、漏洞关联、类型/关键词检索、统计
  - 扫描完成后**自动从服务指纹提取组件**（nmap service/product/version → 组件，常见服务自动分类）；支持手动提取与手动录入
  - 新接口：`GET/POST /api/components`、`/api/components/stats`、`/api/components/extract`、`GET/PUT/DELETE /api/components/:id`、`GET/POST /api/components/:id/vulns`
  - 前端新增「组件管理」页（统计卡片/类型筛选/主机实例/漏洞关联/从扫描提取）
  - 组件数据随 SQLite 持久化
- 实测：提取 4 个组件（Tomcat/MySQL/nginx/OpenSSH，自动分类正确）、重复创建去重、主机实例关联、统计全部通过

### v3.5.0（2026-11-13）· 完整迭代 🚀

- 变更范围：后端 + 前端 + 文档（安全整改）
- 内容：
  1. **P0 安全整改**：审批重放窗口关闭（一次性 exec_key + executing 状态机）、职责分离（不可自审）、admin 免审批改为可配置且默认关闭；密码哈希升级 scrypt（16 字节盐，旧哈希登录自动升级）；默认口令首次登录强制改密；webhook 密钥 API 掩码回显；终端/WebShell/通知异常信息收敛（仅审计留痕）
  2. **P1 Agent 工具调用循环**：新增 `POST /api/ai/agent`——Claude function calling（tools 协议）真实驱动扫描引擎（nmap_scan/list_assets/get_scan/create_report），模拟模式亦真实调用工具；前端新增「Agent 工具调用」面板（调用轨迹+结论+Token）；「多智能体编排」措辞修正为「多模式 AI 编排」
  3. 整改复查文档：`docs/security-remediation.md`（核验结论 + 整改记录 + P2/P3 待办清单）
- 说明：政府域名拦截（tool_guard）维持不实现（项目方决策，风险自担，见整改文档）

### v3.4.0-UI2（2026-11-13）· 纯 UI 迭代 🎨

- 变更范围：前端界面（logo 与 favicon 替换，不涉及后端接口与部署）
- 内容：顶部 logo 由文字图标替换为品牌 logo 图片（frontend/public/logo.png，512×512）；新增 favicon.ico（含 16/32 等多尺寸）；产品前端与演示 demo 同步替换（demo 内嵌 base64 保持离线单文件）
- 交付物：`LinkSec_AutoTest_AI_v3.4.0-UI2.zip`、`LinkSec_AutoTest_AI_v3.4.0-UI2_功能演示demo.html`

### v3.4.0-UI1（2026-11-13）· 纯 UI 迭代 🎨

- 变更范围：前端界面（仅演示页面，不涉及产品后端代码与部署）
- 内容：功能演示 HTML 升级至 v3.4.0——新增「Token 用量」页面（对话/任务双维度 + 单条明细，模拟 /api/ai/tokens 接口）、AI 分析页单次用量展示、扫描任务自动计入任务维度 Token；同步去特征化（编排面板等文案）
- 交付物：`LinkSec_AutoTest_AI_v3.4.0-UI1_功能演示demo.html`

### v3.4.0（2026-11-13）· 完整迭代 🚀

- 变更范围：后端 + 前端 + 文档
- 内容：
  1. **去特征化**：清除源码中全部外部参考特征（注释、路径名、流程名、外部下载链接等）；`backend/Dockerfile` 的 nuclei 改用 Kali 官方源安装，移除全部外部下载调用
  2. **Token 用量统计（按单个任务 / 单次对话维度，非全局汇总）**：新增 `backend/token_usage.py`；AI 分析、多智能体编排、技能执行、攻击链分析、AI 分析任务、扫描 AI 阶段与报告生成均按所属对话/任务记录输入/输出/总 Token；模拟模式为启发式估算、真实 AI 模式使用 API 精确值；新增接口 `GET /api/ai/tokens?scope=conversation|task`、`GET /api/ai/tokens/stats`、`GET /api/ai/tokens/<id>`；前端新增「Token 用量」页面（对话/任务双维度 + 单条明细）与 AI 页单次用量展示

### v3.3.1（2026-11-13）· 完整迭代 🚀

- 变更范围：部署交付
- 内容：私有部署源结构（长期源码部署源）——`deploy-server/` 新增 `gen_latest.py`（latest.json 版本清单生成）、`nginx-deploy.conf`（8443 只读静态托管，仅放行清单/日志/部署包三类文件）、`update.sh`（客户端更新：版本比对 / SHA256 校验 / 自动备份 / 失败回滚 / --check / --force / --rollback）
- 部署源地址约定：`https://134.175.131.134:8443`
- 版本号：应用 health 与前端平台信息同步升级为 v3.3.1

### v3.3.0-UI1（2026-11-13）· 纯 UI 迭代 🎨

- 变更范围：前端界面（仅交付演示页面，不涉及产品后端代码与部署）
- 内容：v3.3 全功能演示 HTML（单文件离线可用）——登录/RBAC、总览面板、资产管理、审批中心、机器人接入、用户与角色、AI 多智能体编排、攻击链图谱与回放、漏洞状态流转、系统设置
- 交付物：`LinkSec_AutoTest_AI_v3.3.0-UI1_功能演示demo.html`

### v3.3.0（2026-11-13）· 完整迭代 🚀

- 变更范围：后端 + 前端 + 文档
- 内容：补齐功能——资产管理、平台 RBAC（多用户/角色/登录）、人机协同审批（高危操作审批+回放执行）、机器人多通道接入、SQLite 持久化、漏洞状态流转、攻击链图谱与步骤回放、AI 多智能体编排（single/deep/plan-execute/supervisor）、报告导出（Markdown/HTML）
- 后端新增：`backend/ext_v3.py`、`storage.py`、`rbac.py`、`assets.py`、`approvals.py`、`bots.py`
- 前端新增页面：资产管理、机器人接入、审批中心、用户与角色、登录界面
- 说明：未包含 gov 网站阻止渗透功能（按需求排除）
- 交付物：`LinkSec_AutoTest_AI_v3.3.0.zip`、部署手册 docx（含附录 C）

### v3.2.1（基线版本）

- 变更范围：原始交付包
- 内容：Flask 后端（扫描引擎 + AI 分析）+ 全中文单页前端 + Kali/Docker 双部署方式
- 交付物：`LinkSec_AutoTest_AI_Deploy_1.zip`、产品说明V0.1.docx
