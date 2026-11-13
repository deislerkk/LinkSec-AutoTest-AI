"""
LinkSec·AutoTest AI — AI 分析模块
对接 Anthropic Claude API 进行智能漏洞分析与报告生成
"""

import os
import json
import anthropic
from datetime import datetime
from token_usage import estimate_tokens


SYSTEM_PROMPT = """你是 LinkSec·AutoTest AI 平台的核心安全分析引擎。
你的职责是：
1. 分析渗透测试发现的漏洞，评估风险等级和利用可行性
2. 识别漏洞之间的关联关系和潜在攻击链
3. 提供详细的修复建议和优先级排序
4. 生成专业的渗透测试报告

请以简洁、专业的中文回答，重点突出安全风险和实际影响。
对于 CVE 漏洞，请结合具体目标环境分析实际威胁。"""


class AIAnalyst:
    def __init__(self):
        api_key = os.environ.get('ANTHROPIC_API_KEY', '')
        if api_key:
            self.client = anthropic.Anthropic(api_key=api_key)
        else:
            self.client = None

    def analyze(self, prompt: str, context: dict = None) -> dict:
        """
        分析漏洞或攻击链
        如未配置 API Key，返回模拟分析结果
        """
        if self.client:
            return self._real_analyze(prompt, context)
        return self._mock_analyze(prompt, context)

    def generate_report(self, scan: dict) -> dict:
        """生成渗透测试报告"""
        if self.client:
            return self._real_report(scan)
        return self._mock_report(scan)

    # ─── 多智能体编排（多智能体编排：single/deep/plan-execute/supervisor）───

    def orchestrate(self, goal: str, mode: str = 'single') -> dict:
        """按编排模式对目标进行智能分析。

        single        单智能体：直接分析
        deep          深度模式：分析 + 自省复核补充
        plan-execute  计划-执行：先生成阶段计划，再逐阶段产出结果
        supervisor    监督模式：拆分为多个专家视角并行分析后汇总
        """
        mode = mode or 'single'
        if mode not in ('single', 'deep', 'plan-execute', 'supervisor'):
            mode = 'single'
        if self.client:
            return self._real_orchestrate(goal, mode)
        return self._mock_orchestrate(goal, mode)

    def _real_orchestrate(self, goal: str, mode: str) -> dict:
        usage_log = []

        def call(prompt, max_tokens=1024):
            try:
                msg = self.client.messages.create(
                    model='claude-sonnet-4-20250514',
                    max_tokens=max_tokens,
                    system=SYSTEM_PROMPT,
                    messages=[{'role': 'user', 'content': prompt}]
                )
                u = msg.usage
                usage_log.append((u.input_tokens, u.output_tokens))
                return msg.content[0].text
            except Exception as e:
                return f'（AI 调用失败：{e}）'

        result = {'success': True, 'mode': mode, 'goal': goal,
                  'timestamp': datetime.now().isoformat()}
        if mode == 'single':
            result['analysis'] = call(goal)
        elif mode == 'deep':
            first = call(goal)
            second = call(f'请审阅以下初步分析，指出遗漏的风险点与不足，并给出补充：\n\n{first}')
            result['analysis'] = first
            result['review'] = second
        elif mode == 'plan-execute':
            plan_txt = call(f'请将以下目标拆解为 4-6 个可执行阶段（仅输出阶段清单）：\n{goal}')
            stages = [s.strip(' -•1234567890.') for s in plan_txt.splitlines() if s.strip()][:6]
            result['plan'] = stages
            result['steps'] = [{'stage': s, 'result': call(f'执行阶段：{s}\n总体目标：{goal}')}
                               for s in stages]
        else:  # supervisor
            experts = ['外网攻击面分析', 'Web 应用安全', '内网横向移动', '修复与加固']
            parts = [{'expert': e, 'output': call(f'你作为{e}专家，分析目标：{goal}')}
                     for e in experts]
            summary = call('请汇总以下多位专家分析，形成统一结论：\n\n'
                           + '\n\n'.join(f'【{p["expert"]}】\n{p["output"]}' for p in parts))
            result['parts'] = parts
            result['summary'] = summary
        pt = sum(u[0] for u in usage_log)
        ct = sum(u[1] for u in usage_log)
        result['usage'] = {'prompt_tokens': pt, 'completion_tokens': ct,
                           'total_tokens': pt + ct, 'estimated': False,
                           'calls': len(usage_log)}
        return result

    def _mock_orchestrate(self, goal: str, mode: str) -> dict:
        result = {'success': True, 'mode': mode, 'goal': goal,
                  'model': 'mock (配置 ANTHROPIC_API_KEY 启用真实 AI)',
                  'timestamp': datetime.now().isoformat()}
        if mode == 'single':
            result['analysis'] = self._mock_analyze(goal, {}).get('analysis', '')
        elif mode == 'deep':
            result['analysis'] = self._mock_analyze(goal, {}).get('analysis', '')
            result['review'] = ('**深度复核**\n\n初步分析覆盖了主要风险，但建议补充：\n'
                                '1. 供应链与第三方组件风险未纳入评估\n'
                                '2. 需结合资产台账核对遗漏的暴露面\n'
                                '3. 建议增加渗透前后对比指标，便于量化修复效果')
        elif mode == 'plan-execute':
            result['plan'] = ['信息收集与资产测绘', '端口与服务扫描', 'Web 应用审计',
                              '漏洞验证与利用', '横向移动与权限评估', '报告与修复建议']
            result['steps'] = [
                {'stage': s, 'result': self._mock_analyze(
                    f'执行阶段 {s}，目标 {goal}', {}).get('analysis', '').split('\n\n')[0]}
                for s in result['plan']
            ]
        else:  # supervisor
            result['parts'] = [
                {'expert': '外网攻击面分析',
                 'output': f'对 {goal} 的外网暴露面分析：建议优先排查 VPN 网关与边界设备的已知 CVE，'
                           '结合资产测绘确认暴露端口收敛情况。'},
                {'expert': 'Web 应用安全',
                 'output': '建议对 Web 资产开展 OWASP Top10 专项审计，重点关注注入类与反序列化漏洞，'
                          '并对登录入口实施爆破防护。'},
                {'expert': '内网横向移动',
                 'output': '内网侧应重点检测 SMB/AD 相关漏洞（如 EternalBlue、SMBGhost），'
                          '并评估域控到普通主机的访问控制强度。'},
                {'expert': '修复与加固',
                 'output': '按 CVSS 与业务影响排序修复：P0 立即打补丁/下线，P1 一周内修复，'
                          'P2 纳入下月维护窗口；同步部署微隔离策略。'},
            ]
            result['summary'] = ('**监督汇总**\n\n综合四位专家意见：目标存在边界设备与内网双高风险面，'
                                 '建议优先处置 VPN/边界 CVE 与 SMB 类漏洞，按 P0/P1/P2 分级推进修复，'
                                 '并通过微隔离切断横向移动路径。')
        # 估算用量：输入 = goal，输出 = 各结果文本之和
        out_text = json.dumps({k: v for k, v in result.items()
                               if k in ('analysis', 'review', 'plan', 'steps', 'parts', 'summary')},
                              ensure_ascii=False)
        pt = estimate_tokens(goal)
        ct = estimate_tokens(out_text)
        result['usage'] = {'prompt_tokens': pt, 'completion_tokens': ct,
                           'total_tokens': pt + ct, 'estimated': True}
        return result

    # ─── 真实 AI 调用 ──────────────────────────────────────────────────────────

    def _real_analyze(self, prompt: str, context: dict) -> dict:
        context_str = json.dumps(context, ensure_ascii=False, indent=2) if context else '无'
        full_prompt = f"""
扫描上下文：
{context_str}

分析请求：
{prompt}
"""
        try:
            message = self.client.messages.create(
                model='claude-sonnet-4-20250514',
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                messages=[{'role': 'user', 'content': full_prompt}]
            )
            u = message.usage
            return {
                'success':   True,
                'analysis':  message.content[0].text,
                'model':     'claude-sonnet-4',
                'timestamp': datetime.now().isoformat(),
                'usage': {
                    'prompt_tokens': u.input_tokens,
                    'completion_tokens': u.output_tokens,
                    'total_tokens': u.input_tokens + u.output_tokens,
                    'estimated': False,
                },
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _real_report(self, scan: dict) -> dict:
        vulns_summary = json.dumps(
            [{'name': v.get('name'), 'cve': v.get('cve'), 'cvss': v.get('cvss'),
              'severity': v.get('severity'), 'host': v.get('host')}
             for v in scan.get('_vuln_details', [])],
            ensure_ascii=False, indent=2
        )
        prompt = f"""
请为以下渗透测试结果生成专业报告：

目标：{scan.get('target')}
扫描配置：{scan.get('profile_name')}
扫描时间：{scan.get('started_at')} ~ {scan.get('finished_at')}
发现主机：{len(scan.get('hosts', []))} 台
风险评分：{scan.get('risk_score')} / 10

漏洞清单：
{vulns_summary}

请生成包含：执行摘要、主要发现、攻击链分析、修复建议（按优先级排序）的报告。
"""
        try:
            message = self.client.messages.create(
                model='claude-sonnet-4-20250514',
                max_tokens=2048,
                system=SYSTEM_PROMPT,
                messages=[{'role': 'user', 'content': prompt}]
            )
            u = message.usage
            return {
                'success':   True,
                'report':    message.content[0].text,
                'scan_id':   scan.get('id'),
                'generated': datetime.now().isoformat(),
                'usage': {
                    'prompt_tokens': u.input_tokens,
                    'completion_tokens': u.output_tokens,
                    'total_tokens': u.input_tokens + u.output_tokens,
                    'estimated': False,
                },
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ─── 模拟分析（无 API Key 时） ─────────────────────────────────────────────

    def _mock_analyze(self, prompt: str, context: dict) -> dict:
        responses = {
            'cve': (
                '**漏洞分析**\n\n'
                '该漏洞属于严重级别，CVSS 评分 9.8，攻击向量为网络可达，无需用户交互。\n\n'
                '**潜在影响**：攻击者可在目标系统上执行任意代码，完全控制受影响主机。\n\n'
                '**攻击链**：互联网 → 暴露端口 → 利用漏洞 → 获取 Shell → 横向移动\n\n'
                '**修复建议**：立即应用官方补丁，同时配置 WAF 规则缓解攻击面。'
            ),
            'exploit': (
                '**攻击链分析**\n\n'
                '初始突破口：利用 CVE-2024-21762 获取目标系统 Shell（CVSS 9.8）\n\n'
                '横向移动：通过内网扫描发现 SMBv3 未修补主机，利用 EternalBlue 传播\n\n'
                '权限提升：利用 MySQL 弱口令获取数据库权限，通过 UDF 提权至 root\n\n'
                '持久化：写入 Crontab / 计划任务，植入反向 Shell\n\n'
                '**影响范围**：预计可横向控制内网 60%+ 主机'
            ),
            'remediation': (
                '**修复优先级排序**\n\n'
                '🔴 **P0 - 立即处理（24小时内）**\n'
                '1. 修复 CVE-2024-21762（Fortinet RCE）- 打补丁或临时关闭服务\n'
                '2. 修复 CVE-2021-44228（Log4Shell）- 升级 Log4j2 至 2.17.1+\n\n'
                '🟠 **P1 - 本周内处理**\n'
                '3. 修补 SMBGhost（CVE-2020-0796）- 应用 KB4551762\n'
                '4. 修改 MySQL 弱口令，禁止 root 远程登录\n\n'
                '🟡 **P2 - 本月内处理**\n'
                '5. 升级 OpenSSH 至最新版本\n'
                '6. 禁用 TLS 1.0/1.1，仅保留 TLS 1.2/1.3'
            ),
            'pivot': (
                '**横向移动路径分析**\n\n'
                '路径 1：192.168.10.5（Fortinet VPN）→ 内网网关 → 10.0.1.0/24 全段\n\n'
                '路径 2：192.168.10.22（Log4Shell）→ 服务账户凭据 → 数据库服务器集群\n\n'
                '路径 3：192.168.10.11（SMBGhost）→ 域控制器 → 全域主机\n\n'
                '**最高风险路径**：路径 3 可能导致域控沦陷，影响全部内网资产。\n\n'
                '建议在各子网间部署微隔离策略，限制非必要的 SMB/RDP 横向流量。'
            ),
        }
        # 关键词匹配
        p = prompt.lower()
        if 'cve' in p or '漏洞' in p or '解析' in p:
            key = 'cve'
        elif 'exploit' in p or '利用链' in p or '攻击链' in p:
            key = 'exploit'
        elif 'remedia' in p or '修复' in p or '建议' in p:
            key = 'remediation'
        else:
            key = 'pivot'

        return {
            'success':   True,
            'analysis':  responses[key],
            'model':     'mock (配置 ANTHROPIC_API_KEY 启用真实 AI)',
            'timestamp': datetime.now().isoformat(),
            'usage': {
                'prompt_tokens': estimate_tokens(prompt),
                'completion_tokens': estimate_tokens(responses[key]),
                'total_tokens': estimate_tokens(prompt) + estimate_tokens(responses[key]),
                'estimated': True,
            },
        }

    def _mock_report(self, scan: dict) -> dict:
        target  = scan.get('target', 'N/A')
        risk    = scan.get('risk_score', 0)
        n_vulns = len(scan.get('vuln_ids', []))

        report = f"""# LinkSec·AutoTest AI 渗透测试报告

**目标**：{target}  
**风险评分**：{risk} / 10  
**扫描时间**：{scan.get('started_at', 'N/A')} ~ {scan.get('finished_at', 'N/A')}  
**发现漏洞**：{n_vulns} 个  

---

## 一、执行摘要

本次渗透测试对目标 `{target}` 进行了全面的安全评估，共发现 **{n_vulns} 个安全漏洞**，综合风险评分为 **{risk}/10**（{"高风险" if risk >= 7 else "中风险" if risk >= 4 else "低风险"}）。

存在多个严重级别漏洞可被攻击者利用，建议按优先级立即开展修复工作。

---

## 二、主要发现

- 🔴 严重漏洞：可直接导致系统被完全控制
- 🟠 高危漏洞：攻击者可获取敏感信息或部分控制权
- 🟡 中危漏洞：增加攻击成功概率，需结合其他漏洞利用

---

## 三、修复建议（按优先级）

1. **立即修复**：所有 CVSS ≥ 9.0 的严重漏洞，优先打补丁并部署 WAF 缓解规则
2. **本周修复**：CVSS 7.0~8.9 的高危漏洞，重点关注远程可利用漏洞
3. **计划修复**：CVSS 4.0~6.9 的中危漏洞，纳入下次维护窗口

---

*报告由 LinkSec·AutoTest AI v3.2.1 自动生成*
"""
        return {
            'success':   True,
            'report':    report,
            'scan_id':   scan.get('id'),
            'generated': datetime.now().isoformat(),
            'usage': {
                'prompt_tokens': estimate_tokens(target),
                'completion_tokens': estimate_tokens(report),
                'total_tokens': estimate_tokens(target) + estimate_tokens(report),
                'estimated': True,
            },
        }
