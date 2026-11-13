"""
LinkSec·AutoTest AI — 真实扫描引擎
对接 Kali Linux 工具链：nmap · masscan · nikto · hydra · enum4linux · whatweb · gobuster · nuclei
"""

import uuid
import time
import subprocess
import shutil
import json
import re
import os
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Optional
from token_usage import LEDGER, estimate_tokens


# ══════════════════════════════════════════════════════════════════
# 工具可用性检测
# ══════════════════════════════════════════════════════════════════
TOOLS = {
    'nmap':       shutil.which('nmap'),
    'masscan':    shutil.which('masscan'),
    'nikto':      shutil.which('nikto'),
    'hydra':      shutil.which('hydra'),
    'enum4linux': shutil.which('enum4linux'),
    'whatweb':    shutil.which('whatweb'),
    'gobuster':   shutil.which('gobuster'),
    'nuclei':     shutil.which('nuclei'),
    'smbclient':  shutil.which('smbclient'),
    'curl':       shutil.which('curl'),
}

# 扫描配置 → 执行哪些阶段
SCAN_PROFILES = {
    'quick_recon': {
        'name':   '快速侦察',
        'stages': ['discovery', 'port_scan'],
        'nmap_flags': '-T4 --top-ports 1000',
    },
    'full_pentest': {
        'name':   '全面渗透',
        'stages': ['discovery', 'port_scan', 'service_enum', 'vuln_scan', 'web_scan', 'ai_analysis', 'report'],
        'nmap_flags': '-T4 -p- --min-rate 5000',
    },
    'aggressive': {
        'name':   '激进模式',
        'stages': ['discovery', 'port_scan', 'service_enum', 'vuln_scan', 'web_scan', 'brute_force', 'ai_analysis', 'report'],
        'nmap_flags': '-T5 -p- --min-rate 10000',
    },
    'stealth': {
        'name':   '隐匿模式',
        'stages': ['discovery', 'port_scan', 'service_enum', 'vuln_scan', 'report'],
        'nmap_flags': '-T2 -sS --top-ports 500',
    },
    'web_app_audit': {
        'name':   'Web应用审计',
        'stages': ['port_scan', 'service_enum', 'web_scan', 'vuln_scan', 'ai_analysis', 'report'],
        'nmap_flags': '-T4 -p 80,443,8080,8443,8888,3000,5000,9090',
    },
}

STAGE_NAMES = {
    'discovery':     '主机发现 (Nmap Ping)',
    'port_scan':     '端口扫描 + 服务识别',
    'service_enum':  '服务深度枚举',
    'vuln_scan':     '漏洞扫描 (Nmap NSE + Nuclei)',
    'web_scan':      'Web 应用扫描 (Nikto + WhatWeb)',
    'brute_force':   '弱口令爆破 (Hydra)',
    'ai_analysis':   'AI 攻击链分析',
    'report':        '报告生成',
}

# CVSS 知识库（用于 NSE 脚本结果匹配增强）
VULN_KB = {
    'ms17-010':        ('MS17-010 EternalBlue SMB RCE',     'CVE-2017-0144', 9.8, 'critical', 'SMB/445',    '应用 MS17-010 补丁，禁用 SMBv1'),
    'cve-2014-0160':   ('Heartbleed OpenSSL 信息泄露',       'CVE-2014-0160', 7.5, 'high',     'HTTPS/443',  '升级 OpenSSL 至 1.0.1g+'),
    'cve-2021-44228':  ('Log4Shell JNDI 远程代码执行',       'CVE-2021-44228',10.0,'critical', 'HTTP/8080',  '升级 Log4j2 至 2.17.1+'),
    'cve-2020-0796':   ('SMBGhost SMBv3 压缩 RCE',          'CVE-2020-0796', 10.0,'critical', 'SMB/445',    '应用 KB4551762 补丁，禁用 SMBv3 压缩'),
    'cve-2019-0708':   ('BlueKeep RDP 预授权 RCE',          'CVE-2019-0708', 9.8, 'critical', 'RDP/3389',   '应用 MS19-0708 补丁，禁用 RDP 或启用 NLA'),
    'cve-2018-15473':  ('OpenSSH 用户名枚举',                'CVE-2018-15473',5.3, 'medium',   'SSH/22',     '升级 OpenSSH 至 7.8+，配置 fail2ban'),
    'cve-2021-41773':  ('Apache 路径穿越 RCE',              'CVE-2021-41773',7.5, 'high',     'HTTP/80',    '升级 Apache 至 2.4.50+'),
    'cve-2022-22965':  ('Spring4Shell 远程代码执行',         'CVE-2022-22965',9.8, 'critical', 'HTTP/8080',  '升级 Spring Framework 至 5.3.18+'),
    'http-shellshock': ('ShellShock Bash 远程代码执行',      'CVE-2014-6271', 10.0,'critical', 'HTTP/80',    '升级 Bash，修补 CGI 配置'),
    'ssl-poodle':      ('POODLE SSL v3.0 降级攻击',         'CVE-2014-3566', 3.4, 'low',      'HTTPS/443',  '禁用 SSLv3，仅允许 TLS 1.2+'),
    'ssl-heartbleed':  ('Heartbleed OpenSSL 信息泄露',       'CVE-2014-0160', 7.5, 'high',     'HTTPS/443',  '升级 OpenSSL 至 1.0.1g+'),
    'http-csrf':       ('跨站请求伪造 (CSRF)',               'OWASP-A08',     4.3, 'medium',   'HTTP/80',    '实施 CSRF Token 验证机制'),
    'http-sql-injection': ('SQL 注入漏洞',                  'OWASP-A03',     8.8, 'high',     'HTTP/80',    '使用参数化查询，部署 WAF'),
    'ftp-anon':        ('FTP 匿名登录开放',                  'MISCONFIG-FTP', 7.5, 'high',     'FTP/21',     '禁用 FTP 匿名访问，改用 SFTP'),
    'smb-vuln-ms08-067': ('MS08-067 NetAPI 远程代码执行',   'CVE-2008-4250', 10.0,'critical', 'SMB/445',    '应用 MS08-067 补丁'),
    'rdp-vuln-ms12-020': ('MS12-020 RDP 拒绝服务漏洞',     'CVE-2012-0002', 9.3, 'critical', 'RDP/3389',   '应用 MS12-020 补丁，禁用 RDP 或限制访问'),
}

SEVERITY_CVSS_MAP = {
    'critical': (9.0, 10.0),
    'high':     (7.0, 8.9),
    'medium':   (4.0, 6.9),
    'low':      (0.1, 3.9),
}


# ══════════════════════════════════════════════════════════════════
# 辅助：运行外部命令
# ══════════════════════════════════════════════════════════════════
def _run(cmd: list, timeout: int = 300) -> tuple[int, str, str]:
    """运行外部命令，返回 (returncode, stdout, stderr)"""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, '', f'命令超时（>{timeout}s）：{" ".join(cmd)}'
    except FileNotFoundError:
        return -2, '', f'工具未找到：{cmd[0]}'
    except Exception as e:
        return -3, '', str(e)


def _severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0: return 'critical'
    if cvss >= 7.0: return 'high'
    if cvss >= 4.0: return 'medium'
    return 'low'


# ══════════════════════════════════════════════════════════════════
# 扫描引擎主类
# ══════════════════════════════════════════════════════════════════
class ScanEngine:
    def __init__(self):
        self._scans: dict  = {}
        self._vulns: dict  = {}
        self._settings = {
            'max_concurrent_scans': 3,
            'default_profile':      'full_pentest',
            'timeout_seconds':      600,
            'ai_model':             'claude-sonnet-4',
            'nmap_sudo':            True,   # nmap SYN 扫描需要 root
            'nuclei_templates':     '~/.local/nuclei-templates',
            'wordlist_small':       '/usr/share/wordlists/dirb/common.txt',
            'wordlist_pass':        '/usr/share/wordlists/rockyou.txt',
            'hydra_threads':        16,
        }

    # ──────────────────────────────────────────────────────────────
    # 生命周期
    # ──────────────────────────────────────────────────────────────
    def create_scan(self, target: str, profile: str = 'full_pentest') -> str:
        scan_id      = str(uuid.uuid4())[:8]
        profile_info = SCAN_PROFILES.get(profile, SCAN_PROFILES['full_pentest'])
        self._scans[scan_id] = {
            'id':           scan_id,
            'target':       target,
            'profile':      profile,
            'profile_name': profile_info['name'],
            'status':       'running',
            'progress':     0,
            'stages':       [],
            'logs':         [],
            'hosts':        [],       # [{ip, hostname, os, ports:[{port,proto,service,version}]}]
            'vuln_ids':     [],
            'risk_score':   0.0,
            'tools_used':   [],
            'started_at':   datetime.now().isoformat(),
            'finished_at':  None,
            '_stop':        False,
            '_proc':        None,     # 当前子进程（用于中止）
        }
        self._log(scan_id, 'info', 'LinkSec·AutoTest AI 引擎初始化 — 工具链检测中…')
        available = [t for t, p in TOOLS.items() if p]
        missing   = [t for t, p in TOOLS.items() if not p]
        self._log(scan_id, 'ok',   f'可用工具：{", ".join(available)}')
        if missing:
            self._log(scan_id, 'warn', f'未检测到工具（跳过对应阶段）：{", ".join(missing)}')
        self._log(scan_id, 'info', f'扫描配置：{profile_info["name"]} | 目标：{target}')
        return scan_id

    def run_scan(self, scan_id: str):
        scan     = self._scans.get(scan_id)
        if not scan:
            return
        profile  = SCAN_PROFILES.get(scan['profile'], SCAN_PROFILES['full_pentest'])
        stages   = profile['stages']
        total    = len(stages)

        handlers = {
            'discovery':    self._stage_discovery,
            'port_scan':    self._stage_port_scan,
            'service_enum': self._stage_service_enum,
            'vuln_scan':    self._stage_vuln_scan,
            'web_scan':     self._stage_web_scan,
            'brute_force':  self._stage_brute_force,
            'ai_analysis':  self._stage_ai_analysis,
            'report':       self._stage_report,
        }

        for i, stage_id in enumerate(stages):
            if scan.get('_stop'):
                scan['status'] = 'stopped'
                self._log(scan_id, 'warn', '扫描已被用户中止')
                return

            stage_entry = {
                'id':         stage_id,
                'name':       STAGE_NAMES.get(stage_id, stage_id),
                'status':     'running',
                'started_at': datetime.now().isoformat(),
            }
            scan['stages'].append(stage_entry)
            scan['progress'] = int((i / total) * 100)
            self._log(scan_id, 'run', f'▶ [{STAGE_NAMES.get(stage_id, stage_id)}] 开始…')

            try:
                handler = handlers.get(stage_id)
                if handler:
                    handler(scan_id, profile)
            except Exception as e:
                self._log(scan_id, 'err', f'阶段异常：{e}')

            stage_entry['status']      = 'done'
            stage_entry['finished_at'] = datetime.now().isoformat()
            scan['progress'] = int(((i + 1) / total) * 100)

        # 计算综合风险评分
        vuln_list = [self._vulns[v] for v in scan['vuln_ids'] if v in self._vulns]
        if vuln_list:
            scores = [v['cvss'] for v in vuln_list]
            scan['risk_score'] = round(max(scores) * 0.6 + (sum(scores) / len(scores)) * 0.4, 1)

        scan['progress']    = 100
        scan['status']      = 'completed'
        scan['finished_at'] = datetime.now().isoformat()
        self._log(scan_id, 'ok',
            f'✅ 扫描完成。发现主机 {len(scan["hosts"])} 台，漏洞 {len(scan["vuln_ids"])} 个，风险评分 {scan["risk_score"]}/10')

    def stop_scan(self, scan_id: str) -> bool:
        scan = self._scans.get(scan_id)
        if not scan:
            return False
        scan['_stop'] = True
        proc = scan.get('_proc')
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass
        return True

    # ──────────────────────────────────────────────────────────────
    # 阶段 1：主机发现
    # ──────────────────────────────────────────────────────────────
    def _stage_discovery(self, scan_id: str, profile: dict):
        scan   = self._scans[scan_id]
        target = scan['target']

        if not TOOLS['nmap']:
            self._log(scan_id, 'warn', 'nmap 未安装，跳过主机发现')
            return

        cmd = ['nmap', '-sn', '--open', '-T4', target, '-oG', '-']
        if self._settings.get('nmap_sudo') and os.geteuid() == 0:
            cmd = ['nmap', '-sn', '--open', '-T4', '-PE', '-PP', '-PS80,443', target, '-oG', '-']

        self._log(scan_id, 'run', f'$ {" ".join(cmd)}')
        rc, out, err = _run(cmd, timeout=120)

        if rc != 0:
            self._log(scan_id, 'warn', f'主机发现返回码 {rc}：{err[:200]}')

        hosts_found = []
        for line in out.splitlines():
            # Nmap grepable 格式：Host: 192.168.1.1 (hostname)  Status: Up
            m = re.match(r'Host:\s+(\S+)\s+\(([^)]*)\)\s+Status:\s+Up', line)
            if m:
                ip, hostname = m.group(1), m.group(2)
                hosts_found.append({'ip': ip, 'hostname': hostname or ip, 'os': '', 'ports': []})

        if not hosts_found:
            # 目标可能是单 IP/域名，直接加入
            hosts_found = [{'ip': target, 'hostname': target, 'os': '', 'ports': []}]

        scan['hosts'] = hosts_found
        scan['tools_used'].append('nmap-discovery')
        self._log(scan_id, 'ok', f'主机发现完成：{len(hosts_found)} 台主机在线')
        for h in hosts_found[:10]:
            self._log(scan_id, 'info', f'  ↳ {h["ip"]}  {h["hostname"]}')

    # ──────────────────────────────────────────────────────────────
    # 阶段 2：端口扫描 + 服务识别
    # ──────────────────────────────────────────────────────────────
    def _stage_port_scan(self, scan_id: str, profile: dict):
        scan    = self._scans[scan_id]
        target  = scan['target']
        flags   = profile.get('nmap_flags', '-T4 --top-ports 1000')
        nmap_xml = f'/tmp/linksec_{scan_id}_portscan.xml'

        if not TOOLS['nmap']:
            self._log(scan_id, 'warn', 'nmap 未安装，跳过端口扫描')
            return

        # 对发现的主机构建目标列表（最多 50 台）
        host_ips = [h['ip'] for h in scan['hosts']][:50] or [target]
        targets  = ' '.join(host_ips)

        cmd = f'nmap {flags} -sV -sC -O --osscan-guess -oX {nmap_xml} {targets}'
        if os.geteuid() == 0:
            cmd = f'nmap {flags} -sS -sV -sC -O --osscan-guess -oX {nmap_xml} {targets}'

        self._log(scan_id, 'run', f'$ {cmd}')
        rc, out, err = _run(cmd.split(), timeout=self._settings['timeout_seconds'])

        if rc not in (0, 1) and rc != -1:  # nmap rc=1 可能只是警告
            self._log(scan_id, 'warn', f'nmap 端口扫描异常（rc={rc}）')

        # 解析 XML
        try:
            self._parse_nmap_xml(scan_id, nmap_xml)
        except Exception as e:
            self._log(scan_id, 'warn', f'Nmap XML 解析失败：{e}')

        scan['tools_used'].append('nmap-portscan')

        total_ports = sum(len(h.get('ports', [])) for h in scan['hosts'])
        self._log(scan_id, 'ok', f'端口扫描完成：{total_ports} 个开放端口，覆盖 {len(scan["hosts"])} 台主机')

    def _parse_nmap_xml(self, scan_id: str, xml_path: str):
        """解析 Nmap XML 输出，更新 hosts 列表"""
        scan = self._scans[scan_id]
        if not os.path.exists(xml_path):
            return

        tree = ET.parse(xml_path)
        root = tree.getroot()

        # 重建 hosts（带端口信息）
        new_hosts = []
        for host_el in root.findall('host'):
            status = host_el.find('status')
            if status is None or status.get('state') != 'up':
                continue

            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host_el.find('address')
            if addr_el is None:
                continue
            ip = addr_el.get('addr', '')

            hostname = ip
            for hn in host_el.findall('.//hostname'):
                hostname = hn.get('name', ip)
                break

            os_guess = ''
            for osmatch in host_el.findall('.//osmatch'):
                os_guess = osmatch.get('name', '')
                break

            ports = []
            for port_el in host_el.findall('.//port'):
                state_el = port_el.find('state')
                if state_el is None or state_el.get('state') != 'open':
                    continue
                portid   = port_el.get('portid', '')
                protocol = port_el.get('protocol', 'tcp')
                svc_el   = port_el.find('service')
                svc_name = svc_el.get('name', '') if svc_el is not None else ''
                svc_ver  = svc_el.get('version', '') if svc_el is not None else ''
                svc_prod = svc_el.get('product', '') if svc_el is not None else ''
                ports.append({
                    'port':    portid,
                    'proto':   protocol,
                    'service': svc_name,
                    'version': f'{svc_prod} {svc_ver}'.strip(),
                })
                self._log(scan_id, 'info', f'  {ip}:{portid}/{protocol}  {svc_name}  {svc_prod} {svc_ver}'.strip())

            new_hosts.append({'ip': ip, 'hostname': hostname, 'os': os_guess, 'ports': ports})

        if new_hosts:
            scan['hosts'] = new_hosts

    # ──────────────────────────────────────────────────────────────
    # 阶段 3：服务深度枚举（SMB / FTP / SNMP / RDP）
    # ──────────────────────────────────────────────────────────────
    def _stage_service_enum(self, scan_id: str, profile: dict):
        scan = self._scans[scan_id]
        found_services = self._collect_services(scan)

        # ─ SMB / NetBIOS → enum4linux ─
        smb_hosts = found_services.get('smb', [])
        if smb_hosts and TOOLS['enum4linux']:
            for ip in smb_hosts[:3]:
                if scan.get('_stop'):
                    break
                self._log(scan_id, 'run', f'$ enum4linux -a {ip}')
                rc, out, err = _run(['enum4linux', '-a', ip], timeout=60)
                self._parse_enum4linux(scan_id, ip, out)
        elif smb_hosts:
            self._log(scan_id, 'warn', 'enum4linux 未安装，跳过 SMB 枚举')

        # ─ FTP 匿名登录检测 ─
        ftp_hosts = found_services.get('ftp', [])
        if ftp_hosts and TOOLS['nmap']:
            targets = ' '.join(ftp_hosts[:5])
            cmd = f'nmap -p 21 --script ftp-anon,ftp-syst {targets}'
            self._log(scan_id, 'run', f'$ {cmd}')
            rc, out, err = _run(cmd.split(), timeout=60)
            if 'Anonymous FTP login allowed' in out:
                for ip in ftp_hosts:
                    if 'Anonymous FTP login allowed' in out:
                        self._add_vuln(scan_id, ip, 'ftp-anon')
                        self._log(scan_id, 'err', f'FTP 匿名登录开放：{ip}:21')

        # ─ SNMP 社区字符串枚举 ─
        snmp_hosts = found_services.get('snmp', [])
        if snmp_hosts and TOOLS['nmap']:
            targets = ' '.join(snmp_hosts[:5])
            cmd = f'nmap -sU -p 161 --script snmp-info,snmp-brute {targets}'
            self._log(scan_id, 'run', f'$ {cmd}')
            rc, out, err = _run(cmd.split(), timeout=90)
            if 'public' in out.lower() or 'private' in out.lower():
                self._log(scan_id, 'warn', f'SNMP 默认社区字符串开放：{snmp_hosts}')

        scan['tools_used'].append('service-enum')
        self._log(scan_id, 'ok', '服务枚举阶段完成')

    def _parse_enum4linux(self, scan_id: str, ip: str, output: str):
        """从 enum4linux 输出提取有价值的信息"""
        scan = self._scans[scan_id]
        if 'Null session' in output or 'null session' in output:
            self._log(scan_id, 'warn', f'{ip} SMB 空会话（Null Session）可访问')
        users = re.findall(r'user:\[(.*?)\]', output)
        if users:
            self._log(scan_id, 'info', f'{ip} 枚举到用户：{", ".join(set(users[:10]))}')
        shares = re.findall(r'Sharename\s+(\S+)', output)
        if shares:
            self._log(scan_id, 'info', f'{ip} SMB 共享：{", ".join(shares[:10])}')

    # ──────────────────────────────────────────────────────────────
    # 阶段 4：漏洞扫描（Nmap NSE + Nuclei）
    # ──────────────────────────────────────────────────────────────
    def _stage_vuln_scan(self, scan_id: str, profile: dict):
        scan = self._scans[scan_id]

        # ─ Nmap 漏洞脚本 ─
        if TOOLS['nmap']:
            self._nmap_vuln_scripts(scan_id)

        # ─ Nuclei ─
        if TOOLS['nuclei']:
            self._nuclei_scan(scan_id)
        else:
            self._log(scan_id, 'warn', 'nuclei 未安装，跳过模板漏洞扫描')

        scan['tools_used'].append('vuln-scan')

    def _nmap_vuln_scripts(self, scan_id: str):
        scan     = self._scans[scan_id]
        host_ips = [h['ip'] for h in scan['hosts']][:20]
        if not host_ips:
            return
        targets  = ' '.join(host_ips)
        nmap_xml = f'/tmp/linksec_{scan_id}_vuln.xml'

        # 常用 NSE 漏洞检测脚本
        scripts = ','.join([
            'vuln',                 # 全部 vuln 类脚本
            'smb-vuln-ms17-010',
            'smb-vuln-ms08-067',
            'smb-vuln-ms10-054',
            'smb-vuln-ms10-061',
            'ssl-heartbleed',
            'ssl-poodle',
            'http-shellshock',
            'http-csrf',
            'http-sql-injection',
            'ftp-anon',
            'rdp-vuln-ms12-020',
        ])

        cmd = f'nmap -p- --script {scripts} -oX {nmap_xml} {targets}'
        self._log(scan_id, 'run', f'$ {cmd[:120]}…')
        rc, out, err = _run(cmd.split(), timeout=self._settings['timeout_seconds'])

        # 解析 NSE 脚本结果
        try:
            if os.path.exists(nmap_xml):
                self._parse_nmap_vuln_xml(scan_id, nmap_xml)
        except Exception as e:
            self._log(scan_id, 'warn', f'NSE 结果解析失败：{e}')

        # 同时从文本输出匹配关键词
        self._parse_nmap_text_vulns(scan_id, out)

    def _parse_nmap_vuln_xml(self, scan_id: str, xml_path: str):
        """从 Nmap XML 中提取 NSE 漏洞脚本结果"""
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for host_el in root.findall('host'):
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host_el.find('address')
            if addr_el is None:
                continue
            ip = addr_el.get('addr', '')
            for script_el in host_el.findall('.//script'):
                script_id  = script_el.get('id', '').lower()
                script_out = script_el.get('output', '')
                # 判断是否为真实漏洞（排除 NOT VULNERABLE）
                if 'not vulnerable' in script_out.lower():
                    continue
                if 'vulnerable' in script_out.lower() or 'VULNERABLE' in script_out:
                    self._add_vuln(scan_id, ip, script_id, extra_info=script_out[:300])
                    self._log(scan_id, 'err', f'[NSE] {script_id} → {ip} 存在漏洞')
                elif script_id in VULN_KB:
                    self._add_vuln(scan_id, ip, script_id, extra_info=script_out[:200])

    def _parse_nmap_text_vulns(self, scan_id: str, text: str):
        """从 nmap 文本输出匹配漏洞关键词"""
        ip_block = None
        for line in text.splitlines():
            ip_match = re.match(r'Nmap scan report for (?:\S+ \()?(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip_block = ip_match.group(1)
            if ip_block and ('VULNERABLE' in line or 'vulnerable' in line.lower()):
                for kb_key in VULN_KB:
                    if kb_key.lower() in line.lower():
                        self._add_vuln(scan_id, ip_block, kb_key)

    def _nuclei_scan(self, scan_id: str):
        scan     = self._scans[scan_id]
        host_ips = [h['ip'] for h in scan['hosts']][:20]
        if not host_ips:
            return

        # 构建目标文件
        target_file = f'/tmp/linksec_{scan_id}_targets.txt'
        with open(target_file, 'w') as f:
            for ip in host_ips:
                f.write(ip + '\n')
                # 对常见端口也生成 URL
                for h in scan['hosts']:
                    if h['ip'] == ip:
                        for p in h.get('ports', []):
                            if p['service'] in ('http', 'https', 'http-alt'):
                                scheme = 'https' if p['service'] == 'https' else 'http'
                                f.write(f'{scheme}://{ip}:{p["port"]}\n')

        out_json = f'/tmp/linksec_{scan_id}_nuclei.json'
        cmd = [
            'nuclei',
            '-l', target_file,
            '-severity', 'critical,high,medium',
            '-json-export', out_json,
            '-silent',
            '-timeout', '10',
            '-retries', '1',
        ]
        self._log(scan_id, 'run', f'$ {" ".join(cmd)}')
        rc, out, err = _run(cmd, timeout=300)

        # 解析 JSON 输出
        try:
            if os.path.exists(out_json):
                with open(out_json) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            item = json.loads(line)
                            self._add_vuln_from_nuclei(scan_id, item)
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            self._log(scan_id, 'warn', f'Nuclei 输出解析失败：{e}')

    def _add_vuln_from_nuclei(self, scan_id: str, item: dict):
        """从 Nuclei JSON 结果生成漏洞记录"""
        info = item.get('info', {})
        name = info.get('name', '未知漏洞')
        sev  = (info.get('severity') or 'medium').lower()
        cvss_meta = info.get('classification', {}).get('cvss-score', 0)
        try:
            cvss = float(cvss_meta) if cvss_meta else {'critical':9.5,'high':7.5,'medium':5.0,'low':2.0}.get(sev, 5.0)
        except (ValueError, TypeError):
            cvss = {'critical':9.5,'high':7.5,'medium':5.0,'low':2.0}.get(sev, 5.0)

        cve_list = info.get('classification', {}).get('cve-id', [])
        cve      = cve_list[0] if cve_list else info.get('tags', ['N/A'])[0]

        host      = item.get('host', item.get('ip', 'unknown'))
        matched   = item.get('matched-at', host)
        port_part = re.search(r':(\d+)', matched)
        port      = port_part.group(1) if port_part else '80'

        vuln_id = str(uuid.uuid4())[:8]
        vuln = {
            'id':           vuln_id,
            'scan_id':      scan_id,
            'name':         name,
            'cve':          cve,
            'cvss':         cvss,
            'severity':     sev,
            'service':      f'PORT/{port}',
            'host':         host,
            'description':  info.get('description', ''),
            'remediation':  '; '.join(info.get('remediation', '') or []),
            'status':       'detected',
            'source':       'nuclei',
            'discovered_at':datetime.now().isoformat(),
        }
        self._vulns[vuln_id] = vuln
        self._scans[scan_id]['vuln_ids'].append(vuln_id)
        level_cn = {'critical':'严重','high':'高危','medium':'中危','low':'低危'}
        tag = 'err' if sev == 'critical' else 'warn' if sev == 'high' else 'info'
        self._log(scan_id, tag, f'[Nuclei/{level_cn.get(sev,sev)}] {name} @ {host} — CVSS {cvss}')

    # ──────────────────────────────────────────────────────────────
    # 阶段 5：Web 应用扫描（Nikto + WhatWeb + Gobuster）
    # ──────────────────────────────────────────────────────────────
    def _stage_web_scan(self, scan_id: str, profile: dict):
        scan = self._scans[scan_id]
        web_targets = self._collect_web_targets(scan)

        if not web_targets:
            self._log(scan_id, 'info', '未发现 HTTP/HTTPS 服务，跳过 Web 扫描')
            return

        for url in web_targets[:5]:    # 最多扫 5 个 Web 目标
            if scan.get('_stop'):
                break

            # ─ WhatWeb 指纹识别 ─
            if TOOLS['whatweb']:
                self._log(scan_id, 'run', f'$ whatweb -a 3 {url}')
                rc, out, err = _run(['whatweb', '-a', '3', url], timeout=30)
                if out:
                    self._log(scan_id, 'info', f'[WhatWeb] {url}: {out[:200]}')

            # ─ Nikto 漏洞扫描 ─
            if TOOLS['nikto']:
                nikto_out = f'/tmp/linksec_{scan_id}_nikto.csv'
                cmd = ['nikto', '-h', url, '-Format', 'csv', '-o', nikto_out, '-Tuning', '123457890']
                self._log(scan_id, 'run', f'$ {" ".join(cmd)}')
                rc, out, err = _run(cmd, timeout=180)
                try:
                    self._parse_nikto_csv(scan_id, nikto_out, url)
                except Exception as e:
                    self._log(scan_id, 'warn', f'Nikto 解析失败：{e}')

            # ─ Gobuster 目录枚举 ─
            wl = self._settings.get('wordlist_small', '/usr/share/wordlists/dirb/common.txt')
            if TOOLS['gobuster'] and os.path.exists(wl):
                cmd = ['gobuster', 'dir', '-u', url, '-w', wl, '-q', '--no-error', '-t', '20']
                self._log(scan_id, 'run', f'$ {" ".join(cmd)}')
                rc, out, err = _run(cmd, timeout=120)
                found_paths = re.findall(r'(/\S+)\s+\(Status:\s*(\d+)', out)
                for path, status in found_paths[:20]:
                    self._log(scan_id, 'info', f'[Gobuster] {url}{path}  HTTP {status}')

        scan['tools_used'].append('web-scan')
        self._log(scan_id, 'ok', f'Web 扫描完成（{len(web_targets)} 个目标）')

    def _parse_nikto_csv(self, scan_id: str, csv_path: str, url: str):
        if not os.path.exists(csv_path):
            return
        import csv
        with open(csv_path, newline='', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                desc    = row.get('description', '') or row.get('msg', '')
                osvdb   = row.get('OSVDB', '') or 'NIKTO'
                if not desc or len(desc) < 10:
                    continue
                # 映射严重程度
                sev  = 'medium'
                cvss = 5.0
                if any(k in desc.lower() for k in ['xss', 'injection', 'rce', 'remote code']):
                    sev, cvss = 'high', 7.5
                elif any(k in desc.lower() for k in ['default', 'password', 'credentials']):
                    sev, cvss = 'high', 8.0
                elif any(k in desc.lower() for k in ['disclosure', 'information', 'expose']):
                    sev, cvss = 'medium', 5.3

                vuln_id = str(uuid.uuid4())[:8]
                host    = re.sub(r'https?://', '', url).split(':')[0]
                self._vulns[vuln_id] = {
                    'id':           vuln_id,
                    'scan_id':      scan_id,
                    'name':         f'Nikto: {desc[:80]}',
                    'cve':          osvdb,
                    'cvss':         cvss,
                    'severity':     sev,
                    'service':      'HTTP/Web',
                    'host':         host,
                    'description':  desc,
                    'remediation':  '参考 Nikto 文档及相关 CVE 修复建议',
                    'status':       'detected',
                    'source':       'nikto',
                    'discovered_at':datetime.now().isoformat(),
                }
                self._scans[scan_id]['vuln_ids'].append(vuln_id)
                tag = 'err' if sev == 'critical' else 'warn' if sev == 'high' else 'info'
                self._log(scan_id, tag, f'[Nikto/{sev}] {desc[:100]}')

    # ──────────────────────────────────────────────────────────────
    # 阶段 6：弱口令爆破（Hydra）
    # ──────────────────────────────────────────────────────────────
    def _stage_brute_force(self, scan_id: str, profile: dict):
        scan = self._scans[scan_id]
        if not TOOLS['hydra']:
            self._log(scan_id, 'warn', 'hydra 未安装，跳过弱口令爆破')
            return

        wl_pass = self._settings.get('wordlist_pass', '/usr/share/wordlists/rockyou.txt')
        if not os.path.exists(wl_pass):
            # 尝试常见路径
            for alt in ['/usr/share/wordlists/rockyou.txt.gz',
                        '/usr/share/wordlists/fasttrack.txt',
                        '/usr/share/wordlists/metasploit/unix_passwords.txt']:
                if os.path.exists(alt):
                    wl_pass = alt
                    break
            else:
                self._log(scan_id, 'warn', f'密码字典不存在：{wl_pass}，跳过爆破')
                return

        threads = self._settings.get('hydra_threads', 16)
        found   = self._collect_services(scan)

        # SSH 爆破
        for ip in found.get('ssh', [])[:3]:
            if scan.get('_stop'):
                break
            cmd = ['hydra', '-L', '/usr/share/wordlists/metasploit/unix_users.txt',
                   '-P', wl_pass, '-t', str(threads), '-f', ip, 'ssh', '-q']
            self._log(scan_id, 'run', f'$ {" ".join(cmd)}')
            rc, out, err = _run(cmd, timeout=120)
            self._parse_hydra_output(scan_id, ip, 'SSH/22', out)

        # FTP 爆破
        for ip in found.get('ftp', [])[:3]:
            if scan.get('_stop'):
                break
            cmd = ['hydra', '-l', 'anonymous', '-p', 'anonymous', ip, 'ftp', '-q']
            self._log(scan_id, 'run', f'$ {" ".join(cmd)}')
            rc, out, err = _run(cmd, timeout=60)
            self._parse_hydra_output(scan_id, ip, 'FTP/21', out)

        scan['tools_used'].append('hydra-brute')
        self._log(scan_id, 'ok', '弱口令爆破阶段完成')

    def _parse_hydra_output(self, scan_id: str, ip: str, service: str, output: str):
        """解析 Hydra 破解成功结果"""
        for line in output.splitlines():
            m = re.search(r'\[(\d+)\]\[(\S+)\] host: (\S+)\s+login: (\S+)\s+password: (\S+)', line)
            if m:
                port, proto, host, login, password = m.groups()
                vuln_id = str(uuid.uuid4())[:8]
                desc    = f'发现弱口令：用户名 "{login}"，密码 "{password}"'
                self._vulns[vuln_id] = {
                    'id':           vuln_id,
                    'scan_id':      scan_id,
                    'name':         f'{service} 弱口令',
                    'cve':          'WEAK-CRED',
                    'cvss':         9.0,
                    'severity':     'critical',
                    'service':      service,
                    'host':         ip,
                    'description':  desc,
                    'remediation':  '立即修改弱口令，配置账户锁定策略，禁用默认账户',
                    'status':       'exploit_confirmed',
                    'source':       'hydra',
                    'discovered_at':datetime.now().isoformat(),
                }
                self._scans[scan_id]['vuln_ids'].append(vuln_id)
                self._log(scan_id, 'err', f'[Hydra/严重] {service} 弱口令 @ {ip}  {login}:{password}')

    # ──────────────────────────────────────────────────────────────
    # 阶段 7：AI 攻击链分析（汇总后提示后端）
    # ──────────────────────────────────────────────────────────────
    def _stage_ai_analysis(self, scan_id: str, profile: dict):
        scan  = self._scans[scan_id]
        crit  = [v for v in scan['vuln_ids'] if self._vulns.get(v, {}).get('severity') == 'critical']
        high  = [v for v in scan['vuln_ids'] if self._vulns.get(v, {}).get('severity') == 'high']
        self._log(scan_id, 'info',
            f'LinkSec AI 分析：严重 {len(crit)} 个 / 高危 {len(high)} 个 → 构建攻击链模型…')
        # 识别可能的横向移动路径
        hosts_with_crit = set()
        for vid in crit:
            v = self._vulns.get(vid)
            if v:
                hosts_with_crit.add(v['host'])
        if hosts_with_crit:
            self._log(scan_id, 'warn',
                f'AI 识别高危跳板主机：{", ".join(list(hosts_with_crit)[:5])}')
        self._log(scan_id, 'ok', 'AI 攻击链分析完成，完整报告请在报告页面生成')
        # v3.4：按单个任务（扫描）记录 Token 用量（模拟模式为估算值）
        prompt = f'扫描 AI 攻击链分析：目标 {scan.get("target")}，严重 {len(crit)} 个 / 高危 {len(high)} 个'
        output = f'攻击链模型：{"；".join(hosts_with_crit) or "无高危跳板主机"}'
        LEDGER.record('task', scan_id, f'扫描 AI 分析 {scan.get("target","")}',
                      'mock', estimate_tokens(prompt), estimate_tokens(output),
                      note='扫描阶段：AI 攻击链分析')

    # ──────────────────────────────────────────────────────────────
    # 阶段 8：报告生成（标记）
    # ──────────────────────────────────────────────────────────────
    def _stage_report(self, scan_id: str, profile: dict):
        self._log(scan_id, 'ok', '✅ LinkSec AI 渗透测试报告已准备，可在"扫描历史"页面下载')
        # v3.4：按单个任务（扫描）记录报告生成 Token（估算值）
        scan = self._scans.get(scan_id, {})
        n_vulns = len(scan.get('vuln_ids', []))
        prompt = f'生成渗透测试报告：目标 {scan.get("target")}，漏洞 {n_vulns} 个'
        output = f'报告：执行摘要/主要发现/修复建议（{n_vulns} 个漏洞）'
        LEDGER.record('task', scan_id, f'扫描报告 {scan.get("target","")}',
                      'mock', estimate_tokens(prompt), estimate_tokens(output),
                      note='扫描阶段：报告生成')

    # ──────────────────────────────────────────────────────────────
    # 辅助：添加漏洞记录（基于知识库）
    # ──────────────────────────────────────────────────────────────
    def _add_vuln(self, scan_id: str, ip: str, kb_key: str, extra_info: str = ''):
        """根据知识库 key 添加漏洞"""
        if kb_key not in VULN_KB:
            return
        name, cve, cvss, severity, service, remediation = VULN_KB[kb_key]
        # 避免重复添加同一主机同一漏洞
        existing = [
            v for v in [self._vulns.get(vid) for vid in self._scans[scan_id]['vuln_ids']]
            if v and v['cve'] == cve and v['host'] == ip
        ]
        if existing:
            return

        vuln_id = str(uuid.uuid4())[:8]
        self._vulns[vuln_id] = {
            'id':           vuln_id,
            'scan_id':      scan_id,
            'name':         name,
            'cve':          cve,
            'cvss':         cvss,
            'severity':     severity,
            'service':      service,
            'host':         ip,
            'description':  extra_info or name,
            'remediation':  remediation,
            'status':       'exploit_confirmed' if severity == 'critical' else 'detected',
            'source':       'nmap-nse',
            'discovered_at':datetime.now().isoformat(),
        }
        self._scans[scan_id]['vuln_ids'].append(vuln_id)
        level_cn = {'critical':'严重','high':'高危','medium':'中危','low':'低危'}
        tag = 'err' if severity == 'critical' else 'warn' if severity == 'high' else 'info'
        self._log(scan_id, tag, f'[NSE/{level_cn.get(severity,severity)}] {name} @ {ip} — CVSS {cvss}')

    # ──────────────────────────────────────────────────────────────
    # 辅助：按服务分组
    # ──────────────────────────────────────────────────────────────
    def _collect_services(self, scan: dict) -> dict:
        """返回 {service_name: [ip, ...]}"""
        result: dict[str, list] = {}
        svc_map = {
            'ssh':    ['ssh'],
            'ftp':    ['ftp'],
            'smb':    ['microsoft-ds', 'netbios-ssn', 'smb'],
            'snmp':   ['snmp'],
            'rdp':    ['ms-wbt-server', 'rdp'],
            'mysql':  ['mysql'],
            'http':   ['http'],
            'https':  ['https', 'ssl'],
        }
        for host in scan.get('hosts', []):
            ip = host['ip']
            for port_info in host.get('ports', []):
                svc = port_info.get('service', '').lower()
                for key, patterns in svc_map.items():
                    if any(p in svc for p in patterns):
                        result.setdefault(key, [])
                        if ip not in result[key]:
                            result[key].append(ip)
        return result

    def _collect_web_targets(self, scan: dict) -> list:
        """收集所有 HTTP/HTTPS URL"""
        targets = []
        target  = scan.get('target', '')
        # 如果目标本身是 URL
        if target.startswith('http://') or target.startswith('https://'):
            targets.append(target)
        for host in scan.get('hosts', []):
            ip = host['ip']
            for port_info in host.get('ports', []):
                svc  = port_info.get('service', '').lower()
                port = port_info.get('port', '')
                if svc in ('http', 'http-alt', 'http-proxy') or port in ('80', '8080', '8888', '3000', '5000'):
                    targets.append(f'http://{ip}:{port}')
                elif svc in ('https', 'ssl', 'https-alt') or port in ('443', '8443'):
                    targets.append(f'https://{ip}:{port}')
        return list(dict.fromkeys(targets))   # 去重保序

    # ──────────────────────────────────────────────────────────────
    # 日志
    # ──────────────────────────────────────────────────────────────
    def _log(self, scan_id: str, level: str, message: str):
        scan = self._scans.get(scan_id)
        if scan is None:
            return
        scan['logs'].append({
            'ts':      datetime.now().strftime('%H:%M:%S'),
            'level':   level,
            'message': message,
        })

    # ──────────────────────────────────────────────────────────────
    # 查询接口（对外 API）
    # ──────────────────────────────────────────────────────────────
    def get_scan(self, scan_id: str) -> Optional[dict]:
        scan = self._scans.get(scan_id)
        if not scan:
            return None
        return {k: v for k, v in scan.items() if not k.startswith('_')}

    def get_all_scans(self) -> list:
        return [
            {k: v for k, v in s.items() if not k.startswith('_')}
            for s in sorted(self._scans.values(), key=lambda x: x['started_at'], reverse=True)
        ]

    def get_vulnerabilities(self, severity=None, scan_id=None) -> list:
        vulns = list(self._vulns.values())
        if severity:
            vulns = [v for v in vulns if v['severity'] == severity]
        if scan_id:
            vulns = [v for v in vulns if v['scan_id'] == scan_id]
        return sorted(vulns, key=lambda v: v['cvss'], reverse=True)

    def get_vulnerability(self, vuln_id: str) -> Optional[dict]:
        return self._vulns.get(vuln_id)

    def get_dashboard_stats(self) -> dict:
        all_vulns = list(self._vulns.values())
        all_scans = list(self._scans.values())
        running   = [s for s in all_scans if s['status'] == 'running']
        completed = [s for s in all_scans if s['status'] == 'completed']
        by_sev    = {}
        for v in all_vulns:
            by_sev[v['severity']] = by_sev.get(v['severity'], 0) + 1
        recent = sorted(all_scans, key=lambda x: x['started_at'], reverse=True)[:5]
        return {
            'total_scans':     len(all_scans),
            'running_scans':   len(running),
            'completed_scans': len(completed),
            'total_vulns':     len(all_vulns),
            'by_severity':     by_sev,
            'tools_available': {k: bool(v) for k, v in TOOLS.items()},
            'recent_scans': [{k: v for k, v in s.items() if not k.startswith('_')} for s in recent],
        }

    def get_settings(self) -> dict:
        return {k: v for k, v in self._settings.items() if not k.startswith('_')}

    def update_settings(self, data: dict):
        self._settings.update(data)
