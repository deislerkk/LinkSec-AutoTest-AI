# -*- coding: utf-8 -*-
"""
LinkSec·AutoTest AI — 组件管理（v3.6.0）
目标主机上运行的软件组件台账：Web 服务器 / 中间件 / 框架 / 数据库 / 库 / 操作系统 / 网络设备。

组件是「资产」与「漏洞」之间的关键一层：
    资产（域名/IP）→ 组件（名称+版本）→ 漏洞/CVE 关联

- 支持从扫描结果（服务指纹）自动提取组件（名称+版本去重）
- 手动维护组件台账（厂商/类型/版本/标签）
- 组件关联主机与漏洞，支撑版本化漏洞排查（如 Log4j 2.14.x 全量排查）
"""
import uuid
from datetime import datetime

COMPONENT_TYPES = ('web_server', 'middleware', 'framework', 'database', 'library', 'os', 'device', 'other')
COMPONENT_TYPE_CN = {
    'web_server': 'Web服务器', 'middleware': '中间件', 'framework': '框架',
    'database': '数据库', 'library': '组件库', 'os': '操作系统',
    'device': '网络设备', 'other': '其他',
}
# 常见服务名 → 组件类型映射（用于扫描指纹自动分类）
SERVICE_TYPE_MAP = {
    'http': 'web_server', 'https': 'web_server', 'nginx': 'web_server',
    'apache': 'web_server', 'iis': 'web_server', 'tomcat': 'web_server',
    'jetty': 'web_server', 'lighttpd': 'web_server', 'caddy': 'web_server',
    'weblogic': 'middleware', 'websphere': 'middleware', 'jboss': 'middleware',
    'mysql': 'database', 'mariadb': 'database', 'postgresql': 'database',
    'mongodb': 'database', 'redis': 'database', 'oracle': 'database',
    'mssql': 'database', 'elasticsearch': 'database',
    'ssh': 'other', 'openssh': 'other', 'ftp': 'other', 'vsftpd': 'other',
    'smtp': 'other', 'dns': 'other', 'rdp': 'other', 'smb': 'other',
    'telnet': 'other', 'snmp': 'other', 'ldap': 'other', 'vnc': 'other',
}


def _uid():
    return str(uuid.uuid4())[:8]


def _now():
    return datetime.now().isoformat(timespec='seconds')


def classify_service(service, product):
    s = ((service or '') + ' ' + (product or '')).lower()
    for key, ctype in SERVICE_TYPE_MAP.items():
        if key in s:
            return ctype
    return 'other'


class ComponentStore:
    def __init__(self, store_dict):
        self.components = store_dict      # dict: id -> component
        self._index = {}                  # (name_lower, version_lower) -> id

    def rebuild_index(self):
        self._index = {
            (c['name'].lower(), (c.get('version') or '').lower()): c['id']
            for c in self.components.values()
        }

    def create(self, name, version='', ctype='other', **extra):
        if not name or not name.strip():
            return None, '组件名不能为空'
        key = (name.strip().lower(), (version or '').strip().lower())
        if key in self._index and self._index[key] in self.components:
            return self.components[self._index[key]], 'duplicate'
        cid = _uid()
        comp = {
            'id': cid, 'name': name.strip(),
            'vendor': extra.get('vendor', ''),
            'type': ctype if ctype in COMPONENT_TYPES else 'other',
            'version': (version or '').strip(),
            'hosts': [],              # [{ip, port, service, scan_id}]
            'asset_ids': extra.get('asset_ids', []),
            'vuln_ids': extra.get('vuln_ids', []),
            'tags': extra.get('tags', []),
            'notes': extra.get('notes', ''),
            'source': extra.get('source', 'manual'),   # manual | scan
            'created_at': _now(), 'updated_at': _now(),
        }
        self.components[cid] = comp
        self._index[key] = cid
        return comp, None

    def update(self, cid, d):
        c = self.components.get(cid)
        if not c:
            return None
        for k in ('name', 'vendor', 'type', 'version', 'tags', 'notes'):
            if k in d:
                c[k] = d[k]
        c['updated_at'] = _now()
        self.rebuild_index()
        return c

    def delete(self, cid):
        c = self.components.pop(cid, None)
        if c:
            self.rebuild_index()
        return c

    def query(self, ctype=None, q=None, page=1, per=50):
        out = list(self.components.values())
        if ctype:
            out = [c for c in out if c['type'] == ctype]
        if q:
            ql = q.lower()
            out = [c for c in out if ql in c['name'].lower() or ql in (c.get('vendor') or '').lower()
                   or ql in (c.get('version') or '').lower()]
        out.sort(key=lambda c: (-len(c.get('hosts', [])), c['name'].lower()))
        total = len(out)
        return {'total': total, 'page': page, 'per_page': per, 'data': out[(page - 1) * per:page * per]}

    def stats(self):
        by_type = {t: 0 for t in COMPONENT_TYPES}
        hosts = set()
        with_vulns = 0
        for c in self.components.values():
            by_type[c['type']] = by_type.get(c['type'], 0) + 1
            for h in c.get('hosts', []):
                hosts.add(f"{h.get('ip')}:{h.get('port')}")
            if c.get('vuln_ids'):
                with_vulns += 1
        return {'total': len(self.components), 'by_type': by_type,
                'hosts_covered': len(hosts), 'with_vulns': with_vulns}

    def link_vuln(self, cid, vuln_id):
        c = self.components.get(cid)
        if not c:
            return False
        if vuln_id not in c['vuln_ids']:
            c['vuln_ids'].append(vuln_id)
            c['updated_at'] = _now()
        return True

    def add_host(self, cid, ip, port, service, scan_id=''):
        c = self.components.get(cid)
        if not c:
            return False
        for h in c['hosts']:
            if h.get('ip') == ip and str(h.get('port')) == str(port):
                return True   # 已存在
        c['hosts'].append({'ip': ip, 'port': port, 'service': service, 'scan_id': scan_id})
        c['updated_at'] = _now()
        return True

    # ── 从扫描结果自动提取组件 ────────────────────────────────────────────────
    def extract_from_scan(self, scan):
        """解析扫描结果的 hosts/ports 服务指纹，自动创建/更新组件并关联主机。"""
        created, updated = 0, 0
        for h in scan.get('hosts', []):
            ip = h.get('ip', '')
            for p in h.get('ports', []):
                service = p.get('service') or p.get('name') or ''
                product = p.get('product') or ''
                version = p.get('version') or ''
                name = product or service
                if not name or service.lower() in ('tcpwrapped',):
                    continue
                ctype = classify_service(service, product)
                comp, status = self.create(name, version, ctype, source='scan')
                if status == 'duplicate':
                    updated += 1
                else:
                    created += 1
                self.add_host(comp['id'], ip, p.get('port', ''), service, scan.get('id', ''))
        return created, updated

    def extract_by_scan_id(self, scan_getter, scan_id):
        scan = scan_getter(scan_id)
        if not scan:
            return None, '扫描不存在'
        return self.extract_from_scan(scan), None
