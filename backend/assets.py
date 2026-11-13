# -*- coding: utf-8 -*-
"""
LinkSec·AutoTest AI — 资产管理
域名 / IP / 端口 / 服务的统一归档与去重，支持导入导出、合并、
扫描覆盖跟踪、漏洞关联与风险状态。
"""
import csv
import io
import ipaddress
import json
import uuid


ASSET_TYPES = ('domain', 'ip', 'port', 'service')
ASSET_RISKS = ('high', 'medium', 'low', 'none')
ASSET_STATUS = ('active', 'offline', 'unknown')


def _uid():
    return str(uuid.uuid4())[:8]


def _now():
    import datetime
    return datetime.datetime.now().isoformat()


def norm_value(atype, value):
    v = (value or '').strip().lower()
    if atype == 'domain':
        return v.rstrip('.')
    return v


def dedup_key(atype, value):
    return f'{atype}:{norm_value(atype, value)}'


class AssetStore:
    def __init__(self, store_dict):
        self.assets = store_dict          # dict: id -> asset
        self._index = {}                  # dedup_key -> id

    def rebuild_index(self):
        self._index = {dedup_key(a['type'], a['value']): a['id'] for a in self.assets.values()}

    def create(self, atype, value, **extra):
        """创建资产；自动去重，重复时返回已存在资产。"""
        if atype not in ASSET_TYPES:
            return None, '非法资产类型'
        key = dedup_key(atype, value)
        if key in self._index and self._index[key] in self.assets:
            return self.assets[self._index[key]], 'duplicate'
        aid = _uid()
        asset = {
            'id': aid, 'type': atype, 'value': norm_value(atype, value),
            'owner': extra.get('owner', ''),
            'business': extra.get('business', ''),
            'risk': extra.get('risk', 'unknown') if extra.get('risk') in ASSET_RISKS else 'unknown',
            'status': extra.get('status', 'active'),
            'tags': extra.get('tags', []),
            'scan_ids': [], 'scan_count': 0, 'last_scan': None,
            'vuln_ids': [], 'notes': extra.get('notes', ''),
            'created_at': _now(), 'updated_at': _now(),
        }
        self.assets[aid] = asset
        self._index[key] = aid
        return asset, None

    def update(self, aid, d):
        a = self.assets.get(aid)
        if not a:
            return None
        old_key = dedup_key(a['type'], a['value'])
        for k in ('owner', 'business', 'risk', 'status', 'tags', 'notes'):
            if k in d:
                a[k] = d[k]
        if 'value' in d and d['value']:
            a['value'] = norm_value(a['type'], d['value'])
            new_key = dedup_key(a['type'], a['value'])
            if old_key != new_key:
                self._index.pop(old_key, None)
                self._index[new_key] = aid
        a['updated_at'] = _now()
        return a

    def delete(self, aid):
        a = self.assets.pop(aid, None)
        if a:
            self._index.pop(dedup_key(a['type'], a['value']), None)
        return a

    def query(self, atype=None, risk=None, status=None, q=None, page=1, per=50):
        out = list(self.assets.values())
        if atype:
            out = [a for a in out if a['type'] == atype]
        if risk:
            out = [a for a in out if a['risk'] == risk]
        if status:
            out = [a for a in out if a['status'] == status]
        if q:
            ql = q.lower()
            out = [a for a in out if ql in a['value'] or ql in a['owner'] or ql in a['business']
                   or any(ql in t.lower() for t in a.get('tags', []))]
        out.sort(key=lambda a: a['created_at'], reverse=True)
        total = len(out)
        return {'total': total, 'page': page, 'per_page': per, 'data': out[(page - 1) * per:page * per]}

    def stats(self):
        by_type = {t: 0 for t in ASSET_TYPES}
        by_risk = {'high': 0, 'medium': 0, 'low': 0, 'unknown': 0}
        covered = 0
        for a in self.assets.values():
            by_type[a['type']] = by_type.get(a['type'], 0) + 1
            by_risk[a['risk']] = by_risk.get(a['risk'], 0) + 1
            if a.get('scan_count', 0) > 0:
                covered += 1
        return {
            'total': len(self.assets), 'by_type': by_type, 'by_risk': by_risk,
            'scanned': covered,
            'with_vulns': sum(1 for a in self.assets.values() if a.get('vuln_ids')),
        }

    def merge(self, ids):
        """合并重复资产：保留最早创建的，汇聚扫描/漏洞/标签。"""
        targets = [self.assets[i] for i in ids if i in self.assets]
        if len(targets) < 2:
            return None, '至少选择 2 个资产'
        primary = min(targets, key=lambda a: a['created_at'])
        for a in targets:
            if a['id'] == primary['id']:
                continue
            primary['scan_ids'] = sorted(set(primary['scan_ids'] + a['scan_ids']))
            primary['vuln_ids'] = sorted(set(primary['vuln_ids'] + a['vuln_ids']))
            primary['tags'] = sorted(set(primary['tags'] + a['tags']))
            primary['scan_count'] = max(primary['scan_count'], a['scan_count'])
            primary['last_scan'] = primary['last_scan'] or a['last_scan']
            if primary['notes'] and a['notes']:
                primary['notes'] += f'；合并自 {a["value"]}: {a["notes"]}'
            self.delete(a['id'])
        primary['updated_at'] = _now()
        return primary, None

    def link_scan(self, aid, scan_id):
        a = self.assets.get(aid)
        if not a:
            return False
        if scan_id not in a['scan_ids']:
            a['scan_ids'].append(scan_id)
        a['scan_count'] = len(a['scan_ids'])
        a['last_scan'] = _now()
        a['updated_at'] = _now()
        return True

    def link_vuln(self, aid, vuln_id):
        a = self.assets.get(aid)
        if not a:
            return False
        if vuln_id not in a['vuln_ids']:
            a['vuln_ids'].append(vuln_id)
        a['updated_at'] = _now()
        return True

    def mark_scan_coverage(self, target, scan_id=None):
        """扫描创建后自动匹配资产并更新覆盖。target 可为 IP/CIDR/域名。
        命中资产时记录 scan_id、累计覆盖次数并刷新 last_scan。返回命中数。"""
        hits = 0
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            net = None
        for a in self.assets.values():
            matched = False
            if a['type'] == 'ip':
                try:
                    ip = ipaddress.ip_address(a['value'])
                except ValueError:
                    ip = None
                if ip and ((net and ip in net) or a['value'] == target):
                    matched = True
            elif a['type'] == 'domain' and a['value'] == target.lower().rstrip('.'):
                matched = True
            elif a['type'] in ('port', 'service') and target in a['value']:
                matched = True
            if matched:
                hits += 1
                if scan_id:
                    self.link_scan(a['id'], scan_id)
        return hits

    # ── 导入 / 导出 ────────────────────────────────────────────────────────
    def import_rows(self, rows):
        """rows: [{type,value,...}]"""
        created, dup = 0, 0
        for r in rows:
            atype = (r.get('type') or 'ip').strip().lower()
            if atype not in ASSET_TYPES or not r.get('value'):
                continue
            asset, status = self.create(atype, r['value'], owner=r.get('owner', ''),
                                        business=r.get('business', ''),
                                        risk=r.get('risk'), tags=r.get('tags', []),
                                        notes=r.get('notes', ''))
            if status == 'duplicate':
                dup += 1
            else:
                created += 1
        return created, dup

    def import_csv(self, text):
        reader = csv.DictReader(io.StringIO(text))
        rows = []
        for row in reader:
            tags = [t.strip() for t in (row.get('tags') or '').split(';') if t.strip()]
            rows.append({'type': row.get('type'), 'value': row.get('value') or row.get('asset'),
                         'owner': row.get('owner'), 'business': row.get('business'),
                         'risk': row.get('risk'), 'tags': tags, 'notes': row.get('notes')})
        return self.import_rows(rows)

    def import_json(self, text):
        data = json.loads(text)
        rows = data if isinstance(data, list) else data.get('assets', [])
        return self.import_rows(rows)

    def export_csv(self, assets=None):
        assets = assets if assets is not None else list(self.assets.values())
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(['type', 'value', 'owner', 'business', 'risk', 'status', 'tags', 'notes'])
        for a in assets:
            w.writerow([a['type'], a['value'], a['owner'], a['business'], a['risk'],
                        a['status'], ';'.join(a.get('tags', [])), a.get('notes', '')])
        return buf.getvalue()

    def export_json(self, assets=None):
        assets = assets if assets is not None else list(self.assets.values())
        return json.dumps(assets, ensure_ascii=False, indent=2)
