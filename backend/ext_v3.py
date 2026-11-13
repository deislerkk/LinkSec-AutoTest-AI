# -*- coding: utf-8 -*-
"""
LinkSec·AutoTest AI v3.3 — 扩展模块（补齐功能）

新增能力：
  · 资产管理（域名/IP/端口/服务 归档、去重、合并、导入导出、扫描覆盖、漏洞关联）
  · 平台 RBAC（多用户 / 角色 / 登录令牌 / 按资源鉴权）
  · 人机协同审批（高危操作审批模式，决策留痕，通过后自动回放执行）
  · 机器人接入（企业微信/钉钉/飞书/Slack/Telegram/QQ/通用 Webhook 通道管理）
  · SQLite 持久化（内存存储快照落盘，重启恢复）
  · 漏洞状态流转（detected→confirmed→exploited→remediated）
  · 攻击链图谱 + 步骤回放数据
  · AI 多智能体编排（single / deep / plan-execute / supervisor）
  · 渗透报告导出（Markdown / HTML）

注：未包含任何目标域名/网站拦截（如政府域名保护）功能。
"""
import re
import uuid

from flask import jsonify, request, Response

import storage as storage_mod
import rbac as rbac_mod
import assets as assets_mod
import approvals as approvals_mod
import bots as bots_mod
import token_usage as token_mod

# 高危操作（需审批）：method + 正则路径 → 展示名
HIGH_RISK_RULES = (
    (re.compile(r'^POST$'), re.compile(r'^/api/c2/sessions/[^/]+/command$'), 'C2 指令下发'),
    (re.compile(r'^POST$'), re.compile(r'^/api/webshells/[^/]+/exec$'), 'WebShell 执行'),
    (re.compile(r'^POST$'), re.compile(r'^/api/terminal/exec$'), '终端命令执行'),
    (re.compile(r'^POST$'), re.compile(r'^/api/terminal/stream$'), '终端流式执行'),
    (re.compile(r'^POST$'), re.compile(r'^/api/skills/[^/]+/execute$'), '技能包执行'),
    (re.compile(r'^POST$'), re.compile(r'^/api/c2/payload$'), 'Payload 生成'),
)

VULN_STATUS_FLOW = {
    'detected':   ('confirmed', 'remediated'),
    'confirmed':  ('exploited', 'remediated', 'detected'),
    'exploited':  ('remediated', 'confirmed'),
    'remediated': ('detected',),
}
VULN_STATUS_CN = {'detected': '已检测', 'confirmed': '已确认', 'exploited': '已验证利用', 'remediated': '已修复'}


def _uid():
    return str(uuid.uuid4())[:8]


def _now():
    import datetime
    return datetime.datetime.now().isoformat()


def register(app, G):
    """G 为 app.py 的 globals()：提供内存存储与工具函数。"""
    _audit = G.get('_audit')
    scan_engine = G['scan_engine']
    ai_analyst = G['ai_analyst']

    # ── 新增内存存储 ────────────────────────────────────────────────────────
    users = {}
    roles = {}
    _assets = {}
    _approvals = {}
    _bot_channels = {}

    # ── SQLite 持久化 ───────────────────────────────────────────────────────
    storage = storage_mod.Storage()
    for name in ('projects', 'vulns_db', 'chains', 'webshells', 'c2_sessions',
                 'knowledge', 'skills', 'tasks', 'audit_logs', 'notifications'):
        ref = G.get('_' + name)
        if ref is not None:
            storage.register(name, ref)
    storage.register('scans', scan_engine._scans)
    storage.register('vulns', scan_engine._vulns)
    storage.register('users', users)
    storage.register('roles', roles)
    storage.register('assets', _assets)
    storage.register('approvals', _approvals)
    storage.register('bot_channels', _bot_channels)
    storage.register('token_records', token_mod.LEDGER.records)
    storage.load()

    # ── RBAC ────────────────────────────────────────────────────────────────
    rbac = rbac_mod.RBAC(users, roles)
    settings = scan_engine.get_settings()
    settings.setdefault('auth_enabled', True)
    settings.setdefault('approval_mode', False)
    settings.setdefault('ai_mode', 'single')

    def auth_enabled():
        return bool(scan_engine.get_settings().get('auth_enabled', True))

    auth_gate = rbac_mod.make_auth_gate(rbac, auth_enabled)

    # ── 资产 / 审批 ─────────────────────────────────────────────────────────
    asset_store = assets_mod.AssetStore(_assets)
    asset_store.rebuild_index()
    approvals = approvals_mod.ApprovalStore(_approvals, audit_cb=_audit)

    # ── 全局钩子：登录保护 → 审批拦截 ──────────────────────────────────────
    @app.before_request
    def _gate_auth():
        return auth_gate()

    @app.before_request
    def _gate_approval():
        if request.method == 'OPTIONS':
            return None
        if not request.path.startswith('/api/'):
            return None
        # 审批通过后的回放执行，直接放行
        exec_aid = request.headers.get('X-Approval-Exec', '')
        if exec_aid and _approvals.get(exec_aid, {}).get('status') == 'approved':
            return None
        if not scan_engine.get_settings().get('approval_mode', False):
            return None
        user = getattr(request, '_user', None)
        if not user:
            return None  # 未登录由鉴权门处理
        if user.get('role') == 'admin':
            return None  # 管理员直接执行
        for mre, pre, name in HIGH_RISK_RULES:
            if mre.match(request.method) and pre.match(request.path):
                body = request.get_json(silent=True) or {}
                a = approvals.create(name, request.method, request.path, body,
                                     request.query_string.decode('utf-8'),
                                     user.get('username', ''))
                return jsonify({
                    'status': 'pending_approval',
                    'approval_id': a['id'],
                    'message': f'操作「{name}」需要审批，已生成审批单 {a["id"]}',
                }), 202
        return None

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 认证 / 用户 / 角色
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    @app.route('/api/auth/login', methods=['POST'])
    def auth_login():
        d = request.get_json(silent=True) or {}
        token, err = rbac.login(d.get('username', ''), d.get('password', ''))
        if not token:
            return jsonify({'error': err}), 401
        user = rbac.resolve(token)
        _audit('auth_login', f'用户 {user["username"]} 登录')
        return jsonify({'token': token, 'user': {k: user[k] for k in
                        ('id', 'username', 'name', 'role') if k in user}})

    @app.route('/api/auth/logout', methods=['POST'])
    def auth_logout():
        rbac.logout(rbac_mod.extract_token())
        return jsonify({'status': 'ok'})

    @app.route('/api/auth/me', methods=['GET'])
    def auth_me():
        user = getattr(request, '_user', None) or rbac.resolve(rbac_mod.extract_token())
        if not user:
            return jsonify({'error': '未登录'}), 401
        return jsonify({k: user[k] for k in ('id', 'username', 'name', 'role') if k in user})

    @app.route('/api/auth/password', methods=['PUT'])
    def auth_password():
        user = getattr(request, '_user', None)
        if not user:
            return jsonify({'error': '未登录'}), 401
        d = request.get_json(silent=True) or {}
        ok, err = rbac.change_password(user['username'], d.get('old_password', ''), d.get('new_password', ''))
        if not ok:
            return jsonify({'error': err}), 400
        _audit('auth_password', f'用户 {user["username"]} 修改密码')
        return jsonify({'status': 'ok'})

    @app.route('/api/users', methods=['GET'])
    def list_users():
        return jsonify([{k: u[k] for k in ('id', 'username', 'name', 'role', 'status', 'created_at', 'last_login') if k in u}
                        for u in users.values()])

    @app.route('/api/users', methods=['POST'])
    def create_user():
        d = request.get_json(silent=True) or {}
        u, err = rbac.create_user(d.get('username', ''), d.get('password', ''), d.get('role', 'viewer'), d.get('name', ''))
        if not u:
            return jsonify({'error': err}), 400
        _audit('user_create', f'创建用户 {u["username"]}（{u["role"]}）')
        return jsonify({k: u[k] for k in ('id', 'username', 'name', 'role', 'status', 'created_at')}), 201

    @app.route('/api/users/<username>', methods=['PUT', 'DELETE'])
    def user_ops(username):
        if request.method == 'PUT':
            u = users.get(username)
            if not u:
                return jsonify({'error': '用户不存在'}), 404
            d = request.get_json(silent=True) or {}
            if 'role' in d and d['role'] in rbac_mod.ROLE_NAMES:
                u['role'] = d['role']
            if 'name' in d:
                u['name'] = d['name']
            if 'status' in d:
                u['status'] = d['status']
            if d.get('password'):
                import hashlib, secrets
                u['salt'] = secrets.token_hex(8)
                u['pwd'] = hashlib.sha256((u['salt'] + d['password']).encode()).hexdigest()
            _audit('user_update', f'更新用户 {username}')
            return jsonify(u)
        me = getattr(request, '_user', None)
        ok, err = rbac.delete_user(username, me.get('username') if me else '')
        if not ok:
            return jsonify({'error': err}), 400
        _audit('user_delete', f'删除用户 {username}')
        return jsonify({'deleted': username})

    @app.route('/api/roles', methods=['GET'])
    def list_roles():
        return jsonify(list(roles.values()))

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 资产管理
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    @app.route('/api/assets', methods=['GET'])
    def list_assets():
        return jsonify(asset_store.query(
            atype=request.args.get('type'), risk=request.args.get('risk'),
            status=request.args.get('status'), q=request.args.get('q'),
            page=int(request.args.get('page', 1)), per=int(request.args.get('per_page', 50))))

    @app.route('/api/assets', methods=['POST'])
    def create_asset():
        d = request.get_json(silent=True) or {}
        asset, dup = asset_store.create(d.get('type', 'ip'), d.get('value', ''),
                                        owner=d.get('owner', ''), business=d.get('business', ''),
                                        risk=d.get('risk'), tags=d.get('tags', []), notes=d.get('notes', ''))
        if asset is None:
            return jsonify({'error': dup}), 400
        if dup == 'duplicate':
            return jsonify({'asset': asset, 'duplicate': True}), 200
        _audit('asset_create', f'新增资产 {asset["type"]}:{asset["value"]}')
        return jsonify(asset), 201

    @app.route('/api/assets/stats', methods=['GET'])
    def assets_stats():
        return jsonify(asset_store.stats())

    @app.route('/api/assets/import', methods=['POST'])
    def import_assets():
        d = request.get_json(silent=True) or {}
        fmt = d.get('format', 'csv')
        content = d.get('content', '')
        try:
            if fmt == 'json':
                created, dup = asset_store.import_json(content)
            else:
                created, dup = asset_store.import_csv(content)
        except Exception as e:
            return jsonify({'error': f'解析失败：{e}'}), 400
        _audit('asset_import', f'导入资产：新增 {created}，去重 {dup}')
        return jsonify({'created': created, 'duplicated': dup})

    @app.route('/api/assets/export', methods=['GET'])
    def export_assets():
        fmt = request.args.get('format', 'csv')
        if fmt == 'json':
            body, mime = asset_store.export_json(), 'application/json'
        else:
            body, mime = asset_store.export_csv(), 'text/csv; charset=utf-8'
        return Response(body, mimetype=mime, headers={
            'Content-Disposition': f'attachment; filename=assets.{fmt}'})

    @app.route('/api/assets/merge', methods=['POST'])
    def merge_assets():
        d = request.get_json(silent=True) or {}
        primary, err = asset_store.merge(d.get('ids', []))
        if primary is None:
            return jsonify({'error': err}), 400
        _audit('asset_merge', f'合并资产 → {primary["type"]}:{primary["value"]}')
        return jsonify(primary)

    @app.route('/api/assets/<aid>', methods=['GET', 'PUT', 'DELETE'])
    def asset_ops(aid):
        if request.method == 'GET':
            a = _assets.get(aid)
            return jsonify(a) if a else (jsonify({'error': '不存在'}), 404)
        if request.method == 'PUT':
            a = asset_store.update(aid, request.get_json(silent=True) or {})
            if not a:
                return jsonify({'error': '不存在'}), 404
            _audit('asset_update', f'更新资产 {a["type"]}:{a["value"]}')
            return jsonify(a)
        a = asset_store.delete(aid)
        if not a:
            return jsonify({'error': '不存在'}), 404
        _audit('asset_delete', f'删除资产 {a["type"]}:{a["value"]}')
        return jsonify({'deleted': aid})

    @app.route('/api/assets/<aid>/link-vuln', methods=['POST'])
    def asset_link_vuln(aid):
        d = request.get_json(silent=True) or {}
        if not asset_store.link_vuln(aid, d.get('vuln_id', '')):
            return jsonify({'error': '资产不存在'}), 404
        return jsonify({'status': 'ok'})

    @app.route('/api/assets/<aid>/link-scan', methods=['POST'])
    def asset_link_scan(aid):
        d = request.get_json(silent=True) or {}
        if not asset_store.link_scan(aid, d.get('scan_id', '')):
            return jsonify({'error': '资产不存在'}), 404
        return jsonify({'status': 'ok'})

    # 扫描创建后自动匹配资产覆盖：见 app.py create_scan 中的调用
    # （app.ext_v3['assets'].mark_scan_coverage(target)）

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 机器人接入
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    @app.route('/api/bots/types', methods=['GET'])
    def bot_types():
        return jsonify(bots_mod.CHANNEL_DEFS)

    @app.route('/api/bots/channels', methods=['GET'])
    def list_bot_channels():
        return jsonify(list(_bot_channels.values()))

    @app.route('/api/bots/channels', methods=['POST'])
    def create_bot_channel():
        d = request.get_json(silent=True) or {}
        ctype = d.get('type', 'webhook')
        if ctype not in bots_mod.CHANNEL_DEFS:
            return jsonify({'error': f'不支持的通道类型：{ctype}'}), 400
        cid = _uid()
        _bot_channels[cid] = {
            'id': cid, 'name': d.get('name', bots_mod.CHANNEL_DEFS[ctype]['name']),
            'type': ctype, 'config': d.get('config', {}),
            'enabled': d.get('enabled', True), 'created_at': _now(),
        }
        _audit('bot_channel_create', f'新增机器人通道 {_bot_channels[cid]["name"]}（{ctype}）')
        return jsonify(_bot_channels[cid]), 201

    @app.route('/api/bots/channels/<cid>', methods=['PUT', 'DELETE'])
    def bot_channel_ops(cid):
        ch = _bot_channels.get(cid)
        if not ch:
            return jsonify({'error': '不存在'}), 404
        if request.method == 'PUT':
            d = request.get_json(silent=True) or {}
            if 'config' in d:
                ch['config'].update(d['config'])
            for k in ('name', 'enabled'):
                if k in d:
                    ch[k] = d[k]
            return jsonify(ch)
        del _bot_channels[cid]
        _audit('bot_channel_delete', f'删除机器人通道 {ch["name"]}')
        return jsonify({'deleted': cid})

    @app.route('/api/bots/channels/<cid>/test', methods=['POST'])
    def test_bot_channel(cid):
        ch = _bot_channels.get(cid)
        if not ch:
            return jsonify({'error': '不存在'}), 404
        d = request.get_json(silent=True) or {}
        status = bots_mod.send_to_channel(ch, d.get('title', 'LinkSec 测试通知'),
                                          d.get('message', '通道连接测试'))
        return jsonify({'channel_id': cid, 'status': status})

    @app.route('/api/bots/send', methods=['POST'])
    def bots_send():
        d = request.get_json(silent=True) or {}
        cids = d.get('channel_ids') or list(_bot_channels.keys())
        title, message = d.get('title', ''), d.get('message', '')
        results = {}
        for cid in cids:
            ch = _bot_channels.get(cid)
            if not ch:
                results[cid] = '通道不存在'
                continue
            results[cid] = bots_mod.send_to_channel(ch, title, message)
        _audit('bot_send', f'机器人通知「{title}」→ {len(cids)} 个通道')
        return jsonify(results)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 人机协同审批
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    @app.route('/api/approvals', methods=['GET'])
    def list_approvals():
        return jsonify(approvals.list(status=request.args.get('status')))

    @app.route('/api/approvals/<aid>', methods=['GET'])
    def get_approval(aid):
        a = _approvals.get(aid)
        return jsonify(a) if a else (jsonify({'error': '不存在'}), 404)

    @app.route('/api/approvals/<aid>/approve', methods=['POST'])
    def approve_approval(aid):
        user = getattr(request, '_user', None)
        if not user:
            return jsonify({'error': '未登录'}), 401
        a, err = approvals.decide(aid, 'approve', user.get('username', ''))
        if not a:
            return jsonify({'error': err}), 400
        if a['status'] != 'approved':
            return jsonify({'error': err or '状态异常'}), 409
        # 回放执行原始请求（带审批放行头）
        try:
            with app.test_client() as c:
                resp = c.open(a['path'], method=a['method'], json=a['json_body'],
                              query_string=a['query_string'],
                              headers={'X-Approval-Exec': aid,
                                       'Authorization': 'Bearer ' + (rbac_mod.extract_token() or '')})
                result = resp.get_json(silent=True)
                approvals.record_exec(aid, 'executed' if resp.status_code < 400 else 'failed',
                                      result, resp.status_code)
                return jsonify({'status': 'executed', 'approval': _approvals[aid]}), resp.status_code
        except Exception as e:
            approvals.record_exec(aid, 'failed', str(e))
            return jsonify({'error': f'执行失败：{e}'}), 500

    @app.route('/api/approvals/<aid>/deny', methods=['POST'])
    def deny_approval(aid):
        user = getattr(request, '_user', None)
        if not user:
            return jsonify({'error': '未登录'}), 401
        a, err = approvals.decide(aid, 'deny', user.get('username', ''))
        if not a:
            return jsonify({'error': err}), 400
        return jsonify(a)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 漏洞状态流转
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    @app.route('/api/vulnerabilities/<vid>/status', methods=['POST'])
    def vuln_status(vid):
        v = scan_engine.get_vulnerability(vid)
        if not v:
            return jsonify({'error': '不存在'}), 404
        d = request.get_json(silent=True) or {}
        new_status = d.get('status')
        cur = v.get('status', 'detected')
        if new_status not in VULN_STATUS_FLOW:
            return jsonify({'error': '非法状态'}), 400
        if cur != new_status and new_status not in VULN_STATUS_FLOW.get(cur, ()):
            return jsonify({'error': f'不允许的状态流转：{cur} → {new_status}'}), 400
        v['status'] = new_status
        if new_status == 'remediated':
            v['remediated_at'] = _now()
        _audit('vuln_status', f'漏洞 {vid} 状态：{VULN_STATUS_CN.get(cur)} → {VULN_STATUS_CN.get(new_status)}')
        return jsonify(v)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 攻击链图谱 + 步骤回放
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    @app.route('/api/chains/<cid>/graph', methods=['GET'])
    def chain_graph(cid):
        c = G.get('_chains', {}).get(cid)
        if not c:
            return jsonify({'error': '不存在'}), 404
        nodes, edges = [], []
        prev = None
        for i, s in enumerate(c.get('steps', [])):
            nid = f'n{i}'
            nodes.append({'id': nid, 'label': s.get('action', '')[:28],
                          'target': s.get('target', ''), 'result': s.get('result', ''),
                          'status': s.get('status', 'done'), 'timestamp': s.get('timestamp', '')})
            if prev:
                edges.append({'from': prev, 'to': nid})
            prev = nid
        return jsonify({'id': cid, 'name': c.get('name'), 'nodes': nodes, 'edges': edges})

    @app.route('/api/chains/<cid>/steps', methods=['POST'])
    def chain_add_step(cid):
        c = G.get('_chains', {}).get(cid)
        if not c:
            return jsonify({'error': '不存在'}), 404
        d = request.get_json(silent=True) or {}
        step = {'action': d.get('action', ''), 'target': d.get('target', ''),
                'result': d.get('result', ''), 'status': d.get('status', 'done'),
                'timestamp': _now()}
        c.setdefault('steps', []).append(step)
        _audit('chain_step', f'攻击链 {cid} 新增步骤：{step["action"][:40]}')
        return jsonify(step), 201

    @app.route('/api/chains/<cid>/steps/<int:idx>', methods=['PUT'])
    def chain_update_step(cid, idx):
        c = G.get('_chains', {}).get(cid)
        if not c:
            return jsonify({'error': '不存在'}), 404
        steps = c.get('steps', [])
        if idx >= len(steps):
            return jsonify({'error': '步骤不存在'}), 404
        d = request.get_json(silent=True) or {}
        steps[idx].update({k: d[k] for k in ('action', 'target', 'result', 'status') if k in d})
        return jsonify(steps[idx])

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # AI 多智能体编排
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    @app.route('/api/ai/orchestrate', methods=['POST'])
    def ai_orchestrate():
        d = request.get_json(silent=True) or {}
        goal = d.get('goal', '')
        mode = d.get('mode', scan_engine.get_settings().get('ai_mode', 'single'))
        if not goal:
            return jsonify({'error': '目标不能为空'}), 400
        result = ai_analyst.orchestrate(goal, mode)
        # v3.4：编排调用计入单个对话（与 /api/ai/analyze 同会话可聚合）
        if result.get('usage'):
            u = result['usage']
            conv_id = d.get('conversation_id') or f'conv_{_uid()}'
            token_mod.LEDGER.record('conversation', conv_id, goal[:40],
                                    result.get('model', 'unknown'),
                                    u.get('prompt_tokens', 0), u.get('completion_tokens', 0),
                                    note=f'编排模式 {mode}')
            result['conversation_id'] = conv_id
        _audit('ai_orchestrate', f'AI 编排（{mode}）：{goal[:60]}')
        return jsonify(result)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Token 用量（v3.4：按单个任务 / 单次对话维度，非全局汇总）
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    @app.route('/api/ai/tokens', methods=['GET'])
    def list_tokens():
        scope = request.args.get('scope', 'conversation')
        if scope not in ('conversation', 'task'):
            return jsonify({'error': 'scope 必须为 conversation 或 task'}), 400
        return jsonify(token_mod.LEDGER.by_scope(scope))

    @app.route('/api/ai/tokens/stats', methods=['GET'])
    def token_stats():
        return jsonify(token_mod.LEDGER.stats())

    @app.route('/api/ai/tokens/<scope_id>', methods=['GET'])
    def token_detail(scope_id):
        rows = token_mod.LEDGER.detail(scope_id)
        if not rows:
            return jsonify({'error': '无记录'}), 404
        total = sum(r['total_tokens'] for r in rows)
        return jsonify({
            'scope_id': scope_id,
            'records': rows,
            'total_tokens': total,
            'prompt_tokens': sum(r['prompt_tokens'] for r in rows),
            'completion_tokens': sum(r['completion_tokens'] for r in rows),
        })

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 报告导出
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    @app.route('/api/ai/report/<scan_id>/export', methods=['GET'])
    def export_report(scan_id):
        s = scan_engine.get_scan(scan_id)
        if not s:
            return jsonify({'error': '扫描不存在'}), 404
        fmt = request.args.get('format', 'markdown')
        gen = ai_analyst.generate_report(s)
        report = gen.get('report', '')
        # v3.4：导出报告同样计入该任务 Token
        if gen.get('usage'):
            u = gen['usage']
            token_mod.LEDGER.record('task', scan_id, f'报告导出 {scan_id}',
                                    gen.get('model', 'unknown'),
                                    u.get('prompt_tokens', 0), u.get('completion_tokens', 0),
                                    note=f'导出格式 {fmt}')
        if fmt == 'html':
            import html as _html
            body = ('<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">'
                    '<title>渗透测试报告</title><style>body{font-family:sans-serif;max-width:820px;margin:24px auto;line-height:1.7}'
                    'pre{white-space:pre-wrap;background:#f6f8fa;padding:16px;border-radius:8px}</style></head>'
                    f'<body><pre>{_html.escape(report)}</pre></body></html>')
            return Response(body, mimetype='text/html', headers={
                'Content-Disposition': f'attachment; filename=report_{scan_id}.html'})
        return Response(report, mimetype='text/markdown', headers={
            'Content-Disposition': f'attachment; filename=report_{scan_id}.md'})

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 存储信息
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    @app.route('/api/storage/info', methods=['GET'])
    def storage_info():
        return jsonify({'db_path': storage.path, 'stores': sorted(storage._stores.keys())})

    storage.start_autosave(interval=10)
    storage.save()
    import atexit
    atexit.register(storage.save)

    # 暴露给 app.py（可选扩展）
    app.ext_v3 = {
        'storage': storage, 'rbac': rbac, 'assets': asset_store,
        'approvals': approvals, 'channels': _bot_channels,
        'save': storage.save,
    }
    print('[ext_v3] v3.3 扩展模块已加载：资产管理 / RBAC / 审批 / 机器人 / SQLite 持久化 / AI 编排 / Token 用量统计')
    return app.ext_v3
