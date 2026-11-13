# -*- coding: utf-8 -*-
"""
LinkSec·AutoTest AI — 平台 RBAC
多用户、系统角色（admin/operator/viewer）、登录令牌、权限校验。

权限模型：
    admin    — 全部权限（含用户/角色/机器人通道/审批管理）
    operator — 安全运营写权限（扫描/漏洞/资产/攻击链/C2/WebShell/终端/知识/技能/任务/报告）
    viewer   — 只读（所有 GET）
"""
import hashlib
import secrets
import time
from functools import wraps

from flask import g, jsonify, request

ROLE_PERMS = {
    'admin': {'*'},
    'operator': {
        'scan:write', 'vuln:write', 'asset:write', 'chain:write', 'c2:write',
        'webshell:write', 'terminal:write', 'knowledge:write', 'skill:write',
        'task:write', 'bot:write', 'approval:write', 'report:write',
        'project:write',
    },
    'viewer': set(),
}
ROLE_NAMES = {'admin': '管理员', 'operator': '操作员', 'viewer': '观察员'}
# 与「角色」同名的资源写权限（viewer 全部只读）
RESOURCE_WRITE = {
    'projects': 'project:write', 'scans': 'scan:write', 'vulnerabilities': 'vuln:write',
    'assets': 'asset:write', 'chains': 'chain:write', 'c2': 'c2:write',
    'webshells': 'webshell:write', 'terminal': 'terminal:write',
    'knowledge': 'knowledge:write', 'skills': 'skill:write',
    'tasks': 'task:write', 'bots': 'bot:write', 'approvals': 'approval:write',
    'ai': 'report:write', 'notifications': 'bot:write',
}
ADMIN_ONLY_RES = {'users', 'roles'}


# ── 密码哈希（v3.5：scrypt 内存难哈希，替代 SHA-256+短盐）───────────────────
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1


def _hash_scrypt(pwd, salt_hex):
    return hashlib.scrypt(pwd.encode('utf-8'), salt=bytes.fromhex(salt_hex),
                          n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32).hex()


def _legacy_hash(pwd, salt):
    """兼容 v3.4 及更早的 SHA-256 格式（仅用于登录校验，校验通过后自动升级）。"""
    return hashlib.sha256((salt + pwd).encode('utf-8')).hexdigest()


def _make_pwd_hash(password):
    salt = secrets.token_hex(16)
    return f'scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt}${_hash_scrypt(password, salt)}'


def _verify_pwd(password, stored):
    """校验 scrypt 格式哈希，返回 (ok, needs_upgrade)。"""
    if stored and stored.startswith('scrypt$'):
        try:
            _, n, r, p, salt, h = stored.split('$')
            calc = hashlib.scrypt(password.encode('utf-8'), salt=bytes.fromhex(salt),
                                  n=int(n), r=int(r), p=int(p), dklen=32).hex()
            return calc == h, False
        except Exception:
            return False, False
    return False, False


class RBAC:
    def __init__(self, users_store, roles_store, token_ttl=86400):
        self.users = users_store    # dict: username -> user
        self.roles = roles_store    # dict: role -> {name, perms:[...]}
        self.tokens = {}            # token -> {'user': username, 'expires': ts}
        self.token_ttl = token_ttl
        self.ensure_roles()

    def ensure_roles(self):
        for r, name in ROLE_NAMES.items():
            self.roles.setdefault(r, {'id': r, 'name': name, 'perms': sorted(ROLE_PERMS[r])})
        if not self.users:
            self.users['admin'] = self._mk_user('admin', 'admin123', 'admin', '系统管理员')
            self.users['admin']['must_change_password'] = True
            print('[rbac] 已创建默认管理员 admin / admin123（首次登录需修改密码）')

    def _mk_user(self, username, password, role, name=''):
        now = time.strftime('%Y-%m-%dT%H:%M:%S')
        return {
            'id': username, 'username': username, 'name': name or username,
            'role': role if role in ROLE_NAMES else 'viewer',
            'pwd': _make_pwd_hash(password),
            'must_change_password': True,
            'status': 'active', 'created_at': now, 'last_login': None,
        }

    # ── 登录 / 令牌 ─────────────────────────────────────────────────────────
    def login(self, username, password):
        u = self.users.get(username)
        if not u or u.get('status') != 'active':
            return None, '用户名不存在或已禁用'
        ok, upgrade = self._check(u, password)
        if not ok:
            return None, '密码错误'
        if upgrade:
            u['pwd'] = _make_pwd_hash(password)
        token = secrets.token_hex(24)
        self.tokens[token] = {'user': username, 'expires': time.time() + self.token_ttl}
        u['last_login'] = time.strftime('%Y-%m-%dT%H:%M:%S')
        return token, None

    def _check(self, u, password):
        stored = u.get('pwd', '')
        if stored and stored.startswith('scrypt$'):
            return _verify_pwd(password, stored)
        # 旧格式兼容：salt 字段仍在用户记录中（v3.4 迁移场景）
        salt = u.get('salt', '')
        if salt:
            return _legacy_hash(password, salt) == stored, True
        return False, False

    def logout(self, token):
        return self.tokens.pop(token, None) is not None

    def resolve(self, token):
        if not token:
            return None
        t = self.tokens.get(token)
        if not t:
            return None
        if time.time() > t['expires']:
            self.tokens.pop(token, None)
            return None
        return self.users.get(t['user'])

    def has_perm(self, user, perm):
        if not user:
            return False
        role = self.roles.get(user.get('role'), {})
        perms = set(role.get('perms', [])) | ROLE_PERMS.get(user.get('role'), set())
        return '*' in perms or perm in perms

    # ── 用户管理 ───────────────────────────────────────────────────────────
    def create_user(self, username, password, role, name=''):
        if username in self.users:
            return None, '用户已存在'
        self.users[username] = self._mk_user(username, password, role, name)
        return self.users[username], None

    def change_password(self, username, old, new):
        u = self.users.get(username)
        if not u:
            return False, '用户不存在'
        if not new or len(new) < 8:
            return False, '新密码至少 8 位'
        ok, _ = self._check(u, old)
        if not ok:
            return False, '原密码错误'
        u.pop('salt', None)
        u['pwd'] = _make_pwd_hash(new)
        u['must_change_password'] = False
        return True, None

    def delete_user(self, username, by):
        if username == 'admin':
            return False, '不能删除默认管理员'
        if username == by:
            return False, '不能删除自己'
        u = self.users.pop(username, None)
        return u is not None, None


def extract_token():
    """从 Authorization: Bearer <t> 或 ?token= 提取令牌。"""
    h = request.headers.get('Authorization', '')
    if h.startswith('Bearer '):
        return h[7:].strip()
    return request.args.get('token', '')


def make_require_perm(rbac, perm):
    def require_perm(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = rbac.resolve(extract_token())
            if not user:
                return jsonify({'error': '未登录或会话已过期'}), 401
            if not rbac.has_perm(user, perm):
                return jsonify({'error': f'无权限：{perm}（当前角色 {user.get("role")}）'}), 403
            request._user = user
            return fn(*args, **kwargs)
        return wrapper
    return require_perm


def make_auth_gate(rbac, auth_enabled_getter):
    """全局 before_request：登录保护 + 按资源/方法鉴权。返回 None 放行，否则返回响应。"""
    def gate():
        # SSE 流无事件源自动跨域问题，仍走 token 查询参数
        if request.path == '/api/auth/login' or request.path == '/api/health':
            return None
        if not request.path.startswith('/api/'):
            return None
        if not auth_enabled_getter():
            return None
        user = rbac.resolve(extract_token())
        if not user:
            return jsonify({'error': '未登录或会话已过期'}), 401
        g.user = user
        request._user = user   # 供后续钩子（如审批门）读取
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            return None  # 所有已登录角色可读
        # 写操作鉴权
        seg = request.path.split('/api/')[1].split('/')[0] if '/api/' in request.path else ''
        if seg in ADMIN_ONLY_RES:
            perm = '*'
        else:
            perm = RESOURCE_WRITE.get(seg)
        if perm is None:
            perm = '*'
        if not rbac.has_perm(user, perm):
            return jsonify({'error': f'无权限：{perm}（当前角色 {user.get("role")}）'}), 403
        return None
    return gate
