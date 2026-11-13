# -*- coding: utf-8 -*-
"""
LinkSec·AutoTest AI — 人机协同审批
高危操作（C2 指令 / WebShell 执行 / 终端命令 / 技能执行 / Payload 生成）
在开启审批模式后需经审批通过方可执行，决策全程留痕。

工作流：
    操作请求 → 拦截（before_request）→ 生成审批单（pending）
    → 审批人 approve / deny → approve 后以审批人身份回放原请求执行
    → 结果回写审批单（executed / denied），审计留痕
"""
import time
import uuid

HIGH_RISK_PATHS = (
    # (method, 前缀, 展示名)
    ('POST', '/api/c2/sessions/', 'C2 指令下发'),
    ('POST', '/api/webshells/', 'WebShell 执行'),
    ('POST', '/api/terminal/', '终端命令执行'),
    ('POST', '/api/skills/', '技能包执行'),
    ('POST', '/api/c2/payload', 'Payload 生成'),
)


def _uid():
    return str(uuid.uuid4())[:8]


def _now():
    import datetime
    return datetime.datetime.now().isoformat()


def match_high_risk(method, path):
    """判断请求是否为需审批的高危操作。返回 (display_name) 或 None。"""
    for m, prefix, name in HIGH_RISK_PATHS:
        if method == m and path.startswith(prefix):
            return name
    return None


class ApprovalStore:
    def __init__(self, store_dict, audit_cb=None):
        self.approvals = store_dict      # dict: id -> approval
        self.audit = audit_cb            # callable(action, detail)

    def create(self, display, method, path, json_body, query_string, requester, note=''):
        aid = _uid()
        self.approvals[aid] = {
            'id': aid, 'display': display, 'note': note,
            'method': method, 'path': path,
            'json_body': json_body, 'query_string': query_string,
            'requester': requester or 'anonymous',
            'status': 'pending',            # pending|approved|executed|denied|failed
            'decided_by': None, 'decided_at': None,
            'result': None, 'http_status': None,
            'created_at': _now(),
        }
        if self.audit:
            self.audit('approval_create', f'审批单 {aid}：{display}（{requester}）')
        return self.approvals[aid]

    def decide(self, aid, decision, decider):
        a = self.approvals.get(aid)
        if not a:
            return None, '审批单不存在'
        if a['status'] != 'pending':
            return a, f'审批单已处理（{a["status"]}）'
        a['decided_by'] = decider
        a['decided_at'] = _now()
        if decision == 'deny':
            a['status'] = 'denied'
            if self.audit:
                self.audit('approval_deny', f'审批单 {aid} 被 {decider} 拒绝')
            return a, None
        if decision != 'approve':
            return a, '未知决策'
        a['status'] = 'approved'
        if self.audit:
            self.audit('approval_approve', f'审批单 {aid} 被 {decider} 批准')
        return a, None

    def record_exec(self, aid, status, result, http_status=None):
        a = self.approvals.get(aid)
        if not a:
            return
        a['status'] = status
        a['result'] = result
        a['http_status'] = http_status
        if self.audit:
            self.audit('approval_exec', f'审批单 {aid} 执行完成：{status}')

    def list(self, status=None):
        out = list(self.approvals.values())
        if status:
            out = [a for a in out if a['status'] == status]
        out.sort(key=lambda a: a['created_at'], reverse=True)
        return out
