# -*- coding: utf-8 -*-
"""
LinkSec·AutoTest AI — Token 用量统计
按「单个任务」与「单次对话」维度记录输入/输出/总 token 数（非全局汇总）。

- scope = 'conversation'：AI 对话（单次 /api/ai/analyze 或编排调用按对话聚合）
- scope = 'task'       ：任务（/api/tasks 任务 或 扫描任务的 AI 分析/报告阶段）

估算说明：无 API Key（模拟模式）时使用启发式估算（CJK 字符 1:1、
英文单词 ×1.3、其余字符 ×0.5）；真实 AI 模式使用 API 返回的 usage 精确值。
"""
import re
import uuid
from datetime import datetime


def estimate_tokens(text):
    """启发式 token 估算（模拟模式使用）。"""
    if not text:
        return 0
    cjk = len(re.findall(r'[一-鿿　-〿＀-￯]', text))
    words = re.findall(r'[A-Za-z0-9_]+', text)
    word_chars = sum(len(w) for w in words)
    other = len(text) - cjk - word_chars
    return max(1, int(cjk + len(words) * 1.3 + other * 0.5))


def _now():
    return datetime.now().isoformat(timespec='seconds')


class TokenLedger:
    def __init__(self, records_store):
        self.records = records_store      # list[dict]

    def record(self, scope, scope_id, title, model, prompt_tokens, completion_tokens, note=''):
        rec = {
            'id': str(uuid.uuid4())[:8],
            'scope': scope,               # conversation | task
            'scope_id': scope_id,         # 对话 ID 或任务 ID
            'title': (title or '')[:80],
            'model': model or 'unknown',
            'prompt_tokens': int(prompt_tokens or 0),
            'completion_tokens': int(completion_tokens or 0),
            'total_tokens': int(prompt_tokens or 0) + int(completion_tokens or 0),
            'note': note or '',
            'timestamp': _now(),
        }
        self.records.append(rec)
        return rec

    def by_scope(self, scope):
        """按 scope_id 聚合：每个任务/对话一条汇总。"""
        agg = {}
        for r in self.records:
            if r['scope'] != scope:
                continue
            a = agg.setdefault(r['scope_id'], {
                'scope_id': r['scope_id'], 'title': r['title'],
                'messages': 0, 'prompt_tokens': 0, 'completion_tokens': 0,
                'total_tokens': 0, 'model': r['model'],
                'first_at': r['timestamp'], 'last_at': r['timestamp'],
            })
            a['messages'] += 1
            a['prompt_tokens'] += r['prompt_tokens']
            a['completion_tokens'] += r['completion_tokens']
            a['total_tokens'] += r['total_tokens']
            a['last_at'] = r['timestamp']
        return sorted(agg.values(), key=lambda x: x['last_at'], reverse=True)

    def detail(self, scope_id):
        """单个任务/对话的逐条明细。"""
        return [r for r in self.records if r['scope_id'] == scope_id]

    def stats(self):
        convs = {r['scope_id'] for r in self.records if r['scope'] == 'conversation'}
        tasks = {r['scope_id'] for r in self.records if r['scope'] == 'task'}
        return {
            'conversations': len(convs),
            'tasks': len(tasks),
            'records': len(self.records),
        }


# 模块级台账（app.py 与 ext_v3 共用）
LEDGER = TokenLedger([])
