# -*- coding: utf-8 -*-
"""
LinkSec·AutoTest AI — 机器人接入
支持：企业微信 / 钉钉 / 飞书 / Slack / Telegram / QQ / 通用 Webhook。
通道统一管理，通知可自动推送到启用的通道。
"""
import json
import urllib.error
import urllib.request

# 平台 → {字段, payload 构建}
CHANNEL_DEFS = {
    'dingtalk': {'name': '钉钉', 'fields': ['webhook', 'secret'],
                 'help': 'webhook 为钉钉群机器人 Webhook 地址，secret 为加签密钥（可选）'},
    'wecom': {'name': '企业微信', 'fields': ['webhook'],
              'help': 'webhook 为企业微信群机器人地址'},
    'feishu': {'name': '飞书', 'fields': ['webhook', 'secret'],
               'help': 'webhook 为飞书群机器人地址，secret 为签名校验密钥（可选）'},
    'slack': {'name': 'Slack', 'fields': ['webhook'],
              'help': 'webhook 为 Slack Incoming Webhook 地址'},
    'telegram': {'name': 'Telegram', 'fields': ['token', 'chat_id'],
                 'help': 'token 为 Bot Token，chat_id 为目标会话'},
    'qq': {'name': 'QQ', 'fields': ['webhook'],
           'help': 'webhook 为 QQ 机器人 HTTP 上报 / 事件推送地址'},
    'webhook': {'name': '通用 Webhook', 'fields': ['webhook'],
                'help': '任意 HTTP 接口，POST JSON {title, message}'},
}


def build_payload(channel_type, cfg, title, message):
    """按平台协议构造 payload。返回 (url, payload, headers)。"""
    if channel_type == 'dingtalk':
        return cfg['webhook'], {
            'msgtype': 'markdown',
            'markdown': {'title': title, 'text': f'### {title}\n\n{message}'},
        }, {'Content-Type': 'application/json'}
    if channel_type == 'wecom':
        return cfg['webhook'], {
            'msgtype': 'markdown',
            'markdown': {'content': f'**{title}**\n{message}'},
        }, {'Content-Type': 'application/json'}
    if channel_type == 'feishu':
        return cfg['webhook'], {
            'msg_type': 'interactive',
            'card': {
                'header': {'title': {'tag': 'plain_text', 'content': title}},
                'elements': [{'tag': 'div', 'text': {'tag': 'lark_md', 'content': message}}],
            },
        }, {'Content-Type': 'application/json'}
    if channel_type == 'slack':
        return cfg['webhook'], {'text': f'*{title}*\n{message}'}, {'Content-Type': 'application/json'}
    if channel_type == 'telegram':
        token = cfg.get('token', '')
        chat = cfg.get('chat_id', '')
        if not token or not chat:
            raise ValueError('Telegram 需配置 token 与 chat_id')
        return f'https://api.telegram.org/bot{token}/sendMessage', {
            'chat_id': chat, 'text': f'{title}\n{message}', 'parse_mode': 'Markdown',
        }, {'Content-Type': 'application/json'}
    if channel_type == 'qq':
        return cfg['webhook'], {'title': title, 'message': message}, {'Content-Type': 'application/json'}
    if channel_type == 'webhook':
        return cfg['webhook'], {'title': title, 'message': message}, {'Content-Type': 'application/json'}
    raise ValueError(f'未知通道类型：{channel_type}')


def send_to_channel(channel, title, message, timeout=5):
    """向单个通道发送通知，返回状态字符串。"""
    ctype = channel.get('type', 'webhook')
    cfg = channel.get('config', {})
    if not any(cfg.get(f) for f in CHANNEL_DEFS.get(ctype, {}).get('fields', [])):
        return '未配置参数'
    try:
        url, payload, headers = build_payload(ctype, cfg, title, message)
        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'),
                                     headers=headers, method='POST')
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(400).decode('utf-8', 'ignore')
        # 各平台返回码粗校验
        if ctype == 'dingtalk' and '"errcode":0' not in body.replace(' ', ''):
            return f'平台返回异常：{body[:120]}'
        if ctype == 'wecom' and '"errcode":0' not in body.replace(' ', ''):
            return f'平台返回异常：{body[:120]}'
        if ctype == 'telegram' and '"ok":true' not in body.replace(' ', ''):
            return f'平台返回异常：{body[:120]}'
        return 'sent'
    except urllib.error.HTTPError as e:
        return f'失败 HTTP {e.code}：{e.read(120).decode("utf-8", "ignore")}'
    except Exception as e:
        return f'失败：{e}'


def send_to_all(channels, title, message, types=None):
    """向所有启用（且类型匹配）的通道发送。返回逐通道结果。"""
    results = {}
    for ch in channels.values():
        if not ch.get('enabled', True):
            continue
        if types and ch.get('type') not in types:
            continue
        results[ch['id']] = send_to_channel(ch, title, message)
    return results
