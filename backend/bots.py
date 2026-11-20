# -*- coding: utf-8 -*-
"""
LinkSec·AutoTest AI — 机器人接入
支持：企业微信 / 钉钉 / 飞书 / Slack / Telegram / QQ / 通用 Webhook。
通道统一管理，通知可自动推送到启用的通道。
"""
import ipaddress
import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request


def _validate_url(url):
    """v3.7：webhook SSRF 防护 — 仅允许 http/https，默认拒绝私网/回环/链路本地/保留地址。
    自建内网机器人场景可设环境变量 LINKSEC_SSRF_ALLOW_PRIVATE=1 放行内网。"""
    try:
        u = urllib.parse.urlparse(url)
    except Exception:
        return 'URL 格式非法'
    if u.scheme not in ('http', 'https'):
        return '仅允许 http/https 协议'
    host = u.hostname
    if not host:
        return '缺少主机名'
    if os.environ.get('LINKSEC_SSRF_ALLOW_PRIVATE', '') in ('1', 'true', 'yes'):
        return None
    try:
        port = u.port or (443 if u.scheme == 'https' else 80)
        infos = socket.getaddrinfo(host, port)
    except Exception:
        return '无法解析主机'
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return f'拒绝内网/保留地址：{ip}'
    return None

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


def mask_secret(value, keep_head=6, keep_tail=4):
    """v3.5：敏感配置（webhook/token）对外掩码，防止密钥回显。"""
    if not value:
        return ''
    v = str(value)
    if len(v) <= keep_head + keep_tail:
        return '******'
    return v[:keep_head] + '******' + v[-keep_tail:]


def mask_channel(channel):
    """返回对外展示的通道对象（config 中敏感字段掩码）。"""
    out = dict(channel)
    cfg = dict(channel.get('config', {}))
    for k in list(cfg.keys()):
        if k in ('webhook', 'token', 'secret', 'chat_id', 'password'):
            cfg[k] = mask_secret(cfg[k])
    out['config'] = cfg
    return out


def send_to_channel(channel, title, message, timeout=5):
    """向单个通道发送通知，返回状态字符串。"""
    ctype = channel.get('type', 'webhook')
    cfg = channel.get('config', {})
    if not any(cfg.get(f) for f in CHANNEL_DEFS.get(ctype, {}).get('fields', [])):
        return '未配置参数'
    try:
        url, payload, headers = build_payload(ctype, cfg, title, message)
        err = _validate_url(url)
        if err:
            return f'URL 校验失败：{err}'
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
