# -*- coding: utf-8 -*-
"""
LinkSec·AutoTest AI — SQLite 持久化层
对内存存储做 JSON 快照持久化（kv 表），启动时自动恢复，后台线程定时落盘。

用法：
    storage = Storage()
    storage.register('projects', _projects)     # 注册内存 dict / list
    storage.load()                              # 启动时恢复
    storage.start_autosave(interval=10)         # 后台定时保存
    storage.stop()                              # 退出时保存
"""
import json
import os
import sqlite3
import threading

DB_PATH = os.environ.get(
    'LINKSEC_DB',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'linksec.db')
)


class Storage:
    def __init__(self, db_path=None):
        self.db_path = db_path or DB_PATH
        self._stores = {}
        self._stop = threading.Event()
        self._thread = None

    def register(self, name, ref):
        """注册一个内存容器（dict 或 list），按名称快照。"""
        self._stores[name] = ref

    def _conn(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)')
        conn.execute('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)')
        return conn

    def save(self):
        """把所有注册容器快照写入 SQLite。"""
        try:
            conn = self._conn()
            for name, ref in self._stores.items():
                conn.execute(
                    'INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)',
                    (name, json.dumps(ref, ensure_ascii=False, default=str))
                )
            conn.execute(
                'INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)',
                ('last_save', json.dumps({'ts': __import__('datetime').datetime.now().isoformat()}))
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:  # pragma: no cover
            print(f'[storage] save error: {e}')
            return False

    def load(self):
        """启动时从 SQLite 恢复所有注册容器。"""
        if not os.path.exists(self.db_path):
            return 0
        try:
            conn = self._conn()
            rows = conn.execute('SELECT k, v FROM kv').fetchall()
            conn.close()
        except Exception as e:  # pragma: no cover
            print(f'[storage] open error: {e}')
            return 0
        loaded = 0
        for k, v in rows:
            if k not in self._stores:
                continue
            try:
                data = json.loads(v)
                ref = self._stores[k]
                if isinstance(ref, dict):
                    ref.clear()
                    ref.update(data)
                elif isinstance(ref, list):
                    ref[:] = data
                loaded += 1
            except Exception as e:  # pragma: no cover
                print(f'[storage] load error for {k}: {e}')
        print(f'[storage] 已从 {self.db_path} 恢复 {loaded} 个存储单元')
        return loaded

    def start_autosave(self, interval=10):
        def loop():
            while not self._stop.is_set():
                self._stop.wait(interval)
                self.save()
        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self.save()

    @property
    def path(self):
        return self.db_path
