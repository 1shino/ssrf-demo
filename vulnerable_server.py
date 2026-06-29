# -*- coding: utf-8 -*-
"""
真实内网服务 - SSRF 攻击目标
================================
这些是 **真实运行的独立 HTTP 服务**（独立端口、独立进程状态、真实数据），
不再是硬编码的模拟字符串。SSRF 漏洞会对其发起真实的 HTTP 请求并拿到真实响应。

服务列表：
  Redis (KV 存储)       http://127.0.0.1:16379   真实内存 KV + JSON 文件持久化
  MySQL (SQL 引擎)      http://127.0.0.1:13306   真实 SQLite SQL 查询
  内网管理后台          http://127.0.0.1:18080   真实系统信息 / 真实文件 / 真实环境变量
  Elasticsearch (搜索)  http://127.0.0.1:19200   真实全文检索

可单独运行：  python vulnerable_server.py
app.py 启动时也会自动在后台线程拉起这些服务。
"""

from flask import Flask, request, jsonify, Response
import os
import json
import time
import socket
import platform
import sqlite3
import sys
import threading
import re

# 真实数据落地目录（持久化 KV、SQLite、配置、文档）
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'internal_data')
os.makedirs(DATA_DIR, exist_ok=True)


def json_response(data, status=200):
    """返回支持中文的 JSON 响应"""
    return Response(
        json.dumps(data, ensure_ascii=False, indent=2),
        status=status,
        content_type='application/json; charset=utf-8'
    )


def _total_memory_bytes():
    """跨平台获取真实物理内存总量"""
    try:
        if hasattr(os, 'sysconf'):  # POSIX
            return os.sysconf('SC_PHYS_PAGES') * os.sysconf('SC_PAGE_SIZE')
    except (ValueError, OSError):
        pass
    try:
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        m = MEMORYSTATUSEX()
        m.dwLength = ctypes.sizeof(m)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
        return m.ullTotalPhys
    except Exception:
        return None


def _local_ip():
    """获取本机真实内网 IP（连一次 socket，不真正发包）"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


# ============================================================================
# Redis 演示种子数据
# Redis 的真实攻击走 dict/gopher(6379 RESP)，不再提供 HTTP 包装接口(原16379已移除)
# ============================================================================

REDIS_SEED = {
    'user:session': 'abc123xyz',
    'admin:password': 'super_secret_pass',
    'config:debug': 'true',
    'config:db_url': 'mysql://root:db_password_123@192.168.1.100:3306/users_db',
    'token:jwt': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature',
}

# ============================================================================
# SQLite 数据层（供 admin /api/users 与 ES 仿真索引使用）
# 注：真实 MySQL 二进制协议 SSRF 打不动，故不提供 MySQL HTTP 服务(原13306已移除)
# ============================================================================

MYSQL_FILE = os.path.join(DATA_DIR, 'mysql.sqlite')


def _mysql_conn():
    conn = sqlite3.connect(MYSQL_FILE, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def _mysql_init():
    """真实建表 + 真实初始数据"""
    with _mysql_conn() as c:
        c.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                password TEXT,
                email TEXT,
                role TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY,
                name TEXT,
                price REAL,
                stock INTEGER
            );
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY,
                username TEXT,
                ip TEXT,
                action TEXT,
                ts TEXT DEFAULT CURRENT_TIMESTAMP
            );
        ''')
        if c.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
            c.executemany(
                'INSERT INTO users(username,password,email,role) VALUES(?,?,?,?)',
                [
                    ('admin', 'admin123', 'admin@company.com', 'admin'),
                    ('john', 'john456', 'john@company.com', 'user'),
                    ('jane', 'jane789', 'jane@company.com', 'user'),
                    ('root', 'P@ssw0rd!', 'root@company.com', 'superadmin'),
                ],
            )
        if c.execute('SELECT COUNT(*) FROM products').fetchone()[0] == 0:
            c.executemany(
                'INSERT INTO products(name,price,stock) VALUES(?,?,?)',
                [
                    ('SSD 1TB', 599.0, 120),
                    ('Mech Keyboard', 899.0, 35),
                    ('4K Monitor', 2399.0, 18),
                ],
            )
        if c.execute('SELECT COUNT(*) FROM access_logs').fetchone()[0] == 0:
            c.executemany(
                'INSERT INTO access_logs(username,ip,action) VALUES(?,?,?)',
                [
                    ('admin', '192.168.1.50', 'login'),
                    ('john', '10.0.0.12', 'download'),
                    ('admin', '192.168.1.50', 'config_update'),
                ],
            )
        c.commit()


_mysql_init()


# ============================================================================
# 真实内网管理后台 - 端口 18080
# 真实读取系统信息、真实文件、真实环境变量、真实目录扫描
# ============================================================================

admin_app = Flask('admin_server')
admin_app.secret_key = os.environ.get('ADMIN_SECRET', 'admin_secret_key_123')
ADMIN_START = time.time()

# 真实配置文件（含"真实"密钥，演示敏感信息泄露）
ADMIN_CONFIG_FILE = os.path.join(DATA_DIR, 'internal_config.json')
if not os.path.exists(ADMIN_CONFIG_FILE):
    with open(ADMIN_CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump({
            'database_host': '192.168.1.100',
            'database_port': 3306,
            'database_user': 'root',
            'database_password': 'db_password_123',
            'api_key': 'sk-1234567890abcdef',
            'secret_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig',
            'access_password': os.environ.get('ACCESS_PASSWORD', ''),
            'debug': True,
        }, f, ensure_ascii=False, indent=2)


@admin_app.route('/')
def admin_index():
    """内网首页"""
    return """<!DOCTYPE html>
<html><head><title>内部管理系统</title></head>
<body>
<h1>内部管理系统 - 员工门户</h1>
<p>欢迎访问内部管理系统</p>
<ul>
    <li><a href="/api/users">用户列表</a></li>
    <li><a href="/api/config">系统配置</a></li>
    <li><a href="/api/server">服务器信息</a></li>
    <li><a href="/api/env">环境变量</a></li>
    <li><a href="/api/documents">内部文档</a></li>
</ul>
<p style="color:red;">注意：此系统仅限内网访问</p>
</body></html>"""


@admin_app.route('/api/users')
def admin_users():
    """真实用户列表（来自真实 SQLite）"""
    with _mysql_conn() as c:
        rows = [dict(r) for r in c.execute('SELECT id,username,password,email,role FROM users').fetchall()]
    return json_response({
        'status': 'success',
        'count': len(rows),
        'data': rows,
        'warning': '密码为明文存储（真实存于 SQLite users 表）',
    })


@admin_app.route('/api/config')
def admin_config():
    """真实读取磁盘配置文件（真实文件读取）"""
    try:
        with open(ADMIN_CONFIG_FILE, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
    except (OSError, ValueError) as e:
        return json_response({'error': f'读取配置失败: {e}'}, 500)
    return json_response({
        'status': 'success',
        'config_file': ADMIN_CONFIG_FILE,
        'data': cfg,
        'warning': '配置文件真实存在于磁盘，含数据库密码/API密钥',
    })


@admin_app.route('/api/server')
def admin_server():
    """真实服务器信息（platform/socket/os 真实值）"""
    mem = _total_memory_bytes()
    return json_response({
        'status': 'success',
        'data': {
            'hostname': socket.gethostname(),
            'internal_ip': _local_ip(),
            'os': platform.platform(),
            'python': platform.python_version(),
            'cpu_cores': os.cpu_count(),
            'memory_total': f'{mem / (1024**3):.2f} GB' if mem else 'N/A',
            'process_id': os.getpid(),
            'working_dir': os.getcwd(),
            'uptime_seconds': int(time.time() - ADMIN_START),
        },
    })


@admin_app.route('/api/env')
def admin_env():
    """真实环境变量泄露（os.environ 真实值）"""
    return json_response({
        'status': 'success',
        'count': len(os.environ),
        'env': dict(os.environ),
        'warning': '环境变量为进程真实环境，可能含密钥/令牌',
    })


@admin_app.route('/api/documents')
def admin_documents():
    """真实扫描数据目录，返回真实文件及大小/修改时间"""
    docs = []
    try:
        for name in sorted(os.listdir(DATA_DIR)):
            full = os.path.join(DATA_DIR, name)
            if os.path.isfile(full):
                st = os.stat(full)
                docs.append({
                    'name': name,
                    'path': full,
                    'size_bytes': st.st_size,
                    'modified': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime)),
                })
    except OSError:
        pass
    return json_response({'status': 'success', 'directory': DATA_DIR, 'documents': docs})


# ============================================================================
# 真实 Elasticsearch 服务（检索） - 端口 19200
# 对真实文档建立真实内存倒排，返回真实命中
# ============================================================================

es_app = Flask('es_server')
ES_START = time.time()


def _es_build_index():
    """从真实数据源构建真实索引"""
    indices = {}

    # users 索引：来自真实 SQLite
    with _mysql_conn() as c:
        users = [dict(r) for r in c.execute('SELECT * FROM users').fetchall()]
    indices['users'] = users

    # logs 索引：来自真实 access_logs
    with _mysql_conn() as c:
        logs = [dict(r) for r in c.execute('SELECT * FROM access_logs').fetchall()]
    indices['logs'] = logs

    # docs 索引：来自真实磁盘文件内容
    docs = []
    for name in os.listdir(DATA_DIR):
        full = os.path.join(DATA_DIR, name)
        if os.path.isfile(full) and name.endswith(('.json', '.txt', '.md', '.sql')):
            try:
                with open(full, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(2000)
                docs.append({'file': name, 'content': content})
            except OSError:
                pass
    indices['docs'] = docs
    return indices


ES_INDEX = {}


def _es_refresh():
    global ES_INDEX
    ES_INDEX = _es_build_index()


_es_refresh()


@es_app.route('/')
def es_info():
    """真实节点信息"""
    return jsonify({
        'name': socket.gethostname(),
        'cluster_name': 'elasticsearch-emulated',
        'cluster_uuid': os.urandom(16).hex(),
        'version': {
            'number': '7.10.0-emulated',
            'build_type': 'python',
            'lucene_version': '8.7.0-emulated',
        },
        'tagline': 'You Know, for Search',
        'indices': list(ES_INDEX.keys()),
    })


@es_app.route('/_cat/indices')
def es_cat_indices():
    """真实索引统计（真实文档数）"""
    lines = ['health status index            docs.count store.size']
    for name, docs in ES_INDEX.items():
        size = len(json.dumps(docs, ensure_ascii=False).encode('utf-8'))
        lines.append(f"green  open   {name:<16} {len(docs):<10} {size/1024:.2f}kb")
    return '\n'.join(lines), 200, {'Content-Type': 'text/plain'}


@es_app.route('/<index>/_search')
def es_search(index):
    """真实全文检索（子串匹配，返回真实命中与高亮）"""
    q = request.args.get('q', '').lower()
    if index not in ES_INDEX:
        return json_response({'error': f'index [{index}] not found', 'available': list(ES_INDEX.keys())}, 404)
    hits = []
    for doc in ES_INDEX[index]:
        text = json.dumps(doc, ensure_ascii=False).lower()
        if not q or q in text:
            hits.append({'_index': index, '_source': doc})
    return jsonify({
        'took': 1,
        'timed_out': False,
        'hits': {'total': {'value': len(hits)}, 'max_score': 1.0, 'hits': hits},
    })


@es_app.route('/_refresh')
def es_refresh_endpoint():
    """真实重建索引"""
    _es_refresh()
    return json_response({'refreshed': True, 'indices': {k: len(v) for k, v in ES_INDEX.items()}})


# ============================================================================
# 真实 RESP Redis TCP 服务 - 端口 6379
# 这是真实讲 RESP(REdis Serialization Protocol) 的 TCP 服务，供
# dict:// 与 gopher:// SSRF 真实打靶。真实内存数据集、真实 CONFIG SET + SAVE
# 写文件到磁盘，演示 SSRF → Redis 任意文件写（RCE）。
# ============================================================================

import socketserver

REDIS_TCP_PORT = 6379
REDIS_TCP_START = time.time()
RCE_BASE_DIR = os.path.join(DATA_DIR, 'redis_rce')
os.makedirs(RCE_BASE_DIR, exist_ok=True)

# 真实内存数据集（键含冒号，正是 dict:// 难以处理、需要 gopher:// 的场景）
REDIS_TCP_STORE = {
    'admin:password': 'super_secret_pass',
    'user:session': 'abc123xyz',
    'config:debug': 'true',
    'foo': 'bar',
}
REDIS_TCP_CFG = {'dir': RCE_BASE_DIR, 'dbfilename': 'dump.rdb'}
_redis_tcp_lock = threading.Lock()


def _redis_save_to_disk():
    """真实把数据集写到磁盘（SAVE 命令调用）。为安全，写入路径强制落在
    redis_rce 沙箱目录内——但仍是由 SSRF 经 gopher:// 触发的真实文件写。"""
    cfg_dir = REDIS_TCP_CFG.get('dir', RCE_BASE_DIR)
    abs_cfg = os.path.abspath(cfg_dir)
    abs_base = os.path.abspath(RCE_BASE_DIR)
    # 任意 dir 都映射到沙箱内，避免越权写真实系统目录
    if not abs_cfg.startswith(abs_base):
        safe_dir = os.path.join(RCE_BASE_DIR, os.path.basename(cfg_dir.rstrip('/\\')) or 'rce')
    else:
        safe_dir = abs_cfg
    os.makedirs(safe_dir, exist_ok=True)
    path = os.path.join(safe_dir, REDIS_TCP_CFG.get('dbfilename', 'dump.rdb'))
    with open(path, 'w', encoding='utf-8') as f:
        f.write('# Redis RDB dump (emulated) - written via SSRF gopher://\n')
        for k, v in REDIS_TCP_STORE.items():
            f.write(f'{v}\n')
    return path


def _resp_bulk(data):
    """编码 bulk string"""
    b = data.encode('utf-8') if isinstance(data, str) else data
    return b'$' + str(len(b)).encode() + b'\r\n' + b + b'\r\n'


def _resp_array(items):
    out = [b'*' + str(len(items)).encode() + b'\r\n']
    for it in items:
        out.append(_resp_bulk(it) if it is not None else b'$-1\r\n')
    return b''.join(out)


class RedisRespHandler(socketserver.StreamRequestHandler):
    """真实 RESP 协议处理器"""

    # rfile/rbufsize 默认即可
    def handle(self):
        self.connection.settimeout(10)
        while True:
            try:
                line = self.rfile.readline()
            except (socket.timeout, ConnectionError, OSError):
                break
            if not line:
                break
            line = line.rstrip(b'\r\n')
            if not line:
                continue
            try:
                if line.startswith(b'*'):
                    args = self._read_multibulk(line)
                    if args is None:
                        self.wfile.write(b'-ERR incomplete multibulk\r\n')
                        self.wfile.flush()
                        continue
                else:
                    args = line.decode('utf-8', 'ignore').split()
                resp, close = self._dispatch(args)
                if resp is not None:
                    self.wfile.write(resp)
                    self.wfile.flush()
                if close:
                    break
            except Exception as e:
                try:
                    self.wfile.write(f'-ERR server: {e}\r\n'.encode('utf-8'))
                    self.wfile.flush()
                except Exception:
                    pass

    def _read_multibulk(self, header):
        try:
            n = int(header[1:])
        except ValueError:
            return None
        args = []
        for _ in range(n):
            hdr = self.rfile.readline()
            if not hdr or not hdr.startswith(b'$'):
                return None
            ln = int(hdr[1:].strip())
            if ln < 0:
                args.append(None)
                continue
            data = self.rfile.read(ln)
            self.rfile.read(2)  # consume \r\n
            args.append(data.decode('utf-8', 'ignore'))
        return args

    def _dispatch(self, args):
        """返回 (resp_bytes, should_close)"""
        if not args:
            return b'', False
        cmd = args[0].upper()
        rest = args[1:]
        with _redis_tcp_lock:
            if cmd == 'PING':
                return b'+PONG\r\n', False
            if cmd == 'QUIT':
                return b'+OK\r\n', True
            if cmd == 'SELECT' or cmd == 'AUTH' or cmd == 'CLIENT':
                return b'+OK\r\n', False
            if cmd == 'COMMAND':
                return b'*0\r\n', False
            if cmd == 'HELLO':
                return b"-ERR unknown command 'HELLO'\r\n", False
            if cmd == 'INFO':
                info = (
                    f"# Server\r\n"
                    f"redis_version:6.2.6-emulated\r\n"
                    f"redis_mode:standalone\r\n"
                    f"os:{platform.platform()}\r\n"
                    f"process_id:{os.getpid()}\r\n"
                    f"tcp_port:{REDIS_TCP_PORT}\r\n"
                    f"uptime_in_seconds:{int(time.time() - REDIS_TCP_START)}\r\n"
                    f"# Keyspace\r\n"
                    f"db0:keys={len(REDIS_TCP_STORE)},expires=0,avg_ttl=0\r\n"
                )
                return _resp_bulk(info), False
            if cmd == 'GET':
                key = rest[0] if rest else ''
                # 演示便利：被 FLUSHALL/RCE 清空后，访问种子键时自动恢复种子数据，
                # 保证"GET 泄露密码"演示始终可用。RCE 链不含 GET，不影响其写文件。
                if key not in REDIS_TCP_STORE and key in REDIS_SEED:
                    REDIS_TCP_STORE.update(REDIS_SEED)
                val = REDIS_TCP_STORE.get(key)
                return (_resp_bulk(val) if val is not None else b'$-1\r\n'), False
            if cmd == 'SET':
                if len(rest) >= 2:
                    REDIS_TCP_STORE[rest[0]] = rest[1]
                    return b'+OK\r\n', False
                return b'-ERR wrong number of arguments for ' + cmd.encode() + b'\r\n', False
            if cmd == 'DEL':
                n = 0
                for k in rest:
                    if k in REDIS_TCP_STORE:
                        del REDIS_TCP_STORE[k]
                        n += 1
                return f':{n}\r\n'.encode(), False
            if cmd == 'EXISTS':
                n = sum(1 for k in rest if k in REDIS_TCP_STORE)
                return f':{n}\r\n'.encode(), False
            if cmd == 'KEYS':
                pat = rest[0] if rest else '*'
                if pat == '*':
                    keys = list(REDIS_TCP_STORE.keys())
                else:
                    rx = '^' + re.escape(pat).replace('\\*', '.*') + '$'
                    keys = [k for k in REDIS_TCP_STORE if re.match(rx, k)]
                return _resp_array(keys), False
            if cmd == 'TYPE':
                return b'+string\r\n', False
            if cmd == 'FLUSHALL' or cmd == 'FLUSHDB':
                REDIS_TCP_STORE.clear()
                return b'+OK\r\n', False
            if cmd == 'CONFIG':
                sub = (rest[0] if rest else '').upper()
                if sub == 'GET':
                    param = rest[1] if len(rest) > 1 else '*'
                    pairs = []
                    for k, v in REDIS_TCP_CFG.items():
                        if param == '*' or k == param:
                            pairs.extend([k, v])
                    return _resp_array(pairs), False
                if sub == 'SET':
                    if len(rest) >= 3:
                        REDIS_TCP_CFG[rest[1]] = rest[2]
                        return b'+OK\r\n', False
                    return b'-ERR wrong args\r\n', False
                return b'-ERR unknown CONFIG subcommand\r\n', False
            if cmd == 'SAVE' or cmd == 'BGSAVE':
                try:
                    path = _redis_save_to_disk()
                    return f'+OK written to {path}\r\n'.encode('utf-8'), False
                except OSError as e:
                    return f'-ERR save failed: {e}\r\n'.encode('utf-8'), False
            return (b"-ERR unknown command '" + args[0].encode('utf-8', 'ignore')
                    + b"'\r\n"), False


class ThreadingRedisTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


_redis_tcp_server = None


def start_redis_tcp():
    """启动真实 RESP Redis TCP 服务（幂等）"""
    global _redis_tcp_server
    try:
        _redis_tcp_server = ThreadingRedisTCPServer(('127.0.0.1', REDIS_TCP_PORT), RedisRespHandler)
    except OSError as e:
        print(f'[!] RESP Redis TCP 端口 {REDIS_TCP_PORT} 启动失败: {e}')
        return False
    t = threading.Thread(target=_redis_tcp_server.serve_forever, daemon=True)
    t.start()
    print(f'[OK] RESP Redis (dict/gopher 真实打靶) http://127.0.0.1:{REDIS_TCP_PORT}')
    return True


# ============================================================================
# 真实服务探测与种子（Redis 6379 / Elasticsearch 9200）
# Docker 起 → 真服务；未起 → 回退仿真（标志位驱动 wrapper 与模板端口选择）
# ============================================================================

REDIS_HOST = os.environ.get('REDIS_HOST', '127.0.0.1')
REDIS_PORT = int(os.environ.get('REDIS_PORT', '6379'))
ES_HOST = os.environ.get('ES_HOST', '127.0.0.1')
ES_PORT = int(os.environ.get('ES_PORT', '9200'))

REAL_REDIS_UP = False
REAL_ES_UP = False
_real_redis_client = None


def _probe_redis():
    """真实探测：向 6379 发 RESP INFO，返回真 redis-server 版本(非 emulated)才算真。
    避免把我们自己的仿真 RESP 服务误判为真 Redis（二者都回 PONG）。"""
    import socket as _sock
    try:
        s = _sock.create_connection((REDIS_HOST, REDIS_PORT), timeout=1.0)
        s.settimeout(1.5)
        s.sendall(b'*1\r\n$4\r\nINFO\r\n')
        data = b''
        try:
            while len(data) < 4000:
                d = s.recv(4096)
                if not d:
                    break
                data += d
        except OSError:
            pass
        s.close()
        text = data.decode('utf-8', 'ignore')
        return 'redis_version:' in text and 'emulated' not in text
    except OSError:
        return False


def _probe_es():
    """真实探测：HTTP GET / ，返回 200 且含 cluster_name 即真 ES"""
    import urllib.request
    try:
        r = urllib.request.urlopen(f'http://{ES_HOST}:{ES_PORT}/', timeout=2)
        body = r.read().decode('utf-8', 'ignore')
        return r.status == 200 and 'cluster_name' in body
    except Exception:
        return False


def _redis_client():
    """返回 redis-py 客户端（仅当真 Redis 在线）；否则 None（走内存回退）"""
    global _real_redis_client
    if not REAL_REDIS_UP:
        return None
    if _real_redis_client is None:
        try:
            import redis as redislib
            c = redislib.Redis(host=REDIS_HOST, port=REDIS_PORT,
                               decode_responses=True, socket_timeout=2,
                               socket_connect_timeout=2)
            c.ping()
            _real_redis_client = c
        except Exception:
            _real_redis_client = None
    return _real_redis_client


def _seed_real_redis():
    """向真 Redis 写入种子键（演示数据）"""
    c = _redis_client()
    if not c:
        return False
    try:
        for k, v in REDIS_SEED.items():
            c.set(k, v)
        return True
    except Exception:
        return False


def _seed_real_es():
    """向真 Elasticsearch 建索引并索引演示文档"""
    import urllib.request
    base = f'http://{ES_HOST}:{ES_PORT}'
    docs = {
        'users': [
            {'username': 'admin', 'password': 'admin123', 'email': 'admin@company.com', 'role': 'admin'},
            {'username': 'john', 'password': 'john456', 'email': 'john@company.com', 'role': 'user'},
            {'username': 'jane', 'password': 'jane789', 'email': 'jane@company.com', 'role': 'user'},
        ],
        'products': [
            {'name': 'SSD 1TB', 'price': 599.0, 'stock': 120},
            {'name': 'Mech Keyboard', 'price': 899.0, 'stock': 35},
        ],
        'logs': [
            {'username': 'admin', 'ip': '192.168.1.50', 'action': 'login'},
            {'username': 'john', 'ip': '10.0.0.12', 'action': 'download'},
        ],
    }
    try:
        for idx, rows in docs.items():
            for doc in rows:
                req = urllib.request.Request(
                    f'{base}/{idx}/_doc',
                    data=json.dumps(doc).encode('utf-8'),
                    headers={'Content-Type': 'application/json'},
                    method='POST')
                urllib.request.urlopen(req, timeout=5)
        urllib.request.urlopen(f'{base}/_refresh', timeout=5)
        return True
    except Exception:
        return False


def _real_probe_loop():
    """后台探测真服务并种子化（ES 启动慢，重试约 60s）"""
    global REAL_REDIS_UP, REAL_ES_UP
    # Redis 启动快
    for _ in range(10):
        if _probe_redis():
            REAL_REDIS_UP = True
            break
        time.sleep(0.5)
    if REAL_REDIS_UP:
        _seed_real_redis()
    # ES 启动慢，重试 60 次
    for _ in range(60):
        if _probe_es():
            REAL_ES_UP = True
            break
        time.sleep(1.0)
    if REAL_ES_UP:
        _seed_real_es()
    print(f"[REAL] redis={'真(redis-server)' if REAL_REDIS_UP else '仿真回退'} "
          f"es={'真(elasticsearch)' if REAL_ES_UP else '仿真回退'}")


def reseed():
    """重新种子化真 Redis/ES（供 /debug/reseed 调用，FLUSHALL 后重置演示）"""
    ok_r = _seed_real_redis() if REAL_REDIS_UP else None
    ok_e = _seed_real_es() if REAL_ES_UP else None
    return {'redis': ('real' if REAL_REDIS_UP else 'emulated'),
            'es': ('real' if REAL_ES_UP else 'emulated'),
            'reseeded_redis': ok_r, 'reseeded_es': ok_e}


def service_status():
    """供 app.py / 模板查询当前真/仿真模式与端口"""
    return {
        'redis': {'mode': 'real' if REAL_REDIS_UP else 'emulated', 'port': REDIS_PORT},
        'es': {'mode': 'real' if REAL_ES_UP else 'emulated',
               'port': ES_PORT if REAL_ES_UP else 19200},
        'admin': {'mode': 'real-system', 'port': 18080},
    }


# ============================================================================
# 启动逻辑
# ============================================================================

_started = False
_start_lock = threading.Lock()

SERVICE_SPECS = [
    ('admin', admin_app, 18080),
    ('es', es_app, 19200),
]


def start_all_services():
    """在后台守护线程中拉起全部真实内网服务（幂等）"""
    global _started
    with _start_lock:
        if _started:
            return False
        _started = True

    def _run(name, app, port):
        try:
            app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False)
        except OSError as e:
            print(f'[!] {name} 服务端口 {port} 启动失败: {e}')

    for name, app, port in SERVICE_SPECS:
        t = threading.Thread(target=_run, args=(name, app, port), daemon=True)
        t.start()
        time.sleep(0.2)
    print('[OK] 真实内网服务已启动:')
    for name, _, port in SERVICE_SPECS:
        print(f'     - {name:<6} http://127.0.0.1:{port}')
    # 真实 RESP Redis TCP 服务（dict:// / gopher:// 打靶）
    # 真 redis-server 在线时 6379 被占，此处 EADDRINUSE 自动跳过（透明走真 Redis）
    start_redis_tcp()
    # 后台探测真 Redis(6379)/ES(9200) 并种子化；未起则自动回退仿真
    threading.Thread(target=_real_probe_loop, daemon=True).start()
    return True


if __name__ == '__main__':
    print('=' * 60)
    print('启动真实内网服务（SSRF 攻击目标）...')
    print('=' * 60)
    start_all_services()
    print('=' * 60)
    print('可用服务:')
    for name, _, port in SERVICE_SPECS:
        print(f'  - {name:<14} http://127.0.0.1:{port}')
    print(f'  - redis-resp     127.0.0.1:{REDIS_TCP_PORT} (dict/gopher)')
    print('\n按 Ctrl+C 停止全部服务')
    print('=' * 60)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('\n服务已停止')
        sys.exit(0)
