# -*- coding: utf-8 -*-
"""
攻击演示系统 - 主应用程序
基于Flask框架实现B/S架构的攻击演示平台
只保留SSRF攻击演示
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
import os
import hashlib
import time

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24).hex())

# 访问密码（在Railway环境变量中设置 ACCESS_PASSWORD）
ACCESS_PASSWORD = os.environ.get('ACCESS_PASSWORD', '')

# 登录失败次数限制
login_attempts = {}  # {ip: {'count': 0, 'last_attempt': 0}}
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5分钟锁定

def get_password_hash(password):
    """密码哈希"""
    return hashlib.sha256(password.encode()).hexdigest()[:32]

def is_ip_locked(ip):
    """检查IP是否被锁定"""
    if ip not in login_attempts:
        return False
    attempt = login_attempts[ip]
    if attempt['count'] >= MAX_ATTEMPTS:
        if time.time() - attempt['last_attempt'] < LOCKOUT_TIME:
            return True
        else:
            # 锁定时间已过，重置
            login_attempts[ip] = {'count': 0, 'last_attempt': 0}
            return False
    return False

def record_failed_attempt(ip):
    """记录失败尝试"""
    if ip not in login_attempts:
        login_attempts[ip] = {'count': 0, 'last_attempt': 0}
    login_attempts[ip]['count'] += 1
    login_attempts[ip]['last_attempt'] = time.time()

def reset_attempts(ip):
    """重置尝试次数"""
    if ip in login_attempts:
        del login_attempts[ip]

# ==================== 访问密码验证 ====================

@app.before_request
def check_password():
    """检查访问密码"""
    # 暂时禁用密码验证
    return

    if not ACCESS_PASSWORD:
        return  # 没设置密码则跳过

    # 不需要验证的路径
    skip_paths = ['/login', '/static/']
    for path in skip_paths:
        if request.path.startswith(path):
            return

    # 检查cookie中的密码哈希
    password_hash = request.cookies.get('access_token')
    expected_hash = get_password_hash(ACCESS_PASSWORD)
    if password_hash == expected_hash:
        return

    # 未验证则跳转到登录页
    if request.path != '/login':
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """登录页面"""
    error = ''
    client_ip = request.remote_addr

    # 检查IP是否被锁定
    if is_ip_locked(client_ip):
        remaining = int(LOCKOUT_TIME - (time.time() - login_attempts[client_ip]['last_attempt']))
        error = f'登录失败次数过多，请 {remaining} 秒后再试'
        return render_template('login.html', error=error)

    if request.method == 'POST':
        password = request.form.get('password', '')
        if password == ACCESS_PASSWORD:
            # 登录成功，重置尝试次数
            reset_attempts(client_ip)
            resp = redirect(url_for('index'))
            # 使用密码哈希作为cookie，不直接存密码
            resp.set_cookie('access_token', get_password_hash(password),
                          max_age=86400, httponly=True, samesite='Strict')
            return resp
        else:
            # 登录失败，记录尝试
            record_failed_attempt(client_ip)
            remaining = MAX_ATTEMPTS - login_attempts[client_ip]['count']
            if remaining > 0:
                error = f'密码错误，还剩 {remaining} 次机会'
            else:
                error = f'密码错误，账号已锁定 {LOCKOUT_TIME // 60} 分钟'

    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    """退出登录"""
    resp = redirect(url_for('login'))
    resp.delete_cookie('access_password')
    return resp

# ==================== 路由 ====================

@app.route('/')
def index():
    """首页 - 展示系统概览和攻击类型列表"""
    return render_template('index.html')

# ==================== SSRF攻击演示 ====================

@app.route('/ssrf')
def ssrf_demo():
    """SSRF（服务器端请求伪造）演示页面"""
    return render_template('ssrf.html')

@app.route('/ssrf/fetch')
def ssrf_fetch():
    """SSRF漏洞API - 支持防御模式演示"""
    url = request.args.get('url', '')
    defense_mode = request.args.get('defense', 'true').lower() == 'true'

    if not url:
        return jsonify({'success': False, 'error': '请提供URL参数'})

    try:
        import urllib.request
        import urllib.error
        from urllib.parse import urlparse

        parsed = urlparse(url)

        # ===== 防御模式：URL安全检查 =====
        if defense_mode:
            # 1. 协议白名单检查
            allowed_protocols = ['http', 'https']
            if parsed.scheme and parsed.scheme not in allowed_protocols:
                return jsonify({
                    'success': False,
                    'url': url,
                    'error': f'🛡️ 防御拦截: 协议 "{parsed.scheme}" 不在白名单中',
                    'defense': True,
                    'rule': '协议白名单'
                })

            # 2. 内网地址检查
            internal_hosts = ['127.0.0.1', 'localhost', '0.0.0.0', '[::1]']
            if parsed.hostname in internal_hosts:
                return jsonify({
                    'success': False,
                    'url': url,
                    'error': f'🛡️ 防御拦截: 禁止访问内网地址 {parsed.hostname}',
                    'defense': True,
                    'rule': '内网地址过滤'
                })

            # 3. 内网IP段检查
            if parsed.hostname:
                ip_parts = parsed.hostname.split('.')
                if len(ip_parts) == 4:
                    try:
                        first = int(ip_parts[0])
                        second = int(ip_parts[1])
                        # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                        if first == 10 or (first == 172 and 16 <= second <= 31) or (first == 192 and second == 168):
                            return jsonify({
                                'success': False,
                                'url': url,
                                'error': f'🛡️ 防御拦截: 禁止访问内网IP段 {parsed.hostname}',
                                'defense': True,
                                'rule': '内网IP段过滤'
                            })
                    except ValueError:
                        pass

            # 4. SSRF常见关键词检查
            ssrf_keywords = ['internal', 'admin', 'redis', 'mysql', 'elasticsearch', 'mongo']
            path_lower = (parsed.path or '').lower()
            for keyword in ssrf_keywords:
                if keyword in path_lower:
                    return jsonify({
                        'success': False,
                        'url': url,
                        'error': f'🛡️ 防御拦截: URL包含敏感关键词 "{keyword}"',
                        'defense': True,
                        'rule': '关键词过滤'
                    })

        # ===== 正常请求处理 =====

        # 检测是否为file://协议
        if parsed.scheme == 'file':
            file_path = parsed.path
            # Windows路径兼容
            if file_path.startswith('/') and len(file_path) > 2 and file_path[2] == ':':
                file_path = file_path[1:]
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(5000)
                return jsonify({
                    'success': True,
                    'url': url,
                    'status': 200,
                    'content': content
                })
            except FileNotFoundError:
                return jsonify({
                    'success': False,
                    'url': url,
                    'error': f'文件不存在: {file_path}'
                })
            except PermissionError:
                return jsonify({
                    'success': False,
                    'url': url,
                    'error': f'权限不足: {file_path}'
                })

        # 检测是否为本机请求（SSRF攻击目标）
        if parsed.hostname in ('127.0.0.1', 'localhost'):
            path = parsed.path or '/'
            with app.test_client() as client:
                resp = client.get(path)
                content = resp.get_data(as_text=True)
                if len(content) > 5000:
                    content = content[:5000] + '\n... (内容已截断)'
                return jsonify({
                    'success': True,
                    'url': url,
                    'status': resp.status_code,
                    'content': content
                })

        # 外部URL请求
        response = urllib.request.urlopen(url, timeout=5)
        content = response.read().decode('utf-8', errors='ignore')

        # 限制返回内容大小
        if len(content) > 5000:
            content = content[:5000] + '\n... (内容已截断)'

        return jsonify({
            'success': True,
            'url': url,
            'status': response.status,
            'content': content
        })
    except urllib.error.URLError as e:
        return jsonify({
            'success': False,
            'url': url,
            'error': f'请求失败: {str(e.reason)}'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'url': url,
            'error': f'错误: {str(e)}'
        })

# ==================== 模拟内网服务（SSRF攻击目标） ====================

@app.route('/internal/redis')
def mock_redis():
    """模拟Redis服务"""
    return f"""$ redis_version:6.2.6
$ connected_clients:1
$ used_memory:1.2M
$ redis_mode:standalone
$ os:Linux 64 bit
$ tcp_port:6379
$ uptime_in_seconds:3600
$ keyspace_hits:100
$ keyspace_misses:10""", 200, {'Content-Type': 'text/plain'}

@app.route('/internal/redis/get/<key>')
def mock_redis_get(key):
    """模拟Redis GET命令"""
    keys = {
        'user:session': 'abc123xyz',
        'admin:password': 'super_secret_pass',
        'config:debug': 'true'
    }
    if key in keys:
        return f"${len(keys[key])}\r\n{keys[key]}", 200, {'Content-Type': 'text/plain'}
    return "$-1", 200, {'Content-Type': 'text/plain'}

@app.route('/internal/mysql')
def mock_mysql():
    """模拟MySQL服务"""
    return """5.7.34-log
Protocol version: 10
Connection: 127.0.0.1 via TCP/IP
Server characterset: utf8mb4
Db characterset: utf8mb4
Client characterset: utf8mb4
Conn. characterset: utf8mb4""", 200, {'Content-Type': 'text/plain'}

@app.route('/internal/mysql/status')
def mock_mysql_status():
    """模拟MySQL状态"""
    return jsonify({
        'version': '5.7.34',
        'uptime': 86400,
        'connections': 15,
        'queries': 12345,
        'databases': ['information_schema', 'mysql', 'test_db', 'users_db']
    })

@app.route('/internal/admin')
def mock_admin():
    """模拟内网管理后台"""
    return """<!DOCTYPE html>
<html>
<head><title>内部管理系统</title></head>
<body>
<h1>内部管理系统 - 员工门户</h1>
<p>欢迎访问内部管理系统</p>
<ul>
    <li><a href="/internal/admin/api/users">用户列表</a></li>
    <li><a href="/internal/admin/api/config">系统配置</a></li>
    <li><a href="/internal/admin/api/server">服务器信息</a></li>
</ul>
<p style="color: red;">注意：此系统仅限内网访问</p>
</body>
</html>"""

@app.route('/internal/admin/api/users')
def mock_admin_users():
    """获取用户列表（敏感信息泄露）"""
    return jsonify({
        'status': 'success',
        'data': [
            {'id': 1, 'username': 'admin', 'password': 'admin123', 'email': 'admin@company.com', 'role': 'admin'},
            {'id': 2, 'username': 'john', 'password': 'john456', 'email': 'john@company.com', 'role': 'user'},
            {'id': 3, 'username': 'jane', 'password': 'jane789', 'email': 'jane@company.com', 'role': 'user'}
        ],
        'message': '注意：密码为明文存储（模拟漏洞）'
    })

@app.route('/internal/admin/api/config')
def mock_admin_config():
    """获取系统配置（敏感信息泄露）"""
    return jsonify({
        'status': 'success',
        'data': {
            'database_host': '192.168.1.100',
            'database_password': 'db_password_123',
            'api_key': 'sk-1234567890abcdef',
            'secret_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
        },
        'warning': '这些信息不应该对外暴露'
    })

@app.route('/internal/admin/api/server')
def mock_admin_server():
    """获取服务器信息"""
    return jsonify({
        'status': 'success',
        'data': {
            'internal_ip': '192.168.1.50',
            'os': 'Ubuntu 20.04',
            'kernel': '5.4.0-42-generic',
            'cpu': '4 cores',
            'memory': '16GB'
        }
    })

@app.route('/internal/elasticsearch')
def mock_es():
    """模拟Elasticsearch服务"""
    return jsonify({
        'name': 'es-node-1',
        'cluster_name': 'elasticsearch-cluster',
        'cluster_uuid': 'abc123-def456',
        'version': {
            'number': '7.10.0',
            'build_type': 'zip',
            'lucene_version': '8.7.0'
        },
        'tagline': 'You Know, for Search'
    })

@app.route('/internal/elasticsearch/_cat/indices')
def mock_es_indices():
    """模拟Elasticsearch索引列表"""
    return """health status index                uuid                   pri rep docs.count docs.deleted store.size pri.store.size
green  open   users                abc123                   1   0       1000            0      1.2mb          1.2mb
green  open   logs-2024.01.01      def456                   1   0      50000           100     45.2mb         45.2mb
green  open   products             ghi789                   1   0        500            0    256.1kb        256.1kb""", 200, {'Content-Type': 'text/plain'}

# ==================== 防御方法展示 ====================

@app.route('/defense')
def defense():
    """防御方法介绍页面"""
    return render_template('defense.html')

@app.route('/defense/ssrf')
def defense_ssrf():
    """SSRF防御方法"""
    return render_template('defense_ssrf.html')

# ==================== 主程序入口 ====================

if __name__ == '__main__':
    # 从环境变量读取配置，默认开发模式
    debug_mode = os.environ.get('FLASK_DEBUG', 'true').lower() == 'true'
    host = os.environ.get('FLASK_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_PORT', 5000))

    # 启动Flask应用
    app.run(debug=debug_mode, host=host, port=port)
