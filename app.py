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

# ==================== 自动拉起真实内网服务 ====================
# 本平台依赖真实运行的内网服务（独立端口/真实数据）作为 SSRF 攻击目标。
# 在 import 时起服务（后台守护线程，绑定 127.0.0.1 回环端口）。
# 关键：gunicorn 无论是否 --preload，容器内总有一个长驻进程(master 或 worker)
# 持有这些服务线程；同一容器所有进程经 127.0.0.1 回环共享端口，故 /ssrf/fetch
# 在任意 worker 都能打到。唯一需跳过的是本地 Flask debug 的 reloader 父进程
# （由 __name__=='__main__' + WERKZEUG_RUN_MAIN 精确识别），避免父子重复绑定。
def start_internal_services():
    """幂等地拉起真实内网服务（Redis/MySQL/Admin/ES + RESP Redis 6379）"""
    if os.environ.get('AUTO_START_INTERNAL_SERVICES', 'true').lower() != 'true':
        return
    try:
        import vulnerable_server
        vulnerable_server.start_all_services()
    except Exception as e:  # 启动失败不应阻断主应用
        print(f'[!] 内网服务启动失败: {e}')


# 本地 debug 的 reloader 父进程会重复执行脚本并占端口；只在"非脚本入口"或
# "reloader 子进程(WERKZEUG_RUN_MAIN=true)"起。gunicorn 下 __name__ 为 'app'，必起。
_is_reloader_parent = (
    __name__ == '__main__'
    and os.environ.get('FLASK_DEBUG', 'true').lower() == 'true'
    and os.environ.get('WERKZEUG_RUN_MAIN') != 'true'
)
if not _is_reloader_parent:
    start_internal_services()


def json_response(data, status=200):
    """返回支持中文的JSON响应"""
    from flask import Response
    import json
    return Response(
        json.dumps(data, ensure_ascii=False),
        status=status,
        content_type='application/json; charset=utf-8'
    )


def _raw_tcp(host, port, payload, timeout=5):
    """真实裸 TCP：连接 host:port，发送 payload 字节，读取回包。
    用于 dict:// 与 gopher:// 协议真实打靶（如 RESP Redis）。"""
    import socket
    s = socket.create_connection((host, int(port)), timeout=timeout)
    s.settimeout(timeout)
    try:
        if payload:
            s.sendall(payload)
        chunks = []
        total = 0
        try:
            while total < 5000:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
                total += len(data)
        except socket.timeout:
            pass  # 读到超时即认为对端回包结束
        return b''.join(chunks)
    finally:
        try:
            s.close()
        except OSError:
            pass

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
    if not ACCESS_PASSWORD:
        return  # 没设置密码则跳过

    # 不需要验证的路径
    skip_paths = ['/login', '/static/', '/ssrf/fetch', '/debug/']
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
    es_port = 19200
    try:
        import vulnerable_server
        es_port = vulnerable_server.service_status()['es']['port']
    except Exception:
        pass
    return render_template('ssrf.html', es_port=es_port)

@app.route('/ssrf/fetch')
def ssrf_fetch():
    """SSRF漏洞API - 对目标发起真实HTTP请求（防御模式可拦截）"""
    url = request.args.get('url', '')
    defense_mode = request.args.get('defense', 'true').lower() == 'true'

    if not url:
        return json_response({'success': False, 'error': '请提供URL参数'})

    try:
        import urllib.request
        import urllib.error
        import urllib.parse
        from urllib.parse import urlparse

        parsed = urlparse(url)

        # ===== 防御模式：URL安全检查 =====
        if defense_mode:
            # 1. 协议白名单检查
            allowed_protocols = ['http', 'https']
            if parsed.scheme and parsed.scheme not in allowed_protocols:
                return json_response({
                    'success': False,
                    'url': url,
                    'error': f'🛡️ 防御拦截: 协议 "{parsed.scheme}" 不在白名单中',
                    'defense': True,
                    'rule': '协议白名单'
                })

            # 2. 内网地址检查
            internal_hosts = ['127.0.0.1', 'localhost', '0.0.0.0', '[::1]']
            if parsed.hostname in internal_hosts:
                return json_response({
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
                            return json_response({
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
                    return json_response({
                        'success': False,
                        'url': url,
                        'error': f'🛡️ 防御拦截: URL包含敏感关键词 "{keyword}"',
                        'defense': True,
                        'rule': '关键词过滤'
                    })

        # ===== 正常请求处理 =====

        # 检测是否为file://协议 - 真实读取服务器本地文件
        if parsed.scheme == 'file':
            file_path = parsed.path
            # Windows路径兼容
            if file_path.startswith('/') and len(file_path) > 2 and file_path[2] == ':':
                file_path = file_path[1:]
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(5000)
                return json_response({
                    'success': True,
                    'url': url,
                    'status': 200,
                    'content': content
                })
            except FileNotFoundError:
                return json_response({
                    'success': False,
                    'url': url,
                    'error': f'文件不存在: {file_path}'
                })
            except PermissionError:
                return json_response({
                    'success': False,
                    'url': url,
                    'error': f'权限不足: {file_path}'
                })

        # ===== dict:// 协议：真实裸 TCP（攻击 RESP Redis 等） =====
        # 形如 dict://host:port/cmd:arg1:arg2  →  发送 "cmd arg1 arg2\r\nquit\r\n"
        if parsed.scheme == 'dict':
            host = parsed.hostname or '127.0.0.1'
            port = parsed.port or 2628
            path = parsed.path.lstrip('/')
            path = urllib.parse.unquote(path)
            args = path.split(':') if path else []
            cmdline = ' '.join(args)
            payload = (cmdline + '\r\n' + 'quit\r\n').encode('utf-8')
            try:
                raw = _raw_tcp(host, port, payload)
                content = raw.decode('utf-8', errors='ignore')
                if len(content) > 5000:
                    content = content[:5000] + '\n... (内容已截断)'
                return json_response({
                    'success': True,
                    'url': url,
                    'status': 200,
                    'protocol': 'dict',
                    'sent': cmdline,
                    'content': content
                })
            except Exception as e:
                return json_response({
                    'success': False,
                    'url': url,
                    'error': f'dict 请求失败: {str(e)}'
                })

        # ===== gopher:// 协议：真实裸 TCP（逐字节发送，攻击 RESP Redis 等） =====
        # 形如 gopher://host:port/_<payload>  →  跳过类型字符，URL 解码后逐字节发送
        if parsed.scheme == 'gopher':
            host = parsed.hostname or '127.0.0.1'
            port = parsed.port or 70
            path = parsed.path
            if path.startswith('/'):
                path = path[1:]
            if path:  # 跳过 gopher 类型字符（如 _）
                path = path[1:]
            payload = urllib.parse.unquote_to_bytes(path)
            try:
                raw = _raw_tcp(host, port, payload)
                content = raw.decode('utf-8', errors='ignore')
                if len(content) > 5000:
                    content = content[:5000] + '\n... (内容已截断)'
                return json_response({
                    'success': True,
                    'url': url,
                    'status': 200,
                    'protocol': 'gopher',
                    'sent_bytes': len(payload),
                    'content': content
                })
            except Exception as e:
                return json_response({
                    'success': False,
                    'url': url,
                    'error': f'gopher 请求失败: {str(e)}'
                })

        # ===== 真实HTTP请求：对目标URL（含本机真实内网服务端口）发起真实请求 =====
        # 对含空格/中文的 path 与 query 进行安全编码，避免 urllib 抛控制字符错误
        safe_url = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            urllib.parse.quote(parsed.path or '/', safe='/'),
            parsed.params,
            urllib.parse.quote(parsed.query, safe='=&+%'),
            parsed.fragment,
        )) if parsed.scheme in ('http', 'https') else url

        req = urllib.request.Request(safe_url, headers={'User-Agent': 'AttackDemo-SSRF/1.0'})
        response = urllib.request.urlopen(req, timeout=5)
        raw = response.read()
        content = raw.decode('utf-8', errors='ignore')

        # 限制返回内容大小
        if len(content) > 5000:
            content = content[:5000] + '\n... (内容已截断)'

        return json_response({
            'success': True,
            'url': url,
            'status': response.status,
            'content': content
        })
    except urllib.error.HTTPError as e:
        # 真实HTTP错误（如404/500），回显响应体用于分析
        body = ''
        try:
            body = e.read().decode('utf-8', errors='ignore')[:2000]
        except Exception:
            pass
        return json_response({
            'success': True,
            'url': url,
            'status': e.code,
            'content': body,
            'error': f'HTTP {e.code} {e.reason}'
        })
    except urllib.error.URLError as e:
        return json_response({
            'success': False,
            'url': url,
            'error': f'请求失败: {str(e.reason)}'
        })
    except Exception as e:
        return json_response({
            'success': False,
            'url': url,
            'error': f'错误: {str(e)}'
        })


# ==================== 诊断：内网服务状态 ====================

@app.route('/debug/services')
def debug_services():
    """探测各真实内网服务是否在监听（用于排查 Railway 部署）"""
    import socket
    specs = [
        ('redis-http', 16379),
        ('mysql-http', 13306),
        ('admin-http', 18080),
        ('es-http', 19200),
        ('redis-resp(dict/gopher)', 6379),
    ]
    services = {}
    for name, port in specs:
        s = socket.socket()
        s.settimeout(1.0)
        up = (s.connect_ex(('127.0.0.1', port)) == 0)
        try:
            s.close()
        except OSError:
            pass
        services[name] = {'port': port, 'host': '127.0.0.1', 'listening': up}

    auto = os.environ.get('AUTO_START_INTERNAL_SERVICES', 'true')
    return json_response({
        'auto_start_env': auto,
        'services': services,
        'all_up': all(v['listening'] for v in services.values()),
    })


@app.route('/debug/reseed')
def debug_reseed():
    """重新种子化真 Redis/ES（FLUSHALL 后重置演示数据）"""
    try:
        import vulnerable_server
        return json_response(vulnerable_server.reseed())
    except Exception as e:
        return json_response({'error': str(e)}, 500)


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

    # 真实内网服务已在 import 时按 reloader 守卫启动（见文件顶部），此处无需再起。
    # 启动Flask应用
    app.run(debug=debug_mode, host=host, port=port)
