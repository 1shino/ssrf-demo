# -*- coding: utf-8 -*-
"""
模拟内网服务 - 用于SSRF攻击演示
包含多个模拟的内网服务，供SSRF攻击测试
"""

from flask import Flask, jsonify, request
import os
import json

# 模拟Redis服务
redis_app = Flask('redis_server')
redis_data = {
    'version': '6.2.6',
    'keys': {
        'user:session': 'abc123xyz',
        'admin:password': 'super_secret_pass',
        'config:debug': 'true'
    }
}

@redis_app.route('/')
def redis_info():
    """模拟Redis INFO命令响应"""
    return f"""$ redis_version:{redis_data['version']}
$ connected_clients:1
$ used_memory:1.2M
$ redis_mode:standalone
$ os:Windows 64 bit
$ tcp_port:6379
$ uptime_in_seconds:3600
$ keyspace_hits:100
$ keyspace_misses:10""", 200, {'Content-Type': 'text/plain'}

@redis_app.route('/get/<key>')
def redis_get(key):
    """模拟Redis GET命令"""
    if key in redis_data['keys']:
        return f"${len(redis_data['keys'][key])}\r\n{redis_data['keys'][key]}", 200, {'Content-Type': 'text/plain'}
    return "$-1", 200, {'Content-Type': 'text/plain'}

# 模拟MySQL服务
mysql_app = Flask('mysql_server')

@mysql_app.route('/')
def mysql_info():
    """模拟MySQL握手包"""
    return """5.7.34-log
Protocol version: 10
Connection: 127.0.0.1 via TCP/IP
Server characterset: utf8mb4
Db characterset: utf8mb4
Client characterset: utf8mb4
Conn. characterset: utf8mb4""", 200, {'Content-Type': 'text/plain'}

@mysql_app.route('/status')
def mysql_status():
    """模拟MySQL状态"""
    return jsonify({
        'version': '5.7.34',
        'uptime': 86400,
        'connections': 15,
        'queries': 12345,
        'databases': ['information_schema', 'mysql', 'test_db', 'users_db']
    })

# 模拟内网管理后台
admin_app = Flask('admin_server')
admin_app.secret_key = 'admin_secret_key_123'

# 模拟敏感数据
sensitive_data = {
    'users': [
        {'id': 1, 'username': 'admin', 'password': 'admin123', 'email': 'admin@company.com', 'role': 'admin'},
        {'id': 2, 'username': 'john', 'password': 'john456', 'email': 'john@company.com', 'role': 'user'},
        {'id': 3, 'username': 'jane', 'password': 'jane789', 'email': 'jane@company.com', 'role': 'user'}
    ],
    'config': {
        'database_host': '192.168.1.100',
        'database_password': 'db_password_123',
        'api_key': 'sk-1234567890abcdef',
        'secret_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
    },
    'server_info': {
        'internal_ip': '192.168.1.50',
        'os': 'Ubuntu 20.04',
        'kernel': '5.4.0-42-generic',
        'cpu': '4 cores',
        'memory': '16GB'
    }
}

@admin_app.route('/')
def admin_index():
    """内网首页"""
    return """<!DOCTYPE html>
<html>
<head><title>内部管理系统</title></head>
<body>
<h1>内部管理系统 - 员工门户</h1>
<p>欢迎访问内部管理系统</p>
<ul>
    <li><a href="/api/users">用户列表</a></li>
    <li><a href="/api/config">系统配置</a></li>
    <li><a href="/api/server">服务器信息</a></li>
    <li><a href="/api/documents">内部文档</a></li>
</ul>
<p style="color: red;">注意：此系统仅限内网访问</p>
</body>
</html>"""

@admin_app.route('/api/users')
def get_users():
    """获取用户列表（敏感信息泄露）"""
    return jsonify({
        'status': 'success',
        'data': sensitive_data['users'],
        'message': '注意：密码为明文存储（模拟漏洞）'
    })

@admin_app.route('/api/config')
def get_config():
    """获取系统配置（敏感信息泄露）"""
    return jsonify({
        'status': 'success',
        'data': sensitive_data['config'],
        'warning': '这些信息不应该对外暴露'
    })

@admin_app.route('/api/server')
def get_server_info():
    """获取服务器信息"""
    return jsonify({
        'status': 'success',
        'data': sensitive_data['server_info']
    })

@admin_app.route('/api/documents')
def get_documents():
    """获取内部文档列表"""
    return jsonify({
        'status': 'success',
        'documents': [
            {'id': 1, 'title': '员工手册', 'path': '/docs/handbook.pdf'},
            {'id': 2, 'title': '薪资表', 'path': '/docs/salary_2024.xlsx'},
            {'id': 3, 'title': '网络拓扑图', 'path': '/docs/network_topology.png'},
            {'id': 4, 'title': '数据库备份', 'path': '/backup/db_20240101.sql'}
        ]
    })

# 模拟Elasticsearch服务
es_app = Flask('es_server')

@es_app.route('/')
def es_info():
    """模拟Elasticsearch信息"""
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

@es_app.route('/_cat/indices')
def es_indices():
    """模拟Elasticsearch索引列表"""
    return """health status index                uuid                   pri rep docs.count docs.deleted store.size pri.store.size
green  open   users                abc123                   1   0       1000            0      1.2mb          1.2mb
green  open   logs-2024.01.01      def456                   1   0      50000           100     45.2mb         45.2mb
green  open   products             ghi789                   1   0        500            0    256.1kb        256.1kb""", 200, {'Content-Type': 'text/plain'}

@es_app.route('/users/_search')
def es_search_users():
    """模拟搜索用户（返回敏感数据）"""
    return jsonify({
        'hits': {
            'total': {'value': 3},
            'hits': [
                {'_source': {'username': 'admin', 'password_hash': '$2b$12$...hashed...', 'email': 'admin@company.com'}},
                {'_source': {'username': 'john', 'password_hash': '$2b$12$...hashed...', 'email': 'john@company.com'}},
                {'_source': {'username': 'jane', 'password_hash': '$2b$12$...hashed...', 'email': 'jane@company.com'}}
            ]
        }
    })

if __name__ == '__main__':
    import threading
    import time

    print("=" * 60)
    print("启动模拟内网服务...")
    print("=" * 60)

    # 启动Redis模拟服务 (端口 16379)
    def run_redis():
        print("[OK] Redis service started at http://127.0.0.1:16379")
        redis_app.run(host='127.0.0.1', port=16379, debug=False, use_reloader=False)

    # 启动MySQL模拟服务 (端口 13306)
    def run_mysql():
        print("[OK] MySQL service started at http://127.0.0.1:13306")
        mysql_app.run(host='127.0.0.1', port=13306, debug=False, use_reloader=False)

    # 启动内网管理后台 (端口 18080)
    def run_admin():
        print("[OK] Admin panel started at http://127.0.0.1:18080")
        admin_app.run(host='127.0.0.1', port=18080, debug=False, use_reloader=False)

    # 启动Elasticsearch模拟服务 (端口 19200)
    def run_es():
        print("[OK] Elasticsearch service started at http://127.0.0.1:19200")
        es_app.run(host='127.0.0.1', port=19200, debug=False, use_reloader=False)

    # 在后台线程启动各服务
    services = [
        threading.Thread(target=run_redis, daemon=True),
        threading.Thread(target=run_mysql, daemon=True),
        threading.Thread(target=run_admin, daemon=True),
        threading.Thread(target=run_es, daemon=True)
    ]

    for t in services:
        t.start()
        time.sleep(0.5)

    print("=" * 60)
    print("All mock services started!")
    print("")
    print("Available services:")
    print("  - Redis:          http://127.0.0.1:16379")
    print("  - MySQL:          http://127.0.0.1:13306")
    print("  - Admin Panel:    http://127.0.0.1:18080")
    print("  - Elasticsearch:  http://127.0.0.1:19200")
    print("")
    print("Press Ctrl+C to stop all services")
    print("=" * 60)

    # 保持主线程运行
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n服务已停止")
