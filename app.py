# -*- coding: utf-8 -*-
"""
攻击演示系统 - 主应用程序
基于Flask框架实现B/S架构的攻击演示平台
只保留SSRF攻击演示
"""

from flask import Flask, render_template, request, jsonify
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24).hex())

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
    """SSRF漏洞API - 故意不验证URL（演示漏洞）"""
    url = request.args.get('url', '')

    if not url:
        return jsonify({'success': False, 'error': '请提供URL参数'})

    # 故意不做URL验证（演示漏洞）
    # 真实应用中应该验证URL是否为内网地址
    try:
        import urllib.request
        import urllib.error

        # 设置超时
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
