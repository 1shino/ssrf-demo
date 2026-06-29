# -*- coding: utf-8 -*-
"""
gunicorn 配置：在生产(Railway)下与本地一致地拉起真实内网服务。

关键点：内网服务以守护线程监听 127.0.0.1 的回环端口。gunicorn 会先 import 应用
（在 master 进程）再 fork 出 worker；若在 import 时(master)起线程，线程无法越过
fork 进入 worker。因此这里用 post_fork 钩子，在 worker fork 完成后再起服务——
线程归属于 worker，正常存活。

多 worker 时：第一个绑定的 worker 成功，其余 worker 绑定同端口会得到 EADDRINUSE，
被 start_all_services 内部捕获并跳过（无害）；所有 worker 的 /ssrf/fetch 都经回环
连到已绑定的那个 worker 提供的服务，故多 worker 亦可正常工作。
"""

import os


def post_fork(server, worker):
    """每个 worker fork 后调用一次：在此拉起真实内网服务"""
    if os.environ.get('AUTO_START_INTERNAL_SERVICES', 'true').lower() != 'true':
        return
    try:
        import vulnerable_server
        vulnerable_server.start_all_services()
    except Exception as e:  # 不阻断 worker 启动
        server.log.error(f'内网服务启动失败: {e}')


# 单 worker 即可；多 worker 也兼容（见上方说明）
workers = int(os.environ.get('WEB_CONCURRENCY', '1'))
bind = f'0.0.0.0:{os.environ.get("PORT", "5000")}'
