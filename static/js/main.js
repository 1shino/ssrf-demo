/**
 * 攻击演示系统 - 主JavaScript文件
 * 提供前端交互功能
 */

// 页面加载完成后执行
document.addEventListener('DOMContentLoaded', function() {
    console.log('攻击演示系统已加载');

    // 初始化所有功能
    initTabs();
    initAlerts();
    initCodeHighlight();
});

/**
 * 初始化标签页功能
 */
function initTabs() {
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', function() {
            // 获取目标内容区域
            const target = this.getAttribute('data-target');

            // 移除所有active状态
            tabs.forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');

            // 激活当前标签
            this.classList.add('active');
            if (target) {
                document.getElementById(target).style.display = 'block';
            }
        });
    });
}

/**
 * 初始化警告框自动关闭
 */
function initAlerts() {
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        // 5秒后自动关闭
        setTimeout(() => {
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    });
}

/**
 * 初始化代码高亮
 */
function initCodeHighlight() {
    const codeBlocks = document.querySelectorAll('.code-block pre');
    codeBlocks.forEach(block => {
        // 简单的语法高亮
        let html = block.innerHTML;

        // 高亮SQL关键字
        html = html.replace(/\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|AND|OR|UNION|DROP|TABLE|DATABASE)\b/gi,
            '<span style="color: #ff6b6b;">$1</span>');

        // 高亮HTML标签
        html = html.replace(/(&lt;[^&]*&gt;)/g, '<span style="color: #ffa500;">$1</span>');

        // 高亮引号内容
        html = html.replace(/(["'])(?:(?=(\\?))\2.)*?\1/g,
            '<span style="color: #98c379;">$&</span>');

        block.innerHTML = html;
    });
}

/**
 * 显示提示信息
 * @param {string} message - 提示信息
 * @param {string} type - 类型（info, success, warning, danger）
 */
function showAlert(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    alertDiv.textContent = message;

    const container = document.querySelector('.container');
    container.insertBefore(alertDiv, container.firstChild);

    // 3秒后自动关闭
    setTimeout(() => {
        alertDiv.style.opacity = '0';
        setTimeout(() => alertDiv.remove(), 300);
    }, 3000);
}

/**
 * 复制文本到剪贴板
 * @param {string} text - 要复制的文本
 */
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showAlert('已复制到剪贴板', 'success');
    }).catch(err => {
        console.error('复制失败:', err);
        showAlert('复制失败', 'danger');
    });
}

/**
 * 确认操作
 * @param {string} message - 确认信息
 * @returns {boolean} - 是否确认
 */
function confirmAction(message) {
    return confirm(message);
}

/**
 * 格式化JSON显示
 * @param {string} json - JSON字符串
 * @returns {string} - 格式化后的HTML
 */
function formatJSON(json) {
    try {
        const obj = JSON.parse(json);
        return JSON.stringify(obj, null, 2);
    } catch (e) {
        return json;
    }
}

/**
 * 转义HTML特殊字符
 * @param {string} text - 原始文本
 * @returns {string} - 转义后的文本
 */
function escapeHTML(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * XSS演示 - 弹窗测试
 * @param {string} input - 用户输入
 */
function testXSS(input) {
    // 故意不转义，演示XSS漏洞
    document.getElementById('xss-output').innerHTML = input;
}

/**
 * 显示攻击原理说明
 * @param {string} attackType - 攻击类型
 */
function showPrinciple(attackType) {
    const principles = {
        'xss': 'XSS（跨站脚本攻击）是指攻击者在网页中注入恶意脚本代码，当其他用户访问该页面时，脚本会在用户浏览器中执行。',
        'sqli': 'SQL注入是指攻击者通过在输入字段中插入恶意SQL代码，欺骗服务器执行非预期的SQL命令。',
        'cmdi': '命令注入是指攻击者通过在输入参数中插入系统命令，使服务器执行额外的系统命令。',
        'upload': '文件上传漏洞是指服务器未对上传文件进行充分验证，导致攻击者可上传恶意文件（如webshell）。',
        'csrf': 'CSRF（跨站请求伪造）是指攻击者诱导用户访问恶意网站，利用用户已登录的身份执行非预期操作。'
    };

    alert(principles[attackType] || '未知攻击类型');
}

/**
 * 显示防御方法
 * @param {string} attackType - 攻击类型
 */
function showDefense(attackType) {
    const defenses = {
        'xss': '1. 对用户输入进行转义\n2. 使用CSP（内容安全策略）\n3. 使用HttpOnlyCookie\n4. 输入验证和过滤',
        'sqli': '1. 使用参数化查询（预编译语句）\n2. 输入验证和过滤\n3. 最小权限原则\n4. 使用ORM框架',
        'cmdi': '1. 避免使用system/exec等函数\n2. 使用白名单验证输入\n3. 使用API而非命令行\n4. 输入转义特殊字符',
        'upload': '1. 验证文件扩展名\n2. 检查文件MIME类型\n3. 重命名上传文件\n4. 限制上传目录权限\n5. 使用白名单机制',
        'csrf': '1. 使用CSRF Token\n2. 验证Referer头\n3. 使用SameSite Cookie\n4. 关键操作二次验证'
    };

    alert(defenses[attackType] || '未知攻击类型');
}
