---
id: 12-008
title: "🐍 Python代码审计 (Python Code Audit)"
category: 代码审计
category_en: "Code Audit"
difficulty: ★★★
tools: "Bandit, Semgrep, Pyre, CodeQL"
last_updated: 2025-07
tags: ["code-audit", "static-analysis", "php-audit", "java-audit", "javascript-audit"]
subdomain: code-audit
nist_csf: ["PR.IP-12", "ID.RA-01"]
mitre_attack: []
---
# 🐍 Python代码审计 (Python Code Audit)

## 概述
审查Python Web应用和服务中的安全漏洞，包括Django/Flask框架特有漏洞和Python运行时安全问题。

## 核心技能

### 1. Python Web框架审计

```python
# --- Flask审计 ---
# 危险: 调试模式开启
app.run(debug=True)  # 生产环境禁止

# 危险: 模板注入 (Jinja2)
from flask import render_template_string
@app.route('/hello')
def hello():
    name = request.args.get('name', '')
    # 注入: {{config}} / {{''.__class__.__mro__[2].__subclasses__()}}
    return render_template_string(f"<h1>Hello {name}</h1>")

# 安全: 使用render_template
from flask import render_template
@app.route('/hello')
def hello():
    name = request.args.get('name', '')
    return render_template('hello.html', name=name)  # 自动转义

# 危险: SECRET_KEY硬编码
app.config['SECRET_KEY'] = 'hardcoded-key'

# 安全: 使用环境变量
import os
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

# --- Django审计 ---
# 危险: DEBUG=True
DEBUG = True  # 生产环境应设为False

# 危险: ALLOWED_HOSTS开放
ALLOWED_HOSTS = ['*']  # 应限制具体域名

# 危险: SQL注入
User.objects.raw(f"SELECT * FROM users WHERE id = {request.GET['id']}")

# 安全: 使用ORM
User.objects.filter(id=request.GET['id'])

# 危险: SECRET_KEY硬编码
SECRET_KEY = 'hardcoded-key-should-not-be-here'
```

### 2. 命令注入与代码执行

```python
# --- 命令执行危险函数 ---
import os
import subprocess

# 危险
os.system("ping -c 3 " + user_input)
os.popen("nslookup " + user_input)
subprocess.call("ping " + user_input, shell=True)  # shell=True是危险信号
subprocess.Popen("ping " + user_input, shell=True)

# 安全
import shlex
subprocess.call(["ping", "-c", "3", validate_ip(user_input)])
subprocess.call(shlex.split(f"ping -c 3 {validate_ip(user_input)}"))

# --- eval/exec注入 ---
# 危险
eval(user_input)  # 执行任意代码
exec(user_input)  # 执行任意代码

# 安全: 使用ast.literal_eval替代eval
import ast
try:
    result = ast.literal_eval(user_input)  # 安全地解析字面量
except ValueError:
    # 处理错误
    pass

# --- pickle反序列化 ---
# 危险
import pickle
data = pickle.loads(user_input)  # 可执行任意代码

# 安全: 使用JSON替代
import json
data = json.loads(user_input)

# --- yaml.load ---
# 危险
import yaml
data = yaml.load(user_input)  # 默认不安全

# 安全
data = yaml.safe_load(user_input)

# --- requests库SSRF ---
# 需要验证URL
import requests
# 危险
url = request.form['url']
response = requests.get(url, timeout=10)

# 安全: URL白名单验证
ALLOWED_URLS = ['https://api.example.com', 'https://api.trusted.com']
def is_safe_url(url):
    return any(url.startswith(allowed) for allowed in ALLOWED_URLS)
```

### 3. 模板注入 (SSTI)

```python
# --- Jinja2模板注入 ---
# 检测点: 用户输入被传入模板渲染

# 危险
from flask import render_template_string
template = request.args.get('template')
html = render_template_string(template)

# 漏洞利用payload
# {{ config }}
# {{ ''.__class__.__mro__[2].__subclasses__() }}
# {{ cycler.__init__.__globals__.os.popen('id').read() }}
# {{ lipsum.__globals__["os"].popen('cat /etc/passwd').read() }}

# 简单检测
# http://target.com/?name={{7*7}} -> 返回49说明存在SSTI

# 安全: 使用白名单模板
ALLOWED_TEMPLATES = ['welcome.html', 'profile.html', 'about.html']
# 或使用SandboxedEnvironment
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()
template = env.from_string(user_input)  # 限制了危险操作

# --- Django模板注入 ---
# Django模板自动转义较安全
# 但手动标记safe可能引入XSS
{{ user_input|safe }}  # 危险，关闭自动转义
```

### 4. 反序列化漏洞

```python
# --- 常见反序列化漏洞库 ---
# pickle - 高危
# YAML - 高危 (使用safe_load)
# JSON - 安全
# XML - 中危 (XXE)

# --- pickle利用 ---
import pickle
import os

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('whoami',))

# 生成恶意payload
malicious = pickle.dumps(Exploit())
# 发送到服务器: pickle.loads(malicious)

# --- 防御方法 ---
# 1. 避免使用pickle
# 2. 使用hmac验证数据完整性
import hmac
import hashlib

SECRET_KEY = b'your-secret-key'
data = {"user_id": 123, "role": "user"}
serialized = pickle.dumps(data)
signature = hmac.new(SECRET_KEY, serialized, hashlib.sha256).hexdigest()
safe_data = serialized + signature.encode()

# 验证
def secure_load(data):
    data, sig = data[:-64], data[-64:]
    expected = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    if hmac.compare_digest(sig.decode(), expected):
        return pickle.loads(data)
    raise ValueError("Invalid signature")
```

### 5. 数据库与ORM安全

```python
# --- SQLAlchemy审计 ---
from sqlalchemy import text
from flask_sqlalchemy import SQLAlchemy

# 危险: 拼接SQL
db.session.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))

# 安全: 参数化查询
db.session.execute(text("SELECT * FROM users WHERE id = :id"), {'id': user_id})

# --- Django ORM ---
# 危险: raw SQL
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")

# 安全: 参数化
User.objects.raw("SELECT * FROM users WHERE name = %s", [name])

# --- NoSQL (MongoEngine) ---
# 危险
User.objects.get(username=request.form['username'])

# 攻击: {"username": {"$gt": ""}}
# 安全: 类型验证
from mongoengine.errors import DoesNotExist
try:
    username = str(request.form['username'])  # 强制字符串
    user = User.objects.get(username=username)
except (DoesNotExist, ValueError):
    pass
```

### 6. 安全配置

```python
# --- Django settings.py检查 ---
# 必须检查的安全配置

SECRET_KEY = os.environ['DJANGO_SECRET_KEY']  # 不是硬编码
DEBUG = False                                  # 生产环境关闭
ALLOWED_HOSTS = ['example.com']               # 限制主机头

# Session配置
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True                  # HTTPS
SESSION_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True

# 安全中间件
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    # ...
]

# Content Security Policy
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")

# --- Flask配置检查 ---
app.config.update(
    SECRET_KEY=os.environ['FLASK_SECRET_KEY'],
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    MAX_CONTENT_LENGTH=16 * 1024 * 1024  # 16MB上传限制
)
```

### 7. 自动化审计

```bash
# Bandit - Python安全扫描器
bandit -r /path/to/project/
bandit -r /path/to/project/ -f html -o report.html
bandit -r /path/to/project/ --ignore B101  # 忽略特定规则

# 自定义Bandit配置
# .bandit.yaml
# skips: ['B101', 'B301']
# exclude: ['/tests/', '/migrations/']

# Safety - 依赖安全检查
safety check
safety check -r requirements.txt

# Pyre - 类型检查和污点分析
pyre --source-directory src check

# Pylint + 自定义安全规则
pylint --load-plugins=pylint_django --disable=all --enable=fixme /path/to/project/

# grep搜索模式
# 命令执行
grep -rn "os.system\|os.popen\|subprocess.call\|subprocess.Popen\|eval(\|exec(" --include="*.py"

# 反序列化
grep -rn "pickle.loads\|pickle.load\|yaml.load\|shelve.open\|marshal.load" --include="*.py"

# 数据库注入
grep -rn "raw_query\|raw(" --include="*.py"

# 危险函数
grep -rn "shell=True\|allow_url_fopen\|enableAutoType\|__reduce__" --include="*.py"

# 调试配置
grep -rn "DEBUG=True\|debug=True\|app.run(" --include="*.py"
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Bandit | Python安全扫描 | https://github.com/PyCQA/bandit |
| Safety | 依赖安全检查 | https://github.com/pyupio/safety |
| Semgrep | 代码搜索/SAST | https://semgrep.dev/ |
| Pyre | 类型检查+安全 | https://pyre-check.org/ |
| Flake8-Security | Flake8安全插件 | https://github.com/waynehoover/flake8-security |
| Pyt | Python污点分析 | https://github.com/python-security/pyt |

## 参考资源
- [OWASP Python Security](https://owasp.org/www-project-python-security/)
- [Python Security Documentation](https://docs.python.org/3/library/security_warnings.html)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Django Security Guide](https://docs.djangoproject.com/en/stable/topics/security/)
- [Flask Security Considerations](https://flask.palletsprojects.com/en/stable/security/)
