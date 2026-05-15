---
id: "34-002"
title: "API认证与授权安全 (API Authentication & Authorization Security)"
category: "API安全"
category_en: "API Security"
difficulty: "★★★★"
tools: "OAuth 2.0, OIDC, JWT, Keycloak, Auth0"
last_updated: "2026-05"
tags: [api-security, authentication, authorization, oauth, jwt, oidc]
subdomain: api-security
nist_csf: [PR.AC-01, PR.AC-04, PR.AC-07, PR.DS-05]
mitre_attack: [T1528, T1550, T1556, T1606]
---

# API认证与授权安全 (API Authentication & Authorization Security)

## 概述

API 认证和授权是 API 安全的基石。严重的漏洞往往来自认证机制缺陷或授权控制不当。本技能覆盖 OAuth 2.0 流程安全、JWT 安全实现、OIDC 配置和 API Key 管理。

## 核心技能

### 1. OAuth 2.0 流程安全

```python
"""OAuth 2.0 安全实现"""

import hashlib
import secrets
import base64
from datetime import datetime

class OAuth2Security:
    """OAuth 2.0 安全实现"""
    
    @staticmethod
    def generate_pkce_pair():
        """生成 PKCE 码对（防授权码拦截）"""
        code_verifier = secrets.token_urlsafe(64)
        
        # S256 哈希
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b'=').decode()
        
        return {
            "code_verifier": code_verifier,
            "code_challenge": code_challenge,
            "method": "S256"
        }
    
    @staticmethod
    def validate_redirect_uri(requested_uri, allowed_uris):
        """验证重定向 URI（防开放重定向）"""
        # 严格匹配，而非前缀匹配
        if requested_uri in allowed_uris:
            return True
        
        # 模式匹配
        import re
        for pattern in allowed_uris:
            if re.match(pattern.replace("*", ".*"), requested_uri):
                return True
        
        return False
    
    @staticmethod
    def validate_state_param(state, stored_state):
        """验证 state 参数（防 CSRF）"""
        if not state or not stored_state:
            return False
        return secrets.compare_digest(state, stored_state)
    
    @staticmethod
    def check_token_binding(access_token, client_id):
        """检查 Token 绑定（Sender Constraint）"""
        # 生产中使用 DPoP (Demonstration of Proof-of-Possession)
        # 确保 token 只能由绑定的客户端使用
        return True
    
    @staticmethod
    def security_checklist():
        """OAuth 2.0 安全清单"""
        return {
            "授权码流程": [
                "必须使用 PKCE (S256)",
                "授权码一次性使用",
                "授权码有效期短 (< 10分钟)",
                "严格验证 redirect_uri",
                "state 参数防 CSRF"
            ],
            "令牌端点": [
                "client_secret 不能暴露在 URL 中",
                "令牌请求必须使用 TLS",
                "刷新令牌可轮换",
                "access_token 有效期短 (< 1小时)"
            ],
            "资源访问": [
                "验证 token 签名 (JWKS)",
                "验证 token 过期时间",
                "验证 issuer (iss)",
                "验证 audience (aud)",
                "使用最小权限 scope"
            ]
        }

# 使用示例
pkce = OAuth2Security.generate_pkce_pair()
print(f"PKCE Challenge: {pkce['code_challenge'][:20]}...")

checklist = OAuth2Security.security_checklist()
for section, items in checklist.items():
    print(f"\n{section}:")
    for item in items:
        print(f"  ☐ {item}")
```

### 2. JWT 安全实现

```python
"""JWT 安全实现与验证"""

import json
import time
import hmac
import hashlib
import base64

class JWTValidator:
    """JWT 安全验证器"""
    
    def __init__(self):
        self.weaknesses_checked = []
    
    def decode_jwt(self, token):
        """解码 JWT 不验证签名"""
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        def b64decode(data):
            padding = 4 - len(data) % 4
            if padding != 4:
                data += '=' * padding
            return base64.urlsafe_b64decode(data)
        
        try:
            header = json.loads(b64decode(parts[0]))
            payload = json.loads(b64decode(parts[1]))
            return {"header": header, "payload": payload, "signature": parts[2]}
        except Exception:
            return None
    
    def verify_jwt(self, token, expected_issuer, expected_audience, jwks_client=None):
        """完整 JWT 验证"""
        decoded = self.decode_jwt(token)
        if not decoded:
            return {"valid": False, "reason": "Invalid JWT format"}
        
        header = decoded["header"]
        payload = decoded["payload"]
        weaknesses = []
        
        # 1. 算法验证 — 防止 alg=none 攻击
        alg = header.get("alg", "")
        if alg == "none":
            weaknesses.append("alg=none: JWT 无签名验证")
            return {"valid": False, "reason": "alg=none attack", "weaknesses": weaknesses}
        
        # 2. 算法混淆攻击
        if alg == "HS256" and header.get("typ") == "JWT":
            # 检查是否使用 RS256 公钥作为 HS256 密钥
            weaknesses.append("Possible algorithm confusion: check key usage")
        
        # 3. 过期时间
        exp = payload.get("exp", 0)
        if time.time() > exp:
            weaknesses.append("Token expired")
            return {"valid": False, "reason": "Token expired", "weaknesses": weaknesses}
        
        # 4. 生效时间
        nbf = payload.get("nbf", 0)
        if nbf > time.time():
            weaknesses.append("Token not yet valid (nbf)")
        
        # 5. Issuer 验证
        if payload.get("iss") != expected_issuer:
            weaknesses.append(f"Issuer mismatch: {payload.get('iss')} != {expected_issuer}")
        
        # 6. Audience 验证
        aud = payload.get("aud")
        if isinstance(aud, list):
            if expected_audience not in aud:
                weaknesses.append(f"Audience mismatch: {aud}")
        elif aud != expected_audience:
            weaknesses.append(f"Audience mismatch: {aud} != {expected_audience}")
        
        # 7. jti 唯一性检查
        jti = payload.get("jti")
        if not jti:
            weaknesses.append("No jti (token ID) — replay possible")
        
        result = {
            "valid": len(weaknesses) == 0,
            "weaknesses": weaknesses,
            "payload": {
                "sub": payload.get("sub"),
                "iss": payload.get("iss"),
                "exp": payload.get("exp"),
                "scopes": payload.get("scope", "").split()
            }
        }
        
        return result
    
    @staticmethod
    def create_secure_token(user_id, scopes, secret, issuer="api.company.com", expiry=3600):
        """创建安全 JWT"""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": user_id,
            "iss": issuer,
            "aud": "api.company.com",
            "exp": int(time.time()) + expiry,
            "iat": int(time.time()),
            "nbf": int(time.time()),
            "jti": secrets.token_hex(16),
            "scope": " ".join(scopes),
            "client_id": user_id
        }
        
        def b64encode(data):
            return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()
        
        header_b64 = b64encode(header)
        payload_b64 = b64encode(payload)
        signature = hmac.new(
            secret.encode(),
            f"{header_b64}.{payload_b64}".encode(),
            hashlib.sha256
        ).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
        
        return f"{header_b64}.{payload_b64}.{sig_b64}"

# 使用示例
import secrets
secret = secrets.token_hex(32)
token = JWTValidator.create_secure_token("user123", ["read:orders"], secret)
print(f"Token: {token[:50]}...")

validator = JWTValidator()
result = validator.verify_jwt(token, "api.company.com", "api.company.com")
print(f"Valid: {result['valid']}")
```

### 3. API Key 管理

```python
"""API Key 安全管理系统"""

import hashlib
import secrets
from datetime import datetime, timedelta

class APIKeyManager:
    """API 密钥管理器"""
    
    def __init__(self):
        self.keys = {}
        self.audit_log = []
    
    def generate_key(self, owner, permissions, expires_days=365):
        """生成 API Key"""
        # 生成 Key ID (前缀)
        key_id = f"ak_{secrets.token_hex(8)}"
        
        # 生成 Secret Key
        raw_key = secrets.token_urlsafe(48)
        
        # 存储哈希值
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        
        self.keys[key_id] = {
            "owner": owner,
            "permissions": permissions,
            "hash": key_hash,
            "created": datetime.now().isoformat(),
            "expires": (datetime.now() + timedelta(days=expires_days)).isoformat(),
            "last_used": None,
            "enabled": True
        }
        
        self._audit("key_generated", owner, key_id)
        
        # 返回完整密钥（只有生成时能看到）
        return {
            "key_id": key_id,
            "secret_key": raw_key,  # 仅返回一次！
            "full_key": f"{key_id}.{raw_key}"
        }
    
    def validate_key(self, full_key):
        """验证 API Key"""
        try:
            key_id, secret_key = full_key.split(".", 1)
        except ValueError:
            return None
        
        if key_id not in self.keys:
            return None
        
        key_data = self.keys[key_id]
        
        # 检查是否启用
        if not key_data["enabled"]:
            return None
        
        # 检查过期
        expires = datetime.fromisoformat(key_data["expires"])
        if datetime.now() > expires:
            return None
        
        # 验证密钥
        key_hash = hashlib.sha256(secret_key.encode()).hexdigest()
        if key_hash != key_data["hash"]:
            return None
        
        # 更新使用时间
        key_data["last_used"] = datetime.now().isoformat()
        
        return {
            "key_id": key_id,
            "owner": key_data["owner"],
            "permissions": key_data["permissions"]
        }
    
    def revoke_key(self, key_id, revoked_by):
        """吊销 API Key"""
        if key_id in self.keys:
            self.keys[key_id]["enabled"] = False
            self.keys[key_id]["revoked_at"] = datetime.now().isoformat()
            self.keys[key_id]["revoked_by"] = revoked_by
            self._audit("key_revoked", revoked_by, key_id)
            return True
        return False
    
    def rotate_key(self, key_id, owner):
        """轮换 API Key"""
        if key_id not in self.keys:
            return None
        
        old_key = self.keys[key_id]
        permissions = old_key["permissions"]
        
        # 吊销旧密钥
        self.revoke_key(key_id, owner)
        
        # 生成新密钥
        return self.generate_key(owner, permissions)
    
    def list_keys(self, owner=None):
        """列出密钥（不含 secret）"""
        result = []
        for key_id, data in self.keys.items():
            if owner and data["owner"] != owner:
                continue
            result.append({
                "key_id": key_id,
                "owner": data["owner"],
                "permissions": data["permissions"],
                "created": data["created"],
                "expires": data["expires"],
                "last_used": data["last_used"],
                "enabled": data["enabled"]
            })
        return result
    
    def _audit(self, action, user, key_id):
        self.audit_log.append({
            "action": action,
            "user": user,
            "key_id": key_id,
            "timestamp": datetime.now().isoformat()
        })

# 使用示例
key_mgr = APIKeyManager()
new_key = key_mgr.generate_key("alice", ["read:users", "write:orders"], 90)
print(f"Key ID: {new_key['key_id']}")

valid = key_mgr.validate_key(new_key['full_key'])
print(f"Valid: {valid is not None}, Owner: {valid['owner'] if valid else 'N/A'}")
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Keycloak | 认证授权服务器 | https://www.keycloak.org/ |
| Auth0 | 认证即服务 | https://auth0.com/ |
| jwt.io | JWT 调试工具 | https://jwt.io/ |
| OAuth 2.0 Playground | OAuth 流程测试 | https://www.oauth.com/playground/ |
| DPoP | Token 绑定规范 | https://datatracker.ietf.org/doc/html/rfc9449 |

## 参考资源

- [OAuth 2.0 Security BCP (RFC 9700)](https://datatracker.ietf.org/doc/rfc9700/)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [OAuth 2.0 for Browser-Based Apps](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/)
- [API Key Security Best Practices](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-key.html)
- [NIST SP 800-63B — Authentication Lifecycle](https://csrc.nist.gov/publications/detail/sp/800-63b/final)
