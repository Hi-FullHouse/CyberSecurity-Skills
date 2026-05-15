---
id: "32-001"
title: "企业IAM策略与架构 (Enterprise IAM Strategy & Architecture)"
category: "身份与访问管理"
category_en: "Identity & Access Management"
difficulty: "★★★"
tools: "Okta, Azure AD, Keycloak, LDAP, FreeIPA"
last_updated: "2026-05"
tags: [iam, identity-management, access-control, sso, directory-services]
subdomain: identity-access-management
nist_csf: [PR.AC-01, PR.AC-04, PR.AC-06, ID.AM-05]
mitre_attack: [T1078, T1528, T1550, T1556]
---

# 企业IAM策略与架构 (Enterprise IAM Strategy & Architecture)

## 概述

身份与访问管理（IAM）是企业安全架构的基石。有效的 IAM 策略确保正确的用户在正确的时间以正确的理由访问正确的资源。本技能覆盖 IAM 架构设计、身份生命周期管理、访问控制模型、SSO 和 MFA 实施。

## 核心技能

### 1. IAM 架构与访问控制模型

```python
"""IAM 访问控制模型"""

from enum import Enum
from typing import List, Dict

class AccessModel(Enum):
    """访问控制模型"""
    DAC = "Discretionary AC"      # 自主访问控制
    MAC = "Mandatory AC"          # 强制访问控制
    RBAC = "Role-Based AC"        # 基于角色的访问控制
    ABAC = "Attribute-Based AC"   # 基于属性的访问控制
    PBAC = "Policy-Based AC"      # 基于策略的访问控制

class RBACEngine:
    """基于角色的访问控制引擎"""
    
    def __init__(self):
        self.users = {}
        self.roles = {}
        self.permissions = {}
        self.role_assignments = {}
    
    def create_role(self, role_name, parent_role=None):
        """创建角色"""
        self.roles[role_name] = {
            "name": role_name,
            "parent": parent_role,
            "permissions": set()
        }
    
    def assign_permission(self, role_name, permission):
        """为角色分配权限"""
        if role_name in self.roles:
            self.roles[role_name]["permissions"].add(permission)
    
    def assign_role(self, user_id, role_name):
        """为用户分配角色"""
        if user_id not in self.role_assignments:
            self.role_assignments[user_id] = set()
        self.role_assignments[user_id].add(role_name)
    
    def check_access(self, user_id, required_permission):
        """检查用户是否有权限"""
        if user_id not in self.role_assignments:
            return False
        
        for role_name in self.role_assignments[user_id]:
            if role_name in self.roles:
                # 检查当前角色
                if required_permission in self.roles[role_name]["permissions"]:
                    return True
                # 检查父角色
                parent = self.roles[role_name]["parent"]
                while parent:
                    if required_permission in self.roles[parent]["permissions"]:
                        return True
                    parent = self.roles[parent].get("parent")
        
        return False
    
    def user_effective_permissions(self, user_id):
        """获取用户有效权限"""
        effective = set()
        if user_id not in self.role_assignments:
            return effective
        
        for role_name in self.role_assignments[user_id]:
            if role_name in self.roles:
                effective.update(self.roles[role_name]["permissions"])
                parent = self.roles[role_name]["parent"]
                while parent:
                    effective.update(self.roles[parent]["permissions"])
                    parent = self.roles[parent].get("parent")
        
        return effective

# 使用示例
rbac = RBACEngine()
rbac.create_role("admin")
rbac.create_role("soc_analyst", parent_role="admin")
rbac.create_role("viewer")

rbac.assign_permission("admin", "incident:write")
rbac.assign_permission("admin", "incident:read")
rbac.assign_permission("soc_analyst", "incident:write")
rbac.assign_permission("viewer", "incident:read")

rbac.assign_role("alice", "soc_analyst")
rbac.assign_role("bob", "viewer")

print(f"Alice can write incidents: {rbac.check_access('alice', 'incident:write')}")
print(f"Bob can write incidents: {rbac.check_access('bob', 'incident:write')}")
```

### 2. 身份生命周期管理

```python
"""身份生命周期管理"""

from datetime import datetime, timedelta

class IdentityLifecycle:
    """身份生命周期管理"""
    
    STAGES = ["provisioning", "active", "suspended", "terminated"]
    
    def __init__(self):
        self.identities = {}
    
    def provision(self, user_data):
        """账号创建"""
        user_id = user_data.get("email", user_data.get("username"))
        identity = {
            "id": user_id,
            "username": user_data.get("username"),
            "email": user_data.get("email"),
            "full_name": user_data.get("full_name"),
            "department": user_data.get("department"),
            "manager": user_data.get("manager"),
            "stage": "provisioning",
            "created": datetime.now().isoformat(),
            "last_access": None,
            "groups": [],
            "mfa_enabled": False
        }
        
        # 自动加入默认组
        identity["groups"] = user_data.get("initial_groups", ["all_employees"])
        
        self.identities[user_id] = identity
        identity["stage"] = "active"
        return identity
    
    def add_to_group(self, user_id, group):
        """加入用户组"""
        if user_id in self.identities:
            if group not in self.identities[user_id]["groups"]:
                self.identities[user_id]["groups"].append(group)
    
    def remove_from_group(self, user_id, group):
        """从用户组移除"""
        if user_id in self.identities:
            self.identities[user_id]["groups"] = [
                g for g in self.identities[user_id]["groups"] if g != group
            ]
    
    def suspend(self, user_id):
        """账号挂起"""
        if user_id in self.identities:
            self.identities[user_id]["stage"] = "suspended"
            self.identities[user_id]["suspended_at"] = datetime.now().isoformat()
    
    def terminate(self, user_id):
        """账号删除"""
        if user_id in self.identities:
            self.identities[user_id]["stage"] = "terminated"
            self.identities[user_id]["terminated_at"] = datetime.now().isoformat()
            # 记录审核日志
            self._audit_log(user_id, "terminated")
    
    def certify_access(self, certifier, user_id):
        """访问认证（定期审查）"""
        if user_id in self.identities:
            self.identities[user_id]["last_certified"] = datetime.now().isoformat()
            self.identities[user_id]["certified_by"] = certifier
            return True
        return False
    
    def detect_inactive_accounts(self, days=90):
        """检测非活跃账号"""
        threshold = datetime.now() - timedelta(days=days)
        inactive = []
        for uid, identity in self.identities.items():
            if identity["stage"] == "active":
                last = identity.get("last_access")
                if last and datetime.fromisoformat(last) < threshold:
                    inactive.append(uid)
                elif not last:
                    inactive.append(uid)
        return inactive
    
    def _audit_log(self, user_id, action):
        """记录审计日志"""
        print(f"[AUDIT] {datetime.now().isoformat()} | {action} | {user_id}")

# 使用示例
lifecycle = IdentityLifecycle()
alice = lifecycle.provision({
    "username": "alice",
    "email": "alice@company.com",
    "full_name": "Alice Wang",
    "department": "Security",
    "manager": "bob",
    "initial_groups": ["all_employees", "security_team"]
})
lifecycle.add_to_group("alice@company.com", "soc_team")
print(f"Alice groups: {alice['groups']}")
```

### 3. SSO 与 MFA 实施

```bash
# SAML 2.0 配置要点
# SAML 使用 XML 签名断言在 IdP 和 SP 之间传递身份信息

# SAML 断言示例结构
# <saml:Assertion>
#   <saml:Issuer>https://idp.company.com/</saml:Issuer>
#   <saml:Subject>
#     <saml:NameID>alice@company.com</saml:NameID>
#   </saml:Subject>
#   <saml:Conditions NotBefore="..." NotOnOrAfter="..."/>
#   <saml:AuthnStatement AuthnInstant="..."/>
#   <saml:AttributeStatement>
#     <saml:Attribute Name="role">admin</saml:Attribute>
#   </saml:AttributeStatement>
# </saml:Assertion>

# OAuth 2.0 / OpenID Connect 流程
# 授权码流程:
# 1. 用户 → 应用: 登录请求
# 2. 应用 → IdP: 授权请求 + redirect_uri
# 3. IdP → 用户: 登录页面
# 4. 用户 → IdP: 凭据 + 同意
# 5. IdP → 应用: 授权码 (redirect)
# 6. 应用 → IdP: 授权码 + client_secret → access_token
# 7. 应用 → 资源: access_token → 受保护资源

# MFA 配置 (Keycloak 示例)
# 登录 Keycloak 管理控制台
# 配置领域 → 认证 → 所需操作 → 配置 OTP

# Keycloak 配置 MFA 策略
kcadm.sh update realms/myrealm -s 'otpPolicyType=totp'
kcadm.sh update realms/myrealm -s 'otpPolicyDigits=6'
kcadm.sh update realms/myrealm -s 'otpPolicyPeriod=30'

# 配置条件 MFA（基于风险）
# 低风险: 仅密码
# 中风险: 密码 + TOTP
# 高风险: 密码 + TOTP + 地理位置验证
```

### 4. 最小权限原则实施

```python
"""最小权限实施框架"""

class LeastPrivilegeEnforcer:
    """最小权限强制执行"""
    
    def __init__(self):
        self.policies = []
    
    def add_policy(self, service, action, allowed_users, conditions=None):
        """添加最小权限策略"""
        self.policies.append({
            "service": service,
            "action": action,
            "allowed_users": set(allowed_users),
            "conditions": conditions or {}
        })
    
    def check_request(self, user, service, action, context=None):
        """检查请求是否合规"""
        context = context or {}
        
        # 查找匹配策略
        for policy in self.policies:
            if policy["service"] == service and policy["action"] == action:
                # 检查用户是否在允许列表
                if user not in policy["allowed_users"]:
                    return {
                        "allowed": False,
                        "reason": f"User {user} not authorized for {service}:{action}",
                        "policy": policy
                    }
                
                # 检查条件
                for cond_key, cond_val in policy["conditions"].items():
                    if context.get(cond_key) != cond_val:
                        return {
                            "allowed": False,
                            "reason": f"Condition {cond_key}={cond_val} not met",
                            "policy": policy
                        }
                
                return {"allowed": True, "policy": policy}
        
        # 默认拒绝
        return {"allowed": False, "reason": "No matching policy"}
    
    def generate_access_review(self):
        """生成访问审查报告"""
        report = {}
        for policy in self.policies:
            key = f"{policy['service']}:{policy['action']}"
            report[key] = {
                "users": list(policy["allowed_users"]),
                "user_count": len(policy["allowed_users"]),
                "conditions": policy["conditions"]
            }
        return report

# 使用示例
enforcer = LeastPrivilegeEnforcer()
enforcer.add_policy("s3", "read", ["alice", "bob"], {"ip_range": "10.0.0.0/8"})
enforcer.add_policy("s3", "write", ["alice"])
enforcer.add_policy("admin:api", "*", ["admin_alice"])

result = enforcer.check_request("bob", "s3", "write")
print(f"Bob write s3: {result['allowed']} — {result['reason']}")

result = enforcer.check_request("bob", "s3", "read", {"ip_range": "10.0.1.5"})
print(f"Bob read s3: {result['allowed']} — {result['reason']}")
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Keycloak | 开源 IAM 与 SSO | https://www.keycloak.org/ |
| Okta | 企业 IAM 云平台 | https://www.okta.com/ |
| Azure AD | 微软身份平台 | https://azure.microsoft.com/products/active-directory/ |
| FreeIPA | 开源身份管理 | https://www.freeipa.org/ |
| LDAP | 目录服务协议 | https://openldap.org/ |

## 参考资源

- [NIST SP 800-63 — Digital Identity Guidelines](https://csrc.nist.gov/publications/detail/sp/800-63/3/final)
- [IAM Best Practices — Gartner](https://www.gartner.com/en/documents/identity-access-management)
- [OAuth 2.0 Specification](https://oauth.net/2/)
- [OpenID Connect Specification](https://openid.net/connect/)
- [CIS IAM Benchmarks](https://www.cisecurity.org/benchmark/amazon_web_services)
