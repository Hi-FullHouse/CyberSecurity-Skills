---
id: "32-002"
title: "PAM特权账号管理 (Privileged Access Management)"
category: "身份与访问管理"
category_en: "Identity & Access Management"
difficulty: "★★★★"
tools: "CyberArk, HashiCorp Vault, BeyondTrust, ManageEngine, Teleport"
last_updated: "2026-05"
tags: [pam, privileged-access, secrets-management, vault, just-in-time]
subdomain: identity-access-management
nist_csf: [PR.AC-01, PR.AC-04, PR.AC-06, PR.DS-05]
mitre_attack: [T1078, T1555, T1556, T1569]
---

# PAM特权账号管理 (Privileged Access Management)

## 概述

特权账号是攻击者的首要目标。PAM（Privileged Access Management）通过管理、监控和保护特权凭证，减少攻击面。本技能覆盖特权凭证管理、会话监控、Just-In-Time 权限提升、密码轮换和审计等核心能力。

## 核心技能

### 1. 特权凭证管理

```python
"""特权凭证安全存储与轮换"""

import hashlib
import secrets
import string
from datetime import datetime

class PrivilegedCredentialManager:
    """特权凭证管理器"""
    
    def __init__(self):
        self.vault = {}  # 加密存储
        self.access_log = []
        self.rotation_policy = {
            "root": {"interval_days": 30, "length": 32},
            "service": {"interval_days": 90, "length": 24},
            "application": {"interval_days": 180, "length": 16}
        }
    
    def store_credential(self, name, credential_type, username, password):
        """存储凭证"""
        entry = {
            "name": name,
            "type": credential_type,
            "username": username,
            "password": self._encrypt(password),
            "created": datetime.now().isoformat(),
            "last_rotated": datetime.now().isoformat(),
            "status": "active"
        }
        self.vault[name] = entry
        self._audit("store", name)
        return name
    
    def get_credential(self, name, requester, reason):
        """获取凭证（审计记录）"""
        if name not in self.vault:
            raise ValueError(f"Credential {name} not found")
        
        self.access_log.append({
            "credential": name,
            "requester": requester,
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
            "action": "retrieve"
        })
        
        entry = self.vault[name]
        return {
            "username": entry["username"],
            "password": self._decrypt(entry["password"])
        }
    
    def rotate_credential(self, name):
        """自动轮换密码"""
        if name not in self.vault:
            raise ValueError(f"Credential {name} not found")
        
        entry = self.vault[name]
        policy = self.rotation_policy.get(entry["type"], 
                                          {"length": 20, "interval_days": 90})
        
        # 生成新密码
        new_password = self._generate_password(policy["length"])
        
        # 更新存储
        entry["password"] = self._encrypt(new_password)
        entry["last_rotated"] = datetime.now().isoformat()
        entry["previous_passwords"] = entry.get("previous_passwords", []) + [entry["password"]]
        
        self._audit("rotate", name)
        return {"name": name, "new_password": new_password}
    
    def check_rotation_due(self):
        """检查需要轮换的凭证"""
        due_for_rotation = []
        now = datetime.now()
        
        for name, entry in self.vault.items():
            policy = self.rotation_policy.get(entry["type"], 
                                              {"interval_days": 90})
            last_rotated = datetime.fromisoformat(entry["last_rotated"])
            days_since = (now - last_rotated).days
            
            if days_since >= policy["interval_days"]:
                due_for_rotation.append({
                    "name": name,
                    "type": entry["type"],
                    "days_since_rotation": days_since,
                    "max_interval": policy["interval_days"]
                })
        
        return due_for_rotation
    
    def _generate_password(self, length=24):
        """生成安全随机密码"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    def _encrypt(self, password):
        """加密存储（生产中使用 KMS）"""
        return f"encrypted:{password[::-1]}"
    
    def _decrypt(self, encrypted):
        """解密"""
        return encrypted.replace("encrypted:", "")[::-1]
    
    def _audit(self, action, credential_name):
        """审计日志"""
        print(f"[PAM AUDIT] {datetime.now().isoformat()} | {action} | {credential_name}")

# 使用示例
pam = PrivilegedCredentialManager()
pam.store_credential("db-root", "root", "dbadmin", "P@ssw0rd123!")
pam.store_credential("svc-api", "service", "svc_api", "ApiSvc#456")
print(pam.get_credential("db-root", "alice", "Database maintenance"))
```

### 2. Just-In-Time 权限提升

```python
"""JIT 权限提升"""

from datetime import datetime, timedelta

class JITPrivilegeElevation:
    """Just-In-Time 权限提升"""
    
    def __init__(self):
        self.active_elevations = {}
        self.approval_queue = []
    
    def request_elevation(self, user, target, permission, reason, duration_minutes=30):
        """请求临时权限提升"""
        request_id = f"JIT-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        request = {
            "id": request_id,
            "user": user,
            "target": target,
            "permission": permission,
            "reason": reason,
            "duration": duration_minutes,
            "status": "pending",
            "requested_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(minutes=duration_minutes)).isoformat()
        }
        
        # 自动审批低风险提升
        if self._auto_approve(request):
            request["status"] = "approved"
            request["approved_by"] = "auto"
            self._activate(request)
        else:
            self.approval_queue.append(request)
        
        return request
    
    def approve_request(self, request_id, approver):
        """审批权限提升"""
        for req in self.approval_queue:
            if req["id"] == request_id:
                req["status"] = "approved"
                req["approved_by"] = approver
                req["approved_at"] = datetime.now().isoformat()
                self._activate(req)
                self.approval_queue.remove(req)
                return req
        return None
    
    def _auto_approve(self, request):
        """自动审批规则"""
        # 低风险目标 + 工作时间 + 短时间
        low_risk_targets = ["dev-*", "test-*"]
        is_low_risk = any(
            request["target"].startswith(t.replace("*", ""))
            for t in low_risk_targets
        )
        within_work_hours = 8 <= datetime.now().hour <= 18
        short_duration = request["duration"] <= 30
        
        return is_low_risk and within_work_hours and short_duration
    
    def _activate(self, request):
        """激活提升的权限"""
        self.active_elevations[request["user"]] = {
            "target": request["target"],
            "permission": request["permission"],
            "expires_at": request["expires_at"]
        }
    
    def check_access(self, user, target, permission):
        """检查是否有有效权限"""
        if user in self.active_elevations:
            elev = self.active_elevations[user]
            expires = datetime.fromisoformat(elev["expires_at"])
            if datetime.now() < expires:
                return True
            else:
                del self.active_elevations[user]  # 自动过期
        
        return False
    
    def revoke_elevation(self, user):
        """撤销提升的权限"""
        if user in self.active_elevations:
            del self.active_elevations[user]
            return True
        return False

# 使用示例
jit = JITPrivilegeElevation()
req = jit.request_elevation(
    "alice", "db-prod", "SELECT",
    "Emergency database query for incident investigation",
    15
)
print(f"Request {req['id']}: {req['status']}")
print(f"Access valid: {jit.check_access('alice', 'db-prod', 'SELECT')}")
```

### 3. 特权会话管理

```python
"""特权会话监控与录制"""

class PrivilegedSessionManager:
    """特权会话管理"""
    
    ACTIVE_SESSIONS = {}
    
    @classmethod
    def start_session(cls, user, target, protocol="SSH"):
        """启动特权会话"""
        import uuid
        session_id = str(uuid.uuid4())[:8]
        
        session = {
            "id": session_id,
            "user": user,
            "target": target,
            "protocol": protocol,
            "started_at": datetime.now().isoformat(),
            "commands": [],
            "status": "active",
            "recorded": True
        }
        
        cls.ACTIVE_SESSIONS[session_id] = session
        print(f"[SESSION] Started: {user} → {target} ({protocol})")
        return session_id
    
    @classmethod
    def log_command(cls, session_id, command):
        """记录会话中的命令"""
        if session_id in cls.ACTIVE_SESSIONS:
            cls.ACTIVE_SESSIONS[session_id]["commands"].append({
                "timestamp": datetime.now().isoformat(),
                "command": command
            })
    
    @classmethod
    def end_session(cls, session_id):
        """结束会话"""
        if session_id in cls.ACTIVE_SESSIONS:
            cls.ACTIVE_SESSIONS[session_id]["status"] = "ended"
            cls.ACTIVE_SESSIONS[session_id]["ended_at"] = datetime.now().isoformat()
            
            session = cls.ACTIVE_SESSIONS[session_id]
            duration = datetime.fromisoformat(session["ended_at"]) - \
                       datetime.fromisoformat(session["started_at"])
            
            print(f"[SESSION] Ended: {session_id} ({duration.total_seconds():.0f}s)")
            return cls.generate_session_report(session_id)
        return None
    
    @classmethod
    def generate_session_report(cls, session_id):
        """生成会话报告"""
        session = cls.ACTIVE_SESSIONS.get(session_id)
        if not session:
            return None
        
        # 检测危险命令
        dangerous = ["rm -rf", "shutdown", "userdel", "chmod 777"]
        alerts = []
        for cmd in session.get("commands", []):
            for danger in dangerous:
                if danger in cmd["command"]:
                    alerts.append({
                        "command": cmd["command"],
                        "timestamp": cmd["timestamp"],
                        "alert": f"Dangerous command: {danger}"
                    })
        
        return {
            "session_id": session_id,
            "user": session["user"],
            "target": session["target"],
            "duration": str(datetime.fromisoformat(session["ended_at"]) - 
                          datetime.fromisoformat(session["started_at"])),
            "total_commands": len(session.get("commands", [])),
            "alerts": alerts
        }

# 使用示例
sid = PrivilegedSessionManager.start_session("admin_alice", "db-prod-01")
PrivilegedSessionManager.log_command(sid, "SELECT * FROM users;")
PrivilegedSessionManager.log_command(sid, "DROP TABLE logs;")  # Dangerous
report = PrivilegedSessionManager.end_session(sid)
print(f"Alerts: {len(report['alerts'])}")
```

### 4. PAM 架构部署

```bash
# HashiCorp Vault 部署与配置
# 安装 Vault
wget https://releases.hashicorp.com/vault/1.16.0/vault_1.16.0_linux_amd64.zip
unzip vault_1.16.0_linux_amd64.zip
sudo mv vault /usr/local/bin/

# Vault 配置 (config.hcl)
cat > /etc/vault/config.hcl << 'EOF'
storage "raft" {
  path = "/opt/vault/data"
  node_id = "node1"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = false
  tls_cert_file = "/etc/vault/certs/cert.pem"
  tls_key_file  = "/etc/vault/certs/key.pem"
}
api_addr = "https://vault.company.com:8200"
cluster_addr = "https://vault.company.com:8201"
seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "alias/vault-unseal"
}
EOF

# 启动 Vault
vault server -config=/etc/vault/config.hcl

# 初始化 Vault（仅在首次）
vault operator init -key-shares=5 -key-threshold=3

# 解封 Vault
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>

# 启用 secret 引擎
vault secrets enable -path=secret kv-v2

# 存储凭证
vault kv put secret/db/prod username=dbadmin password='P@ssw0rd!'

# 配置动态 secret（数据库动态凭据）
vault mount database
vault write database/config/prod-db \
  plugin_name=mysql-database-plugin \
  connection_url="{{username}}:{{password}}@tcp(db.company.com:3306)/" \
  allowed_roles="readonly" \
  username="vault_admin" \
  password="admin_pass"

vault write database/roles/readonly \
  db_name=prod-db \
  creation_statements="CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';GRANT SELECT ON *.* TO '{{name}}'@'%';" \
  default_ttl="1h" \
  max_ttl="24h"

# CyberArk 核心模块
# 1. Vault: 凭证加密存储
# 2. PSM: 特权会话管理器
# 3. CPM: 密码自动轮换
# 4. AIM: 应用身份管理
# 5. PTA: 特权威胁分析

# CyberArk 策略配置
# 密码策略:
# - 复杂性: 大写 + 小写 + 数字 + 特殊字符
# - 长度: 20-30 字符
# - 轮换频率: 30 天（root）/ 90 天（服务账号）
# - 重用限制: 禁止使用前 5 次密码
# - 立即轮换: 检出后立即变更密码

# PSM 会话管理
# 支持协议: RDP, SSH, WinRM, PSQL, MySQL
# 会话录制: 录屏 + 命令文本
# 危险命令: 实时告警阻断
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| CyberArk | 企业 PAM 平台 | https://www.cyberark.com/ |
| HashiCorp Vault | 密钥管理平台 | https://www.vaultproject.io/ |
| BeyondTrust | 特权访问管理 | https://www.beyondtrust.com/ |
| Teleport | 基础设施访问控制 | https://goteleport.com/ |
| ManageEngine PAM | PAM 解决方案 | https://www.manageengine.com/privileged-access-management/ |

## 参考资源

- [NIST SP 800-207 — Zero Trust / PAM](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [CyberArk PAM Best Practices](https://www.cyberark.com/resources/privileged-access-management)
- [HashiCorp Vault Documentation](https://developer.hashicorp.com/vault/docs)
- [Gartner PAM Market Guide](https://www.gartner.com/en/documents/market-guide-for-privileged-access-management)
- [CIS PAM Controls](https://www.cisecurity.org/controls/privileged-access-management)
