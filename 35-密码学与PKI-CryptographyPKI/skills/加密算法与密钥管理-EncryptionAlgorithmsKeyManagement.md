---
id: "35-003"
title: "加密算法与密钥管理 (Encryption Algorithms & Key Management)"
category: "密码学与PKI"
category_en: "Cryptography & PKI"
difficulty: "★★★★"
tools: "OpenSSL, GPG, HashiCorp Vault, HSM, age"
last_updated: "2026-05"
tags: [cryptography, encryption, key-management, symmetric, asymmetric, hsm]
subdomain: cryptography-pki
nist_csf: [PR.DS-01, PR.DS-02, PR.DS-05, PR.DS-06]
mitre_attack: [T1552, T1573, T1587, T1608]
---

# 加密算法与密钥管理 (Encryption Algorithms & Key Management)

## 概述

密码学是信息安全的基础，密钥管理则是密码学的核心难题。本技能覆盖对称与非对称加密算法、哈希函数、数字签名、密钥生命周期管理和硬件安全模块（HSM）的基础应用。

## 核心技能

### 1. 加密算法对比

```python
"""加密算法对比与选择"""

class CryptoAlgorithmGuide:
    """加密算法指南"""
    
    ALGORITHMS = {
        "对称加密": {
            "AES-256-GCM": {
                "type": "对称",
                "key_size": 256,
                "security": "安全",
                "performance": "快",
                "use_case": "数据加密、TLS",
                "note": "推荐 — 认证加密(AEAD)"
            },
            "AES-256-CBC": {
                "type": "对称",
                "key_size": 256,
                "security": "安全（需 HMAC）",
                "performance": "快",
                "use_case": "文件加密",
                "note": "需配合 HMAC 防篡改"
            },
            "ChaCha20-Poly1305": {
                "type": "对称",
                "key_size": 256,
                "security": "安全",
                "performance": "快（移动端更优）",
                "use_case": "移动设备、TLS",
                "note": "Google 推荐移动端优先"
            },
            "3DES": {
                "type": "对称",
                "key_size": 112,
                "security": "不安全",
                "performance": "慢",
                "use_case": "弃用",
                "note": "SWEET32 攻击 — 停止使用"
            }
        },
        "非对称加密": {
            "RSA-4096": {
                "type": "非对称",
                "key_size": 4096,
                "security": "安全",
                "performance": "慢",
                "use_case": "数字签名、密钥交换",
                "note": "广泛兼容"
            },
            "ECDSA-P256": {
                "type": "非对称",
                "key_size": 256,
                "security": "安全",
                "performance": "快",
                "use_case": "数字签名（推荐）",
                "note": "性能优于 RSA"
            },
            "Ed25519": {
                "type": "非对称",
                "key_size": 256,
                "security": "安全",
                "performance": "非常快",
                "use_case": "SSH 密钥、签名",
                "note": "OpenSSH 推荐"
            },
            "ECDH": {
                "type": "非对称",
                "key_size": 256,
                "security": "安全",
                "performance": "快",
                "use_case": "密钥交换",
                "note": "前向安全性"
            }
        },
        "哈希函数": {
            "SHA-256": {
                "type": "哈希",
                "output": 256,
                "security": "安全",
                "use_case": "完整性验证、签名",
                "note": "推荐使用"
            },
            "SHA-3": {
                "type": "哈希",
                "output": 256,
                "security": "安全",
                "use_case": "新系统（未来兼容）",
                "note": "NIST 最新标准"
            },
            "SHA-1": {
                "type": "哈希",
                "output": 160,
                "security": "不安全",
                "use_case": "弃用",
                "note": "SHAttered 碰撞攻击"
            },
            "MD5": {
                "type": "哈希",
                "output": 128,
                "security": "不安全",
                "use_case": "仅校验用",
                "note": "已破解 — 不可用于安全"
            }
        }
    }
    
    @staticmethod
    def recommend_algorithm(use_case):
        """根据场景推荐算法"""
        recommendations = {
            "tls": "TLS 1.3 + AES-256-GCM / ChaCha20-Poly1305 + ECDHE",
            "file_encryption": "AES-256-GCM (推荐) 或 age (现代工具)",
            "digital_signature": "Ed25519 (推荐) 或 ECDSA-P256",
            "password_storage": "Argon2id (推荐) 或 bcrypt/scrypt",
            "key_exchange": "ECDH + Curve25519 (X25519)",
            "disk_encryption": "AES-256-XTS (LUKS/BitLocker)",
            "message_integrity": "HMAC-SHA256",
        }
        return recommendations.get(use_case, "See algorithm table")
    
    @staticmethod
    def key_strength_equivalent():
        """密钥强度等价表"""
        return {
            "Symmetric": {"AES-128": "RSA-3072", "ECDSA-256": "Security: 128-bit"},
            "Symmetric": {"AES-256": "RSA-15360", "ECDSA-512": "Security: 256-bit"},
        }

# 使用示例
for category, algos in CryptoAlgorithmGuide.ALGORITHMS.items():
    print(f"\n{category}:")
    for name, info in algos.items():
        security = info.get("security", "")
        print(f"  {name}: {security}")
```

### 2. 加密实践

```bash
# 对称加密 — OpenSSL
# AES-256-GCM 加密（推荐）
# 加密
openssl enc -aes-256-gcm -salt -pbkdf2 -iter 100000 \
  -in secret.txt -out secret.enc -pass pass:"your-password"

# 解密
openssl enc -d -aes-256-gcm -pbkdf2 -iter 100000 \
  -in secret.enc -out secret.txt -pass pass:"your-password"

# AES-256-CBC + HMAC
# 加密
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
  -in secret.txt -out secret.enc -pass pass:"your-password"

# 非对称加密 — 使用 OpenSSL
# 生成 RSA 密钥对
openssl genrsa -out private.pem 4096
openssl rsa -pubout -in private.pem -out public.pem

# 使用公钥加密
openssl pkeyutl -encrypt -pubin -inkey public.pem \
  -in secret.txt -out secret.enc

# 使用私钥解密
openssl pkeyutl -decrypt -inkey private.pem \
  -in secret.enc -out secret.txt

# 数字签名
# 签名
openssl dgst -sha256 -sign private.pem -out message.sig message.txt

# 验证签名
openssl dgst -sha256 -verify public.pem -signature message.sig message.txt

# 生成 Ed25519 密钥（现代推荐）
openssl genpkey -algorithm Ed25519 -out ed25519_private.pem
openssl pkey -in ed25519_private.pem -pubout -out ed25519_public.pem

# GPG 加密
# 生成 GPG 密钥对
gpg --full-generate-key

# 导出公钥
gpg --armor --export alice@company.com > alice_pubkey.asc

# 加密文件
gpg --armor --encrypt --recipient alice@company.com secret.txt

# 解密文件
gpg --decrypt secret.txt.asc > secret.txt

# 使用 age（现代加密工具）
# 生成密钥
age-keygen -o key.txt

# 加密
age -r age1abc123... -o secret.age secret.txt

# 解密
age -d -i key.txt -o secret.txt secret.age
```

### 3. 密钥管理

```python
"""密钥安全管理系统"""

import hashlib
import secrets
from datetime import datetime, timedelta

class KeyManager:
    """密钥管理器"""
    
    KEY_CLASSIFICATIONS = {
        "c0": "最高机密 — HSM 保护，永不离开硬件",
        "c1": "机密 — 加密存储，严格访问控制",
        "c2": "内部 — 加密存储",
        "c3": "公开 — 无保护要求"
    }
    
    def __init__(self):
        self.keys = {}
        self.access_log = []
    
    def generate_key(self, key_type, key_size, purpose, 
                     classification="c1", rotation_days=365):
        """生成密钥"""
        key_id = f"key-{secrets.token_hex(8)}"
        
        # 生成密钥材料
        if key_type == "aes":
            key_material = secrets.token_bytes(key_size // 8)
        elif key_type == "hmac":
            key_material = secrets.token_bytes(key_size // 8)
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
        
        key = {
            "id": key_id,
            "type": key_type,
            "size": key_size,
            "purpose": purpose,
            "classification": classification,
            "created": datetime.now().isoformat(),
            "expires": (datetime.now() + timedelta(days=rotation_days)).isoformat(),
            "status": "active",
            "version": 1,
            "access_count": 0
        }
        
        # 生产环境应使用 KMS 加密存储
        self.keys[key_id] = {
            "metadata": key,
            "material": key_material  # 生产环境不存储明文
        }
        
        self._audit("GENERATE", key_id)
        return key_id
    
    def get_key(self, key_id, requester, reason):
        """获取密钥（带审计）"""
        if key_id not in self.keys:
            raise ValueError(f"Key {key_id} not found")
        
        key_data = self.keys[key_id]
        
        # 检查过期
        expires = datetime.fromisoformat(key_data["metadata"]["expires"])
        if datetime.now() > expires:
            key_data["metadata"]["status"] = "expired"
            raise ValueError(f"Key {key_id} has expired")
        
        # 审计
        key_data["metadata"]["access_count"] += 1
        self._audit("ACCESS", key_id, requester, reason)
        
        return {
            "key_id": key_id,
            "material": key_data["material"],
            "metadata": key_data["metadata"]
        }
    
    def rotate_key(self, key_id):
        """轮换密钥"""
        old_key = self.keys.get(key_id)
        if not old_key:
            raise ValueError(f"Key {key_id} not found")
        
        old_meta = old_key["metadata"]
        
        # 标记旧密钥为退役
        old_key["metadata"]["status"] = "retired"
        
        # 生成新版本密钥
        new_key_id = self.generate_key(
            old_meta["type"],
            old_meta["size"],
            old_meta["purpose"],
            old_meta["classification"]
        )
        
        # 关联版本
        self.keys[new_key_id]["metadata"]["version"] = old_meta["version"] + 1
        self.keys[new_key_id]["metadata"]["predecessor"] = key_id
        
        self._audit("ROTATE", key_id, note=f"New key: {new_key_id}")
        return new_key_id
    
    def destroy_key(self, key_id, reason):
        """安全销毁密钥"""
        if key_id in self.keys:
            # 零化密钥材料
            key_len = len(self.keys[key_id]["material"])
            self.keys[key_id]["material"] = bytes(key_len)
            self.keys[key_id]["metadata"]["status"] = "destroyed"
            
            self._audit("DESTROY", key_id, note=reason)
            return True
        return False
    
    def list_keys(self, status="active"):
        """列出密钥"""
        return [
            k["metadata"] for k in self.keys.values()
            if k["metadata"]["status"] == status
        ]
    
    def _audit(self, action, key_id, user="system", note=""):
        self.access_log.append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "key_id": key_id,
            "user": user,
            "note": note
        })

# 使用示例
km = KeyManager()
key_id = km.generate_key("aes", 256, "database_encryption", "c1", 365)
print(f"Generated key: {key_id}")

key_data = km.get_key(key_id, "alice", "Database decryption")
print(f"Key type: {key_data['metadata']['type']}, Size: {key_data['metadata']['size']}")
```

### 4. HSM 与云 KMS

```bash
# 硬件安全模块 (HSM) 基础操作
# PKCS#11 接口 — 通过 p11tool
# 初始化 HSM
p11tool --provider /usr/lib/softhsm/libsofthsm2.so \
  --init-token --label "Company HSM" --so-pin "1234" --pin "5678"

# 生成密钥（在 HSM 内部）
p11tool --provider /usr/lib/softhsm/libsofthsm2.so \
  --generate-privkey RSA --bits 2048 \
  --label "server-key" \
  --login --pin "5678"

# 列出 HSM 中的密钥
p11tool --provider /usr/lib/softhsm/libsofthsm2.so \
  --list-all --login --pin "5678"

# 使用 HSM 签名
p11tool --provider /usr/lib/softhsm/libsofthsm2.so \
  --sign --label "server-key" \
  --hash sha256 \
  --in message.txt --out message.sig \
  --login --pin "5678"

# AWS KMS — 云密钥管理
# 创建 KMS 密钥
aws kms create-key --description "Database encryption key" --key-usage ENCRYPT_DECRYPT

# 创建密钥别名
aws kms create-alias --alias-name alias/db-key --target-key-id <key-id>

# 加密数据
aws kms encrypt \
  --key-id alias/db-key \
  --plaintext fileb://secret.txt \
  --output text --query CiphertextBlob \
  --output-file secret.enc

# 解密数据
aws kms decrypt \
  --ciphertext-blob fileb://secret.enc \
  --output text --query Plaintext | base64 --decode > secret.txt

# 自动密钥轮换
aws kms enable-key-rotation --key-id <key-id>

# Azure Key Vault
# 创建密钥库
az keyvault create --name "company-kv" --resource-group security

# 存储密钥
az keyvault key create --vault-name "company-kv" --name "db-key" --protection software

# 加密
az keyvault key encrypt --vault-name "company-kv" --name "db-key" --algorithm RSA-OAEP --value "secret-data"

# GCP Cloud KMS
# 创建密钥环
gcloud kms keyrings create "security-ring" --location "global"

# 创建密钥
gcloud kms keys create "db-key" --location "global" --keyring "security-ring" --purpose "encryption"

# 加密
gcloud kms encrypt --location "global" --keyring "security-ring" --key "db-key" --plaintext-file secret.txt --ciphertext-file secret.enc
```

```python
"""密钥使用最佳实践速查"""

key_best_practices = {
    "密钥生命周期": [
        "使用 KMS/HSM 生成和存储密钥",
        "密钥永不离开加密边界",
        "定期轮换密钥（建议 1 年）",
        "密钥销毁前先验证不再使用"
    ],
    "加密策略": [
        "数据加密使用 AES-256-GCM（认证加密）",
        "传输加密使用 TLS 1.3",
        "密码存储使用 Argon2id/bcrypt",
        "数字签名使用 Ed25519/ECDSA"
    ],
    "密钥分类": [
        "C0: HSM 保护（CA 根密钥、支付密钥）",
        "C1: KMS 加密存储（数据库密钥、API 密钥）",
        "C2: 配置加密（服务间通信密钥）",
        "C3: 无保护要求（公钥）"
    ],
    "审计要求": [
        "所有密钥操作记录审计日志",
        "密钥访问必须双人审批",
        "定期密钥使用审查（季度）",
        "密钥泄露立即轮换"
    ]
}

for category, items in key_best_practices.items():
    print(f"\n{category}:")
    for item in items:
        print(f"  • {item}")
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| OpenSSL | 通用加密工具集 | https://www.openssl.org/ |
| GPG | 邮件/文件加密 | https://gnupg.org/ |
| age | 现代文件加密 | https://age-encryption.org/ |
| HashiCorp Vault | 密钥管理平台 | https://www.vaultproject.io/ |
| SoftHSM | 软件 HSM 模拟 | https://github.com/opendnssec/SoftHSMv2 |

## 参考资源

- [NIST SP 800-57 — Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [NIST SP 800-175B — Cryptographic Standards](https://csrc.nist.gov/publications/detail/sp/800-175b/final)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [AWS KMS Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
- [NSA CNSA 2.0 — Quantum-Resistant Algorithms](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/NSA_CNSA_2.0_ALGORITHMS_.PDF)
