---
id: "35-002"
title: "PKI架构与证书安全管理 (PKI Architecture & Certificate Management)"
category: "密码学与PKI"
category_en: "Cryptography & PKI"
difficulty: "★★★★"
tools: "OpenSSL, EasyRSA, CFSSL, Vault PKI, EJBCA"
last_updated: "2026-05"
tags: [pki, certificate-authority, certificate-management, x509, chain-of-trust]
subdomain: cryptography-pki
nist_csf: [PR.AC-01, PR.DS-01, PR.DS-05, ID.AM-03]
mitre_attack: [T1552, T1587, T1588, T1608]
---

# PKI架构与证书安全管理 (PKI Architecture & Certificate Management)

## 概述

公钥基础设施（PKI）是数字信任的基石，也是企业安全基础设施的关键组件。本技能覆盖 CA 搭建、证书签发与管理、证书生命周期管理和私有 PKI 的最佳实践。

## 核心技能

### 1. 私有 CA 搭建

```bash
# 使用 OpenSSL 搭建私有 CA

# 1. 创建 Root CA
# 生成根 CA 密钥
openssl genrsa -aes256 -out root_ca.key 4096

# 自签名根 CA 证书（10年有效期）
openssl req -x509 -new -nodes -key root_ca.key \
  -sha256 -days 3650 \
  -out root_ca.crt \
  -subj "/C=CN/O=Company Root CA/CN=Company Root Certificate Authority"

# 2. 创建 Intermediate CA
# 生成中间 CA 密钥
openssl genrsa -aes256 -out intermediate_ca.key 4096

# 生成 CSR
openssl req -new -key intermediate_ca.key \
  -out intermediate_ca.csr \
  -subj "/C=CN/O=Company PKI/CN=Company Intermediate CA"

# 用根 CA 签署中间 CA 证书（5年有效期）
openssl x509 -req -in intermediate_ca.csr \
  -CA root_ca.crt -CAkey root_ca.key -CAcreateserial \
  -out intermediate_ca.crt -days 1825 -sha256 \
  -extfile intermediate.ext

# 3. 创建服务器证书
# 生成服务器密钥
openssl genrsa -out server.company.com.key 2048

# 生成 CSR
openssl req -new -key server.company.com.key \
  -out server.company.com.csr \
  -subj "/C=CN/O=Company/CN=server.company.com"

# 创建 SAN 配置文件
cat > san.ext << 'EOF'
subjectAltName=DNS:server.company.com,DNS:api.company.com
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF

# 用中间 CA 签署服务器证书（1年有效期）
openssl x509 -req -in server.company.com.csr \
  -CA intermediate_ca.crt -CAkey intermediate_ca.key -CAcreateserial \
  -out server.company.com.crt -days 365 -sha256 \
  -extfile san.ext

# 创建完整证书链
cat server.company.com.crt intermediate_ca.crt > fullchain.crt

# 验证证书链
openssl verify -CAfile root_ca.crt -untrusted intermediate_ca.crt server.company.com.crt
```

### 2. 证书生命周期管理

```python
"""证书生命周期管理系统"""

from datetime import datetime, timedelta
import json

class CertificateLifecycle:
    """证书生命周期管理"""
    
    def __init__(self):
        self.certificates = {}
        self.audit_log = []
    
    def issue_certificate(self, cn, san_list=None, validity_days=365, cert_type="server"):
        """签发证书"""
        cert_id = f"CERT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        cert = {
            "id": cert_id,
            "common_name": cn,
            "san": san_list or [cn],
            "type": cert_type,
            "status": "active",
            "issued": datetime.now().isoformat(),
            "expires": (datetime.now() + timedelta(days=validity_days)).isoformat(),
            "issuer": "Company Intermediate CA",
            "revoked": False
        }
        
        self.certificates[cert_id] = cert
        self._log("ISSUE", cert_id, f"Issued {cert_type} cert for {cn}")
        return cert
    
    def revoke_certificate(self, cert_id, reason="unspecified"):
        """吊销证书"""
        if cert_id not in self.certificates:
            raise ValueError(f"Certificate {cert_id} not found")
        
        self.certificates[cert_id].update({
            "revoked": True,
            "revoked_at": datetime.now().isoformat(),
            "revocation_reason": reason
        })
        
        self._log("REVOKE", cert_id, f"Revoked: {reason}")
        return True
    
    def renew_certificate(self, cert_id):
        """续期证书"""
        old = self.certificates.get(cert_id)
        if not old:
            raise ValueError(f"Certificate {cert_id} not found")
        
        # 吊销旧证书
        self.revoke_certificate(cert_id, "renewed")
        
        # 签发新证书
        return self.issue_certificate(
            old["common_name"],
            old["san"],
            validity_days=365
        )
    
    def check_expiry_warnings(self):
        """检查到期预警"""
        warnings = []
        now = datetime.now()
        
        for cert_id, cert in self.certificates.items():
            if cert["status"] != "active" or cert.get("revoked"):
                continue
            
            expires = datetime.fromisoformat(cert["expires"])
            days_left = (expires - now).days
            
            if days_left <= 30:
                warnings.append({
                    "cert_id": cert_id,
                    "cn": cert["common_name"],
                    "days_left": days_left,
                    "action": "renew_now" if days_left <= 14 else "renew_soon"
                })
        
        return warnings
    
    def get_certificate_summary(self):
        """获取证书汇总"""
        total = len(self.certificates)
        active = sum(1 for c in self.certificates.values() if c["status"] == "active" and not c.get("revoked"))
        expired = sum(1 for c in self.certificates.values() if datetime.fromisoformat(c["expires"]) < datetime.now())
        revoked = sum(1 for c in self.certificates.values() if c.get("revoked"))
        
        return {
            "total": total,
            "active": active,
            "expired": expired,
            "revoked": revoked,
            "expiring_soon": len(self.check_expiry_warnings())
        }
    
    def _log(self, action, cert_id, message):
        self.audit_log.append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "cert_id": cert_id,
            "message": message
        })

# 使用示例
pki = CertificateLifecycle()
cert = pki.issue_certificate("api.company.com", 
    ["api.company.com", "admin.company.com"], 365)
print(f"Issued: {cert['id']} for {cert['common_name']}")

warnings = pki.check_expiry_warnings()
print(f"Expiring: {len(warnings)} certificates")
```

### 3. 证书撤销与 OCSP

```bash
# 证书撤销列表 (CRL)
# 生成 CRL
openssl ca -gencrl -out crl.pem -config openssl.cnf

# 查看 CRL
openssl crl -in crl.pem -text -noout

# CRL 有效期配置
# default_crl_days = 30 (30天后过期)
# 定期更新 CRL 并分发

# OCSP (Online Certificate Status Protocol)
# 配置 OCSP 响应服务器
openssl ocsp -index index.txt \
  -CA root_ca.crt \
  -rsigner ocsp_response.crt \
  -rkey ocsp_response.key \
  -port 8080 \
  -text

# 客户端查询 OCSP
openssl ocsp -issuer intermediate_ca.crt \
  -cert server.crt \
  -url http://ocsp.company.com:8080 \
  -CAfile root_ca.crt

# OCSP Stapling — 服务器主动提供 OCSP 状态
# Nginx 配置
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 1.1.1.1 valid=300s;

# 验证 OCSP Stapling
openssl s_client -connect api.company.com:443 -status -servername api.company.com 2>&1 | grep -A 20 "OCSP response"

# CRL 分发点配置
# 在 openssl.cnf 中:
# crlDistributionPoints=URI:http://crl.company.com/crl.pem

# OCSP 响应服务器配置
# authorityInfoAccess=OCSP;URI:http://ocsp.company.com
```

### 4. 自动化 PKI 管理

```bash
# Vault PKI — 自动化证书管理
# 启用 PKI 引擎
vault secrets enable pki
vault secrets enable -path=pki_int pki

# 配置根 CA
vault write pki/root/generate/internal \
  common_name="Company Root CA" \
  ttl=87600h

# 配置中间 CA
vault write pki_int/intermediate/generate/internal \
  common_name="Company Intermediate CA"
  
# 签署中间 CA
vault write pki/root/sign-intermediate \
  csr=@pki_int.csr ttl=43800h

# 设置中间 CA
vault write pki_int/intermediate/set-signed certificate=@signed.crt

# 创建角色
vault write pki_int/roles/webserver \
  allowed_domains="company.com" \
  allow_subdomains=true \
  max_ttl=720h \
  key_type=rsa \
  key_bits=2048

# 签发证书
vault write pki_int/issue/webserver \
  common_name="api.company.com" \
  alt_names="admin.company.com" \
  ttl=168h

# CFSSL — CloudFlare PKI 工具
# 安装 CFSSL
go get github.com/cloudflare/cfssl/cmd/cfssl
go get github.com/cloudflare/cfssl/cmd/cfssljson

# 初始化 CA
cfssl genkey -initca ca-csr.json | cfssljson -bare ca

# 使用 config 文件生成
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config ca-config.json \
  -profile=server server-csr.json | cfssljson -bare server

# ca-config.json
cat > ca-config.json << 'EOF'
{
  "signing": {
    "default": {"expiry": "8760h"},
    "profiles": {
      "server": {
        "expiry": "8760h",
        "usages": ["signing", "key encipherment", "server auth"]
      },
      "client": {
        "expiry": "8760h",
        "usages": ["signing", "key encipherment", "client auth"]
      },
      "peer": {
        "expiry": "8760h",
        "usages": ["signing", "key encipherment", "server auth", "client auth"]
      }
    }
  }
}
EOF

# mTLS 配置示例
# 生成客户端证书
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config ca-config.json \
  -profile=client client-csr.json | cfssljson -bare client

# Nginx mTLS 配置
# ssl_client_certificate /etc/ssl/certs/ca.crt;
# ssl_verify_client on;
# ssl_verify_depth 2;
```

```python
"""PKI 健康检查自动化"""

class PKIHealthCheck:
    """PKI 基础设施健康检查"""
    
    CHECKS = {
        "root_ca": [
            "密钥未泄露", "私钥加密存储",
            "离线存储", "有效期 > 5年"
        ],
        "intermediate_ca": [
            "密钥未泄露", "CRL 定期生成",
            "OCSP 在线", "有效期 > 1年"
        ],
        "certificate_operations": [
            "CRL 未过期", "OCSP 响应正常",
            "证书透明度日志", "密钥长度 ≥ 2048"
        ]
    }
    
    def __init__(self):
        self.results = {}
    
    def run_all_checks(self):
        """运行所有 PKI 检查"""
        for category, checks in self.CHECKS.items():
            self.results[category] = []
            for check in checks:
                # 生产环境替换为真实检查逻辑
                self.results[category].append({
                    "check": check,
                    "status": "passed",
                    "details": ""
                })
        return self.results
    
    def health_score(self):
        """PKI 健康评分"""
        total = 0
        passed = 0
        for category, results in self.results.items():
            for result in results:
                total += 1
                if result["status"] == "passed":
                    passed += 1
        return round(passed / total * 100, 1) if total else 0
    
    def report(self):
        """生成健康报告"""
        return {
            "overall_health": self.health_score(),
            "grade": "A" if self.health_score() >= 90 else "B" if self.health_score() >= 75 else "C",
            "details": self.results
        }

checker = PKIHealthCheck()
checker.run_all_checks()
print(f"PKI Health Score: {checker.health_score()}%")
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| OpenSSL | PKI 工具集 | https://www.openssl.org/ |
| EasyRSA | 简易 CA 管理 | https://github.com/OpenVPN/easy-rsa |
| CFSSL | CloudFlare PKI 工具 | https://github.com/cloudflare/cfssl |
| Vault PKI | 自动化 PKI 引擎 | https://www.vaultproject.io/docs/secrets/pki |
| EJBCA | 企业 PKI 平台 | https://www.ejbca.org/ |

## 参考资源

- [NIST SP 800-57 — Key Management / PKI](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [RFC 5280 — X.509 PKI](https://datatracker.ietf.org/doc/html/rfc5280)
- [RFC 6960 — OCSP](https://datatracker.ietf.org/doc/html/rfc6960)
- [OpenSSL PKI Tutorial](https://pki-tutorial.readthedocs.io/)
- [Vault PKI Documentation](https://developer.hashicorp.com/vault/docs/secrets/pki)
