---
id: "35-001"
title: "TLS/SSL安全配置与审计 (TLS/SSL Security Configuration & Audit)"
category: "密码学与PKI"
category_en: "Cryptography & PKI"
difficulty: "★★★"
tools: "OpenSSL, testssl.sh, nmap, certbot, SSL Labs"
last_updated: "2026-05"
tags: [tls, ssl, certificate, cipher, security-configuration, audit]
subdomain: cryptography-pki
nist_csf: [PR.DS-01, PR.DS-02, PR.DS-05, DE.CM-07]
mitre_attack: [T1573, T1587, T1608]
---

# TLS/SSL安全配置与审计 (TLS/SSL Security Configuration & Audit)

## 概述

TLS/SSL 是保护网络通信安全的基石协议。错误的 TLS 配置可能导致中间人攻击、协议降级和信息泄露。本技能覆盖 TLS 协议原理、安全配置方法、证书部署和自动化安全审计。

## 核心技能

### 1. TLS 协议与密码套件

```python
"""TLS 安全配置分析"""

class TLSSecurityAnalyzer:
    """TLS 安全配置分析"""
    
    # TLS 协议版本安全性
    TLS_VERSIONS = {
        "1.3": {"secure": True, "year": 2018, "note": "推荐 — 最新安全标准"},
        "1.2": {"secure": True, "year": 2008, "note": "可接受 — 需禁用弱密码套件"},
        "1.1": {"secure": False, "year": 2006, "note": "弃用 — 易受 BEAST 攻击"},
        "1.0": {"secure": False, "year": 1999, "note": "弃用 — 存在多个已知漏洞"},
        "3.0": {"secure": False, "year": 1996, "note": "弃用 — POODLE"},
        "2.0": {"secure": False, "year": 1995, "note": "弃用"},
        "1.0": {"secure": False, "year": 1994, "note": "弃用 — SSL"},
    }
    
    # 密码套件安全性评估
    CIPHER_EVALUATION = {
        "TLS_AES_256_GCM_SHA384": {"security": "secure", "note": "TLS 1.3 默认"},
        "TLS_CHACHA20_POLY1305_SHA256": {"security": "secure", "note": "移动设备推荐"},
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": {"security": "secure", "note": "PFS"},
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": {"security": "secure", "note": "PFS"},
        "TLS_RSA_WITH_AES_256_CBC_SHA256": {"security": "weak", "note": "无 PFS"},
        "TLS_RSA_WITH_AES_128_CBC_SHA": {"security": "weak", "note": "无 PFS"},
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA": {"security": "insecure", "note": "SWEET32"},
        "TLS_RSA_WITH_RC4_128_SHA": {"security": "insecure", "note": "RC4 已破解"},
    }
    
    @staticmethod
    def get_recommended_config():
        """获取推荐 TLS 配置"""
        return {
            "min_tls_version": "1.2",
            "preferred_tls_version": "1.3",
            "ciphers": [
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_AES_128_GCM_SHA256",
                "ECDHE-RSA-AES256-GCM-SHA384",
                "ECDHE-RSA-AES128-GCM-SHA256"
            ],
            "options": [
                "Disable SSLv2/v3",
                "Disable TLS 1.0/1.1",
                "Enable HSTS",
                "Enable OCSP Stapling",
                "Disable Compression",
                "Enable Perfect Forward Secrecy"
            ]
        }
    
    @staticmethod
    def rate_config(tls_versions, ciphers):
        """为 TLS 配置评级"""
        score = 100
        
        # 检查 TLS 版本
        if "1.0" in tls_versions or "1.1" in tls_versions:
            score -= 30
        if "3.0" in str(tls_versions) or "2.0" in str(tls_versions):
            score -= 50
        
        # 检查弱密码
        weak_count = sum(1 for c in ciphers if 
                        "3DES" in c or "RC4" in c or "DES" in c)
        score -= weak_count * 20
        
        # 检查是否支持 PFS
        has_pfs = any("ECDHE" in c or "DHE" in c for c in ciphers)
        if not has_pfs:
            score -= 20
        
        # 检查 TLS 1.3
        has_tls13 = "1.3" in tls_versions
        if has_tls13:
            score += 10
        
        return max(0, min(100, score))

# 使用示例
config = TLSSecurityAnalyzer.get_recommended_config()
print(f"Min TLS: {config['min_tls_version']}")
print(f"Recommended ciphers: {len(config['ciphers'])}")
```

### 2. TLS 配置实践

```bash
# Nginx TLS 安全配置
# 推荐 TLS 配置 (Mozilla Intermediate)
cat > /etc/nginx/conf.d/tls.conf << 'EOF'
server {
    listen 443 ssl http2;
    server_name api.company.com;
    
    # 证书配置
    ssl_certificate /etc/ssl/certs/company.crt;
    ssl_certificate_key /etc/ssl/private/company.key;
    
    # TLS 版本
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # 密码套件
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    
    # 优先使用服务器密码顺序
    ssl_prefer_server_ciphers off;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 1.1.1.1;
    
    # 安全头
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # 会话缓存
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    
    # DH 参数
    ssl_dhparam /etc/ssl/certs/dhparam.pem;
}
EOF

# 生成 DH 参数（2048位以上）
sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
```

```bash
# Apache TLS 安全配置
cat > /etc/httpd/conf.d/tls.conf << 'EOF'
<VirtualHost *:443>
    ServerName api.company.com
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/company.crt
    SSLCertificateKeyFile /etc/ssl/private/company.key
    
    # TLS 版本
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    
    # 密码套件
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    
    SSLHonorCipherOrder off
    
    # HSTS
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    
    # OCSP
    SSLUseStapling on
    SSLStaplingResponderTimeout 5
    SSLStaplingReturnResponderErrors off
    SSLStaplingCache shmcb:/var/run/ocsp(128000)
</VirtualHost>
EOF
```

### 3. TLS 安全审计

```bash
# testssl.sh — TLS 安全审计
# 安装
git clone https://github.com/drwetter/testssl.sh.git
cd testssl.sh

# 快速检查
./testssl.sh --quick api.company.com:443

# 完整扫描
./testssl.sh --full api.company.com:443

# 检查特定漏洞
./testssl.sh --heartbleed api.company.com:443
./testssl.sh --poodle api.company.com:443
./testssl.sh --breach api.company.com:443

# 输出 JSON 报告
./testssl.sh --jsonfile tls_report.json api.company.com:443

# 检查证书信息
./testssl.sh --certificate api.company.com:443

# 检查密码套件
./testssl.sh --cipher-per-proto api.company.com:443

# 使用 nmap 扫描 TLS
nmap --script ssl-enum-ciphers -p 443 api.company.com
nmap --script ssl-cert -p 443 api.company.com
nmap --script ssl-heartbleed -p 443 api.company.com
nmap --script ssl-dh-params -p 443 api.company.com

# OpenSSL 命令行审计
# 查看服务器证书
openssl s_client -connect api.company.com:443 -servername api.company.com 2>/dev/null | openssl x509 -text

# 查看支持的 TLS 版本
openssl s_client -connect api.company.com:443 -tls1_3 2>/dev/null | head -5
openssl s_client -connect api.company.com:443 -tls1_2 2>/dev/null | head -5

# 检查 OCSP 状态
openssl ocsp -issuer ca.crt -cert server.crt \
  -url http://ocsp.company.com -text
```

```python
"""TLS 证书自动检测"""

import subprocess
import json
from datetime import datetime

class TLSCertChecker:
    """TLS 证书到期检查"""
    
    def __init__(self, domains):
        self.domains = domains
    
    def check_cert_expiry(self, domain, port=443):
        """检查证书到期时间"""
        cmd = f"openssl s_client -connect {domain}:{port} -servername {domain} 2>/dev/null | openssl x509 -noout -dates"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            return {"domain": domain, "error": "Connection failed"}
        
        dates = {}
        for line in result.stdout.strip().split("\n"):
            if "notBefore" in line:
                dates["not_before"] = line.split("=")[1]
            elif "notAfter" in line:
                dates["not_after"] = line.split("=")[1]
        
        # 计算到期天数
        if "not_after" in dates:
            expiry = datetime.strptime(dates["not_after"], "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.now()).days
            
            return {
                "domain": domain,
                "expires": dates["not_after"],
                "days_left": days_left,
                "status": "expired" if days_left <= 0 else
                         "critical" if days_left <= 14 else
                         "warning" if days_left <= 30 else "ok",
                "renewal_recommended": days_left <= 30
            }
        
        return {"domain": domain, "error": "Could not parse certificate"}
    
    def check_all(self):
        """检查所有域名"""
        results = []
        for domain in self.domains:
            result = self.check_cert_expiry(domain)
            results.append(result)
        return results

# 使用示例
checker = TLSCertChecker(["api.company.com", "www.company.com", "mail.company.com"])
results = checker.check_all()
for r in results:
    if "days_left" in r:
        print(f"{r['domain']}: {r['days_left']} days left ({r['status']})")
```

### 4. 证书部署自动化

```bash
# Let's Encrypt — 自动证书部署
# 安装 certbot
sudo apt-get install certbot python3-certbot-nginx

# 自动获取并配置证书
sudo certbot --nginx -d api.company.com -d www.company.com

# DNS 验证（通配符证书）
sudo certbot certonly --manual --preferred-challenges dns \
  -d *.company.com -d company.com

# 自动续期
sudo certbot renew --dry-run

# 设置 cron 自动续期
echo "0 3 * * * /usr/bin/certbot renew --quiet --post-hook 'systemctl reload nginx'" | sudo crontab -

# 证书链管理
# 完整的证书链顺序: 服务器证书 → 中间证书 → 根证书
cat server.crt intermediate.crt > fullchain.crt

# 验证证书链
openssl verify -CAfile ca.crt -untrusted intermediate.crt server.crt

# 证书格式转换
# PEM → PFX (Windows)
openssl pkcs12 -export -out certificate.pfx \
  -inkey private.key -in certificate.crt -certfile ca.crt

# PEM → DER (二进制)
openssl x509 -in certificate.crt -outform der -out certificate.der

# 查看证书详细信息
openssl x509 -in certificate.crt -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After|DNS:"
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| testssl.sh | TLS 安全测试 | https://testssl.sh/ |
| OpenSSL | TLS 工具集 | https://www.openssl.org/ |
| certbot | Let's Encrypt 客户端 | https://certbot.eff.org/ |
| nmap ssl-enum-ciphers | TLS 密码扫描 | https://nmap.org/ |
| SSL Labs | TLS 在线测试 | https://www.ssllabs.com/ssltest/ |

## 参考资源

- [Mozilla TLS Configuration Generator](https://ssl-config.mozilla.org/)
- [NIST SP 800-52 Rev 2 — TLS Guidelines](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
- [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [Qualys SSL Labs — SSL/TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)
