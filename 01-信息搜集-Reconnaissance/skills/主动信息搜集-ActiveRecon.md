---
id: 01-002
title: "🎯 主动信息搜集 (Active Reconnaissance)"
category: 信息搜集
category_en: Reconnaissance
difficulty: ★★★
tools: "Nmap, Masscan, Zmap"
last_updated: 2025-07
tags: ["reconnaissance", "osint", "information-gathering", "dns-enumeration", "passive-recon"]
subdomain: reconnaissance
nist_csf: ["ID.AM-01", "ID.AM-04", "DE.CM-01"]
mitre_attack: ["T1595", "T1592", "T1590", "T1596"]
---
# 🎯 主动信息搜集 (Active Reconnaissance)

## 概述
直接与目标系统交互，探测开放的端口、运行的服务和操作系统信息。**注意：主动探测会留下源IP记录。**

## 核心技能

### 1. Nmap 全面扫描

**基础扫描：**
```bash
# 快速扫描常见端口
nmap -sS -T4 -F target.com

# 全面端口扫描 (1-65535)
nmap -sS -sV -sC -p- -T4 target.com

# 操作系统检测
nmap -O target.com

# 版本检测
nmap -sV --version-intensity 9 target.com

# 禁用DNS解析（加速）
nmap -n -sS -p- -T4 target.com
```

**NSE脚本扫描：**
```bash
# 默认安全脚本
nmap -sV -sC target.com

# 漏洞扫描
nmap --script vuln target.com

# 暴力破解
nmap --script brute target.com

# 特定服务脚本
nmap --script http-headers,http-title,http-server-header target.com

# 自定义NSE脚本目录
nmap --script /path/to/scripts -p80 target.com
```

**扫描策略：**
```bash
# 隐秘扫描（慢速）
nmap -sS -T2 --max-rate=10 target.com

# IDS规避（随机延迟）
nmap -sS -T2 --scan-delay=1s --randomize-hosts target.com

# 分段扫描（分段规避检测）
nmap -sS -p 1-10000 target.com
nmap -sS -p 10001-20000 target.com
nmap -sS -p 20001-65535 target.com
```

### 2. Masscan 高速扫描

```bash
# 高速扫描（每秒10万包）
masscan -p1-65535 --rate=100000 target.com

# 指定网卡
masscan -p80,443,8080 --rate=100000 -e eth0 target.com

# 输出为nmap格式
masscan -p80,443 --rate=100000 -oL output.txt target.com
```

### 3. RustScan (现代高速扫描器)

```bash
# 快速扫描并自动管道到nmap
rustscan -a target.com -- -sV -sC

# 批量扫描
rustscan -a targets.txt --range 1-65535 -- -sV
```

### 4. 服务指纹识别

```bash
# HTTP服务指纹
curl -I http://target.com
curl -s http://target.com | head -20

# 使用Netcat获取服务Banner
nc -v target.com 80
echo -e "HEAD / HTTP/1.0\r\n\r\n" | nc target.com 80

# 使用OpenSSL（HTTPS）
openssl s_client -connect target.com:443
```

### 5. ICMP探测
```bash
# Ping扫描
ping -c 3 target.com
nmap -sn 192.168.1.0/24

# 多种ICMP类型探测
nmap -PE -PP -PM 192.168.1.0/24
```

## Nmap脚本详解

| NSE脚本 | 用途 |
|:---|:---|
| http-headers | 获取HTTP响应头 |
| http-title | 获取页面标题 |
| http-server-header | 获取服务器版本 |
| http-enum | 枚举Web目录/文件 |
| http-methods | 检查允许的HTTP方法 |
| ssl-cert | 获取SSL证书信息 |
| ssl-enum-ciphers | 枚举支持的加密套件 |
| smb-os-discovery | SMB操作系统发现 |
| dns-zone-transfer | DNS区域传输检测 |

## 参考资源
- [Nmap官方文档](https://nmap.org/docs.html)
- [NSE脚本索引](https://nmap.org/nsedoc/)
- [RustScan GitHub](https://github.com/RustScan/RustScan)
- [Masscan GitHub](https://github.com/robertdavidgraham/masscan)
