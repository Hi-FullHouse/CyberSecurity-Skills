---
id: 01-001
title: "🌐 DNS枚举 (DNS Enumeration)"
category: 信息搜集
category_en: Reconnaissance
difficulty: ★★
tools: "dnsenum, dig, nslookup, fierce"
last_updated: 2025-07
tags: ["reconnaissance", "osint", "information-gathering", "dns-enumeration", "passive-recon"]
subdomain: reconnaissance
nist_csf: ["ID.AM-01", "ID.AM-04", "DE.CM-01"]
mitre_attack: ["T1595", "T1592", "T1590", "T1596"]
---
# 🌐 DNS枚举 (DNS Enumeration)

## 概述
通过DNS查询获取目标域名的IP、NS记录、MX记录、TXT记录等信息，发现目标网络拓扑结构。

## 核心技能

### 1. 基础DNS查询

```bash
# A记录查询
nslookup -type=A example.com
dig A example.com

# MX记录（邮件服务器）
nslookup -type=MX example.com
dig MX example.com

# NS记录（名称服务器）
nslookup -type=NS example.com
dig NS example.com

# TXT记录（SPF/DKIM等）
nslookup -type=TXT example.com
dig TXT example.com

# SOA记录
dig SOA example.com

# CNAME记录
dig CNAME sub.example.com

# AAAA记录（IPv6）
dig AAAA example.com

# ANY记录（所有记录）
dig ANY example.com
```

### 2. DNS区域传输 (Zone Transfer)

```bash
# 尝试区域传输（很少成功，但值得一试）
dig AXFR @ns1.example.com example.com

# 使用nslookup
nslookup
> server ns1.example.com
> ls -d example.com

# 使用dnsrecon
dnsrecon -d example.com -t axfr

# 使用dnsenum
dnsenum --enum example.com
```

### 3. 反向DNS查询

```bash
# PTR记录（IP反查域名）
dig -x 8.8.8.8

# 批量反向查询
nmap -sL 192.168.1.0/24 | grep "domain"

# dnsrecon反向查询
dnsrecon -r 192.168.1.0/24 -n 8.8.8.8
```

### 4. 暴力DNS枚举

```bash
# dnsenum
dnsenum --dnsserver 8.8.8.8 -f subdomains.txt example.com

# dnsrecon
dnsrecon -d example.com -D subdomains.txt -t brt

# fierce（老旧但有效）
fierce --domain example.com --subdomains subdomains.txt

# 使用massdns（高速）
massdns -r resolvers.txt -t A -o S -w results.txt subdomains.txt
```

### 5. DNS解析器探测

```bash
# 查找可用的DNS解析器
dnsrecon -d example.com -t std
nmap -sU -p53 --script=dns-recursion 192.168.1.0/24
```

### 6. 泛解析检测

```bash
# 检查是否存在泛解析
dig nonexistent.example.com

# 如果是，需要更精确的子域名枚举策略
```

### 7. DNSSEC检测

```bash
# 检查DNSSEC配置
dig DNSKEY example.com
dig DS example.com

# dnsrecon DNSSEC检测
dnsrecon -d example.com -t dnssec
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| dig | 基础DNS查询 | Linux自带 |
| nslookup | 基础DNS查询 | Linux/Windows自带 |
| dnsenum | 综合DNS枚举 | https://github.com/fwaeytens/dnsenum |
| dnsrecon | DNS探测框架 | https://github.com/darkoperator/dnsrecon |
| fierce | DNS暴力枚举 | https://github.com/mschwager/fierce |
| massdns | 高速DNS解析器 | https://github.com/blechschmidt/massdns |

## 常见记录类型

| 记录类型 | 说明 | 用途 |
|:---|:---|:---|
| A | IPv4地址 | 解析域名到IP |
| AAAA | IPv6地址 | 解析域名到IPv6 |
| CNAME | 别名记录 | 域名别名映射 |
| MX | 邮件交换 | 邮件服务器 |
| NS | 名称服务器 | DNS服务器 |
| TXT | 文本记录 | SPF/DKIM/验证 |
| SOA | 授权起始 | 区域权威信息 |
| PTR | 反向记录 | IP到域名 |
| SRV | 服务记录 | 特定服务定位 |

## 参考资源
- [DNS枚举技术详解](https://0xpatrik.com/subdomain-enumeration/)
- [massdns GitHub](https://github.com/blechschmidt/massdns)
- [DNSDB API](https://www.dnsdb.info/)
