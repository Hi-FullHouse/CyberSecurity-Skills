---
id: 01-003
title: "🔗 子域名探测 (Subdomain Discovery)"
category: 信息搜集
category_en: Reconnaissance
difficulty: ★★★
tools: "Subfinder, Amass, Sublist3r"
last_updated: 2025-07
tags: ["reconnaissance", "osint", "information-gathering", "dns-enumeration", "passive-recon"]
subdomain: reconnaissance
nist_csf: ["ID.AM-01", "ID.AM-04", "DE.CM-01"]
mitre_attack: ["T1595", "T1592", "T1590", "T1596"]
---
# 🔗 子域名探测 (Subdomain Discovery)

## 概述
发现目标域名的所有子域名，扩大攻击面。子域名可能包含测试环境、管理后台、API端点等敏感资源。

## 核心技能

### 1. 被动子域名收集（不接触目标）

```bash
# Subfinder - 最常用的被动子域名工具
subfinder -d example.com -o subdomains.txt

# Amass - 强大的被动收集
amass enum -passive -d example.com -o amass_passive.txt

# Sublist3r - 多引擎查询
sublist3r -d example.com -o sublist3r.txt

# AssetFinder
assetfinder --subs-only example.com
```

### 2. 主动子域名收集

```bash
# Amass主动枚举
amass enum -active -d example.com -o amass_active.txt

# Gobuster DNS暴力破解
gobuster dns -d example.com -w subdomains_top10000.txt -t 50

# dnsrecon暴力破解
dnsrecon -d example.com -D subdomains.txt -t brt
```

### 3. 证书透明度日志

```bash
# crt.sh
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# CertSpotter
curl -s "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | sort -u

# Google CT
curl -s "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?domain=example.com&include_subdomains=true"
```

### 4. DNS数据聚合API

```bash
# SecurityTrails
curl -s "https://api.securitytrails.com/v1/domain/example.com/subdomains" -H "APIKEY: YOUR_KEY" | jq -r '.subdomains[]' | awk '{print $1".example.com"}'

# AlienVault OTX
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns" | jq -r '.passive_dns[].hostname' | sort -u

# VirusTotal
curl -s "https://www.virustotal.com/api/v3/domains/example.com/subdomains?limit=40" -H "x-apikey: YOUR_KEY" | jq -r '.data[].id'

# Shodan
shodan search "hostname:example.com" --fields ip_str,hostnames
```

### 5. DNS解析验证

```bash
# 解析所有子域名到IP
while read sub; do
  ip=$(dig +short $sub.example.com A)
  if [ -n "$ip" ]; then
    echo "$sub.example.com -> $ip"
  fi
done < subdomains.txt

# 使用massdns批量解析
massdns -r resolvers.txt -t A -o S -w resolved.txt subdomains.txt

# httprobe - 检测存活HTTP/HTTPS
cat resolved.txt | httprobe -c 50 -t 3000

# httpx - 更强大的存活检测
httpx -l resolved.txt -title -status-code -tech-detect -o alive.txt
```

### 6. 子域名接管检查

```bash
# Subjack - 子域名劫持检测
subjack -w subdomains.txt -t 100 -timeout 30 -o takeover.txt -ssl

# SubOver
subover -l subdomains.txt

# Nuclei接管模板
nuclei -l subdomains.txt -t ~/nuclei-templates/takeovers/
```

### 7. JavaScript/页面解析

```bash
# SubdomainJS - 从JS文件提取子域名
subdomainjs -d example.com

# LinkFinder - 从JS中提取端点
linkfinder -i https://example.com/app.js -o cli

# gau - 从URL获取所有端点
gau example.com | unfurl -u domains | sort -u
```

## 子域名发现技术对比

| 技术 | 类型 | 速度 | 效果 |
|:---|:---:|:---:|:---:|
| 字典暴力 | 主动 | 中 | 依赖字典质量 |
| 证书透明度 | 被动 | 快 | 非常好 |
| DNS聚合API | 被动 | 快 | 好 |
| 搜索引擎 | 被动 | 中 | 一般 |
| 域名传送 | 主动 | 快 | 很少成功 |
| Permutation | 主动 | 慢 | 发现更多 |

## 常用工具

| 工具 | 特性 | 链接 |
|:---|:---|:---|
| Subfinder | 快速被动收集 | https://github.com/projectdiscovery/subfinder |
| Amass | 全功能发现 | https://github.com/OWASP/Amass |
| Sublist3r | Python工具 | https://github.com/aboul3la/Sublist3r |
| massdns | 高速解析 | https://github.com/blechschmidt/massdns |
| httpx | 存活检测 | https://github.com/projectdiscovery/httpx |
| gau | URL收集 | https://github.com/lc/gau |
| uncover | API收集 | https://github.com/projectdiscovery/uncover |

## 参考资源
- [Subdomain Enumeration: 2025 Methodology](https://0xpatrik.com/subdomain-enumeration-2025/)
- [ProjectDiscovery Blog](https://blog.projectdiscovery.io/)
- [Amass用户指南](https://github.com/OWASP/Amass/blob/master/doc/user_guide.md)
