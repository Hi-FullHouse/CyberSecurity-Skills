---
id: 01-007
title: "🕵️ 被动信息搜集 (Passive Reconnaissance / OSINT)"
category: 信息搜集
category_en: Reconnaissance
difficulty: ★★
tools: "Google Dork, Shodan, Maltego, theHarvester"
last_updated: 2025-07
tags: ["reconnaissance", "osint", "information-gathering", "dns-enumeration", "passive-recon"]
subdomain: reconnaissance
nist_csf: ["ID.AM-01", "ID.AM-04", "DE.CM-01"]
mitre_attack: ["T1595", "T1592", "T1590", "T1596"]
---
# 🕵️ 被动信息搜集 (Passive Reconnaissance / OSINT)

## 概述
不直接与目标系统交互，通过公开渠道收集目标信息。这种方式不会被目标察觉，是渗透测试的第一步。

## 核心技能

### 1. Google Hacking (Google Dork)
利用Google高级搜索语法搜索敏感信息。

**常用Dork语法：**
| 语法 | 用途 | 示例 |
|:---|:---|:---|
| `site:` | 限定域名 | `site:example.com` |
| `filetype:` | 限定文件类型 | `filetype:pdf` |
| `intitle:` | 搜索标题 | `intitle:"index of"` |
| `inurl:` | 搜索URL | `inurl:admin` |
| `intext:` | 搜索正文 | `intext:"password"` |

**常用Dork示例：**
```text
# 管理后台
site:target.com intitle:login | intitle:admin

# 敏感文件
site:target.com filetype:sql | filetype:env | filetype:bak

# 目录遍历
intitle:"index of" site:target.com

# 配置文件泄露
site:target.com inurl:config.php

# 日志文件
site:target.com filetype:log
```

### 2. WHOIS查询
查询域名注册信息。

```bash
# Linux
whois example.com

# 在线查询
# https://who.is/
# https://www.reg.com/whois
```

### 3. 邮件信息收集
```bash
# theHarvester - 收集邮箱、子域名、IP
theHarvester -d example.com -b google,linkedin,bing

# Hunter.io - 在线邮件查询
# https://hunter.io/search/example.com
```

### 4. 社交网络信息
```bash
# Sherlock - 在社交网络搜索用户名
sherlock username

# 查找员工信息
# LinkedIn - 搜索公司员工
# Twitter/X - 搜索公司相关账号
```

### 5. 历史数据/存档
```bash
# WayBack Machine - 查看历史页面
# https://web.archive.org/web/*/example.com

# 通过Wayback获取历史URL
curl "https://web.archive.org/cdx/search/cdx?url=example.com/*&output=text" | cut -d' ' -f3
```

### 6. 证书透明度 (Certificate Transparency)
```bash
# crt.sh - 通过SSL证书查找子域名
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq .

# CertSpotter
# https://certspotter.com/api/v0/certs?domain=example.com
```

### 7. 代码仓库泄露
```bash
# GitHub搜索敏感信息
# 搜索语法: "example.com" "password"
# 搜索语法: "example.com" "api_key"
# 搜索语法: "example.com" "aws_secret"

# GitDorker - 自动化GitHub搜索
gitdorker -d example.com

# truffleHog - 扫描git仓库中的密钥
trufflehog git https://github.com/user/repo
```

### 8. DNS历史记录
```bash
# SecurityTrails
curl -s "https://api.securitytrails.com/v1/domain/example.com" -H "APIKEY: xxx"

# PassiveTotal
# https://community.riskiq.com/
```

## 常用工具
| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Maltego | 图形化关联分析 | https://www.maltego.com/ |
| theHarvester | 邮件/子域名收集 | https://github.com/laramies/theHarvester |
| Recon-ng | 全功能OSINT框架 | https://github.com/lanmaster53/recon-ng |
| SpiderFoot | 自动化OSINT | https://www.spiderfoot.net/ |
| Sherlock | 用户名搜索 | https://github.com/sherlock-project/sherlock |
| GHDB | Google Hacking数据库 | https://www.exploit-db.com/google-hacking-database |

## 参考资源
- [OSINT Framework](https://osintframework.com/)
- [IntelTechniques OSINT Tools](https://inteltechniques.com/tools/)
- [Bellingcat OSINT资源](https://www.bellingcat.com/resources/)
