---
id: 01-004
title: "🖥️ 目标技术栈识别 (Technology Stack Fingerprinting)"
category: 信息搜集
category_en: Reconnaissance
difficulty: ★★★
tools: "WhatWeb, Wappalyzer, Nmap NSE, BuiltWith"
last_updated: 2025-07
tags: ["reconnaissance", "osint", "information-gathering", "dns-enumeration", "passive-recon"]
subdomain: reconnaissance
nist_csf: ["ID.AM-01", "ID.AM-04", "DE.CM-01"]
mitre_attack: ["T1595", "T1592", "T1590", "T1596"]
---
# 🖥️ 目标技术栈识别 (Technology Stack Fingerprinting)

## 概述
识别目标网站/系统使用的 Web 服务器、后端语言、前端框架、CMS、CDN、WAF 等技术组件，为后续漏洞利用提供方向。

## 核心技能

### 1. 基础信息获取

```bash
# HTTP响应头分析
curl -s -I http://example.com
curl -s -I https://example.com

# 请求示例输出
# HTTP/1.1 200 OK
# Server: nginx/1.24.0
# X-Powered-By: PHP/8.1.0
# Set-Cookie: PHPSESSID=xxx
# X-Generator: WordPress 6.x

# 查看完整响应
curl -s -D - http://example.com -o /dev/null

# 使用OpenSSL查看HTTPS信息
openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -text
```

### 2. WhatWeb 指纹识别

```bash
# 基础扫描
whatweb example.com

# 详细输出
whatweb -v example.com

# 聚合扫描（不请求每条规则）
whatweb -a 3 example.com

# 批量扫描
whatweb -i urls.txt --log-verbose=results.txt
```

### 3. Wappalyzer (命令行 & 浏览器扩展)

```bash
# 使用wappalyzer-cli
wappalyzer https://example.com

# 浏览器扩展
# 安装Wappalyzer Chrome/Firefox扩展
# 访问目标网站即可在工具栏查看技术栈
```

### 4. Nmap 服务指纹

```bash
# HTTP服务探测
nmap -sV --script=http-headers,http-server-header,http-title example.com

# 全面HTTP分析
nmap -sV -p80,443 --script=http-enum,http-methods,http-shellshock,http-php-version example.com
```

### 5. 常见组件识别方法

**CMS识别：**
```bash
# WordPress
curl -s http://example.com/readme.html
curl -s http://example.com/wp-admin/
curl -s http://example.com/wp-json/

# Joomla
curl -s http://example.com/administrator/
curl -s http://example.com/components/

# Drupal
curl -s http://example.com/CHANGELOG.txt
curl -s http://example.com/node/1

# Discuz
curl -s http://example.com/api/
curl -s http://example.com/admin.php

# 织梦CMS
curl -s http://example.com/data/admin/ver.txt
```

**JavaScript框架识别：**
```bash
# 查看HTML是否有特定ID/Class
curl -s http://example.com | grep -i "react\|vue\|angular\|jquery"

# 检测Vue/React特征
# Vue: data-v-xxxxx 属性
# React: __NEXT_DATA__, __NUXT__
# Angular: ng-version 属性
```

### 6. WAF检测

```bash
# wafw00f - WAF识别工具
wafw00f http://example.com

# 手动检测 - 发送恶意请求看封堵特征
curl -s -A "')" http://example.com
# 云WAF: Cloudflare, Akamai, Alibaba Cloud WAF
# 开源WAF: ModSecurity, Naxsi
# 商业WAF: F5 BIG-IP, Imperva, Palo Alto

# 常见WAF特征
# Cloudflare: cf-ray, __cfduid
# ModSecurity: 403 Forbidden
# F5: X-Cnection, TS cookie
```

### 7. CDN检测

```bash
# DNS解析查看CDN
dig example.com

# CDN识别
# Cloudflare: 104.16.0.0/12
# Akamai: 23.0.0.0/12
# Fastly: 151.101.0.0/16
# 阿里云CDN: 47.0.0.0/8
# 腾讯云CDN: 1.30.0.0/15

# CDN检测工具
cdncheck -u https://example.com
```

## 常见组件特征速查

| 组件 | 典型特征 | 检测方式 |
|:---|:---|:---|
| Nginx | `Server: nginx` | 响应头 |
| Apache | `Server: Apache` | 响应头 |
| IIS | `Server: Microsoft-IIS` | 响应头 |
| PHP | `X-Powered-By: PHP` | 响应头 |
| ASP.NET | `X-AspNet-Version` | 响应头 |
| Java/JSP | `JSESSIONID` Cookie | Cookie |
| WordPress | `/wp-content/`, `/wp-admin/` | URL路径 |
| ThinkPHP | `thinkphp` in header | 响应头 |
| Laravel | `laravel_session` Cookie | Cookie |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| WhatWeb | Web技术栈识别 | https://github.com/urbanadventurer/WhatWeb |
| Wappalyzer | 浏览器/CLI识别 | https://www.wappalyzer.com/ |
| wafw00f | WAF识别 | https://github.com/EnableSecurity/wafw00f |
| cdncheck | CDN检测 | https://github.com/projectdiscovery/cdncheck |
| httpheader | 自定义头分析 | 在线/curl |

## 参考资源
- [BuiltWith - 技术栈查询](https://builtwith.com/)
- [Netcraft - 网站技术分析](https://sitereport.netcraft.com/)
- [W3Techs - Web技术统计](https://w3techs.com/)
