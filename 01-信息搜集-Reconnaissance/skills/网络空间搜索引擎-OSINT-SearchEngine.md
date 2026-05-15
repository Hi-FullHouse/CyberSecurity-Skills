---
id: 01-006
title: "🌍 网络空间搜索引擎 (Cyberspace Search Engine)"
category: 信息搜集
category_en: Reconnaissance
difficulty: ★★★
tools: "Fofa, ZoomEye, Shodan, Censys"
last_updated: 2025-07
tags: ["reconnaissance", "osint", "information-gathering", "dns-enumeration", "passive-recon"]
subdomain: reconnaissance
nist_csf: ["ID.AM-01", "ID.AM-04", "DE.CM-01"]
mitre_attack: ["T1595", "T1592", "T1590", "T1596"]
---
# 🌍 网络空间搜索引擎 (Cyberspace Search Engine)

## 概述
利用网络空间搜索引擎直接搜索全球联网设备、网站和服务，快速定位目标的信息系统资产。

## 核心技能

### 1. Shodan

**基础搜索语法：**
```bash
# 搜索指定端口
port:80

# 搜索指定服务
apache
nginx
OpenSSH

# 搜索指定国家/城市
country:CN
city:Beijing

# 搜索组织
org:"Tencent"
org:"Alibaba"

# 组合搜索
apache country:CN port:443
"OpenSSH" country:US

# 排除条件
!iis
-country:CN
```

**实战案例：**
```bash
# 搜索Web服务器
http.title:"Login" country:CN

# 搜索摄像头
"webcam" country:CN

# 搜索SCADA系统
"SCADA" country:CN port:502

# 搜索MongoDB（未认证）
"MongoDB Server Information" port:27017

# 搜索Elasticsearch
port:9200 "elasticsearch"

# 搜索Redis
port:6379 "redis_version"
```

**Shodan CLI：**
```bash
# 命令行搜索
shodan search "apache country:CN"

# 获取主机详情
shodan host 1.2.3.4

# 统计信息
shodan stats --facets port:100 apache

# 下载结果
shodan download result.json.gz "apache country:CN"
```

### 2. ZoomEye

```bash
# 基础搜索
app:nginx
port:443
country:CN

# 搜索Web指纹
title:"phpMyAdmin"
header:"thinkphp"

# 设备搜索
device:router
service:ftp
```

### 3. FOFA (Fingerprinting Of All Assets)

**搜索语法：**
```text
# 基础语法
domain="example.com"
ip="1.1.1.0/24"
port="80"
protocol="https"

# Web组件
app="Apache"
app="Nginx"
app="ThinkPHP"
app="Discuz"

# 标题搜索
title="后台管理"
title="登录"

# Body内容
body="phpinfo"
body="Welcome to nginx"

# Header搜索
header="thinkphp"
header="X-Powered-By"

# 证书搜索
cert="example.com"
```

**FOFA CLI (fofa-cli)：**
```bash
# 搜索并导出
fofa -q 'domain="example.com" && port="80"' -o results.csv

# 统计
fofa -q 'app="ThinkPHP"' --count
```

### 4. Censys

```bash
# 搜索指定服务
services.service_name: HTTP
services.port: 443

# 搜索证书
tags: trusted

# 搜索操作系统
metadata.os: Windows
```

### 5. Hunter (鹰图平台)

```text
# 域名/IP搜索
domain:"example.com"
ip:"1.1.1.0/24"

# Web指纹
web.title="login"
web.body="admin"
```

### 6. 综合使用技巧

```bash
# 多引擎交叉验证
# 同一IP在不同引擎中的结果可能不同

# 资产扩散搜索
# 已知IP → 搜索同网段 → 搜索同域名 → 搜索同证书

# 证书关系搜索
# 找到目标SSL证书，搜索所有使用该证书的IP
```

## 各平台对比

| 平台 | 侧重 | 免费额度 | 特点 |
|:---|:---|:---:|:---|
| Shodan | IoT/设备 | 基础版免费 | 全球最大设备搜索引擎 |
| FOFA | Web指纹 | 注册即用 | 中文网站覆盖好 |
| ZoomEye | 网络设备 | 有限免费 | 国内老牌平台 |
| Censys | 证书/IP | API免费 | 学术背景，数据全面 |
| Hunter | Web资产 | 每日限额 | 国产，Web指纹强 |

## 搜索策略

1. **域名扩散**：从已知域名搜索所有关联IP
2. **IP扩散**：从已知IP搜索同C段
3. **证书扩散**：从SSL证书搜索其他使用同一证书的站点
4. **组件扩散**：从已知Web组件搜索相同组件的站点
5. **邮件扩散**：从邮箱反查域名

## 参考资源
- [Shodan Search Guide](https://help.shodan.io/)
- [FOFA语法文档](https://fofa.info/user/help)
- [ZoomEye帮助文档](https://www.zoomeye.org/help)
- [Censys搜索语法](https://search.censys.io/search/definitions)
