---
id: 02-006
title: "🌐 网络漏洞扫描 (Network Vulnerability Scanning)"
category: 漏洞扫描
category_en: "Vulnerability Scanning"
difficulty: ★★★
tools: "Nmap, OpenVAS, Nessus, Nexpose"
last_updated: 2025-07
tags: ["vulnerability-scanning", "web-security", "network-security", "database-security"]
subdomain: vulnerability-scanning
nist_csf: ["ID.RA-01", "DE.CM-08", "PR.IP-12"]
mitre_attack: ["T1595", "T1589", "T1592"]
---
# 🌐 网络漏洞扫描 (Network Vulnerability Scanning)

## 概述
通过网络扫描发现主机和服务中的已知漏洞，包括操作系统漏洞、服务漏洞和错误配置。

## 核心技能

### 1. OpenVAS/GVM 漏洞扫描

```bash
# 启动Greenbone Vulnerability Manager
gvm-start

# 创建扫描目标
gvm-cli --gmp-username admin --gmp-password password \
  socket --socketpath /var/run/gvmd.sock \
  --xml "<create_target><name>Target</name><hosts>192.168.1.0/24</hosts></create_target>"

# 创建并启动扫描任务
gvm-cli --gmp-username admin --gmp-password password \
  socket --socketpath /var/run/gvmd.sock \
  --xml "<start_task><task_id>TASK_ID</task_id></start_task>"

# 导出PDF报告
gvm-cli --gmp-username admin --gmp-password password \
  socket --socketpath /var/run/gvmd.sock \
  --xml "<get_reports><report_id>REPORT_ID</report_id><format_id>c402cc3e-b531-11e1-9163-406186ea4fc5</format_id></get_reports>" > report.pdf
```

### 2. Nessus 漏洞扫描

```bash
# 启动Nessus
systemctl start nessusd

# 使用nessuscli创建策略
nessuscli policy create --name "Internal Scan" --policy-type "basic"

# 命令行扫描
nessuscli scan new --name "Scan_1" --target "192.168.1.0/24" --policy "Internal Scan"

# 使用API
curl -s -k -X POST "https://localhost:8834/scans" \
  -H "X-Api-Token: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"uuid": "SCAN_UUID", "settings": {"name": "Scan", "text_targets": "192.168.1.0/24"}}'
```

### 3. Nmap NSE漏洞扫描

```bash
# 全面漏洞扫描
nmap -sV --script vuln 192.168.1.0/24

# 安全检测脚本集
nmap -sV --script "safe" 192.168.1.0/24

# 特定漏洞检测
nmap -sV --script http-vuln* 192.168.1.100

# 暴力破解检测
nmap -sV --script brute 192.168.1.100

# 全部漏洞脚本（谨慎使用）
nmap -sV --script "vuln and safe" 192.168.1.0/24

# 导出HTML报告
nmap -sV --script vuln -oX scan.xml 192.168.1.0/24
xsltproc scan.xml -o scan.html
```

### 4. 服务专项扫描

**SMB扫描：**
```bash
# SMB漏洞检测
nmap -p445 --script smb-vuln* 192.168.1.0/24

# SMB枚举
enum4linux -a 192.168.1.100
smbclient -L //192.168.1.100 -N

# EternalBlue检测
nmap -p445 --script smb-vuln-ms17-010 192.168.1.0/24
```

**SNMP扫描：**
```bash
# SNMP枚举
nmap -sU -p161 --script snmp* 192.168.1.0/24

# 暴力破解SNMP社区字符串
onesixtyone -c community.txt -i hosts.txt

# SNMPWalk
snmpwalk -c public -v2c 192.168.1.100
```

**数据库扫描：**
```bash
# MySQL扫描
nmap -p3306 --script mysql* 192.168.1.0/24

# MSSQL扫描
nmap -p1433 --script ms-sql* 192.168.1.0/24

# Redis扫描
nmap -p6379 --script redis* 192.168.1.0/24

# MongoDB扫描
nmap -p27017 --script mongodb* 192.168.1.0/24
```

### 5. Web服务漏洞扫描

```bash
# HTTP方法检测
nmap -p80,443 --script http-methods 192.168.1.0/24

# WebDAV检测
nmap -p80,443 --script http-webdav-scan 192.168.1.0/24

# Shellshock检测
nmap -p80,443 --script http-shellshock 192.168.1.0/24

# SSL/TLS检测
nmap -p443 --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed 192.168.1.0/24
```

### 6. 漏洞结果管理

```bash
# 解析Nmap XML结果
python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('scan.xml')
for host in tree.findall('host'):
    addr = host.find('address').get('addr')
    for port in host.findall('ports/port'):
        portid = port.get('portid')
        state = port.find('state').get('state')
        if state == 'open':
            print(f'{addr}:{portid} - OPEN')
"

# 批量漏洞汇总
nmap -sV --script vuln -oA network_scan 192.168.1.0/24
grep -r "VULNERABLE" network_scan.nse
```

## 漏洞等级分类

| 等级 | CVSS评分 | 响应要求 | 示例 |
|:---|:---:|:---|:---|
| 严重 | 9.0-10.0 | 立即修复 | RCE、EternalBlue |
| 高危 | 7.0-8.9 | 24小时内 | SQL注入、未授权访问 |
| 中危 | 4.0-6.9 | 72小时内 | XSS、信息泄露 |
| 低危 | 0.1-3.9 | 下次更新 | Banner泄露、未加密服务 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| OpenVAS/GVM | 开源漏洞扫描器 | https://www.greenbone.net/ |
| Nessus | 商业漏洞扫描器 | https://www.tenable.com/products/nessus |
| Nexpose | 漏洞管理平台 | https://www.rapid7.com/products/nexpose/ |
| vulners | NSE漏洞脚本 | https://github.com/vulnersCom/nmap-vulners |
| searchsploit | 漏洞库搜索 | https://www.exploit-db.com/searchsploit |

## 参考资源
- [NVD - National Vulnerability Database](https://nvd.nist.gov/)
- [Exploit-DB](https://www.exploit-db.com/)
- [CVE Mitre](https://cve.mitre.org/)
- [Vulners Database](https://vulners.com/)
