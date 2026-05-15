---
id: 14-006
title: "🌐 网络安全合规评估 (Network Security Compliance Assessment)"
category: 安全审计
category_en: "Security Audit"
difficulty: ★★★
tools: "Nmap NSE, Wireshark, Nipper, OpenVAS"
last_updated: 2025-07
tags: ["security-audit", "compliance", "cloud-audit", "container-audit", "network-audit"]
subdomain: security-audit
nist_csf: ["ID.GV-01", "ID.RM-01", "ID.SC-01"]
mitre_attack: []
---
# 🌐 网络安全合规评估 (Network Security Compliance Assessment)

## 概述
对网络环境进行安全评估与合规检查，包括防火墙策略审计、网络分段检查、入侵检测评估、VPN安全审计、DNS安全、网络设备基线配置等。

## 核心技能

### 1. 防火墙策略审计

**策略清理与优化：**
```bash
# iptables审计
iptables -L -n -v                              # 查看规则匹配统计
iptables -t nat -L -n -v                       # NAT规则

# 查找无效规则（匹配计数为0）
iptables -L INPUT -n -v | awk '$1 == 0 {print}'

# 使用Nipper分析防火墙配置
nipper --input=firewall-config.txt --output=report.html
```

**防火墙策略Checklist：**
```text
□ 默认拒绝策略（Deny All, Default Deny）
□ 最小化开放端口（仅开放业务端口）
□ 规则顺序优化（最常用规则前移）
□ 过期规则清理（>90天未命中）
□ 变更审批流程
□ 策略冗余检查
□ 地区限制（Geo-IP Blocking）
```

### 2. 网络分段与隔离审计

```bash
# 网络拓扑发现
nmap -sn 10.0.0.0/24                            # 发现存活主机
nmap -T4 -A -iL hosts.txt                       # 服务发现

# VLAN隔离测试
nmap --script broadcast-dhcp-discover
nmap --script broadcast-igmp-discovery

# 检查不必要的网络路径
traceroute 10.0.0.1                              # 网络路径跟踪
mtr 10.0.0.1                                     # 持续路径质量测试

# 检查ACL配置
show access-lists                                # Cisco ACL
show ip access-lists                             # Cisco IP ACL
```

### 3. 入侵检测/防御系统（IDS/IPS）评估

**Snort/Suricata规则审计：**
```bash
# 检查规则加载情况
snort -c /etc/snort/snort.conf -T                # Snort测试模式
suricata -T -c /etc/suricata/suricata.yaml       # Suricata测试

# 规则有效性检查
suricata-update list-sources                     # 检查规则源
suricata-update enable-source et/open            # 启用ET规则

# 告警分析
grep -c "CLASSIFICATION" /var/log/suricata/fast.log  # 告警数量统计
grep "ET PRO" /var/log/suricata/fast.log | sort | uniq -c | sort -rn | head -20
```

**IDS/IPS审计要点：**
```text
□ 签名规则是否定期更新（建议<24小时）
□ 是否有误报分析流程
□ 告警响应SLA是否达标
□ 加密流量是否旁路（需要SSL解密）
□ 是否有覆盖盲区（DMZ、云环境）
□ 传感器部署位置是否合理
```

### 4. VPN安全审计

**VPN配置检查：**
```bash
# OpenVPN审计
cat /etc/openvpn/server.conf                     # 检查配置文件

# 推荐配置
tls-version-min 1.2                              # TLS版本
cipher AES-256-GCM                               # 加密算法
auth SHA512                                       # 认证算法
tls-crypt /etc/openvpn/tls-crypt.key             # TLS加密
duplicate-cn                                     # 防重放
```

**IPSec VPN检查：**
```bash
# 检查IKE配置
strongswan statusall                             # 查看所有连接
ipsec status                                     # IPSec状态

# 推荐配置
IKE: AES256-GCM / SHA384 / DH Group 14+
ESP: AES256-GCM / SHA256 / PFS

# 检查VPN日志
journalctl -u strongswan
cat /var/log/secure | grep "VPN"
```

### 5. DNS安全审计

```bash
# DNSSEC检查
dig dnssec example.com
delv example.com

# DNS over HTTPS/TLS检查
kdig +tls @1.1.1.1 example.com
curl -H "accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=example.com"

# 开放DNS解析器检查
nmap -sU -p 53 --script dns-recursion <target>
dig @8.8.8.8 example.com                         # 测试递归查询

# DNS区域传输检查
dig axfr @ns1.example.com example.com            # 检查是否允许AXFR
```

### 6. 网络设备基线配置

**Cisco IOS基线检查：**
```text
! 检查以下配置项
show running-config | include aaa                # AAA配置
show running-config | include snmp               # SNMP配置
show running-config | include ntp                # NTP配置
show running-config | include "service password-encryption"
show running-config | include "no ip http server"
show ip interface brief                          # 接口状态
show vlan                                        # VLAN配置
show port-security                               # 端口安全
```

**检查自动化脚本：**
```bash
#!/bin/bash
# 网络设备基线检查脚本
DEVICES=("192.168.1.1" "192.168.1.2")
for DEV in "${DEVICES[@]}"; do
    echo "=== Checking $DEV ==="
    
    # 检查SSH版本
    nmap -p 22 --script ssh2-enum-algos $DEV
    
    # 检查端口开放
    nmap -p- --min-rate=10000 $DEV | grep open
    
    # 检查TLS弱套件
    testssl.sh $DEV:443
    
    echo "=== Done $DEV ==="
done
```

## 常用工具
| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Nipper | 网络设备配置审计 | https://www.titania.com/products/nipper/ |
| Nmap | 网络映射与端口扫描 | https://nmap.org/ |
| Wireshark | 网络流量分析 | https://www.wireshark.org/ |
| testssl.sh | TLS/SSL安全审计 | https://testssl.sh/ |
| Snort/Suricata | IDS/IPS | https://suricata.io/ |
| Zeek (Bro) | 网络安全监控 | https://zeek.org/ |
| RITA | 网络流量分析框架 | https://github.com/activecm/rita |

## 参考资源
- [NIST SP 800-41 Rev 1 防火墙指南](https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final)
- [NIST SP 800-94 入侵检测指南](https://csrc.nist.gov/publications/detail/sp/800-94/rev-1/draft)
- [CIS Network Infrastructure Security Guide](https://www.cisecurity.org/insights/white-papers/security-primer-network-infrastructure-security)
- [OWASP Network Security](https://cheatsheetseries.owasp.org/cheatsheets/Network_Security_Cheat_Sheet.html)
