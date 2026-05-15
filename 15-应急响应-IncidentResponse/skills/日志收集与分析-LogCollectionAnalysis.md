---
id: 15-011
title: "📜 日志收集与分析 (Log Collection & Analysis)"
category: 应急响应
category_en: "Incident Response"
difficulty: ★★★
tools: "ELK Stack, Splunk, Wazuh, Graylog"
last_updated: 2025-07
tags: ["incident-response", "forensics", "memory-forensics", "threat-hunting", "ransomware"]
subdomain: incident-response
nist_csf: ["RS.RP-01", "RS.CO-02", "RS.AN-01", "RS.MI-01"]
mitre_attack: ["T1486", "T1490", "T1485", "T1562"]
---
# 📜 日志收集与分析 (Log Collection & Analysis)

## 概述
日志是应急响应中最关键的证据来源。通过对操作系统、网络设备、应用系统和云服务的日志进行系统化收集和分析，还原攻击路径、确定影响范围并提取入侵指标（IoC）。

## 核心技能

### 1. 关键日志源

```text
┌─ 操作系统日志 ─────────────────┐
│ Windows: Security, System, App │
│ Linux:   /var/log/auth.log     │
│          /var/log/syslog       │
│          /var/log/kern.log     │
└────────────────────────────────┘

┌─ 网络安全设备日志 ─────────────┐
│ Firewall: 连接日志、NAT日志      │
│ IDS/IPS:  告警日志              │
│ Proxy:    访问日志              │
│ VPN:      登录登出日志           │
└────────────────────────────────┘

┌─ 应用服务日志 ─────────────────┐
│ Web:     access.log, error.log │
│ DB:      慢查询日志、审计日志    │
│ AD:      Domain Controller日志 │
│ DNS:     查询日志               │
└────────────────────────────────┘

┌─ 云服务日志 ───────────────────┐
│ AWS:     CloudTrail, S3访问日志│
│ Azure:   Activity Log, NSG流日志│
│ GCP:     Cloud Audit Logs      │
└────────────────────────────────┘
```

### 2. Windows日志采集与分析

```powershell
# 使用PowerShell收集关键事件
# 登录事件 (Event ID 4624=成功登录, 4625=失败登录)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625} -MaxEvents 1000

# 账户管理事件 (4720=新建用户, 4728=添加组成员)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720,4728,4732,4756}

# 进程创建 (4688=进程创建, 需要审计策略配置)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688}

# 计划任务创建 (4698)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4698}

# 事件日志清除 (1102=安全日志清除)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102}

# 导出日志为CSV
wevtutil epl Security C:\incident\security_export.evtx
Get-WinEvent -Path C:\incident\security_export.evtx | Export-Csv log.csv
```

**关键Windows事件ID速查：**

| 事件ID | 描述 | 攻击关联 |
|:---:|:---|:---|
| 4624 | 登录成功 | 暴力破解成功、横向移动 |
| 4625 | 登录失败 | 暴力破解 |
| 4634 | 注销 | 用户行为追踪 |
| 4648 | 显式凭据登录 | Pass-the-Hash横向移动 |
| 4672 | 管理员登录 | 特权账号使用 |
| 4688 | 进程创建 | 恶意软件执行 |
| 4698 | 计划任务创建 | 持久化 |
| 4702 | 计划任务更新 | 持久化篡改 |
| 4720 | 用户账户创建 | 后门账户 |
| 1102 | 安全日志清除 | 痕迹清除 |
| 5156 | 连接允许 | 网络连接 |
| 5157 | 连接拒绝 | 横向移动阻止 |

### 3. Linux日志采集与分析

```bash
# 认证日志 — 重点关注SSH爆破和异常登录
cat /var/log/auth.log | grep -i "failed password" | awk '{print $1,$2,$3,$9,$11}' | sort | uniq -c | sort -nr

# 查看最近登录记录
last -10
lastb -10  # 失败登录记录

# 系统日志 — 重点检查异常进程和网络连接
cat /var/log/syslog | grep -i "error\|fail\|alert\|attack"

# 检查sudo使用记录（Indicator: 提权尝试）
cat /var/log/auth.log | grep -i "sudo"

# 检查cron任务（Indicator: 持久化）
cat /var/log/syslog | grep -i cron
ls -la /var/spool/cron/crontabs/
ls -la /etc/cron*

# 检查系统启动项
ls -la /etc/init.d/
ls -la /etc/systemd/system/multi-user.target.wants/
systemctl list-unit-files --state=enabled
```

### 4. Web日志分析

```bash
# Apache/Nginx访问日志分析

# 查找SQL注入尝试
cat access.log | grep -iE "union.*select|select.*from|1=1|--|'"

# 查找文件包含尝试
cat access.log | grep -iE "\.\./|\.\.\\|/etc/passwd|/proc/self"

# 查找扫描和探测行为
cat access.log | awk '{print $1}' | sort | uniq -c | sort -nr | head -20

# 查找异常状态码（500=服务端错误, 403=禁止访问, 401=未授权）
cat access.log | awk '{print $9}' | sort | uniq -c | sort -nr

# 查找POST请求中的可疑payload
cat access.log | grep "POST" | grep -iE "eval|exec|system|passthru|shell_exec"

# 使用goaccess生成分析报告（快速排查）
goaccess access.log --log-format=COMBINED -o report.html

# Nginx审计日志
# 需要先启用: http { log_format audit '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for"'; }
```

### 5. SIEM平台部署与查询

**Elastic Stack (ELK) 快速部署：**
```bash
# Docker Compose启动ELK
wget https://raw.githubusercontent.com/elastic/stack-docker/master/docker-compose.yml
docker-compose up -d

# 导入日志
filebeat -e -c filebeat.yml
```

**Splunk 常用查询：**
```splunk
# 所有登录失败事件
index=windows EventCode=4625 | stats count by Account_Name, Workstation_Name, IpAddress

# 横向移动检测 — 通过RDP向多台主机登录
index=windows EventCode=4624 LogonType=10 | stats dc(Computer) as target_count by Account_Name | where target_count > 3

# 检测可疑进程执行
index=windows EventCode=4688 | search "powershell -enc" OR "cmd /c" OR "wscript" OR "cscript"

# 检测数据外传 — 大流量外出连接
index=network bytes_out > 1000000 | stats sum(bytes_out) as total by src_ip, dest_ip | where total > 10000000
```

**Wazuh（开源HIDS/SIEM）：**
```bash
# 快速部署Wazuh Agent
WAZUH_MANAGER="10.0.0.100" yum install wazuh-agent
systemctl start wazuh-agent

# 常用告警规则（/var/ossec/rules/）
# ● 文件完整性监控 (FIM)
# ● Rootkit检测
# ● 异常命令执行
# ● 恶意软件检测
```

### 6. 时间线重建

```mermaid
timeline
    title 攻击时间线重建
    10:00 : 攻击者进行端口扫描
    10:15 : SQL注入成功，获取Webshell
    10:20 : 上传提权工具
    10:35 : 获取SYSTEM权限
    11:00 : 安装远控木马
    11:30 : 内网横向移动
    12:00 : 导出域哈希
    12:30 : 清理日志文件
```

**关键时间线问题：**
- 第一次异常行为发生的准确时间？
- 攻击者在系统中停留了多久？
- 数据外传从什么时候开始？
- 最后一个恶意行为是什么时候？

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| ELK Stack | 日志聚合与分析 | https://www.elastic.co/ |
| Splunk | SIEM与日志分析平台 | https://www.splunk.com/ |
| Wazuh | 开源HIDS+SIEM | https://wazuh.com/ |
| Grafana Loki | 轻量级日志聚合 | https://grafana.com/loki/ |
| GoAccess | Web日志实时分析 | https://goaccess.io/ |
| Zabbix | 监控告警 | https://www.zabbix.com/ |
| Graylog | 集中式日志管理 | https://www.graylog.org/ |
| Sysmon | Windows系统监控 | https://learn.microsoft.com/sysinternals/downloads/sysmon |

## 参考资源

- [SANS — Windows Forensic Analysis](https://www.sans.org/white-papers/windows-forensic-analysis/)
- [Microsoft 安全事件ID参考](https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-auditing)
- [ELK — 安全分析最佳实践](https://www.elastic.co/guide/en/security/current)
- [MITRE ATT&CK — 数据源映射](https://attack.mitre.org/datasources/)
