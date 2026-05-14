---
id: "15-009"
title: "🔎 威胁狩猎 (Threat Hunting)"
category: "应急响应"
category_en: "Incident Response"
difficulty: "★★★★★"
tools: "KQL, YARA, Sigma, MITRE ATT&CK, ELK"
last_updated: "2025-07"
---
# 🔎 威胁狩猎 (Threat Hunting)

## 概述
威胁狩猎（Threat Hunting）是一种主动性的网络安全分析方法，旨在基于假设驱动，在攻击造成实质性损害之前发现隐蔽的威胁。参照 **SANS Threat Hunting Maturity Model** 和 **MITRE ATT&CK** 框架的最佳实践。

## 核心技能

### 1. 威胁狩猎成熟度模型

```text
级别 1 (初始级)   ── 依赖自动化告警，被动响应
     │
级别 2 (程序级)   ── 基于已知IoC进行常规性狩猎
     │
级别 3 (创新级)   ── 基于威胁情报和TTP进行数据挖掘
     │
级别 4 (领先级)   ── 基于假设驱动的持续狩猎，自动化和集成
```

### 2. 基于MITRE ATT&CK的狩猎循环

```text
┌──────────────────────────────────┐
│    步骤1：假设生成                  │
│    ● 基于最新威胁情报               │
│    ● 基于企业内部风险               │
│    ● 基于新漏洞/攻击技术            │
└──────────────┬───────────────────┘
               ▼
┌──────────────────────────────────┐
│    步骤2：数据收集                  │
│    ● 确定需要分析的数据源            │
│    ● 收集时间范围内的数据            │
│    ● 确保数据完整性和可用性          │
└──────────────┬───────────────────┘
               ▼
┌──────────────────────────────────┐
│    步骤3：数据分析和发现             │
│    ● 应用检测分析技术                │
│    ● 识别异常模式和IoC              │
│    ● 进行深度溯源分析                │
└──────────────┬───────────────────┘
               ▼
┌──────────────────────────────────┐
│    步骤4：调查和验证                 │
│    ● 确认是否误报                   │
│    ● 确定影响范围                   │
│    ● 提取TTP和IoC                  │
└──────────────┬───────────────────┘
               ▼
┌──────────────────────────────────┐
│    步骤5：响应与反馈                 │
│    ● 触发IR流程（如确认事件）        │
│    ● 更新检测规则                   │
│    ● 输出狩猎报告并迭代             │
└──────────────────────────────────┘
```

### 3. 常用狩猎假设示例

| # | 假设 | 相关ATT&CK技术 | 数据源 |
|:---:|:---|:---|:---|
| 1 | 攻击者使用PowerShell进行无文件攻击 | T1059.001 | ScriptBlock日志、EventID 4104 |
| 2 | 攻击者通过RDP暴力破解获得初始访问 | T1110.001 | Security 4625、TerminalServices |
| 3 | 攻击者使用Cobalt Strike进行C2通信 | T1071.001 | 网络流量、JA3指纹 |
| 4 | 攻击者使用DLL侧加载执行恶意代码 | T1574.002 | Sysmon EventID 7、DLL加载日志 |
| 5 | 攻击者通过计划任务维持持久化 | T1053.005 | Security 4698、Task Scheduler日志 |
| 6 | 攻击者使用Living-off-the-Land二进制 | T1218 | Process Creation 4688 |
| 7 | 攻击者通过SMB横向移动 | T1021.002 | Security 4624 LogonType 3 |

### 4. KQL (Kusto Query Language) 狩猎查询

```kusto
// === Azure Sentinel/Log Analytics 常用狩猎查询 ===

// 1. 查找PowerShell编码命令执行
DeviceProcessEvents
| where ProcessCommandLine has_any ("-e ", "-enc ", "-EncodedCommand")
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
| project Timestamp, DeviceName, UserName, ProcessCommandLine
| top 100 by Timestamp desc

// 2. 查找异常时间活动（深夜登录）
// 检测非工作时间的登录行为
SigninLogs
| where TimeGenerated between (datetime(2024-01-01) .. datetime(2024-12-31))
| where hour_of_day(TimeGenerated) between (0 .. 6)  // 凌晨0-6点
| where ResultType == "0"  // 成功登录
| summarize Count = count() by UserPrincipalName, IPAddress, AppDisplayName
| where Count > 3
| order by Count desc

// 3. 查找异常数据外传 — 大量文件操作
DeviceFileEvents
| where FolderPath startswith "C:\\Users" and FileName endswith ".docx"
| summarize FileCount = dcount(FileName) by DeviceName, UserName, bin(TimeGenerated, 1h)
| where FileCount > 50
| order by FileCount desc

// 4. 查找可疑计划任务创建
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| extend TaskName = parse_json(AdditionalFields).TaskName
| extend TaskCommand = parse_json(AdditionalFields).TaskCommand
| where TaskCommand has_any ("powershell", "cmd", "wscript", "cscript", "rundll32")
| project Timestamp, DeviceName, UserName, TaskName, TaskCommand

// 5. 查找异常网络出站连接（可疑端口）
DeviceNetworkEvents
| where RemotePort in (4444, 8888, 6666, 1337, 5555, 8080, 8443, 53, 123)
| where RemoteIPType == "IPv4" and not(ipv4_is_private(RemoteIP))
| project Timestamp, DeviceName, RemoteIP, RemotePort, LocalIP
```

### 5. Sigma 规则编写

Sigma 是通用签名格式，可转换为SIEM/Sysmon查询：

```yaml
# Sigma规则示例 — 检测Certutil下载文件
title: Certutil Used to Download File
id: 7d44e2d4-1628-4e1d-8e8c-6ff4c656138d
status: experimental
description: Detects use of certutil to download files from remote
author: IR Team
date: 2024/01/01
tags:
    - attack.defense_evasion
    - attack.t1140
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\certutil.exe'
        CommandLine|contains:
            - '-urlcache'
            - '-split'
            - '-download'
            - 'http'
    filter:
        CommandLine|contains: 'DisplayDNS'
    condition: selection and not filter
falsepositives:
    - Legitimate admin usage
level: high
```

```bash
# 使用sigmac转换规则
sigmac -t splunk -c tools/config/generic/sysmon.yml rule.yml
sigmac -t elk -c tools/config/generic/sysmon.yml rule.yml
sigmac -t qradar rule.yml
sigmac -t microsoft365defender rule.yml
```

### 6. YARA 狩猎规则

```yara
// YARA规则 — 检测Mimikatz内存特征
rule mimikatz_memory
{
    meta:
        description = "Detect Mimikatz in memory"
        author = "IR Team"
        reference = "https://github.com/gentilkiwi/mimikatz"
        hash = "8a9f5e4b3c2d1e0f"

    strings:
        $s1 = "mimikatz" ascii wide
        $s2 = "sekurlsa" ascii wide
        $s3 = "wdigest" ascii wide
        $s4 = "kerberos" ascii wide
        $s5 = "MSV" ascii wide
        $s6 = "\\*" Password" ascii wide

    condition:
        3 of ($s*) and filesize < 2MB
}
```

```bash
# 对内存dump进行YARA狩猎
yara64.exe /path/to/rules/mimikatz.yar memory.dmp

# 对磁盘文件全局扫描
yara64.exe -r /path/to/rules/ /mnt/forensic_mount/

# 使用Thor Lite（自动化狩猎工具）
thor-lite-util.exe --scan C:\ --yara-rules rules/
```

### 7. 基于ATT&CK TTP的狩猎Checklist

```text
=== 初始访问 (Initial Access) ===
□ 检查近期Exploit活动（Web应用日志）
□ 检查钓鱼邮件落地情况（邮件网关）
□ 检查RDP/SSH暴力破解源IP

=== 执行 (Execution) ===
□ 检查PowerShell ScriptBlock日志 (EventID 4104)
□ 检查WMI活动 (EventID 5861)
□ 检查MSHTA/Rundll32/Regsvr32执行

=== 持久化 (Persistence) ===
□ 检查启动项注册表 (Run/RunOnce)
□ 检查计划任务创建 (EventID 4698)
□ 检查服务安装 (EventID 7045)

=== 提权 (Privilege Escalation) ===
□ 检查UAC绕过 (EventID 4672)
□ 检查Token窃取 (SeDebugPrivilege)
□ 检查提权EXP的执行痕迹

=== 防御绕过 (Defense Evasion) ===
□ 检查进程注入 (Sysmon EventID 8)
□ 检查事件日志清除 (EventID 1102/104)
□ 检查未签名进程 (Code Integrity)

=== 凭据访问 (Credential Access) ===
□ 检查LSASS进程访问 (Sysmon EventID 10)
□ 检查SAM文件访问
□ 检查NTDS提取痕迹

=== 横向移动 (Lateral Movement) ===
□ 检查PsExec使用 (Service创建)
□ 检查WMI/WinRM远程执行
□ 检查SMB共享访问

=== 数据外传 (Exfiltration) ===
□ 检查大流量外出连接
□ 检查DNS TXT查询异常
□ 检查压缩工具使用（RAR/7Z）
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| MITRE ATT&CK | TTP基准框架 | https://attack.mitre.org/ |
| Sigma | SIEM通用签名格式 | https://github.com/SigmaHQ/sigma |
| YARA | 恶意软件识别规则 | https://github.com/VirusTotal/yara |
| KQL | Kusto查询语言有奖问答 | https://learn.microsoft.com/azure/data-explorer/kusto/query/ |
| DeepBlueCLI | PowerShell事件分析 | https://github.com/sans-blue-team/DeepBlueCLI |
| Hayabusa | 基于EventLog的狩猎工具 | https://github.com/Yamato-Security/hayabusa |
| HELK | 狩猎ELK平台 | https://github.com/Cyb3rWard0g/HELK |
| Chainsaw | 快速EventLog狩猎 | https://github.com/WithSecureLabs/chainsaw |

## 参考资源

- [SANS — Threat Hunting: A Methodology](https://www.sans.org/white-papers/threat-hunting-methodology/)
- [SANS Threat Hunting Maturity Model](https://www.sans.org/white-papers/threat-hunting-maturity-model/)
- [MITRE ATT&CK — 狩猎中心](https://attack.mitre.org/resources/threat-hunting/)
- [DFIR Report — 真实狩猎案例](https://thedfirreport.com/)
- [Awesome Threat Hunting](https://github.com/hunters-forge/awesome-threat-hunting)
