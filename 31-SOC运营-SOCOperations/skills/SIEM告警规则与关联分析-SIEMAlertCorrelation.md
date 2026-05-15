---
id: "31-001"
title: "SIEM告警规则与关联分析 (SIEM Alert Rules & Correlation)"
category: "SOC运营"
category_en: "SOC Operations"
difficulty: "★★★★"
tools: "Splunk, Elastic Security, Azure Sentinel, QRadar, Sigma"
last_updated: "2026-05"
tags: [siem, detection, correlation-rules, alerting, security-monitoring]
subdomain: soc-operations
nist_csf: [DE.CM-01, DE.CM-04, DE.AE-03]
mitre_attack: [T1046, T1071, T1082, T1560, T1580]
---

# SIEM告警规则与关联分析 (SIEM Alert Rules & Correlation)

## 概述

SIEM（Security Information and Event Management）是现代安全运营的核心平台。高效的告警规则和关联分析能够将海量日志转化为可操作的安全告警。本技能覆盖主流 SIEM 平台的检测规则编写、跨数据源关联分析、误报优化规则和安全场景建模。

## 核心技能

### 1. Splunk 检测规则

```splunk
# Splunk — 基础检测规则

# 1. 暴力破解检测（多个登录失败后成功）
index=windows EventCode=4625
| stats count by Account_Name, Workstation_Name, src_ip
| where count > 5
| join type=inner Account_Name, Workstation_Name [
    search index=windows EventCode=4624
    | stats values(_time) as success_time by Account_Name, Workstation_Name
]
| eval severity="high"
| table Account_Name, src_ip, count, success_time

# 2. 可疑 PowerShell 执行
index=windows EventCode=4104
| search ScriptBlockText=*-EncodedCommand* OR ScriptBlockText=*DownloadString* OR ScriptBlockText=*Invoke-*Mimikatz*
| stats count by ComputerName, Account_Name, ScriptBlockText
| eval severity="high"

# 3. 横向移动 — 服务创建
index=windows EventCode=7045
| search Service_Type=*kernel* OR Image_Path=*\\*.exe*
| lookup threat_intel_ioc.csv image_path AS Image_Path OUTPUT match
| search match=*
| table _time, ComputerName, Account_Name, Service_Name, Image_Path

# 4. DNS 查询异常 — 高熵域名
index=dns sourcetype=bro:dns
| eval domain_length=len(query)
| eval entropy=len(query) - len(replace(query, "[a-z]", ""))
| where domain_length > 30 OR entropy > 15
| stats count by query, src_ip
| where count > 10
| eval severity="medium"
```

```splunk
# Splunk — 高级关联规则

# 5. 多阶段攻击检测
# 阶段1: 网络扫描 → 阶段2: 漏洞利用 → 阶段3: 横向移动

# 阶段1 — 端口扫描检测
index=network sourcetype=flow
| stats dc(dest_port) as port_count by src_ip
| where port_count > 50
| eval phase="recon", severity="low"

# 阶段2 — 漏洞利用尝试（Web Shell 检测）
index=proxy sourcetype=iis
| search url=*.aspx* OR url=*.php* OR url=*.jsp*
| search "cmd=" OR "exec=" OR "wget" OR "certutil"
| stats count by src_ip, cs_uri_stem
| eval phase="exploit", severity="medium"

# 阶段3 — 横向移动检测（从阶段2 IP 发起的网络连接）
index=network sourcetype=flow
| search src_ip IN (从阶段2获取的IP列表)
| stats count by src_ip, dest_ip, dest_port
| where dest_port=445 OR dest_port=3389 OR dest_port=5985
| eval phase="lateral", severity="high"

# 汇总关联
| eval risk_score = (phase_recon*0.2) + (phase_exploit*0.3) + (phase_lateral*0.5)
```

### 2. Elastic Security 检测规则

```kql
# Elastic Security — KQL 查询与规则

# 1. 异常进程创建
process where event.action == "start" and (
  /* 源自 Office 应用的 shell */
  (process.parent.name : ("WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE", "POWERPNT.EXE")
   and process.name : ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe")) or
  
  /* 从临时目录运行 */
  (process.name : ("rundll32.exe", "regsvr32.exe", "mshta.exe")
   and process.args : ("*\\Temp\\*", "*\\Windows\\Temp\\*", "*\\AppData\\*"))
)
| where event.action == "start"
| stats count by host.name, user.name, process.name, process.parent.name

# 2. 批量文件加密检测（勒索软件行为）
file where event.action in ("creation", "rename") and (
  file.extension : ("*.crypt", "*.encrypted", "*.lockbit", "*.enc", "*.Ryuk") or
  file.name : ("*.README*.txt", "*.HOW_TO_DECRYPT*")
)
| stats count as encrypted_count by host.name, user.name
| where encrypted_count > 50
| eval severity = "critical"
```

```kql
# 3. Elastic — 数据外传检测
network where event.action == "connection" and (
  /* 非标准端口 HTTPS */
  (destination.port not in (443, 80, 8080) and network.protocol == "tls") or
  
  /* DNS TXT 响应异常大小 */
  (dns.response_code == "NOERROR" and dns.type == "answer"
   and dns.answer_type == "txt"
   and length(dns.answer_data) > 200)
)
| stats count by destination.ip, host.name

# 4. 异常计划任务创建
file where event.action == "creation" and file.path : "C:\\Windows\\Tasks\\*"
  and file.path : "*.job"
| stats count by host.name, user.name, file.name, file.path
```

### 3. 跨数据源关联分析

```python
"""跨数据源关联引擎"""

import json
from datetime import datetime, timedelta

class CorrelationEngine:
    """SIEM 关联分析引擎"""
    
    def __init__(self, config=None):
        self.rules = []
        self.alerts = []
        self.correlation_window = timedelta(minutes=10)
    
    def add_correlation_rule(self, rule):
        """添加关联规则"""
        self.rules.append(rule)
    
    def evaluate(self, events):
        """评估事件序列进行关联"""
        correlated_alerts = []
        
        for rule in self.rules:
            # 按时间窗口分组
            matched_sequences = self._find_sequence(events, rule)
            
            for seq in matched_sequences:
                alert = self._build_alert(rule, seq)
                correlated_alerts.append(alert)
        
        return correlated_alerts
    
    def _find_sequence(self, events, rule):
        """在事件流中查找规则定义的事件序列"""
        sequences = []
        required_steps = rule.get("steps", [])
        
        # 按来源分组
        from collections import defaultdict
        by_source = defaultdict(list)
        for evt in events:
            by_source[evt.get("src_ip", evt.get("user"))].append(evt)
        
        for source, source_events in by_source.items():
            # 按时间排序
            source_events.sort(key=lambda e: e.get("timestamp", ""))
            
            # 检查是否包含所有步骤
            matched = []
            step_idx = 0
            for evt in source_events:
                if step_idx < len(required_steps):
                    if self._event_matches(evt, required_steps[step_idx]):
                        matched.append(evt)
                        step_idx += 1
            
            if len(matched) == len(required_steps):
                sequences.append({
                    "source": source,
                    "events": matched,
                    "time_span": str(
                        datetime.fromisoformat(matched[-1]["timestamp"].replace("Z","")) - 
                        datetime.fromisoformat(matched[0]["timestamp"].replace("Z",""))
                    )
                })
        
        return sequences
    
    def _event_matches(self, event, step):
        """检查事件是否匹配步骤定义"""
        for key, value in step.get("match", {}).items():
            if event.get(key) != value:
                return False
        return True
    
    def _build_alert(self, rule, sequence):
        """构建关联告警"""
        return {
            "rule": rule["name"],
            "severity": rule.get("severity", "medium"),
            "source": sequence["source"],
            "events_count": len(sequence["events"]),
            "time_span": sequence["time_span"],
            "events": [
                {"type": e.get("event_type"), 
                 "time": e.get("timestamp")} 
                for e in sequence["events"]
            ],
            "timestamp": datetime.now().isoformat(),
            "recommended_action": rule.get("action", "investigate")
        }

# 使用示例
engine = CorrelationEngine()

# 定义横向移动关联规则
rule = {
    "name": "Lateral Movement Detection",
    "severity": "high",
    "steps": [
        {"match": {"event_type": "failed_logon", "count": 5}},
        {"match": {"event_type": "service_creation"}},
        {"match": {"event_type": "network_connection", "dest_port": 445}}
    ],
    "action": "block_source"
}
engine.add_correlation_rule(rule)
```

### 4. 告警优化与误报管理

```python
"""告警质量优化"""

class AlertTuning:
    """告警调优与误报率管理"""
    
    def __init__(self):
        self.alert_history = []
    
    def calculate_false_positive_rate(self, alerts_with_review):
        """计算误报率"""
        total = len(alerts_with_review)
        if total == 0:
            return 0
        
        false_positives = sum(
            1 for a in alerts_with_review 
            if a.get("review_result") == "false_positive"
        )
        return round(false_positives / total * 100, 1)
    
    def suggest_threshold_adjustment(self, rule_stats):
        """基于统计建议阈值调整"""
        adjustments = []
        
        for rule_name, stats in rule_stats.items():
            daily_avg = stats.get("daily_alert_count", 0)
            fp_rate = stats.get("fp_rate", 0)
            
            if daily_avg > 1000:
                adjustments.append({
                    "rule": rule_name,
                    "issue": "告警量过高",
                    "suggestion": f"提高阈值: {stats.get('current_threshold', 0)} → {stats.get('current_threshold', 0) * 2}"
                })
            
            if fp_rate > 30:
                adjustments.append({
                    "rule": rule_name,
                    "issue": f"误报率 {fp_rate}%",
                    "suggestion": "添加排除条件"
                })
        
        return adjustments
    
    def whitelist_example(self):
        """告警白名单配置"""
        whitelist = {
            "ips": ["127.0.0.1", "10.0.0.0/8"],
            "users": ["SYSTEM", "NT AUTHORITY\\*"],
            "processes": ["svchost.exe", "csrss.exe", "winlogon.exe"],
            "domains": ["*.windowsupdate.com", "*.microsoft.com"],
            "rules": ["已知扫描器 - Nessus", "合规扫描 - Qualys"]
        }
        return whitelist
    
    def optimize_rule(self, rule_template):
        """优化检测规则减少误报"""
        optimized = rule_template.copy()
        
        # 添加排除条件
        optimized["excluding"] = {
            "known_good": ["admin_workstations"],
            "non_production": ["dev_*", "test_*"],
            "maintenance_windows": ["00:00-06:00"]
        }
        
        # 添加过滤条件
        optimized["filtering"] = {
            "min_confidence": 30,
            "min_severity": "medium",
            "require_context": True
        }
        
        # 分组聚合减少噪音
        optimized["aggregation"] = {
            "group_by": "src_ip",
            "time_window": "5m",
            "min_count": 3
        }
        
        return optimized

# 规则优化示例
optimizer = AlertTuning()
optimized = optimizer.optimize_rule({
    "rule": "Multiple Failed Logons",
    "condition": "EventCode=4625 count>5"
})
print(json.dumps(optimized, indent=2))
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Splunk | SIEM 与日志分析 | https://www.splunk.com/ |
| Elastic Security | SIEM 检测引擎 | https://www.elastic.co/security |
| Azure Sentinel | 云原生 SIEM | https://azure.microsoft.com/products/microsoft-sentinel/ |
| Sigma | 通用检测规则格式 | https://github.com/SigmaHQ/sigma |
| EventQuery | Windows 事件查询 | https://github.com/0xrawsec/EVTX-ETL-Resources |

## 参考资源

- [Splunk Security Essentials](https://www.splunk.com/en_us/software/security-essentials.html)
- [Elastic Security Detection Rules](https://github.com/elastic/detection-rules)
- [SigmaHQ Rules Repository](https://github.com/SigmaHQ/sigma/tree/master/rules)
- [SOC Detection Engineering — Medium](https://medium.com/soc-detection-engineering)
- [MITRE ATT&CK Detection Engineering](https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/)
