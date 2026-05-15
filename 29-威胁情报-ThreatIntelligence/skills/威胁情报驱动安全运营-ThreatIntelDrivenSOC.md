---
id: "29-004"
title: "威胁情报驱动安全运营 (Threat Intel Driven Security Operations)"
category: "威胁情报"
category_en: "Threat Intelligence"
difficulty: "★★★★"
tools: "Splunk, Elastic, MISP, TheHive, OpenCTI, Shuffle"
last_updated: "2026-05"
tags: [threat-intelligence, security-operations, automation, ioc, intel-driven]
subdomain: threat-intelligence
nist_csf: [DE.CM-04, DE.AE-03, RS.AN-01, RS.CO-02]
mitre_attack: [T1041, T1071, T1568, T1573]
---

# 威胁情报驱动安全运营 (Threat Intel Driven Security Operations)

## 概述

威胁情报的核心价值在于驱动安全运营决策。本技能覆盖 IOC 自动化导入、威胁情报与 SIEM 联动、基于情报的告警优先级排序、自动化阻断响应等场景。通过将外部情报与内部遥测数据关联，实现从"被动告警"到"情报驱动"的运营升级。

## 核心技能

### 1. SIEM 与威胁情报联动

```splunk
# Splunk — IOC 查询自动化

# 导入威胁情报源到 Splunk
# 通过 Lookup 或 Threat Intelligence Framework app
| inputlookup threat_intel_ioc.csv
| eval ioc_type=case(
    match(ioc, "^(\d{1,3}\.){3}\d{1,3}$"), "ip",
    match(ioc, "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"), "domain",
    match(ioc, "^[a-fA-F0-9]{32}$"), "md5",
    match(ioc, "^[a-fA-F0-9]{64}$"), "sha256",
    1=1, "other"
)

# 将威胁情报与网络流量关联
index=network sourcetype=flow
| eval ioc_type = "ip"
| lookup threat_intel_ioc.csv ioc AS dest_ip OUTPUT ioc AS match, confidence
| search match=*
| stats count by dest_ip, confidence, src_ip
| where count > 0
| eval severity=case(
    confidence > 80, "critical",
    confidence > 50, "high",
    confidence > 20, "medium",
    1=1, "low"
)

# 实时 DNS 查询与恶意域名匹配
index=dns sourcetype=bro:dns
| lookup threat_intel_domains.csv domain AS query OUTPUT category AS threat_category
| search threat_category=*
| stats count by query, threat_category, src_ip
| sort -count
```

```kql
# Azure Sentinel / KQL — 威胁情报关联
let intel_iocs = externaldata(IOC: string, Type: string, Confidence: int)
[@"https://yourstorage.blob.core.windows.net/iocs/ioc_list.csv"]
with(format="csv");
let malicious_ips = intel_iocs | where Type == "ip" | project IOC;
SigninLogs
| where IPAddress in (malicious_ips)
| project TimeGenerated, UserPrincipalName, IPAddress, RiskLevelDuringSignIn
| join kind=inner (
    ThreatIntelligenceIndicator
    | where Active == true
) on $left.IPAddress == $right.NetworkIP
| project TimeGenerated, UserPrincipalName, IPAddress, ThreatType, ConfidenceScore
```

```python
"""自动将威胁情报导入 Splunk / Elastic"""

import requests
import json
from datetime import datetime

class IntelSIEMSync:
    """威胁情报 → SIEM 同步器"""
    
    def __init__(self, intel_source, siem_target):
        self.source = intel_source
        self.target = siem_target
    
    def push_to_splunk(self, iocs):
        """将 IOC 推送到 Splunk KV Store"""
        # Splunk KV Store API
        headers = {"Authorization": "Splunk YOUR_TOKEN"}
        payload = {
            "iocs": [
                {"ioc": i["value"], "type": i["type"], 
                 "confidence": i.get("confidence", 50),
                 "source": self.source,
                 "expires": (datetime.now().isoformat())}
                for i in iocs
            ]
        }
        # requests.post(f"{self.target}/services/storage/collections/data/ioc_store/batch_save", 
        #              json=payload, headers=headers)
        pass
    
    def push_to_elastic(self, iocs):
        """将 IOC 推送到 Elasticsearch"""
        for ioc in iocs:
            doc = {
                "@timestamp": datetime.now().isoformat(),
                "ioc": ioc["value"],
                "type": ioc["type"],
                "confidence": ioc.get("confidence", 50),
                "source": self.source,
                "tags": ["threat-intel", "auto-imported"],
                "expires": datetime.now().isoformat()
            }
            # requests.post(f"{self.target}/threat_intel/_doc/", json=doc)
        pass
```

### 2. 情报驱动告警分级

```python
"""基于威胁情报的告警优先级评分"""

class IntelDrivenAlertPrioritizer:
    """使用威胁情报增强告警分级"""
    
    def __init__(self):
        self.ioc_db = {
            "known_c2_ips": {"185.220.101.50": {"severity": "critical", "family": "Emotet"}},
            "malicious_domains": {"evil.com": {"severity": "high", "family": "CobaltStrike"}},
        }
    
    def enrich_alert(self, alert):
        """使用威胁情报丰富告警"""
        enrichment = {
            "intel_match": False,
            "severity_boost": 0,
            "threat_family": None,
            "recommended_action": "monitor"
        }
        
        # 检查源 IP
        src_ip = alert.get("src_ip", "")
        if src_ip in self.ioc_db.get("known_c2_ips", {}):
            intel = self.ioc_db["known_c2_ips"][src_ip]
            enrichment["intel_match"] = True
            enrichment["severity_boost"] += 3
            enrichment["threat_family"] = intel["family"]
        
        # 检查目标域名
        dest_domain = alert.get("dest_domain", "")
        if dest_domain in self.ioc_db.get("malicious_domains", {}):
            intel = self.ioc_db["malicious_domains"][dest_domain]
            enrichment["intel_match"] = True
            enrichment["severity_boost"] += 2
            enrichment["threat_family"] = intel["family"]
        
        # 计算最终严重性
        base_severity = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        base = base_severity.get(alert.get("severity", "low"), 1)
        final_score = min(base + enrichment["severity_boost"], 4)
        reverse_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}
        alert["enriched_severity"] = reverse_map[final_score]
        alert["intel_enrichment"] = enrichment
        
        return alert
    
    def bulk_enrich(self, alerts):
        """批量丰富告警"""
        enriched = [self.enrich_alert(a) for a in alerts]
        # 按丰富后的严重性排序
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        enriched.sort(key=lambda a: sev_order.get(a["enriched_severity"], 99))
        return enriched

# 使用示例
prioritizer = IntelDrivenAlertPrioritizer()
alert = {"id": "ALT-001", "src_ip": "185.220.101.50", 
         "severity": "medium", "alert_type": "malware_detected"}
enriched = prioritizer.enrich_alert(alert)
print(f"Original: {alert['severity']} → Enriched: {enriched['enriched_severity']}")
print(f"Intel match: {enriched['intel_enrichment']['intel_match']}")
```

### 3. 自动化响应（基于情报）

```python
"""基于威胁情报的自动化响应编排"""

import requests
import json

class IntelDrivenResponse:
    """情报驱动的自动化响应"""
    
    def __init__(self):
        self.playbooks = {
            "block_ip_firewall": self.block_ip_firewall,
            "quarantine_endpoint": self.quarantine_endpoint,
            "disable_account": self.disable_account,
            "alert_soc": self.alert_soc
        }
    
    def evaluate_and_respond(self, alert):
        """评估告警并执行响应"""
        intel = alert.get("intel_enrichment", {})
        if not intel.get("intel_match"):
            return {"action": "none", "reason": "No intel match"}
        
        severity = alert.get("enriched_severity", "low")
        responses = []
        
        if severity == "critical":
            if alert.get("alert_type") == "c2_communication":
                responses.append(self.playbooks["block_ip_firewall"](alert))
                responses.append(self.playbooks["quarantine_endpoint"](alert))
            elif alert.get("alert_type") == "credential_theft":
                responses.append(self.playbooks["disable_account"](alert))
        elif severity == "high":
            responses.append(self.playbooks["alert_soc"](alert))
            responses.append(self.playbooks["block_ip_firewall"](alert))
        
        return {"responses": responses, "severity": severity}
    
    def block_ip_firewall(self, alert):
        src_ip = alert.get("src_ip", "")
        # API call to firewall
        # requests.post("https://firewall-api/block", json={"ip": src_ip})
        return {"action": "block_ip", "target": src_ip, "status": "executed"}
    
    def quarantine_endpoint(self, alert):
        host = alert.get("host", "")
        # API call to EDR
        # requests.post(f"https://edr-api/isolate/{host}")
        return {"action": "quarantine", "target": host, "status": "executed"}
    
    def disable_account(self, alert):
        user = alert.get("user", "")
        return {"action": "disable_account", "target": user, "status": "pending_review"}
    
    def alert_soc(self, alert):
        # Send to SIEM/SOAR
        return {"action": "soc_notify", "message": f"Intel-driven alert: {alert['id']}", "status": "sent"}

# SOAR 工作流示例（Shuffle / Tines 兼容格式）
soar_workflow = {
    "name": "Threat Intel Driven Block",
    "triggers": [{"type": "webhook", "name": "intel_alert"}],
    "steps": [
        {"name": "Enrich with Threat Intel", "action": "misp_lookup"},
        {"name": "Check Confidence", "action": "condition", 
         "if": "confidence > 70"},
        {"name": "Block at Firewall", "action": "firewall_block"},
        {"name": "Isolate Endpoint", "action": "edr_isolate"},
        {"name": "Create Ticket", "action": "create_ticket"}
    ]
}
print(json.dumps(soar_workflow, indent=2))
```

### 4. 情报运营度量

```python
"""威胁情报运营 KPI"""

class IntelOpsMetrics:
    """情报运营效能度量"""
    
    def __init__(self):
        self.metrics = {
            "total_iocs_processed": 0,
            "iocs_ingested_by_siem": 0,
            "iocs_matched_alerts": 0,
            "false_positive_rate": 0.0,
            "alert_to_block_time": 0,  # minutes
            "feed_quality_scores": {}
        }
    
    def calculate_kpis(self, logs):
        """从运营日志计算 KPI"""
        # IOC 时效性
        from datetime import datetime
        freshness = []
        for ioc in logs.get("iocs", []):
            if ioc.get("first_seen") and ioc.get("last_seen"):
                delta = datetime.fromisoformat(ioc["last_seen"]) - \
                        datetime.fromisoformat(ioc["first_seen"])
                freshness.append(delta.days)
        
        if freshness:
            avg_lifetime = sum(freshness) / len(freshness)
        
        # 告警到行动时间
        action_times = []
        for alert in logs.get("resolved_alerts", []):
            if alert.get("resolved") and alert.get("created"):
                t = (alert["resolved"] - alert["created"]).total_seconds() / 60
                action_times.append(t)
        
        avg_response = sum(action_times) / len(action_times) if action_times else 0
        
        # ROIs
        return {
            "avg_ioc_lifetime_days": round(sum(freshness)/len(freshness), 1) if freshness else 0,
            "avg_response_time_minutes": round(avg_response, 1),
            "intel_match_rate": round(
                self.metrics["iocs_matched_alerts"] / max(self.metrics["total_iocs_processed"], 1) * 100, 1
            ),
            "estimated_threats_prevented": self.metrics["iocs_matched_alerts"]
        }

# 使用示例
kpi = IntelOpsMetrics()
print(json.dumps(kpi.calculate_kpis({"iocs": [], "resolved_alerts": []}), indent=2))
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| MISP | 威胁情报共享与关联 | https://www.misp-project.org/ |
| OpenCTI | 开源威胁情报平台 | https://github.com/OpenCTI-Platform/opencti |
| TheHive | 安全事件响应平台 | https://thehive-project.org/ |
| Shuffle | 开源 SOAR 平台 | https://shuffler.io/ |
| Tines | 自动化 SOAR | https://www.tines.com/ |

## 参考资源

- [CrowdStrike — Intel-Driven SOC](https://www.crowdstrike.com/cybersecurity-101/threat-intelligence/)
- [SANS — Threat Intelligence Informed Security Operations](https://www.sans.org/white-papers/threat-intelligence/)
- [NIST SP 800-150 — CTI Sharing and Operations](https://csrc.nist.gov/publications/detail/sp/800-150/final)
- [OpenCTI Documentation](https://docs.opencti.io/)
- [Shuffle SOAR Documentation](https://shuffler.io/docs)
