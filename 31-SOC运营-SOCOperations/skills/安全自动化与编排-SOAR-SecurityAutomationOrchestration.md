---
id: "31-003"
title: "安全自动化与编排 (Security Automation & Orchestration - SOAR)"
category: "SOC运营"
category_en: "SOC Operations"
difficulty: "★★★★"
tools: "Shuffle, Splunk SOAR, Tines, Palo Alto XSOAR, n8n"
last_updated: "2026-05"
tags: [soar, automation, orchestration, playbook, security-automation]
subdomain: soc-operations
nist_csf: [RS.CO-01, RS.CO-02, RS.MI-01, RS.MI-02]
mitre_attack: [T1580, T1587, T1588]
---

# 安全自动化与编排 (Security Automation & Orchestration - SOAR)

## 概述

SOAR（Security Orchestration, Automation and Response）是将安全运营自动化的核心平台。通过工作流编排、API 联动和自动化响应，SOAR 能够大幅缩短平均响应时间（MTTR），提升 SOC 运营效率。本技能覆盖 SOAR 工作流设计、常见集成场景、自动化剧本开发和运营指标。

## 核心技能

### 1. SOAR 工作流基础

```python
"""SOAR 工作流引擎核心"""

import json
from datetime import datetime
from typing import Dict, List, Callable

class SOARWorkflow:
    """SOAR 工作流引擎"""
    
    def __init__(self, name: str):
        self.name = name
        self.triggers = []
        self.steps = []
        self.conditions = {}
        self.actions = {}
        self.variables = {}
    
    def add_trigger(self, trigger_type: str, config: dict):
        """添加触发器"""
        self.triggers.append({
            "type": trigger_type,
            "config": config,
            "created": datetime.now().isoformat()
        })
    
    def add_step(self, step: dict):
        """添加工作流步骤"""
        self.steps.append(step)
    
    def add_condition(self, name: str, expression: str, 
                      true_step: str, false_step: str):
        """添加条件分支"""
        self.conditions[name] = {
            "expression": expression,
            "true": true_step,
            "false": false_step
        }
    
    def register_action(self, name: str, handler: Callable):
        """注册执行动作"""
        self.actions[name] = handler
    
    def execute(self, event: dict):
        """执行工作流"""
        context = {
            "event": event,
            "variables": self.variables.copy(),
            "results": {},
            "start_time": datetime.now().isoformat()
        }
        
        # 检查触发器
        for trigger in self.triggers:
            if not self._match_trigger(trigger, event):
                return {"status": "no_match", "event": event["id"]}
        
        # 按步骤执行
        for step in self.steps:
            result = self._execute_step(step, context)
            context["results"][step["name"]] = result
            
            if step.get("critical") and not result.get("success"):
                return {"status": "failed", "step": step["name"], "error": result.get("error")}
        
        return {
            "status": "completed",
            "workflow": self.name,
            "duration": str(datetime.now() - datetime.fromisoformat(context["start_time"])),
            "results": context["results"]
        }
    
    def _match_trigger(self, trigger: dict, event: dict) -> bool:
        """检查事件是否匹配触发器"""
        config = trigger["config"]
        for key, value in config.get("match", {}).items():
            if event.get(key) != value:
                return False
        return True
    
    def _execute_step(self, step: dict, context: dict) -> dict:
        """执行单个步骤"""
        action_type = step.get("action", "")
        if action_type in self.actions:
            return self.actions[action_type](step.get("params", {}), context)
        return {"success": False, "error": f"Unknown action: {action_type}"}

# 定义自动化动作
def block_ip(params, context):
    """阻断 IP 地址"""
    ip = params.get("ip", context["event"].get("src_ip"))
    firewall_api = params.get("api_endpoint", "https://firewall-api/block")
    
    # 模拟 API 调用
    print(f"[ACTION] Blocking IP: {ip} via {firewall_api}")
    return {
        "success": True,
        "action": "block_ip",
        "target": ip,
        "timestamp": datetime.now().isoformat()
    }

def isolate_host(params, context):
    """隔离主机"""
    host = params.get("host", context["event"].get("host"))
    edr_api = params.get("api_endpoint", "https://edr-api/isolate")
    
    print(f"[ACTION] Isolating host: {host} via {edr_api}")
    return {
        "success": True,
        "action": "isolate_host",
        "target": host,
        "timestamp": datetime.now().isoformat()
    }

# 构建自动化工作流
workflow = SOARWorkflow("Malware Response")
workflow.add_trigger("alert", {"match": {"alert_type": "malware", "severity": "high"}})
workflow.register_action("block_ip", block_ip)
workflow.register_action("isolate_host", isolate_host)
workflow.add_step({"name": "block_malicious_ip", "action": "block_ip", "params": {}, "critical": True})
workflow.add_step({"name": "isolate_affected_host", "action": "isolate_host", "params": {}, "critical": True})
```

### 2. 常见集成场景

```python
"""SOAR 集成与联动"""

import json
from datetime import datetime

class SOARIntegration:
    """SOAR 工具集成"""
    
    def __init__(self):
        self.integrations = {}
    
    def splunk_hunt(self, query, timeout=60):
        """集成 Splunk 搜索"""
        import requests
        # Splunk 搜索 API
        url = "https://splunk:8089/services/search/jobs"
        auth = ("admin", "password")
        payload = {"search": f"search {query}", "earliest_time": "-1h"}
        
        # response = requests.post(url, auth=auth, data=payload, verify=False)
        return {"query": query, "status": "submitted"}
    
    def misp_lookup_ioc(self, ioc):
        """集成 MISP 情报查询"""
        from pymisp import PyMISP
        # misp = PyMISP("https://misp.local", "API_KEY", ssl=False)
        # result = misp.search(controller="attributes", value=ioc)
        return {"ioc": ioc, "matches": 0}
    
    def crowdstrike_falcon_query(self, hostname):
        """集成 CrowdStrike Falcon"""
        # falcon = FalconAPI(client_id, client_secret)
        # devices = falcon.devices_query(hostname)
        return {"hostname": hostname, "device_id": "DEVICE-001"}
    
    def virus_total_analyze(self, hash_value):
        """集成 VirusTotal 分析"""
        import requests
        # url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        # headers = {"x-apikey": "API_KEY"}
        # response = requests.get(url, headers=headers)
        return {
            "hash": hash_value,
            "malicious": 12,
            "total": 72,
            "score": "malicious"
        }
    
    def thehive_create_case(self, alert_data):
        """集成 TheHive 创建案例"""
        # TheHive API
        case = {
            "title": alert_data.get("title", "SOAR Auto-Created"),
            "description": alert_data.get("description", ""),
            "severity": alert_data.get("severity", 2),
            "tags": alert_data.get("tags", []),
            "source": alert_data.get("source", "soar"),
            "autoCreated": True
        }
        # response = requests.post("https://thehive/api/v1/case", json=case)
        return {"case_id": "CASE-001", "status": "created"}
    
    def slack_notify(self, channel, message):
        """集成 Slack 通知"""
        import requests
        webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK"
        payload = {
            "channel": channel,
            "text": message,
            "username": "SOAR Bot"
        }
        # requests.post(webhook_url, json=payload)
        return {"channel": channel, "status": "sent"}
    
    def email_notify(self, to, subject, body):
        """集成邮件通知"""
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["To"] = to
        # smtp = smtplib.SMTP("smtp.company.com")
        # smtp.send_message(msg)
        return {"to": to, "subject": subject, "status": "sent"}

# 使用示例
soar = SOARIntegration()
print(soar.virus_total_analyze("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"))
print(soar.thehive_create_case({
    "title": "Malware Detected on SRV-APP-01",
    "severity": 3,
    "description": "Automated case from SOAR workflow",
    "tags": ["malware", "auto"]
}))
```

### 3. SOAR 完整工作流示例

```python
"""自动化恶意软件处置工作流"""

import json

class AutomatedMalwareResponse:
    """自动化恶意软件响应流程"""
    
    def __init__(self):
        self.integration = SOARIntegration()
        self.workflow_result = {
            "case_id": None,
            "steps": [],
            "status": "initiated",
            "timeline": {}
        }
    
    def run(self, alert):
        """执行完整响应流程"""
        alert_id = alert.get("id", "unknown")
        print(f"[SOAR] Processing alert {alert_id}")
        
        # Step 1: 威胁情报丰富
        print("[1/6] Enriching with threat intelligence...")
        ioc = alert.get("hash", alert.get("ip", ""))
        vt_result = self.integration.virus_total_analyze(ioc)
        self.workflow_result["steps"].append({
            "step": "intel_enrichment",
            "result": vt_result
        })
        
        # Step 2: 确认恶意
        if vt_result.get("score") != "malicious":
            print("[SOAR] Alert confirmed benign, closing...")
            self.workflow_result["status"] = "closed_benign"
            return self.workflow_result
        
        # Step 3: Splunk 溯源
        print("[2/6] Hunting in SIEM...")
        host = alert.get("host", "")
        hunt_query = f"index=* {host} earliest=-7d"
        self.integration.splunk_hunt(hunt_query)
        
        # Step 4: 创建 TheHive 案例
        print("[3/6] Creating incident case...")
        case = self.integration.thehive_create_case({
            "title": f"Malware Alert: {alert.get('name', alert_id)}",
            "severity": 3,
            "description": f"Auto-created from SOAR. Host: {host}, IOC: {ioc}",
            "tags": ["malware", "soar-auto", "high"]
        })
        self.workflow_result["case_id"] = case["case_id"]
        
        # Step 5: 自动化阻断
        print("[4/6] Blocking at firewall...")
        src_ip = alert.get("src_ip", "")
        if src_ip:
            block_result = block_ip({"ip": src_ip}, {})
            self.workflow_result["steps"].append(block_result)
        
        # Step 6: 隔离端点
        print("[5/6] Isolating endpoint...")
        isolate_result = isolate_host({"host": host}, {})
        self.workflow_result["steps"].append(isolate_result)
        
        # Step 7: 通知
        print("[6/6] Sending notifications...")
        self.integration.slack_notify("#soc-alerts",
            f"🚨 SOAR Auto-Response Complete\n"
            f"Alert: {alert.get('name', alert_id)}\n"
            f"Case: {case['case_id']}\n"
            f"Actions: IP blocked, Host isolated")
        
        self.workflow_result["status"] = "completed"
        print("[SOAR] Response workflow completed successfully")
        return self.workflow_result

# 使用示例
responder = AutomatedMalwareResponse()
result = responder.run({
    "id": "ALT-789",
    "name": "Suspicious PowerShell Execution",
    "host": "SRV-APP-01",
    "src_ip": "185.220.101.50",
    "hash": "ef537f25c895bfa782526529a9b63d97aa63164d24a2b3d2d10ce0e4b5c6d7e8",
    "severity": "high"
})
print(json.dumps(result, indent=2))
```

### 4. SOAR 运营指标

```python
"""SOAR 效能度量"""

class SOARMetrics:
    """SOAR 运营指标"""
    
    def __init__(self):
        self.metrics = {
            "total_workflows_executed": 0,
            "workflows_by_type": {},
            "avg_execution_time": 0,
            "success_rate": 0,
            "mttr_savings": 0  # 平均响应时间节省（分钟）
        }
        self.executions = []
    
    def record_execution(self, workflow_name, result, duration_seconds):
        """记录工作流执行"""
        self.executions.append({
            "workflow": workflow_name,
            "result": result["status"],
            "duration": duration_seconds,
            "timestamp": datetime.now().isoformat()
        })
    
    def calculate_kpis(self):
        """计算 KPI"""
        total = len(self.executions)
        if total == 0:
            return self.metrics
        
        self.metrics["total_workflows_executed"] = total
        
        # 按类型统计
        for exec in self.executions:
            wf = exec["workflow"]
            self.metrics["workflows_by_type"][wf] = \
                self.metrics["workflows_by_type"].get(wf, 0) + 1
        
        # 成功率
        successes = sum(1 for e in self.executions if e["result"] == "completed")
        self.metrics["success_rate"] = round(successes / total * 100, 1)
        
        # 平均执行时间
        durations = [e["duration"] for e in self.executions]
        self.metrics["avg_execution_time"] = round(sum(durations) / len(durations), 1)
        
        # MTTR 节省（对比人工处理）
        manual_mttr = 30  # 人工平均30分钟
        auto_mttr = self.metrics["avg_execution_time"] / 60
        self.metrics["mttr_savings"] = round(manual_mttr - auto_mttr, 1)
        
        # ROI
        self.metrics["roi"] = {
            "manual_hours_saved": round(total * manual_mttr / 60, 1),
            "auto_hours_spent": round(total * auto_mttr / 60, 2),
            "hours_saved": round(total * (manual_mttr - auto_mttr) / 60, 1)
        }
        
        return self.metrics
    
    def dashboard(self):
        """生成效能仪表盘"""
        kpis = self.calculate_kpis()
        return f"""
        ╔═══════════════════════════════════════╗
        ║        SOAR 运营效能仪表盘            ║
        ╠═══════════════════════════════════════╣
        ║ 工作流执行总数: {kpis['total_workflows_executed']:>8}     ║
        ║ 成功率:          {kpis['success_rate']:>7.1f}%    ║
        ║ 平均执行时间:    {kpis['avg_execution_time']:>8.1f}s    ║
        ║ MTTR 节省:       {kpis['mttr_savings']:>8.1f} 分钟  ║
        ║ 人工节省工时:    {kpis.get('roi', {}).get('manual_hours_saved', 0):>8.1f} 小时  ║
        ╚═══════════════════════════════════════╝
        """

# 使用示例
metrics = SOARMetrics()
metrics.record_execution("Malware Response", {"status": "completed"}, 45)
metrics.record_execution("Malware Response", {"status": "completed"}, 52)
metrics.record_execution("Phishing Response", {"status": "completed"}, 30)
metrics.record_execution("Malware Response", {"status": "failed"}, 120)
print(metrics.dashboard())
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Shuffle | 开源 SOAR 平台 | https://shuffler.io/ |
| Splunk SOAR (Phantom) | 商业 SOAR 平台 | https://www.splunk.com/en_us/products/splunk-security-orchestration-and-automation.html |
| Palo Alto XSOAR | 安全编排平台 | https://www.paloaltonetworks.com/cortex/xsoar |
| Tines | 无代码 SOAR | https://www.tines.com/ |
| n8n | 通用工作流自动化 | https://n8n.io/ |

## 参考资源

- [Shuffle SOAR Documentation](https://shuffler.io/docs)
- [Splunk SOAR Playbook Best Practices](https://www.splunk.com/en_us/blog/security/soar-playbook-best-practices.html)
- [XSOAR Marketplace](https://xsoar.pan.dev/marketplace)
- [NIST SP 800-61 — Incident Response with Automation](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SOAR Buyer's Guide — Gartner](https://www.gartner.com/en/documents/3984554)
