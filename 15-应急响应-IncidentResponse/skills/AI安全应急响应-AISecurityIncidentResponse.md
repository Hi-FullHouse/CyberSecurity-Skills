---
id: 15-001
title: "🤖 AI安全应急响应 (AI Security Incident Response)"
category: 应急响应
category_en: "Incident Response"
difficulty: ★★★★
tools: "AI IR Framework, MITRE ATLAS, TheHive"
last_updated: 2025-07
tags: ["incident-response", "forensics", "memory-forensics", "threat-hunting", "ransomware"]
subdomain: incident-response
nist_csf: ["RS.RP-01", "RS.CO-02", "RS.AN-01", "RS.MI-01"]
mitre_attack: ["T1486", "T1490", "T1485", "T1562"]
---
# 🤖 AI安全应急响应 (AI Security Incident Response)

## 概述
AI系统安全事件具有独特的特征：提示注入攻击、模型数据泄露、Agent越权操作、对抗攻击等。本技能覆盖AI安全事件的检测、分析、遏制、清除和复盘全流程，参照 **NIST SP 800-61 Rev 2**、**MITRE ATLAS** 事件响应指南。

## 核心技能

### 1. AI安全事件检测

```python
import json
import time
from typing import Dict, List, Optional
from datetime import datetime, timedelta

class AIIncidentDetector:
    """AI安全事件检测器"""
    
    def __init__(self, model_id: str, alert_webhook: str = None):
        self.model_id = model_id
        self.alert_webhook = alert_webhook
        self.event_log = []
        self.anomaly_thresholds = {
            "prompt_injection_score": 0.8,
            "data_leak_score": 0.7,
            "api_abuse_rate": 100,  # 每分钟请求数
            "output_toxicity": 0.9,
        }
    
    def analyze_request(self, user_input: str, model_output: str, 
                        metadata: Dict) -> Dict:
        """实时分析请求，检测安全事件"""
        alerts = []
        
        # 1. 检测提示注入
        injection_score = self._detect_prompt_injection(user_input)
        if injection_score > self.anomaly_thresholds["prompt_injection_score"]:
            alerts.append({
                "type": "prompt_injection",
                "severity": "high",
                "score": injection_score,
                "evidence": user_input[:200]
            })
        
        # 2. 检测数据泄露
        leak_score = self._detect_data_leakage(model_output)
        if leak_score > self.anomaly_thresholds["data_leak_score"]:
            alerts.append({
                "type": "data_leakage",
                "severity": "critical",
                "score": leak_score,
                "evidence": model_output[:200]
            })
        
        # 3. 检测有害输出
        toxicity_score = self._detect_toxicity(model_output)
        if toxicity_score > self.anomaly_thresholds["output_toxicity"]:
            alerts.append({
                "type": "toxic_output",
                "severity": "medium",
                "score": toxicity_score,
                "evidence": model_output[:200]
            })
        
        # 记录事件
        if alerts:
            incident = {
                "timestamp": datetime.utcnow().isoformat(),
                "model_id": self.model_id,
                "alerts": alerts,
                "metadata": metadata
            }
            self.event_log.append(incident)
            self._trigger_alert(incident)
        
        return {"alerts": alerts, "incident_id": len(self.event_log)}
    
    def _detect_prompt_injection(self, text: str) -> float:
        """使用多策略检测提示注入"""
        score = 0.0
        injection_signals = [
            r"(?i)(忽略|ignore|override|skip).*(指令|instruction|prompt)",
            r"(?i)(system|系统).*(prompt|提示|指令)",
            r"(?i)(DAN|do.anything.now|越狱|jailbreak)",
            r"(?i)(输出|show|reveal|泄露|leak).*(密码|password|secret|密钥|prompt)",
            r"(?i)(假装|pretend|假设|imagine).*(you.are|你是|你能做)",
        ]
        import re
        for signal in injection_signals:
            if re.search(signal, text):
                score += 0.2
        return min(score, 1.0)
    
    def _detect_data_leakage(self, text: str) -> float:
        """检测输出中的数据泄露"""
        import re
        score = 0.0
        
        # PII泄露
        pii_patterns = [
            (r'\b\d{17}[\dXx]\b', 0.8),  # 身份证号
            (r'\b1[3-9]\d{9}\b', 0.7),   # 手机号
            (r'\bsk-[a-zA-Z0-9]{20,}\b', 0.9),  # API Key
            (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 0.4),  # IP
        ]
        for pattern, weight in pii_patterns:
            if re.search(pattern, text):
                score += weight
        
        return min(score, 1.0)
    
    def _trigger_alert(self, incident: Dict):
        """触发告警通知"""
        print(f"""
🚨 AI安全事件告警
事件ID: {len(self.event_log)}
时间: {incident['timestamp']}
模型: {incident['model_id']}
告警数: {len(incident['alerts'])}
严重级别: {max(a['severity'] for a in incident['alerts'])}
        """)
```

### 2. AI事件分级响应

```python
class AIIncidentResponsePlan:
    """AI安全事件响应计划（基于NIST SP 800-61）"""
    
    SEVERITY_LEVELS = {
        "critical": {
            "response_time": "15分钟",
            "escalation": "CSIRT指挥+AI安全专家+法务",
            "actions": [
                "立即暂停模型推理服务",
                "阻断所有受影响的API Key",
                "通知数据保护官",
                "启动取证调查",
                "评估监管通报义务"
            ]
        },
        "high": {
            "response_time": "1小时",
            "escalation": "安全运营团队+AI工程师",
            "actions": [
                "限制受影响功能模块",
                "回滚到安全版本",
                "启动日志分析",
                "实施临时访问控制"
            ]
        },
        "medium": {
            "response_time": "4小时",
            "escalation": "安全运营团队",
            "actions": [
                "加强监控和检测",
                "分析影响范围",
                "制定修复计划"
            ]
        },
        "low": {
            "response_time": "24小时",
            "escalation": "相关运维人员",
            "actions": [
                "记录事件详情",
                "排入常规修复计划"
            ]
        }
    }
    
    def handle_incident(self, incident: Dict) -> Dict:
        """根据严重级别启动响应"""
        severity = self._classify_severity(incident)
        plan = self.SEVERITY_LEVELS[severity]
        
        response = {
            "incident_id": incident.get("incident_id"),
            "severity": severity,
            "response_time": plan["response_time"],
            "assigned_team": plan["escalation"],
            "actions": plan["actions"],
            "status": "in_progress",
            "started_at": datetime.utcnow().isoformat()
        }
        
        return response
    
    def _classify_severity(self, incident: Dict) -> str:
        """对事件进行严重级别分类"""
        alerts = incident.get("alerts", [])
        max_severity = 0
        
        severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        
        for alert in alerts:
            sev = severity_map.get(alert.get("severity", "low"), 0)
            max_severity = max(max_severity, sev)
        
        reverse_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}
        return reverse_map.get(max_severity, "low")
```

### 3. AI事件取证

```python
class AIForensicsCollector:
    """AI安全事件取证数据收集"""
    
    def collect_evidence(self, incident_id: int, 
                         time_window: timedelta = timedelta(hours=1)) -> Dict:
        """收集事件相关证据"""
        evidence = {
            "incident_id": incident_id,
            "collected_at": datetime.utcnow().isoformat(),
            "categories": {}
        }
        
        # 1. 请求日志
        evidence["categories"]["request_logs"] = self._collect_request_logs(
            time_window
        )
        
        # 2. 模型输出缓存
        evidence["categories"]["model_outputs"] = self._collect_model_outputs(
            time_window
        )
        
        # 3. Agent操作日志
        evidence["categories"]["agent_logs"] = self._collect_agent_logs(
            time_window
        )
        
        # 4. 系统指标
        evidence["categories"]["system_metrics"] = self._collect_system_metrics(
            time_window
        )
        
        # 5. 模型变更记录
        evidence["categories"]["model_changes"] = self._collect_model_changes(
            time_window
        )
        
        return evidence
    
    def _collect_request_logs(self, window: timedelta) -> List[Dict]:
        """收集请求日志（模拟实现）"""
        cutoff = datetime.utcnow() - window
        return [
            log for log in self.request_logs  # 从日志存储中检索
            if datetime.fromisoformat(log["timestamp"]) > cutoff
        ]
    
    def preserve_evidence(self, evidence: Dict) -> str:
        """保全证据（写保护存储）"""
        evidence_hash = self._compute_hash(evidence)
        with open(f"evidence_{evidence['incident_id']}.json.wl", "w") as f:
            json.dump(evidence, f)
        return f"证据已保全，哈希: {evidence_hash}"
```

### 4. AI安全事件复盘模板

```text
# AI安全事件复盘报告

## 事件概要
- 事件ID: IR-2024-001
- 发现时间: 2024-01-15 14:23 UTC
- 报告人: 安全监控系统
- 严重级别: Critical
- 当前状态: 已闭环

## 事件时间线
| 时间 | 事件 | 动作 | 负责人 |
|:---|:---|:---|:---:|
| 14:23 | 检测到提示注入攻击 | 自动告警触发 | 系统 |
| 14:25 | 确认攻击有效 | 人工确认 | 安全运营 |
| 14:27 | 暂停推理服务 | 执行遏制 | 平台运维 |
| 14:35 | 阻断攻击者IP和API Key | 执行遏制 | 安全运营 |
| 15:00 | 启动取证分析 | 调查 | IR团队 |
| 18:00 | 修复漏洞并验证 | 清除 | AI工程 |
| 20:00 | 恢复服务 | 恢复 | 平台运维 |
| D+7 | 完成复盘报告 | 复盘 | IR团队 |

## 根因分析
- 直接原因: Prompt模板未对用户输入进行转义
- 间接原因: 缺少输入安全过滤层
- 根本原因: 安全开发流程中缺少LLM安全审查环节

## 影响评估
- 受影响用户: 127人
- 数据泄露: 无（模型输出被安全过滤层拦截）
- 服务中断: 5小时37分钟
- 经济损失: 约¥50,000

## 修复措施
### 短期（已完成）
[✓] 部署输入安全过滤层
[✓] 实施Prompt模板输入转义
[✓] 阻断攻击者来源

### 中期（进行中）
[ ] 实施双模型验证架构
[ ] 增加实时异常检测
[ ] 部署WAF规则

### 长期（计划中）
[ ] 完善AI安全开发流程
[ ] 定期红队测试
[ ] AI安全培训

## 经验教训
1. AI系统安全应纳入SDL流程
2. 需要实时检测和自动响应能力
3. 安全过滤层应作为LLM应用的必备组件
```

### 5. AI事件响应自动化

```python
class AISecuritySOAR:
    """AI安全SOAR自动化响应"""
    
    def __init__(self, playbooks: Dict):
        self.playbooks = playbooks
    
    def auto_respond(self, incident: Dict) -> Dict:
        """根据事件类型自动执行响应剧本"""
        incident_type = self._classify_incident(incident)
        playbook = self.playbooks.get(incident_type, self.playbooks["default"])
        
        executed_actions = []
        for step in playbook["steps"]:
            result = self._execute_step(step, incident)
            executed_actions.append({"step": step["name"], "result": result})
            
            # 如果步骤失败，根据策略处理
            if not result["success"] and step.get("critical", False):
                break
        
        return {
            "incident_id": incident.get("incident_id"),
            "playbook": playbook["name"],
            "actions": executed_actions,
            "status": "completed" if all(a["result"]["success"] for a in executed_actions) else "partial"
        }
    
    def _classify_incident(self, incident: Dict) -> str:
        """对事件进行分类"""
        alert_types = [a["type"] for a in incident.get("alerts", [])]
        
        if "data_leakage" in alert_types:
            return "data_leak"
        elif "prompt_injection" in alert_types:
            return "prompt_injection"
        elif "toxic_output" in alert_types:
            return "toxic_output"
        else:
            return "default"
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| AI Incident Response Framework | AI事件响应框架 | https://github.com/AIIncidentResponse/ |
| MITRE ATLAS Navigator | 攻击矩阵导航 | https://atlas.mitre.org/ |
| ELK Stack | 日志分析 | https://www.elastic.co/ |
| Splunk | SIEM+AI事件关联 | https://www.splunk.com/ |
| TheHive | 事件管理平台 | https://thehive-project.org/ |
| DFIR Tools | 数字取证工具集 | https://github.com/dfir-orchestra/ |

## 参考资源

- [NIST SP 800-61 Rev 2 — Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [MITRE ATLAS — Incident Response](https://atlas.mitre.org/)
- [FIRST AI Incident Response SIG](https://www.first.org/global/sigs/ai/)
- [OWASP LLM Incident Response Guide](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [ENISA — AI Cybersecurity Report](https://www.enisa.europa.eu/publications/artificial-intelligence-cybersecurity-challenges)
