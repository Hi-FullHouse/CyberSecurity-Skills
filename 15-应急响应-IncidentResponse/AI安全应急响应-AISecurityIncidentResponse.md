---
id: "15-001"
title: "🤖 AI安全应急响应 (AI Security Incident Response)"
category: "应急响应"
category_en: "Incident Response"
difficulty: "★★★★"
tools: "AI IR Framework, MITRE ATLAS, TheHive, CVE Database, NVD, Snyk, Trivy"
last_updated: "2025-07"
---

# 🤖 AI安全应急响应 (AI Security Incident Response)

## 概述

AI系统安全事件具有独特的特征：提示注入攻击、模型数据泄露、Agent越权操作、对抗攻击、供应链投毒等。本技能涵盖AI安全事件全生命周期管理——**检测→分类→遏制→取证→清除→恢复→复盘**，并新增**供应链安全阶段**和**漏洞管理阶段**，参照 **NIST SP 800-61 Rev 2**、**MITRE ATLAS™**、**FIRST AI IR SIG**、**OWASP LLM Top 10**、**ISO 27035** 事件管理标准。

---

## 一、准备阶段 (Preparation)

> **标准依据**: NIST SP 800-61 §3.2.1, ISO 27035-1 §6.2

AI安全应急响应的基础是**事前准备**。缺乏准备的团队在事件发生时将陷入被动。

### 1.1 AI安全事件响应团队组建

| 角色 | 职责 | 技能要求 |
|:---|:---|:---|
| IR指挥 | 统筹决策、对外沟通 | CSIRT管理经验 |
| AI安全分析师 | 事件分析、根因定位 | LLM安全、对抗攻击知识 |
| MLOps工程师 | 模型运维、版本回滚 | MLflow、Kubeflow |
| 法务合规 | 监管通报、证据保全 | 数据隐私法规（GDPR/PIPL） |
| 数据保护官 | 数据泄露评估 | 数据分类分级 |

### 1.2 准备检查清单

```python
class AIPreparednessChecker:
    """AI安全应急准备度检查"""
    
    CHECKLIST = {
        "人员": [
            "IR团队已组建并明确角色",
            "24x7值班轮岗制度",
            "定期红蓝演练（≥2次/年）"
        ],
        "工具": [
            "部署AI流量监控（如AIShield/Guardrails）",
            "配置日志聚合（ELK/Loki）",
            "部署威胁情报平台（MISP/OpenCTI）",
            "配置自动化响应剧本（SOAR）"
        ],
        "流程": [
            "事件分级标准已定义",
            "上报链路已测试",
            "证据保全流程已备案",
            "供应链应急联络人已确认"
        ],
        "模型": [
            "模型清单（Model Inventory）已维护",
            "模型版本控制已启用（DVC/MLflow）",
            "模型依赖SBOM已生成",
            "训练数据溯源记录"
        ]
    }
    
    def check_preparedness(self) -> Dict:
        """返回准备度打分"""
        results = {}
        total, passed = 0, 0
        for category, items in self.CHECKLIST.items():
            cat_results = []
            for item in items:
                # 实际项目中接入扫描/问卷系统
                cat_results.append({"check": item, "status": "pending"})
            results[category] = cat_results
        return {"pass_rate": f"{passed}/{total}" if total else "N/A"}
```

---

## 二、检测与发现阶段 (Detection & Discovery)

> **标准依据**: NIST SP 800-61 §3.2.2, MITRE ATLAS Detection

### 2.1 AI安全事件检测

```python
import json
import re
import time
from typing import Dict, List, Optional
from datetime import datetime, timedelta

class AIIncidentDetector:
    """AI安全事件检测器（增强版）"""
    
    def __init__(self, model_id: str, alert_webhook: str = None):
        self.model_id = model_id
        self.alert_webhook = alert_webhook
        self.event_log = []
        self.anomaly_thresholds = {
            "prompt_injection_score": 0.8,
            "data_leak_score": 0.7,
            "api_abuse_rate": 100,  # 每分钟请求数
            "output_toxicity": 0.9,
            "supply_chain_anomaly": 0.75,  # 新增：供应链异常阈值
            "model_poison_score": 0.85,     # 新增：模型投毒检测阈值
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
                "evidence": user_input[:200],
                "mitre_atlas_id": "AML.T0051"  # MITRE ATLAS映射
            })
        
        # 2. 检测数据泄露
        leak_score = self._detect_data_leakage(model_output)
        if leak_score > self.anomaly_thresholds["data_leak_score"]:
            alerts.append({
                "type": "data_leakage",
                "severity": "critical",
                "score": leak_score,
                "evidence": model_output[:200],
                "mitre_atlas_id": "AML.T0024"
            })
        
        # 3. 检测有害输出
        toxicity_score = self._detect_toxicity(model_output)
        if toxicity_score > self.anomaly_thresholds["output_toxicity"]:
            alerts.append({
                "type": "toxic_output",
                "severity": "medium",
                "score": toxicity_score,
                "evidence": model_output[:200],
                "mitre_atlas_id": "AML.T0054"
            })
        
        # 4. 检测供应链相关异常（新增）
        supply_chain_score = self._detect_supply_chain_anomaly(metadata)
        if supply_chain_score > self.anomaly_thresholds["supply_chain_anomaly"]:
            alerts.append({
                "type": "supply_chain_anomaly",
                "severity": "high",
                "score": supply_chain_score,
                "evidence": str(metadata.get("model_source", "unknown")),
                "mitre_atlas_id": "AML.T0019"
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
            # 新增：多层注入模式
            r"(?i)(间接注入|indirect.*inject|second.*order)",
            r"(?i)(越狱|jailbreak.*prompt|prompt.*leak)",
        ]
        for signal in injection_signals:
            if re.search(signal, text):
                score += 0.15
        return min(score, 1.0)
    
    def _detect_data_leakage(self, text: str) -> float:
        """检测输出中的数据泄露"""
        score = 0.0
        
        # PII泄露
        pii_patterns = [
            (r'\b\d{17}[\dXx]\b', 0.8),   # 身份证号
            (r'\b1[3-9]\d{9}\b', 0.7),    # 手机号
            (r'\bsk-[a-zA-Z0-9]{20,}\b', 0.9),   # API Key
            (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 0.4),  # IP
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', 0.5),  # Email
            # 新增：API令牌
            (r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b', 0.9),  # GitHub Token
            (r'\bAKIA[0-9A-Z]{16}\b', 0.9),  # AWS Access Key
        ]
        for pattern, weight in pii_patterns:
            if re.search(pattern, text):
                score += weight
        
        return min(score, 1.0)
    
    def _detect_supply_chain_anomaly(self, metadata: Dict) -> float:
        """检测供应链异常（新增）"""
        score = 0.0
        model_source = metadata.get("model_source", "")
        model_version = metadata.get("model_version", "")
        
        # 1. 未经验证的模型来源
        if not model_source.startswith(("trusted-", "verified-", "internal-")):
            score += 0.3
        
        # 2. 版本与预期不符
        expected_versions = metadata.get("expected_versions", [])
        if expected_versions and model_version not in expected_versions:
            score += 0.3
        
        # 3. 最近有依赖变更
        recent_changes = metadata.get("recent_dependency_changes", [])
        for change in recent_changes:
            if change.get("type") in ("unverified", "unknown"):
                score += 0.2
        
        return min(score, 1.0)
    
    def _trigger_alert(self, incident: Dict):
        """触发告警通知（支持多渠道）"""
        severity = max(a['severity'] for a in incident['alerts'])
        print(f"""
🚨 AI安全事件告警
│ 事件ID:   {len(self.event_log)}
│ 时间:     {incident['timestamp']}
│ 模型:     {incident['model_id']}
│ 严重级别: {severity}
│ 告警数:   {len(incident['alerts'])}
│ MITRE:    {', '.join(a.get('mitre_atlas_id','') for a in incident['alerts'])}
└───────────────────────────────────
        """)
        # 实际应发送到：Slack/PagerDuty/钉钉/飞书
```

### 2.2 检测覆盖矩阵

| 攻击类型 | MITRE ATLAS ID | 检测方法 | 优先级 |
|:---|:---|:---|:---:|
| 直接提示注入 | AML.T0051 | 正则+分类器 | P0 |
| 间接提示注入 | AML.T0051.001 | 上下文分析 | P1 |
| 训练数据投毒 | AML.T0018 | 数据溯源校验 | P0 |
| 模型后门 | AML.T0020 | 异常行为检测 | P0 |
| 供应链投毒 | AML.T0019 | SBOM审计 | P1 |
| 模型反转攻击 | AML.T0024 | 输出监控 | P2 |
| Agent越权 | AML.T0040 | 策略违反检测 | P0 |
| 拒绝服务（算力耗尽） | AML.T0029 | 速率限制+成本监控 | P1 |

---

## 三、分类与优先级评估阶段 (Triage & Prioritization)

> **标准依据**: NIST SP 800-61 §3.2.3, FIRST CVSS for AI

### 3.1 AI事件分级模型（增强版）

```python
class AIIncidentResponsePlan:
    """AI安全事件响应计划（基于NIST SP 800-61 + ISO 27035）"""
    
    SEVERITY_LEVELS = {
        "critical": {
            "response_time": "15分钟",
            "escalation": "CSIRT指挥+AI安全专家+法务+DPO",
            "response_sla": "P0 — 立即响应",
            "actions": [
                "立即暂停模型推理服务",
                "阻断所有受影响的API Key",
                "触发供应链应急联络（如涉及第三方模型）",
                "通知数据保护官（DPO）",
                "启动取证调查",
                "评估监管通报义务（72h GDPR通报）",
                "记录操作日志至区块(chain-of-custody)"
            ]
        },
        "high": {
            "response_time": "1小时",
            "escalation": "安全运营团队+AI工程师+供应链负责人",
            "response_sla": "P1 — 紧急响应",
            "actions": [
                "限制受影响功能模块",
                "回滚到安全版本（含模型回滚）",
                "启动日志分析和证据保全",
                "实施临时访问控制（WAF/rate-limit）",
                "验证下游供应链影响范围"
            ]
        },
        "medium": {
            "response_time": "4小时",
            "escalation": "安全运营团队",
            "response_sla": "P2 — 标准响应",
            "actions": [
                "加强监控和检测",
                "分析影响范围",
                "制定修复计划",
                "排查是否存在供应链依赖风险"
            ]
        },
        "low": {
            "response_time": "24小时",
            "escalation": "相关运维人员",
            "response_sla": "P3 — 低优先级",
            "actions": [
                "记录事件详情",
                "排入常规修复计划",
                "更新安全检测规则"
            ]
        }
    }
    
    # 新增：基于CVSS-AI的评分映射
    CVSS_AI_THRESHOLDS = {
        (9.0, 10.0): "critical",
        (7.0, 8.9): "high",
        (4.0, 6.9): "medium",
        (0.1, 3.9): "low"
    }
    
    def handle_incident(self, incident: Dict) -> Dict:
        """根据严重级别启动响应"""
        severity = self._classify_severity(incident)
        plan = self.SEVERITY_LEVELS[severity]
        
        response = {
            "incident_id": incident.get("incident_id"),
            "severity": severity,
            "response_time": plan["response_time"],
            "response_sla": plan["response_sla"],
            "assigned_team": plan["escalation"],
            "actions": plan["actions"],
            "status": "in_progress",
            "started_at": datetime.utcnow().isoformat(),
            "cvss_ai_score": self._calculate_cvss_ai(incident)
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
    
    def _calculate_cvss_ai(self, incident: Dict) -> float:
        """计算AI事件CVSS评分（简版，参照CVE-5.0框架）"""
        base_score = 0.0
        alerts = incident.get("alerts", [])
        
        for alert in alerts:
            # 基于告警类型的CVSS向量评估
            type_scores = {
                "data_leakage": 9.1,      # 机密性影响高
                "prompt_injection": 7.5,   # 完整性影响高
                "toxic_output": 5.3,       # 影响有限
                "supply_chain_anomaly": 8.2, # 供应链风险高
                "model_poison": 9.3,       # 极严重
            }
            score = type_scores.get(alert.get("type", ""), 5.0)
            base_score = max(base_score, score)
        
        return base_score
```

### 3.2 事件分类矩阵

| 分类 | 描述 | 示例 | 对应ATLAS |
|:---|:---|:---|:---:|
| AI-INT-001 | 提示注入攻击 | 越狱、DAN攻击 | AML.T0051 |
| AI-INT-002 | 数据泄露 | PII泄露、训练数据重建 | AML.T0024 |
| AI-INT-003 | 模型操纵 | 后门触发、对抗样本 | AML.T0020 |
| AI-INT-004 | 供应链攻击 | 依赖投毒、模型替换 | AML.T0019 |
| AI-INT-005 | 滥用与DoS | 算力耗尽、API滥用 | AML.T0029 |
| AI-INT-006 | Agent违规 | 越权操作、工具滥用 | AML.T0040 |
| AI-INT-007 | 合规违规 | 违反GDPR、版权输出 | — |

---

## 四、遏制阶段 (Containment)

> **标准依据**: NIST SP 800-61 §3.2.4

### 4.1 短期遏制

| 措施 | AI场景应用 | 自动化程度 | 执行时间 |
|:---|:---|:---|:---:|
| 阻断来源IP | WAF/API Gateway封禁 | 自动 | <1分钟 |
| 吊销API Key | 立即吊销受影响Key | 自动 | <1分钟 |
| 模型推理暂停 | 暂停模型服务/切流 | 半自动 | <5分钟 |
| Rate-limit | 降低请求频率阈值 | 自动 | <1分钟 |
| 输入过滤 | 激活更严格输入过滤规则 | 自动 | <1分钟 |
| 供应链阻断 | 停用受影响第三方模型调用 | 半自动 | <10分钟 |

### 4.2 长期遏制

```python
class AIIncidentContainment:
    """AI安全事件遏制执行器"""
    
    def short_term_contain(self, incident: Dict) -> List[Dict]:
        """短期遏制措施"""
        actions = []
        alert_types = [a["type"] for a in incident.get("alerts", [])]
        
        if "prompt_injection" in alert_types:
            actions.append({
                "action": "block_malicious_patterns",
                "target": "input_filter",
                "command": "waf_rule_deploy --block prompt-injection",
                "eta": "1min"
            })
        
        if "data_leakage" in alert_types:
            actions.append({
                "action": "enable_output_sanitizer",
                "target": "model_output",
                "command": "enable_pii_redactor --level strict",
                "eta": "30s"
            })
        
        if "supply_chain_anomaly" in alert_types:
            actions.append({
                "action": "quarantine_model_source",
                "target": "model_registry",
                "command": "quarantine --model-id {model_id}",
                "eta": "5min"
            })
        
        return actions
    
    def long_term_contain(self, incident_id: int) -> Dict:
        """长期遏制（补丁/配置变更）"""
        return {
            "incident_id": incident_id,
            "measures": [
                "部署WAF自定义规则",
                "升级输入过滤模型",
                "实施最小权限原则",
                "添加供应链校验步骤",
                "启用模型输出签名验证"
            ]
        }
```

---

## 五、取证阶段 (Forensics)

> **标准依据**: NIST SP 800-86, ISO 27037, ACPO Principles

### 5.1 AI事件取证数据收集

```python
class AIForensicsCollector:
    """AI安全事件取证数据收集（增强版）"""
    
    def collect_evidence(self, incident_id: int, 
                         time_window: timedelta = timedelta(hours=1)) -> Dict:
        """收集事件相关证据"""
        evidence = {
            "incident_id": incident_id,
            "collected_at": datetime.utcnow().isoformat(),
            "chain_of_custody": [],
            "categories": {}
        }
        
        # 1. 请求日志
        evidence["categories"]["request_logs"] = self._collect_request_logs(
            time_window
        )
        evidence["chain_of_custody"].append({
            "action": "collect", "item": "request_logs", 
            "timestamp": datetime.utcnow().isoformat()
        })
        
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
        
        # 6. 新增：供应链证据
        evidence["categories"]["supply_chain"] = self._collect_supply_chain_evidence(
            time_window
        )
        
        # 7. 新增：依赖SBOM快照
        evidence["categories"]["dependency_sbom"] = self._collect_sbom_snapshot(
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
    
    def _collect_supply_chain_evidence(self, window: timedelta) -> Dict:
        """收集供应链证据（新增）"""
        return {
            "model_registry_changes": [],
            "dependency_updates": [],
            "third_party_access_logs": [],
            "model_origin_verification": {}
        }
    
    def _collect_sbom_snapshot(self, window: timedelta) -> Dict:
        """收集SBOM快照（新增）"""
        return {
            "sbom_format": "SPDX-2.3",
            "generated_at": datetime.utcnow().isoformat(),
            "components": []
        }
    
    def preserve_evidence(self, evidence: Dict) -> str:
        """保全证据（写保护存储+哈希链）"""
        import hashlib
        
        # 计算证据哈希
        evidence_str = json.dumps(evidence, sort_keys=True, default=str)
        evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()
        
        # 写入写保护存储
        filename = f"evidence_{evidence['incident_id']}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(f"./evidence/{filename}", "w") as f:
            json.dump(evidence, f, default=str)
        
        # 返回哈希供链式验证
        return f"✅ 证据已保全: {filename}\
🔐 SHA256: {evidence_hash}"
```

### 5.2 取证链模板

```text
╔══════════════════════════════════════════╗
║           证据保管链 (Chain of Custody)   ║
╠══════════════════════════════════════════╣
║ 事件ID:       IR-2024-NNN               ║
║ 保管人:       [姓名/工号]                ║
║ 来源:         [系统/人工]                ║
╠══════════════════════════════════════════╣
║ # │ 证据项        │ 采集人 │ 时间      │ ║
║───┼──────────────┼───────┼───────────║
║ 1 │ 请求日志      │ 系统   │ 14:23:45 │ ║
║ 2 │ 模型输出缓存  │ 系统   │ 14:23:47 │ ║
║ 3 │ API调用轨迹   │ 系统   │ 14:24:01 │ ║
║ 4 │ SBOM快照      │ 系统   │ 14:25:00 │ ║
╠══════════════════════════════════════════╣
║ 转移记录:                                ║
║ 14:30  → IR团队 [签名]                  ║
║ 15:00  → 法务部  [签名]                 ║
╚══════════════════════════════════════════╝
```

### 5.3 AI取证关键技术

| 技术 | 描述 | 工具 |
|:---|:---|:---|
| 内存取证 | 捕获推理时GPU内存快照 | LiME, Volatility |
| 日志关联 | 关联API→模型→Agent日志 | ELK, Splunk |
| 模型指纹 | 比对模型哈希验证完整性 | sha256sum, sigstore |
| 输入重放 | 重放攻击输入复现异常 | curl, Postman |
| Agent轨迹回放 | 重放Agent决策路径 | LangSmith, Arize |
| 依赖溯源 | 追溯SBOM依赖版本变更 | Syft, Grype |

---

## 六、清除与恢复阶段 (Eradication & Recovery)

> **标准依据**: NIST SP 800-61 §3.2.5

### 6.1 清除（Eradication）

```python
class AIEradication:
    """AI安全事件清除"""
    
    def eradicate(self, incident: Dict) -> Dict:
        """执行清除操作"""
        operations = []
        
        alert_types = [a["type"] for a in incident.get("alerts", [])]
        
        if "prompt_injection" in alert_types:
            operations.extend([
                {"op": "update_prompt_template", "desc": "更新prompt模板进行转义"},
                {"op": "deploy_input_filter", "desc": "部署输入安全过滤层"},
                {"op": "patch_model_gateway", "desc": "修补模型网关安全漏洞"}
            ])
        
        if "data_leakage" in alert_types:
            operations.extend([
                {"op": "enable_output_redaction", "desc": "启用输出脱敏"},
                {"op": "rotate_secrets", "desc": "轮换受影响密钥"},
                {"op": "audit_training_data", "desc": "审计训练数据源"}
            ])
        
        if "supply_chain_anomaly" in alert_types:
            operations.extend([
                {"op": "verify_model_integrity", "desc": "验证模型完整性签名"},
                {"op": "update_trusted_sources", "desc": "更新可信来源列表"},
                {"op": "patch_dependency", "desc": "修补供应链依赖漏洞"}
            ])
        
        return {"operations": operations, "status": "eradicating"}
```

### 6.2 恢复（Recovery）

| 步骤 | 动作 | 验证标准 |
|:---|:---|:---|
| 1 | 回滚模型到安全版本 | 模型哈希匹配已知安全版本 |
| 2 | 恢复API服务 | 绿部署→蓝部署，逐步切流 |
| 3 | 验证安全补丁有效性 | 重放攻击payload，确认已被拦截 |
| 4 | 恢复第三方模型调用 | 签名验证通过后逐步放开 |
| 5 | 监控增强期 | 24h增强监控，观察异常回弹 |
| 6 | 通知相关方 | 内部通报 + 客户通知（如适用） |

### 6.3 回滚自动化

```python
class AISafeRollback:
    """AI安全回滚管理器"""
    
    def safe_rollback(self, model_id: str, safe_version: str) -> Dict:
        """执行安全回滚"""
        steps = [
            {"step": "pre_check", "action": "验证目标版本完整性"},
            {"step": "traffic_drain", "action": "排空当前版本流量"},
            {"step": "load_model", "action": f"加载版本 {safe_version}"},
            {"step": "canary_test", "action": "金丝雀测试（5%流量）"},
            {"step": "full_switch", "action": "全量切换"},
            {"step": "validate", "action": "运行安全验证套件"},
        ]
        return {"model_id": model_id, "new_version": safe_version, "steps": steps}
    
    def auto_rollback_on_anomaly(self, threshold: float = 0.05) -> bool:
        """异常率超出阈值时自动回滚"""
        current_error_rate = self._get_current_error_rate()
        if current_error_rate > threshold:
            self._trigger_rollback()
            return True
        return False
```

---

## 七、复盘与改进阶段 (Post-Incident / Lessons Learned)

> **标准依据**: NIST SP 800-61 §3.2.6, ISO 27035-2

### 7.1 AI安全事件复盘模板

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
| 14:40 | 阻断供应链第三方模型调用 | 执行遏制 | 供应链安全 |
| 15:00 | 启动取证分析 | 调查 | IR团队 |
| 18:00 | 修复漏洞并验证 | 清除 | AI工程 |
| 20:00 | 恢复服务 | 恢复 | 平台运维 |
| D+7  | 完成复盘报告 | 复盘 | IR团队 |
| D+14 | 漏洞修复跟踪关闭 | 漏洞管理 | 安全工程 |

## 根因分析（5 Whys）
1. 为什么攻击成功？ → Prompt模板未转义
2. 为什么未转义？ → 代码审查未覆盖安全场景
3. 为什么未覆盖？ → SDL流程中缺少LLM安全审查环节
4. 为什么缺少环节？ → 安全团队对AI安全认知不足
5. 为什么认知不足？ → 需要系统性AI安全培训

### 根因分类
- **直接原因**: Prompt模板未对用户输入进行转义
- **间接原因**: 缺少输入安全过滤层
- **根本原因**: 安全开发流程中缺少LLM安全审查环节
- **供应链因素**: 第三方模型依赖未做完整性校验

## 影响评估
| 维度 | 评估 |
|:---|:---|
| 受影响用户 | 127人 |
| 数据泄露 | 无（模型输出被安全过滤层拦截） |
| 服务中断 | 5小时37分钟 |
| 经济损失 | 约¥50,000 |
| 监管风险 | 无通报义务 |

## 修复措施
### 短期（已完成）
- [✓] 部署输入安全过滤层
- [✓] 实施Prompt模板输入转义
- [✓] 阻断攻击者来源
- [✓] 验证第三方模型完整性

### 中期（进行中）
- [ ] 实施双模型验证架构
- [ ] 增加实时异常检测
- [ ] 部署WAF规则
- [ ] 生成并维护AI供应链SBOM

### 长期（计划中）
- [ ] 完善AI安全开发流程
- [ ] 定期红队测试
- [ ] AI安全全员培训
- [ ] 建立安全模型市场（trusted model registry）

## 漏洞管理关联
| CVE/ID | 组件 | 严重性 | 状态 | 验证人 |
|:---|:---|:---:|:---:|:---:|
| CVE-2024-NNNN | langchain | High | 已修复 | 张三 |
| CVE-2024-NNNN | transformers | Critical | 修复中 | 李四 |
| AI-VULN-001 | prompt模板 | — | 已修复 | 王五 |

## 经验教训
1. AI系统安全应纳入SDL流程
2. 需要实时检测和自动响应能力
3. 安全过滤层应作为LLM应用的必备组件
4. 供应链安全需纳入应急响应范围
5. 漏洞管理应覆盖AI组件全生命周期

## KPI指标
| 指标 | 目标 | 本次 | 结论 |
|:---|:---:|:---:|:---:|
| MTTD（平均检测时间） | <5min | 2min | ✓ |
| MTTR（平均响应时间） | <30min | 12min | ✓ |
| 发现率 | 100% | 98% | ✓ |
| 误报率 | <5% | 3% | ✓ |
| 漏洞修复时间 | <7d | 3d | ✓ |
```

### 7.2 复盘RCA技术

```python
class AIPostIncidentReview:
    """AI事件复盘分析"""
    
    def five_whys_analysis(self, incident: Dict) -> List[str]:
        """5-Why根因分析"""
        chain = []
        problem = incident.get("description", "未知事件")
        
        whys = [
            f"为什么{problem}？ → {incident.get('direct_cause')}",
            f"为什么{incident.get('direct_cause')}？ → {incident.get('indirect_cause')}",
            f"为什么{incident.get('indirect_cause')}？ → {incident.get('root_cause')}",
            f"为什么{incident.get('root_cause')}？ → {incident.get('org_factor')}",
            f"为什么{incident.get('org_factor')}？ → {incident.get('cultural_factor')}",
        ]
        return whys
    
    def generate_improvement_plan(self, root_cause: str) -> List[Dict]:
        """生成改进计划"""
        improvements = {
            "安全流程缺失": [
                {"action": "将LLM安全检查纳入SDL", "owner": "安全架构", "deadline": "30d"},
                {"action": "建立AI安全设计评审", "owner": "安全团队", "deadline": "14d"},
            ],
            "监控不足": [
                {"action": "部署AI行为监控", "owner": "MLOps", "deadline": "21d"},
                {"action": "配置实时告警dashboard", "owner": "可观测团队", "deadline": "7d"},
            ],
            "供应链风险": [
                {"action": "建立模型来源白名单", "owner": "安全架构", "deadline": "7d"},
                {"action": "实施依赖自动扫描", "owner": "DevOps", "deadline": "14d"},
            ],
        }
        return improvements.get(root_cause, [{"action": "补录根因分析", "owner": "IR团队", "deadline": "7d"}])
```

---

## 八、供应链安全阶段 (Supply Chain Security) ⭐【新增】

> **标准依据**: NIST SP 800-161 (Cybersecurity Supply Chain Risk Management), 
> OWASP CycloneDX, SLSA Framework, MITRE ATLAS AML.T0019

### 概述

AI供应链攻击已成为最危险的威胁向量之一。攻击者通过**模型投毒、依赖混淆、预训练后门、第三方API劫持**等方式，在AI系统交付链中植入恶意组件。

### 8.1 AI供应链安全风险分类

| 风险类型 | 描述 | 攻击向量 | 严重性 |
|:---|:---|:---|:---:|
| 模型投毒 (Model Poisoning) | 训练数据或权重中植入后门 | 数据源污染、公开数据集 | 🔴 Critical |
| 依赖混淆 (Dependency Confusion) | 使用同名恶意包替代合法包 | PyPI/npm/Conda | 🔴 Critical |
| 预训练后门 (Pre-trained Backdoor) | 公开模型权重含恶意功能 | HuggingFace、ModelZoo | 🟠 High |
| 第三方API劫持 | 调用链中第三方服务被攻陷 | API Gateway、代理服务 | 🟠 High |
| CI/CD投毒 | 构建流水线被插入恶意步骤 | GitHub Actions、Jenkins | 🟠 High |
| 数据源污染 | 训练/微调数据被篡改 | 爬虫源、标注平台 | 🟡 Medium |

### 8.2 AI供应链安全技能

```python
class AISupplyChainSecurity:
    """AI供应链安全管理"""
    
    def __init__(self, sbom_path: str = None):
        self.sbom = self._load_sbom(sbom_path) if sbom_path else {}
        self.trusted_registry = self._load_trusted_registry()
    
    def verify_model_integrity(self, model_path: str, expected_hash: str) -> bool:
        """验证模型完整性（签名+哈希）"""
        import hashlib
        
        # 1. 计算SHA256
        sha256_hash = hashlib.sha256()
        with open(model_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        actual_hash = sha256_hash.hexdigest()
        
        # 2. 验证签名（基于Sigstore/Cosign）
        signature_valid = self._verify_signature(model_path)
        
        return actual_hash == expected_hash and signature_valid
    
    def audit_sbom(self, sbom: Dict) -> List[Dict]:
        """审计SBOM，查找已知漏洞"""
        vulnerabilities = []
        
        for component in sbom.get("components", []):
            name = component.get("name", "")
            version = component.get("version", "")
            
            # 1. 查CVE数据库
            cves = self._query_cve_database(name, version)
            
            # 2. 查来源可信度
            source = component.get("source", "")
            if source not in self.trusted_registry:
                cves.append({
                    "type": "untrusted_source",
                    "severity": "high",
                    "description": f"组件来源不在白名单: {source}"
                })
            
            # 3. 查版本新鲜度
            if self._is_outdated(component):
                cves.append({
                    "type": "outdated_version",
                    "severity": "medium",
                    "description": f"{name}@{version} 已超过安全支持期"
                })
            
            vulnerabilities.extend(cves)
        
        return vulnerabilities
    
    def generate_sbom(self, model_artifacts: List[str]) -> Dict:
        """生成AI模型SBOM（SPDX格式）"""
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"AI-Model-{datetime.utcnow().strftime('%Y%m%d')}",
            "creationInfo": {
                "creators": [f"Tool: AISupplyChainSecurity"],
                "created": datetime.utcnow().isoformat()
            },
            "components": []
        }
        
        for artifact in model_artifacts:
            sbom["components"].append({
                "SPDXID": f"SPDXRef-{len(sbom['components'])+1}",
                "name": artifact,
                "version": "1.0",
                "supplier": "unknown",
                "checksums": [{"algorithm": "SHA256", "value": "..."}]
            })
        
        return sbom
    
    def _query_cve_database(self, name: str, version: str) -> List[Dict]:
        """查询CVE数据库（模拟实现 — 实际集成NVD API/Grype/Trivy）"""
        # 实际应调用：NVD API、OSV.dev、Grype、Trivy
        return []
    
    def _load_trusted_registry(self) -> set:
        """加载可信来源寄存器"""
        return {
            "pytorch.org", "huggingface.co/verified", 
            "tensorflow.org", "github.com/verified",
            "pypi.org/trusted", "npmjs.com/trusted"
        }
```

### 8.3 AI SBOM（AI软件物料清单）

AI-SBOM是供应链安全的基础。与传统SBOM不同，AI-SBOM需额外覆盖：

| SBOM元素 | 描述 | 示例 |
|:---|:---|:---|
| 模型元数据 | 模型来源、作者、许可证 | `model: codellama-7b` `source: huggingface.co/meta` |
| 训练数据源 | 训练/微调数据集来源 | `dataset: code_alpaca_20k` `license: MIT` |
| 依赖框架 | PyTorch/TensorFlow等版本 | `torch: 2.1.0+cu121` |
| 权重哈希 | 模型权重的完整性校验 | `sha256: a1b2c3...` |
| 硬件依赖 | 运行所需硬件规格 | `gpu: NVIDIA A100` `min_vram: 16G` |
| 数据预处理pipeline | 特征工程、Token化步骤 | `tokenizer: codellama/CodeLlama-7b` |

### 8.4 AI供应链安全检查清单

```text
□ 所有模型来源已列入白名单
□ 模型权重下载后验证SHA256
□ 使用Sigstore/Cosign验证签名
□ 依赖库已使用 `pip audit` / `npm audit` 扫描
□ SBOM已生成并存储在安全位置
□ SBOM变更触发告警通知
□ 第三方API调用已做mTLS认证
□ 训练数据源已验证完整性
□ CI/CD流水线已做供应链安全加固
□ 供应商安全评估已完成（针对第三方模型厂商）
□ SLSA级别≥L3的构建流水线
```

### 8.5 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Syft | 生成SBOM | https://github.com/anchore/syft |
| Grype | 漏洞扫描SBOM | https://github.com/anchore/grype |
| Trivy | 全量漏洞扫描（含容器） | https://github.com/aquasecurity/trivy |
| Sigstore | 签名验证 | https://www.sigstore.dev/ |
| SLSA Framework | 供应链安全等级 | https://slsa.dev/ |
| Dependency-Track | SBOM管理平台 | https://dependencytrack.org/ |
| OWASP CycloneDX | SBOM标准格式 | https://cyclonedx.org/ |

---

## 九、漏洞管理阶段 (Vulnerability Management) ⭐【新增】

> **标准依据**: NIST SP 800-40 Rev 4 (Guide to Enterprise Patch Management), 
> NVD/CVE Framework, ISO 29147 (Vulnerability Disclosure), OWASP Top 10 for LLM

### 概述

AI系统的漏洞管理涵盖**AI组件自身漏洞**（框架漏洞、模型漏洞）和**AI引入的新漏洞类型**（提示注入、对抗攻击）。本阶段覆盖漏洞**查询→验证→评估→修复→复测→关闭**全生命周期。

### 9.1 漏洞查询 (Vulnerability Query)

```python
class AIVulnerabilityManager:
    """AI系统漏洞管理"""
    
    # 重点关注漏洞数据库
    VULN_DATABASES = {
        "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "osv": "https://api.osv.dev/v1/query",
        "github_advisory": "https://api.github.com/advisories",
        "pypi_advisory": "https://pypi.org/advisories/",
    }
    
    # AI框架重点关注
    AI_FRAMEWORKS = [
        "pytorch", "tensorflow", "transformers", "langchain",
        "llama_index", "vllm", "triton-inference-server",
        "mlflow", "kubeflow", "ray", "diffusers",
        "autogen", "crewai", "semantic-kernel"
    ]
    
    def query_cve_by_component(self, component: str, version: str) -> List[Dict]:
        """查询指定组件的CVE漏洞（多源聚合）"""
        vulnerabilities = []
        
        # 1. 查询NVD
        nvd_results = self._query_nvd(component, version)
        vulnerabilities.extend(nvd_results)
        
        # 2. 查询OSV.dev
        osv_results = self._query_osv(component, version)
        vulnerabilities.extend(osv_results)
        
        # 3. 查询GitHub Security Advisories
        gh_results = self._query_github_advisory(component, version)
        vulnerabilities.extend(gh_results)
        
        # 去重和排序
        return self._deduplicate_and_sort(vulnerabilities)
    
    def query_cve_by_keyword(self, keyword: str) -> List[Dict]:
        """按关键词搜索漏洞（主要用于AI特定漏洞类型）"""
        return self._search_vulnerabilities(f"AI {keyword}")
    
    def query_zero_day_signals(self, model_name: str) -> List[Dict]:
        """查询0-day攻击信号（威胁情报）"""
        # 集成：Twitter/Reddit/暗网监控
        signals = []
        sources = [
            "https://threatpost.com/feed",
            "https://thehackernews.com/",
            "https://www.securityweek.com/",
        ]
        # 实际应通过RSS/API获取
        for source in sources:
            signals.append({
                "source": source,
                "model": model_name,
                "detected_at": datetime.utcnow().isoformat(),
                "status": "pending_review"
            })
        return signals
    
    def _query_nvd(self, component: str, version: str) -> List[Dict]:
        """查询NVD数据库"""
        # 模拟实现 — 实际调用 NVD API
        # curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={component}+{version}"
        return [
            {
                "id": "CVE-2024-XXXX",
                "source": "NVD",
                "component": component,
                "version": version,
                "cvss_score": 7.5,
                "severity": "high",
                "description": f"{component} {version} 存在远程代码执行漏洞",
                "published": "2024-06-15",
                "fixed_in": f"{version.split('.')[0]}.{int(version.split('.')[1])+1}.0"
            }
        ]
```

### 9.2 漏洞验证 (Vulnerability Verification)

```python
    def verify_vulnerability(self, component: str, version: str, 
                             cve_id: str, poc: str = None) -> Dict:
        """验证漏洞是否可利用"""
        result = {
            "cve_id": cve_id,
            "component": component,
            "version": version,
            "verified": False,
            "severity": "unknown",
            "exploitable": False,
            "evidence": []
        }
        
        # Step 1: 版本匹配检查
        version_matched = self._check_version_affected(
            component, version, cve_id
        )
        result["evidence"].append({
            "type": "version_check",
            "passed": version_matched,
            "detail": f"版本 {version} 在受影响范围内: {version_matched}"
        })
        
        if not version_matched:
            result["verified"] = False
            result["reason"] = "版本不受影响"
            return result
        
        # Step 2: POC验证（如有）
        if poc:
            try:
                poc_result = self._run_poc(component, version, poc)
                result["exploitable"] = poc_result["exploitable"]
                result["evidence"].append({
                    "type": "poc_execution",
                    "passed": True,
                    "detail": poc_result["detail"]
                })
            except Exception as e:
                result["evidence"].append({
                    "type": "poc_execution",
                    "passed": False,
                    "detail": str(e)
                })
        
        # Step 3: 影响评估
        impact = self._assess_impact(component, cve_id)
        result["severity"] = impact.get("severity", "medium")
        result["verified"] = version_matched or result["exploitable"]
        
        return result
    
    def _check_version_affected(self, component: str, version: str, 
                                 cve_id: str) -> bool:
        """检查版本是否在受影响范围内"""
        # 模拟：实际应查询CPE匹配
        affected_versions = {
            "langchain": {"<=": "0.1.0", ">": "0.0.100"},
            "transformers": {">=": "4.30.0", "<": "4.36.0"},
        }
        return True  # 模拟通过
    
    def _assess_impact(self, component: str, cve_id: str) -> Dict:
        """评估漏洞对AI系统的影响"""
        return {
            "severity": "high",
            "impact": "可能被用于提权或数据泄露",
            "mitigation": "升级到最新版本",
            "workaround": "临时禁用受影响功能"
        }
```

### 9.3 漏洞评级 (CVSS for AI)

| CVSS向量 | 描述 | AI场景示例 |
|:---|:---|:---|
| CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | 远程未授权完整机密性+完整性+可用性影响 | 模型权重替换 |
| CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N | 本地高复杂度需交互低影响 | Prompt注入日志泄露 |
| CVSS:4.0/AI:N/... | AI特定扩展 | 训练数据泄露 |

**AI漏洞CVSS评分示例：**

```python
class AICVSSScorer:
    """AI漏洞CVSS评分器"""
    
    # 基于CVE-5.0 / CVSS 4.0框架
    CVSS_METRICS = {
        "attack_vector": {
            "network": 0.85, "adjacent": 0.62, 
            "local": 0.55, "physical": 0.20
        },
        "attack_complexity": {
            "low": 0.77, "high": 0.44
        },
        "privileges_required": {
            "none": 0.85, "low": 0.62, "high": 0.27
        },
        "user_interaction": {
            "none": 0.85, "required": 0.62
        },
        "scope": {
            "unchanged": 1.0, "changed": 1.22
        }
    }
    
    IMPACT_METRICS = {
        "confidentiality": {"none": 0, "low": 0.22, "high": 0.56},
        "integrity": {"none": 0, "low": 0.22, "high": 0.56},
        "availability": {"none": 0, "low": 0.22, "high": 0.56}
    }
    
    def calculate(self, vector: Dict) -> float:
        """计算CVSS评分"""
        # 简化的CVSS 3.1计算公式
        impact_sub = 1 - (
            (1 - self.IMPACT_METRICS["confidentiality"][vector["confidentiality"]]) *
            (1 - self.IMPACT_METRICS["integrity"][vector["integrity"]]) *
            (1 - self.IMPACT_METRICS["availability"][vector["availability"]])
        )
        
        if vector["scope"] == "unchanged":
            impact = 6.42 * impact_sub
        else:
            impact = 7.52 * (impact_sub - 0.029) - 3.25 * (impact_sub - 0.02) ** 15
        
        exploit = (
            self.CVSS_METRICS["attack_vector"][vector["av"]] * 
            self.CVSS_METRICS["attack_complexity"][vector["ac"]] *
            self.CVSS_METRICS["privileges_required"][vector["pr"]] *
            self.CVSS_METRICS["user_interaction"][vector["ui"]]
        )
        
        if impact <= 0:
            return 0.0
        
        if vector["scope"] == "unchanged":
            score = min(impact + exploit, 10.0) * 1.176
        else:
            score = min(1.08 * (impact + exploit), 10.0)
        
        return round(score, 1)
```

### 9.4 漏洞修复与验证 (Remediation & Validation)

```python
    def remediate_vulnerability(self, vuln: Dict) -> Dict:
        """执行漏洞修复"""
        remediation_plan = {
            "cve_id": vuln.get("cve_id"),
            "component": vuln.get("component"),
            "version": vuln.get("version"),
            "fixed_version": vuln.get("fixed_in"),
            "steps": [],
            "status": "in_progress",
            "assigned_to": None
        }
        
        # 根据漏洞类型制定修复步骤
        vuln_type = self._classify_remediation_type(vuln)
        
        if vuln_type == "upgrade":
            remediation_plan["steps"] = [
                {"order": 1, "action": "确认兼容性", "command": f"pip install {vuln['component']}=={vuln['fixed_in']} --dry-run"},
                {"order": 2, "action": "备份当前版本", "command": f"pip freeze | grep {vuln['component']} > backup_{vuln['component']}.txt"},
                {"order": 3, "action": "升级组件", "command": f"pip install --upgrade {vuln['component']}=={vuln['fixed_in']}"},
                {"order": 4, "action": "运行回归测试", "command": "pytest tests/ -v"},
                {"order": 5, "action": "验证漏洞已修复", "command": f"vuln-scan --check {vuln['cve_id']}"},
            ]
        elif vuln_type == "config_change":
            remediation_plan["steps"] = [
                {"order": 1, "action": "修改配置文件", "command": "..."},
                {"order": 2, "action": "重新加载服务", "command": "systemctl reload ai-inference"},
            ]
        elif vuln_type == "model_patch":
            remediation_plan["steps"] = [
                {"order": 1, "action": "下载安全模型权重", "command": "..."},
                {"order": 2, "action": "验证签名", "command": "cosign verify ..."},
                {"order": 3, "action": "切换模型版本", "command": "mlflow models serve --version fixed"},
            ]
        
        return remediation_plan
    
    def validate_remediation(self, cve_id: str, component: str) -> Dict:
        """验证修复有效性"""
        # 重新扫描验证
        scan_result = self.query_cve_by_component(component, "current")
        fixed = not any(cve["id"] == cve_id for cve in scan_result)
        
        # 运行POC验证（如有）
        poc_passed = not self._try_exploit(component, cve_id)
        
        return {
            "cve_id": cve_id,
            "fixed": fixed,
            "poc_verified": poc_passed,
            "verified_at": datetime.utcnow().isoformat(),
            "verified_by": "system",
            "status": "closed" if (fixed and poc_passed) else "requires_review"
        }
```

### 9.5 AI漏洞管理生命周期

```text
┌───────────────────────────────────────────────────────────┐
│             AI漏洞管理全生命周期流程                         │
├───────────────────────────────────────────────────────────┤
│                                                            │
│  ① 发现 ──→ ② 分类 ──→ ③ 验证 ──→ ④ 评估 ──→ ⑤ 修复 ──→ ⑥ 复测 │
│                                                            │
│  发现途径:       分类标准:     验证方式:    评估维度:                │
│  ┌─────────┐   ┌─────────┐  ┌────────┐  ┌────────┐              │
│  │自动扫描  │   │   CVSS   │  │POC验证  │  │影响范围  │              │
│  │威胁情报  │   │  EPSS    │  │版本比对  │  │利用难度  │              │
│  │红队测试  │   │  KEV     │  │环境复现  │  │防护绕过  │              │
│  │社区通报  │   │  Triage  │  │差异分析  │  │业务影响  │              │
│  └─────────┘   └─────────┘  └────────┘  └────────┘              │
│                                                            │
└───────────────────────────────────────────────────────────┘
```

### 9.6 AI组件漏洞优先级矩阵

| 漏洞组件 | CVSS范围 | EPSS概率 | KEV收录 | 优先级 | SLA |
|:---|:---:|:---:|:---:|:---:|:---:|
| LangChain | 9.0+ | >0.9 | ✅ | **P0-Critical** | 24h |
| PyTorch | 7.0-8.9 | >0.5 | ❌ | **P1-High** | 7d |
| Transformers | 4.0-6.9 | >0.1 | ❌ | **P2-Medium** | 14d |
| MLflow | 0.1-3.9 | <0.1 | ❌ | **P3-Low** | 30d |
| 自定义Agent | — | — | — | **自定义** | 按业务 |

### 9.7 漏洞管理工具集成

```python
class VulnToolIntegration:
    """漏洞扫描工具集成层"""
    
    TOOLS = {
        "trivy": {
            "install": "brew install trivy / choco install trivy",
            "scan": "trivy image --severity CRITICAL,HIGH {image}",
            "scan_fs": "trivy fs --severity CRITICAL,HIGH {path}",
        },
        "grype": {
            "install": "brew install grype / choco install grype",
            "scan": "grype {image} --only-fixed",
            "sbom": "grype sbom:{sbom_path}",
        },
        "safety": {
            "install": "pip install safety",
            "scan": "safety check --full-report",
        },
        "pip_audit": {
            "install": "pip install pip-audit",
            "scan": "pip-audit --desc",
        }
    }
    
    def run_scan(self, tool: str, target: str, args: str = "") -> Dict:
        """运行漏洞扫描"""
        if tool not in self.TOOLS:
            return {"error": f"不支持的扫描工具: {tool}"}
        
        scan_cmd = self.TOOLS[tool]["scan"].format(image=target, path=target)
        if args:
            scan_cmd += f" {args}"
        
        # 实际调用 subprocess.run(scan_cmd, shell=True, capture_output=True)
        print(f"🔍 执行扫描: {scan_cmd}")
        
        return {
            "tool": tool,
            "target": target,
            "command": scan_cmd,
            "status": "scanning",
            "scan_id": f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        }
    
    def aggregate_results(self, scan_ids: List[str]) -> Dict:
        """聚合多工具扫描结果"""
        return {
            "total_vulnerabilities": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_component": {},
            "recommendations": []
        }
```

### 9.8 漏洞管理常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| NVD (National Vulnerability Database) | 官方CVE数据源 | https://nvd.nist.gov/ |
| OSV.dev | 开源漏洞数据库 | https://osv.dev/ |
| Trivy | 全量漏洞扫描器 | https://github.com/aquasecurity/trivy |
| Grype | SBOM漏洞扫描 | https://github.com/anchore/grype |
| Snyk | 开发者漏洞管理平台 | https://snyk.io/ |
| EPSS (Exploit Prediction) | 利用可能性评分 | https://www.first.org/epss |
| CVE Program | 通用漏洞披露 | https://www.cve.org/ |
| Microsoft Security Response Center | AI安全公告 | https://msrc.microsoft.com/ |
| Google AI Red Team | Google AI安全研究 | https://github.com/google/ai-red-team |
| Huntr | AI/ML漏洞悬赏平台 | https://huntr.com/ |

---

## 十、自动化与SOAR阶段 (Automation & SOAR)

> **标准依据**: NIST SP 800-160, SOAR最佳实践

### 10.1 AI安全SOAR自动化响应

```python
class AISecuritySOAR:
    """AI安全SOAR自动化响应（增强版）"""
    
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
        elif "supply_chain_anomaly" in alert_types:
            return "supply_chain"
        elif "toxic_output" in alert_types:
            return "toxic_output"
        else:
            return "default"
    
    def _execute_step(self, step: Dict, incident: Dict) -> Dict:
        """执行自动化剧本步骤"""
        # 实际调用API或执行脚本
        return {"success": True, "output": f"执行完成: {step['name']}"}
```

### 10.2 预定义响应剧本

```yaml
# playbooks/ai_incident_playbooks.yaml
playbooks:
  prompt_injection:
    name: "提示注入响应剧本"
    trigger: "prompt_injection 告警"
    steps:
      - name: "阻断攻击者IP"
        action: "waf_block_ip"
        critical: true
      - name: "吊销API Key"
        action: "revoke_api_key"
        critical: true
      - name: "采集攻击样本"
        action: "capture_payload"
      - name: "更新安全过滤器"
        action: "update_filter_rules"
      - name: "通知安全团队"
        action: "notify_slack"

  data_leak:
    name: "数据泄露响应剧本"
    trigger: "data_leakage 告警"
    steps:
      - name: "暂停推理服务"
        action: "pause_inference"
        critical: true
      - name: "启用输出脱敏"
        action: "enable_redaction"
      - name: "触发数据泄露通知"
        action: "breach_notification"
      - name: "启动取证"
        action: "start_forensics"

  supply_chain:
    name: "供应链攻击响应剧本"
    trigger: "supply_chain_anomaly 告警"
    steps:
      - name: "隔离模型来源"
        action: "quarantine_source"
        critical: true
      - name: "验证模型签名"
        action: "verify_sigstore"
      - name: "回滚依赖版本"
        action: "rollback_dependency"
      - name: "重新生成SBOM"
        action: "regenerate_sbom"
      - name: "通知供应链负责人"
        action: "notify_supply_chain_owner"
```

---

## 附录

### A. 标准映射表

| 标准 | 对应阶段 | 主要内容 |
|:---|:---|:---|
| NIST SP 800-61 Rev 2 | 准备→检测→遏制→取证→清除→恢复→复盘 | IR全流程框架 |
| ISO 27035-1/2 | 准备→检测→评估→响应→复盘 | 事件管理标准 |
| MITRE ATLAS™ | 所有阶段 | AI攻击矩阵映射 |
| NIST SP 800-161 | 供应链安全 | C-SCRM框架 |
| NIST SP 800-40 Rev 4 | 漏洞管理 | 补丁管理指南 |
| OWASP LLM Top 10 | 检测→评估 | LLM漏洞分类 |
| ISO 29147 | 漏洞管理 | 漏洞披露流程 |
| SLSA Framework | 供应链安全 | 构建完整性等级 |

### B. 常用工具

| 工具 | 用途 | 阶段 | 链接 |
|:---|:---|:---|:---|
| AI IR Framework | AI事件响应框架 | 全阶段 | https://github.com/AIIncidentResponse/ |
| MITRE ATLAS Navigator | 攻击矩阵导航 | 检测/评估 | https://atlas.mitre.org/ |
| ELK Stack | 日志分析 | 检测/取证 | https://www.elastic.co/ |
| Splunk | SIEM+AI事件关联 | 检测 | https://www.splunk.com/ |
| TheHive | 事件管理平台 | 全阶段 | https://thehive-project.org/ |
| DFIR Tools | 数字取证工具集 | 取证 | https://github.com/dfir-orchestra/ |
| Trivy | 漏洞扫描 | 漏洞管理 | https://github.com/aquasecurity/trivy |
| Syft | SBOM生成 | 供应链安全 | https://github.com/anchore/syft |
| Grype | 漏洞匹配 | 漏洞管理 | https://github.com/anchore/grype |
| Sigstore | 签名验证 | 供应链安全 | https://www.sigstore.dev/ |
| Dependency-Track | SBOM管理 | 供应链安全 | https://dependencytrack.org/ |
| Snyk | 漏洞管理平台 | 漏洞管理 | https://snyk.io/ |
| Guardrails AI | AI输出安全 | 检测 | https://www.guardrailsai.com/ |
| LangSmith | Agent行为监控 | 检测/取证 | https://smith.langchain.com/ |
| Arize AI | AI可观测性 | 检测/监控 | https://arize.com/ |

### C. 参考资源

- [NIST SP 800-61 Rev 2 — Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [MITRE ATLAS — Incident Response](https://atlas.mitre.org/)
- [FIRST AI Incident Response SIG](https://www.first.org/global/sigs/ai/)
- [OWASP LLM Incident Response Guide](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [ENISA — AI Cybersecurity Report](https://www.enisa.europa.eu/publications/artificial-intelligence-cybersecurity-challenges)
- [NIST SP 800-161 — Cyber Supply Chain Risk Management](https://csrc.nist.gov/publications/detail/sp/800-161/rev-1/final)
- [NIST SP 800-40 Rev 4 — Guide to Enterprise Patch Management](https://csrc.nist.gov/publications/detail/sp/800-40/rev-4/final)
- [ISO 27035 — Incident Management](https://www.iso.org/standard/78973.html)
- [FIRST CVSS v4.0 Specification](https://www.first.org/cvss/v4-0/)
- [SLSA Framework — Supply Chain Levels for Software Artifacts](https://slsa.dev/)
- [OWASP CycloneDX SBOM Standard](https://cyclonedx.org/)
- [CVE Program](https://www.cve.org/)
- [NVD — National Vulnerability Database](https://nvd.nist.gov/)
- [OSV.dev — Open Source Vulnerabilities](https://osv.dev/)