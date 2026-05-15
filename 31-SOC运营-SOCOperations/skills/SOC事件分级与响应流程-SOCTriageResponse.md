---
id: "31-002"
title: "SOC事件分级与响应流程 (SOC Triage & Response)"
category: "SOC运营"
category_en: "SOC Operations"
difficulty: "★★★"
tools: "TheHive, ServiceNow, Jira, Splunk, IR Framework"
last_updated: "2026-05"
tags: [soc, incident-response, triage, severity-classification, playbook]
subdomain: soc-operations
nist_csf: [RS.AN-01, RS.AN-04, RS.AN-05, RS.MI-03]
mitre_attack: [T1580, T1585, T1586, T1590]
---

# SOC事件分级与响应流程 (SOC Triage & Response)

## 概述

安全运营中心（SOC）的核心职能是对安全事件进行高效的分级、分类和响应。本技能覆盖 SOC 事件处理流程，包括告警分类分级、三级处置流程、响应手册（Playbook）以及事件上报和复盘机制。

## 核心技能

### 1. 事件分类与分级

```python
"""安全事件分类分级模型"""

from enum import Enum

class IncidentCategory(str, Enum):
    """事件分类"""
    MALWARE = "malware"
    PHISHING = "phishing"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFIL = "data_exfiltration"
    RANSOMWARE = "ransomware"
    DOS = "denial_of_service"
    WEB_ATTACK = "web_application_attack"
    POLICY_VIOLATION = "policy_violation"
    INSIDER_THREAT = "insider_threat"

class IncidentSeverity:
    """事件严重级别"""

    LEVELS = {
        1: {
            "name": "L1 — 通知级",
            "color": "green",
            "response_time": 240,  # 4小时
            "description": "低风险，无需立即处理",
            "examples": ["单个端口扫描", "低危告警", "合规违例"]
        },
        2: {
            "name": "L2 — 警告级",
            "color": "yellow",
            "response_time": 120,  # 2小时
            "description": "中等风险，需分析确认",
            "examples": ["暴力破解尝试", "钓鱼邮件报告", "可疑进程"]
        },
        3: {
            "name": "L3 — 严重级",
            "color": "orange",
            "response_time": 60,  # 1小时
            "description": "高风险，可能影响业务",
            "examples": ["恶意软件感染", "账号失陷", "Web 入侵"]
        },
        4: {
            "name": "L4 — 紧急级",
            "color": "red",
            "response_time": 15,  # 15分钟
            "description": "极高风险，立即响应",
            "examples": ["勒索软件", "数据外传", "大规模失陷", "APT"]
        }
    }
    
    @staticmethod
    def classify(alert):
        """基于告警特征自动分级"""
        score = 0
        
        # 受影响资产重要性
        asset_criticality = alert.get("asset_criticality", 0)
        score += asset_criticality * 2
        
        # 告警类型权重
        type_weights = {
            "ransomware": 10,
            "data_exfil": 9,
            "c2_beacon": 8,
            "lateral_movement": 7,
            "credential_theft": 6,
            "malware": 5,
            "phishing": 3,
            "scanning": 1
        }
        score += type_weights.get(alert.get("alert_type", ""), 0)
        
        # IOCs 匹配度
        score += alert.get("intel_match_count", 0) * 2
        
        # 用户行为异常
        score += alert.get("user_anomaly_score", 0) * 0.5
        
        # 映射到级别
        if score >= 15:
            return 4
        elif score >= 10:
            return 3
        elif score >= 5:
            return 2
        return 1

# 使用示例
alert = {
    "alert_type": "ransomware",
    "asset_criticality": 5,
    "intel_match_count": 3,
    "user_anomaly_score": 8
}
level = IncidentSeverity.classify(alert)
print(f"Severity: L{level} — {IncidentSeverity.LEVELS[level]['name']}")
```

### 2. 三级响应流程

```python
"""SOC 三级响应处理流程"""

import json
from datetime import datetime
from enum import Enum

class EscalationLevel(Enum):
    """SOC 响应层级"""
    L1_ANALYST = "SOC Tier 1 — 初级分析师"
    L2_ANALYST = "SOC Tier 2 — 中级分析师"
    L3_ENGINEER = "SOC Tier 3 — 高级安全工程师"

class IncidentHandler:
    """安全事件处理器"""
    
    def __init__(self):
        self.current_tier = EscalationLevel.L1_ANALYST
        self.incident = {}
    
    def receive_alert(self, alert):
        """接收并创建事件"""
        self.incident = {
            "id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "alert": alert,
            "created": datetime.now().isoformat(),
            "status": "open",
            "current_tier": self.current_tier,
            "actions": [],
            "notes": []
        }
        return self.incident["id"]
    
    def l1_triage(self, analyst="L1-Analyst"):
        """L1 初级分析师 — 告警验证"""
        if self.current_tier != EscalationLevel.L1_ANALYST:
            return
        
        alert = self.incident["alert"]
        result = {
            "analyst": analyst,
            "phase": "triage",
            "time": datetime.now().isoformat(),
            "findings": [],
            "verdict": None
        }
        
        # 判断是否为误报
        result["verdict"] = self._verify_alert(alert)
        
        if result["verdict"] == "false_positive":
            self.incident["status"] = "closed"
            self.incident["close_reason"] = "误报"
        elif result["verdict"] == "needs_escalation":
            self.incident["current_tier"] = EscalationLevel.L2_ANALYST
            result["recommendation"] = "需要进一步分析"
        
        self.incident["actions"].append(result)
        return result
    
    def l2_analysis(self, analyst="L2-Analyst"):
        """L2 中级分析师 — 深入分析"""
        if self.current_tier != EscalationLevel.L2_ANALYST:
            return
        
        result = {
            "analyst": analyst,
            "phase": "analysis",
            "time": datetime.now().isoformat(),
            "findings": [],
            "affected_assets": [],
            "indicators": []
        }
        
        # 执行深入分析
        alert = self.incident["alert"]
        severity = IncidentSeverity.classify(alert)
        
        if severity >= 3:
            result["severity_level"] = severity
            result["needs_immediate_response"] = True
            self.incident["current_tier"] = EscalationLevel.L3_ENGINEER
        else:
            result["severity_level"] = severity
            result["containment_steps"] = self._generate_containment(alert)
        
        self.incident["actions"].append(result)
        return result
    
    def l3_response(self, engineer="L3-Engineer"):
        """L3 高级工程师 — 应急处置"""
        if self.current_tier != EscalationLevel.L3_ENGINEER:
            return
        
        result = {
            "engineer": engineer,
            "phase": "response",
            "time": datetime.now().isoformat(),
            "containment": [],
            "eradication": [],
            "recovery": []
        }
        
        alert = self.incident["alert"]
        alert_type = alert.get("alert_type", "")
        
        # 根据事件类型执行响应
        if alert_type == "ransomware":
            result["containment"].append("隔离受影响主机")
            result["containment"].append("禁用失陷账号")
            result["eradication"].append("阻断 C2 通信")
            result["recovery"].append("从备份恢复数据")
        elif alert_type == "data_exfil":
            result["containment"].append("阻断出站连接")
            result["eradication"].append("清理后门")
        
        self.incident["actions"].append(result)
        self.incident["status"] = "contained"
        return result
    
    def _verify_alert(self, alert):
        """验证告警真伪"""
        if alert.get("source") == "honeypot":
            return "false_positive"
        if alert.get("intel_match_count", 0) > 0:
            return "confirmed"
        return "needs_escalation"
    
    def _generate_containment(self, alert):
        """生成遏制步骤"""
        return [
            f"Isolate: {alert.get('host', 'affected_host')}",
            "Collect memory dump",
            "Preserve logs"
        ]

# 处理流程示例
handler = IncidentHandler()
handler.receive_alert({
    "alert_type": "ransomware",
    "host": "SRV-APP-01",
    "user": "jdoe",
    "intel_match_count": 2
})
handler.l1_triage("Alice")
handler.l2_analysis("Bob")
handler.l3_response("Charlie")
print(json.dumps(handler.incident, indent=2))
```

### 3. 响应手册 (Playbook)

```python
"""SOC 事件响应手册"""

class IncidentPlaybook:
    """通用事件响应手册"""
    
    @staticmethod
    def ransomware_response():
        """勒索软件响应手册"""
        return {
            "id": "IR-001",
            "name": "勒索软件应急响应",
            "version": "2.0",
            "severity": "L4 紧急级",
            "estimated_time": "2-4 小时",
            
            "steps": {
                "A. 隔离遏制 (0-30min)": [
                    "1. 网络隔离: 断开受影响主机网络连接",
                    "2. 账号禁用: 立即禁用受影响用户账号",
                    "3. 端口阻断: 在防火墙上阻断失陷IP",
                    "4. 域隔离: 若域控受影响，断开域网络"
                ],
                "B. 证据收集 (30-60min)": [
                    "1. 内存镜像: 获取受影响系统内存转储",
                    "2. 日志保存: 保存Windows事件日志、防火墙日志",
                    "3. 样本提取: 提取勒索软件样本（加密隔离）",
                    "4. 截图留存: 对勒索信息、加密文件截图"
                ],
                "C. 分析溯源 (60-120min)": [
                    "1. 入口点分析: 确定初始入侵途径",
                    "2. 横向移动分析: 检查其它受影响系统",
                    "3. IOC 提取: 提取 C2 IP、域名、哈希",
                    "4. 时间线重建: 还原攻击链时间线"
                ],
                "D. 清除恢复 (120-240min)": [
                    "1. 清除恶意软件",
                    "2. 恢复系统至干净快照/备份",
                    "3. 修改所有受影响系统密码",
                    "4. 恢复服务并监控异常"
                ],
                "E. 事后复盘": [
                    "1. 编写事件报告",
                    "2. 根因分析会议",
                    "3. 改进检测规则",
                    "4. 更新响应手册"
                ]
            },
            "checklist": [
                "已隔离受影响系统",
                "已备份加密文件（待解密）",
                "已提取 IOC 到威胁情报平台",
                "已通知管理层和相关方",
                "已报警（如涉及数据泄露）"
            ]
        }
    
    @staticmethod
    def phishing_response():
        """钓鱼邮件响应手册"""
        return {
            "id": "IR-002",
            "name": "钓鱼邮件处置",
            "version": "1.5",
            "severity": "L2 警告级",
            "steps": {
                "A. 快速响应 (0-15min)": [
                    "1. 用户确认: 确认用户是否点击链接/打开附件",
                    "2. 邮件移除: 从所有用户邮箱删除该邮件",
                    "3. 密码重置: 如用户已输入凭据，强制重置密码"
                ],
                "B. 分析 (15-60min)": [
                    "1. 邮件头分析: 检查 SPF/DKIM/DMARC",
                    "2. URL 分析: 提取并分析恶意链接",
                    "3. 附件分析: 沙箱运行附件",
                    "4. IOC 提取: 域名、IP、哈希值"
                ],
                "C. 预防": [
                    "1. 检查邮件网关规则是否需要更新",
                    "2. 向全员发送安全提醒",
                    "3. 更新 URL 过滤规则"
                ]
            }
        }

# 使用示例
playbook = IncidentPlaybook.ransomware_response()
for phase, steps in playbook["steps"].items():
    print(f"\n{phase}")
    for step in steps:
        print(f"  {step}")
```

### 4. 事件上报与复盘

```python
"""安全事件报告模板"""

class IncidentReporter:
    """事件报告生成"""
    
    def __init__(self, incident_data):
        self.data = incident_data
    
    def executive_summary(self):
        """管理层摘要"""
        summary = f"""
        ================================================
        安全事件报告
        ================================================
        事件编号: {self.data.get('id', 'N/A')}
        事件类型: {self.data.get('alert_type', 'N/A')}
        严重级别: {self.data.get('severity', 'L3')}
        发现时间: {self.data.get('detected_at', 'N/A')}
        处置状态: {self.data.get('status', '处理中')}
        
        关键影响:
        - 受影响系统: {self.data.get('affected_systems', 0)}
        - 受影响用户: {self.data.get('affected_users', 0)}
        - 数据类型: {self.data.get('data_type', 'N/A')}
        
        响应行动:
        - 隔离系统: {self.data.get('systems_isolated', 0)}
        - 阻断 IP: {self.data.get('ips_blocked', [])}
        - 恢复时间: {self.data.get('recovery_time', '进行中')}
        """
        return summary
    
    def detailed_report(self):
        """详细技术报告"""
        report = {
            "meta": {
                "incident_id": self.data.get("id"),
                "report_date": datetime.now().isoformat(),
                "classification": "TLP:AMBER",
                "handler": self.data.get("handler")
            },
            "timeline": self.data.get("timeline", []),
            "root_cause": self.data.get("root_cause", {}),
            "iocs": self.data.get("iocs", []),
            "affected_assets": self.data.get("assets", []),
            "containment_steps": self.data.get("containment", []),
            "lessons_learned": self.data.get("lessons", [])
        }
        return report
    
    def lessons_learned(self):
        """事后复盘"""
        return {
            "what_went_well": [
                "检测规则在第1时间触发告警",
                "L1分析师正确分级",
                "应急响应手册执行到位"
            ],
            "what_could_improve": [
                "端点隔离时间需要缩短",
                "事件日志保留时间不足90天",
                "威胁情报同步延迟"
            ],
            "action_items": [
                {"item": "优化端点自动隔离流程", "owner": "SOC Lead", "deadline": "2周"},
                {"item": "增加日志存储容量", "owner": "IT Infra", "deadline": "1个月"},
                {"item": "配置实时威胁情报同步", "owner": "Threat Intel", "deadline": "1周"}
            ]
        }

# 使用示例
reporter = IncidentReporter({
    "id": "INC-2026-05-001",
    "alert_type": "ransomware",
    "severity": "L4",
    "handler": "SOC Team",
    "detected_at": "2026-05-10T14:30:00",
    "status": "resolved",
    "affected_systems": 3,
    "affected_users": 15,
    "systems_isolated": 3,
    "ips_blocked": ["185.220.101.50"]
})
print(reporter.executive_summary())
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| TheHive | 事件响应平台 | https://thehive-project.org/ |
| ServiceNow | IT 服务管理与事件跟踪 | https://www.servicenow.com/ |
| Jira | 事件跟踪与工作流 | https://www.atlassian.com/software/jira |
| Splunk SOAR | 安全编排与响应 | https://www.splunk.com/en_us/products/splunk-security-orchestration-and-automation.html |
| Shuffle | 开源 SOAR | https://shuffler.io/ |

## 参考资源

- [NIST SP 800-61 — Incident Response Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS Incident Response Framework](https://www.sans.org/white-papers/incident-response/)
- [SOC Triage Best Practices — FIRST](https://www.first.org/resources/guides)
- [PICERL Incident Response Model](https://www.cynet.com/incident-response/picerl/)
- [MITRE ATT&CK — Incident Response](https://attack.mitre.org/resources/incident-response/)
