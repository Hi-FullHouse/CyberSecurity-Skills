---
id: "39-002"
title: "风险管理与安全度量 (Risk Management & Security Metrics)"
category: "安全治理与合规"
category_en: "Governance & Compliance"
difficulty: "★★★★"
tools: "FAIR, RiskLens, Archer, Jira, Grafana"
last_updated: "2026-05"
tags: [risk-management, security-metrics, fair, risk-assessment, board-reporting]
subdomain: governance-compliance
nist_csf: [ID.RA-01, ID.RA-02, ID.RA-03, ID.RM-01, ID.SC-01]
mitre_attack: []
---

# 风险管理与安全度量 (Risk Management & Security Metrics)

## 概述

网络安全风险管理是企业安全决策的基础。通过量化风险、测量安全运营效能、向管理层报告风险态势，安全团队可以从"成本中心"转变为"业务赋能者"。本技能覆盖风险评估方法论（FAIR 定量分析）、安全 KPI/KRI、管理层报告和风险处置决策。

## 核心技能

### 1. 风险评估方法论

```python
"""风险评估引擎"""

from enum import Enum
from dataclasses import dataclass
from typing import List, Optional


class RiskLevel(Enum):
    VERY_LOW = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class Asset:
    id: str
    name: str
    type: str  # data, system, infrastructure
    classification: str  # public, internal, confidential, restricted
    owner: str
    replacement_cost: float  # 资产重置成本


@dataclass
class Threat:
    id: str
    name: str
    source: str  # internal, external, partner
    capability: RiskLevel  # 攻击能力
    motivation: RiskLevel  # 攻击动机


class RiskAssessment:
    """风险评估引擎"""
    
    def __init__(self):
        self.risks = []
    
    def qualitative_assessment(self, likelihood: RiskLevel, impact: RiskLevel):
        """定性风险评估 (矩阵法)"""
        # 5x5 风险矩阵
        matrix = {
            (1, 1): 1, (1, 2): 1, (1, 3): 2, (1, 4): 2, (1, 5): 3,
            (2, 1): 1, (2, 2): 2, (2, 3): 2, (2, 4): 3, (2, 5): 4,
            (3, 1): 2, (3, 2): 2, (3, 3): 3, (3, 4): 4, (3, 5): 4,
            (4, 1): 2, (4, 2): 3, (4, 3): 4, (4, 4): 4, (4, 5): 5,
            (5, 1): 3, (5, 2): 4, (5, 3): 4, (5, 4): 5, (5, 5): 5,
        }
        
        risk_score = matrix.get((likelihood.value, impact.value), 3)
        risk_level = RiskLevel(risk_score)
        
        return {
            "method": "qualitative",
            "likelihood": likelihood.name,
            "impact": impact.name,
            "risk_score": risk_score,
            "risk_level": risk_level.name,
            "recommended_action": self._action_for_level(risk_level)
        }
    
    def quantitative_assessment(self, asset_value, exposure_factor, 
                                 annual_rate_of_occurrence):
        """定量风险评估 (ALE法)"""
        # SLE = AV × EF
        single_loss_expectancy = asset_value * exposure_factor
        
        # ALE = SLE × ARO
        annualized_loss_expectancy = single_loss_expectancy * annual_rate_of_occurrence
        
        return {
            "method": "quantitative (ALE)",
            "asset_value": asset_value,
            "exposure_factor": exposure_factor,
            "single_loss_expectancy (SLE)": single_loss_expectancy,
            "annual_rate_of_occurrence (ARO)": annual_rate_of_occurrence,
            "annualized_loss_expectancy (ALE)": annualized_loss_expectancy
        }
    
    def fair_analysis(self, threat_event_frequency, vulnerability,
                       loss_magnitude, control_strength):
        """FAIR 定量风险分析"""
        # FAIR 模型简化: 风险 = f(TEF, Vuln, LossMag, Controls)
        
        # 调整威胁频率 (考虑控制强度)
        adjusted_tef = max(0.1, threat_event_frequency * (1 - control_strength))
        
        # 损失概率
        loss_event_probability = min(1.0, adjusted_tef * vulnerability)
        
        # 年预期损失 (FAIR)
        annual_loss = loss_event_probability * loss_magnitude
        
        # 控制有效性等级
        control_effectiveness = control_strength * 100
        
        return {
            "method": "FAIR",
            "threat_event_frequency": threat_event_frequency,
            "vulnerability": vulnerability,
            "loss_magnitude": loss_magnitude,
            "control_strength": control_strength,
            "adjusted_threat_frequency": round(adjusted_tef, 2),
            "loss_event_probability": round(loss_event_probability, 3),
            "annual_loss_expectancy": round(annual_loss, 2),
            "control_effectiveness": round(control_effectiveness, 1)
        }
    
    @staticmethod
    def _action_for_level(level: RiskLevel) -> str:
        actions = {
            RiskLevel.VERY_LOW: "接受 — 定期监控",
            RiskLevel.LOW: "监控 — 可考虑优化",
            RiskLevel.MEDIUM: "缓解 — 制定改进计划",
            RiskLevel.HIGH: "需立即缓解 — 30天内整改",
            RiskLevel.CRITICAL: "立即处理 — 7天内必须完成整改"
        }
        return actions.get(level, "评估")


# 使用示例
ra = RiskAssessment()
# 定性分析
qual = ra.qualitative_assessment(RiskLevel.HIGH, RiskLevel.CRITICAL)
print(f"Qualitative risk: {qual['risk_level']} — {qual['recommended_action']}")

# 定量分析 (ALE)
quant = ra.quantitative_assessment(
    asset_value=5000000,     # 资产价值 500万
    exposure_factor=0.3,      # 暴露系数 30%
    annual_rate_of_occurrence=0.5  # 年发生率 0.5
)
print(f"Annualized Loss Expectancy: ${quant['annualized_loss_expectancy']:,.0f}")

# FAIR 分析
fair = ra.fair_analysis(
    threat_event_frequency=4,  # 每年4次
    vulnerability=0.25,        # 脆弱性 0.25
    loss_magnitude=1000000,    # 损失 100万
    control_strength=0.6       # 控制强度 0.6
)
print(f"FAIR Annual Loss: ${fair['annual_loss_expectancy']:,.2f}")
```

### 2. 安全 KPI 与 KRI

```python
"""安全度量仪表盘"""

from datetime import datetime, timedelta
from math import sqrt


class SecurityMetricsDashboard:
    """安全运营度量"""
    
    def __init__(self):
        self.metrics = {}
    
    def define_metric(self, name, category, unit, target, warning_threshold):
        """定义安全指标"""
        self.metrics[name] = {
            "category": category,
            "unit": unit,
            "target": target,
            "warning": warning_threshold,
            "history": []
        }
    
    def record_value(self, metric_name, value, period):
        """记录指标值"""
        if metric_name in self.metrics:
            self.metrics[metric_name]["history"].append({
                "timestamp": datetime.now().isoformat(),
                "value": value,
                "period": period
            })
    
    def default_metrics(self):
        """加载默认安全指标"""
        defaults = [
            # 检测类指标
            ("MTTD (平均检测时间)", "检测", "minutes", 30, 60),
            ("MTTR (平均响应时间)", "响应", "minutes", 60, 120),
            ("告警量 (每日)", "检测", "count", 100, 200),
            ("误报率", "检测", "percent", 5, 10),
            
            # 预防类指标
            ("补丁覆盖率", "预防", "percent", 95, 90),
            ("EDR 覆盖率", "预防", "percent", 98, 95),
            ("MFA 覆盖率", "预防", "percent", 95, 90),
            ("漏洞修复时间 (高危)", "预防", "days", 7, 14),
            
            # 响应类指标
            ("SLA 合规率 (P1)", "响应", "percent", 99, 95),
            ("事件升级率", "响应", "percent", 15, 25),
            ("重复告警率", "响应", "percent", 10, 20),
            ("狩猎发现率", "响应", "percent", 5, 3),
            
            # 风险类指标
            ("开放高危漏洞", "风险", "count", 0, 5),
            ("未授权资产", "风险", "count", 0, 3),
            ("不合规设备", "风险", "count", 0, 10),
            ("高风险第三方", "风险", "count", 0, 2),
        ]
        
        for name, category, unit, target, warning in defaults:
            self.define_metric(name, category, unit, target, warning)
    
    def health_score(self):
        """计算安全健康分数"""
        scores = {}
        
        for name, metric in self.metrics.items():
            if not metric["history"]:
                continue
            
            latest = metric["history"][-1]["value"]
            target = metric["target"]
            warning = metric["warning"]
            
            if metric["unit"] == "percent":
                # 百分比越高越好
                ratio = latest / target if target > 0 else 0
                score = min(100, ratio * 100) if "响应" not in metric["category"] else min(100, target / latest * 100 if latest > 0 else 0)
            elif metric["unit"] in ("count", "days"):
                # 值越低越好
                score = max(0, 100 - (latest / max(target, 1)) * 20)
            else:
                score = 50  # 默认
            
            category = metric["category"]
            if category not in scores:
                scores[category] = []
            scores[category].append(min(100, score))
        
        # 计算类别平均分
        category_scores = {}
        for cat, vals in scores.items():
            category_scores[cat] = round(sum(vals) / len(vals), 1)
        
        overall = round(sum(category_scores.values()) / len(category_scores), 1) if category_scores else 0
        
        return {
            "overall_health": overall,
            "category_scores": category_scores,
            "verdict": "Healthy" if overall >= 80 else "Fair" if overall >= 60 else "Poor"
        }


# 使用示例
dashboard = SecurityMetricsDashboard()
dashboard.default_metrics()
dashboard.record_value("MTTD (平均检测时间)", 25, "2026-W19")
dashboard.record_value("补丁覆盖率", 96, "2026-W19")
dashboard.record_value("MFA 覆盖率", 92, "2026-W19")
health = dashboard.health_score()
print(f"Security Health: {health['overall_health']}/100 — {health['verdict']}")
for cat, score in health['category_scores'].items():
    print(f"  {cat}: {score}")
```

### 3. 风险处置与决策

```python
"""风险处置引擎"""

class RiskTreatmentEngine:
    """风险处置决策"""
    
    TREATMENT_OPTIONS = {
        "avoid": "规避 — 终止导致风险的业务活动",
        "mitigate": "缓解 — 实施控制降低风险",
        "transfer": "转移 — 购买保险或外包",
        "accept": "接受 — 明确承认并监控风险"
    }
    
    def __init__(self):
        self.risk_register = []
    
    def add_risk(self, name, likelihood, impact, control_effectiveness):
        """添加风险项"""
        risk = {
            "id": f"RISK-{len(self.risk_register) + 1:04d}",
            "name": name,
            "inherent_likelihood": likelihood,
            "inherent_impact": impact,
            "inherent_score": likelihood * impact,
            "control_effectiveness": control_effectiveness,
            "residual_likelihood": max(1, round(likelihood * (1 - control_effectiveness))),
            "residual_impact": max(1, round(impact * (1 - control_effectiveness))),
            "residual_score": max(1, round(likelihood * impact * (1 - control_effectiveness))),
            "status": "identified"
        }
        
        # 推荐处置方案
        if risk["residual_score"] >= 20:
            risk["recommended_treatment"] = "avoid"
        elif risk["residual_score"] >= 12:
            risk["recommended_treatment"] = "mitigate"
        elif risk["residual_score"] >= 6:
            risk["recommended_treatment"] = "transfer"
        else:
            risk["recommended_treatment"] = "accept"
        
        self.risk_register.append(risk)
        return risk
    
    def risk_heatmap(self):
        """生成风险热力图数据"""
        heatmap = [[0]*5 for _ in range(5)]
        
        for risk in self.risk_register:
            # 固有风险
            il = min(risk["inherent_likelihood"] - 1, 4)
            ii = min(risk["inherent_impact"] - 1, 4)
            heatmap[il][ii] += 1
        
        return heatmap
    
    def treatment_summary(self):
        """处置汇总"""
        summary = {"avoid": 0, "mitigate": 0, "transfer": 0, "accept": 0}
        high_risks = []
        
        for risk in self.risk_register:
            treatment = risk["recommended_treatment"]
            summary[treatment] = summary.get(treatment, 0) + 1
            
            if risk["residual_score"] >= 15:
                high_risks.append(risk)
        
        return {
            "treatment_summary": summary,
            "total_risks": len(self.risk_register),
            "high_risks": high_risks,
            "avg_inherent_score": round(
                sum(r["inherent_score"] for r in self.risk_register) / len(self.risk_register), 1
            ) if self.risk_register else 0,
            "avg_residual_score": round(
                sum(r["residual_score"] for r in self.risk_register) / len(self.risk_register), 1
            ) if self.risk_register else 0,
            "risk_reduction": round(
                (1 - sum(r["residual_score"] for r in self.risk_register) / 
                 max(1, sum(r["inherent_score"] for r in self.risk_register))) * 100, 1
            ) if self.risk_register else 0
        }


# 使用示例
rte = RiskTreatmentEngine()
rte.add_risk("RDP 暴露到互联网", 4, 5, 0.5)  # 高风险
rte.add_risk("缺失关键安全补丁", 3, 4, 0.3)
rte.add_risk("第三方供应商数据泄露", 2, 4, 0.6)
summary = rte.treatment_summary()
print(f"Total risks: {summary['total_risk']}")
print(f"Risk reduction: {summary['risk_reduction']}%")
print(f"Treatments: {summary['treatment_summary']}")
```

```bash
# 管理层报告生成

# 1. 安全仪表盘 (Grafana)
# 使用 Grafana 创建管理层安全仪表盘

# 示例 Grafana API 创建仪表盘
cat > security_dashboard.json << 'JSON'
{
  "dashboard": {
    "title": "CISO 安全态势仪表盘",
    "panels": [
      {
        "title": "安全健康评分",
        "type": "stat",
        "targets": [{"expr": "security_health_score"}]
      },
      {
        "title": "MTTD / MTTR 趋势",
        "type": "graph",
        "targets": [
          {"expr": "avg(mttd_minutes) over last 30d"},
          {"expr": "avg(mttr_minutes) over last 30d"}
        ]
      },
      {
        "title": "风险登记册摘要",
        "type": "table",
        "targets": [{"expr": "risk_register_summary"}]
      },
      {
        "title": "合规趋势",
        "type": "graph",
        "targets": [{"expr": "compliance_score"}]
      }
    ]
  }
}
JSON

# 2. CISO 月度报告模板
cat > cisoreport_template.md << 'TEMPLATE'
# 月度安全态势报告 — YYYY年MM月

## 执行摘要
- 安全健康评分: XX/100 (上个月: XX)
- 本月事件总数: XX (P1: X, P2: X)
- 平均检测时间 (MTTD): XX 分钟
- 平均响应时间 (MTTR): XX 分钟

## 关键指标
| 指标 | 当前值 | 目标 | 状态 |
|------|--------|------|------|
| EDR 覆盖率 | XX% | >98% | ✅/⚠️/❌ |
| 补丁覆盖率 | XX% | >95% | ✅/⚠️/❌ |
| MFA 覆盖率 | XX% | >95% | ✅/⚠️/❌ |
| 高危漏洞修复 | XX 天 | <7天 | ✅/⚠️/❌ |
| SOC SLA 合规 | XX% | >99% | ✅/⚠️/❌ |

## 重大事件
1. [事件标题] — [日期] — [影响]
2. ...

## 风险态势
- 高风险项: X (上月 Y)
- 风险处置率: XX%
- 新发现风险: X

## 改进计划
1. [项目] — [截至日期] — [进展]
2. ...
TEMPLATE

# 3. 自动生成报告脚本
cat > generate_ciso_report.py << 'PYTHON'
import json
from datetime import datetime

# 从数据源拉取指标
metrics = {
    "security_health": 82,
    "mttd_minutes": 28,
    "mttr_minutes": 45,
    "events_total": 127,
    "events_p1": 3,
    "edr_coverage": 97.5,
    "patch_coverage": 94.2,
    "mfa_coverage": 96.8,
    "vuln_remediation_days": 5.2,
    "sla_compliance": 98.7,
    "high_risks": 4,
    "risk_treatment_rate": 78
}

# 生成文本报告
report = f"""
# 月度安全态势报告 — {datetime.now().strftime('%Y年%m月')}

## 执行摘要
- 安全健康评分: {metrics['security_health']}/100
- 本月事件总数: {metrics['events_total']} (P1: {metrics['events_p1']})
- MTTD: {metrics['mttd_minutes']} 分钟 | MTTR: {metrics['mttr_minutes']} 分钟
"""
print(report)
PYTHON
python3 generate_ciso_report.py
```

### 4. 第三方风险管理

```python
"""第三方风险评估"""

class ThirdPartyRiskManager:
    """第三方风险管理"""
    
    ASSESSMENT_CRITERIA = {
        "data_access": {
            "weight": 30,
            "questions": [
                "是否可访问客户数据?",
                "是否可访问 PII/PHI?",
                "数据是否存储在其基础设施中?"
            ]
        },
        "network_access": {
            "weight": 20,
            "questions": [
                "是否可连接到公司网络?",
                "是否使用 VPN/专线?",
                "是否与内部系统集成?"
            ]
        },
        "authentication": {
            "weight": 20,
            "questions": [
                "是否支持 SSO/SAML?",
                "是否有 MFA?",
                "是否有适当的访问控制?"
            ]
        },
        "security_certifications": {
            "weight": 15,
            "questions": [
                "是否有 SOC 2 报告?",
                "是否有 ISO 27001 认证?",
                "是否有其他安全认证?"
            ]
        },
        "incident_response": {
            "weight": 15,
            "questions": [
                "是否有 IR 计划?",
                "是否有数据泄露通知流程?",
                "是否定期进行安全测试?"
            ]
        }
    }
    
    @staticmethod
    def assess_vendor(responses):
        """评估供应商风险"""
        total_score = 0
        max_score = 0
        
        for category, criteria in ThirdPartyRiskManager.ASSESSMENT_CRITERIA.items():
            weight = criteria["weight"]
            max_score += weight * 5
            
            if category in responses:
                score = min(5, max(1, responses[category]))
                total_score += score * weight
        
        normalized = round(total_score / max_score * 100, 1) if max_score else 0
        
        if normalized >= 80:
            risk = "low"
        elif normalized >= 60:
            risk = "medium"
        else:
            risk = "high"
        
        return {
            "total_score": normalized,
            "risk_level": risk,
            "recommended_review": "12个月" if risk == "low" else "6个月" if risk == "medium" else "3个月"
        }


# 使用示例
vendor_risk = ThirdPartyRiskManager.assess_vendor({
    "data_access": 4,     # 分数 1-5
    "network_access": 3,
    "authentication": 5,
    "security_certifications": 5,
    "incident_response": 4
})
print(f"Vendor risk: {vendor_risk['total_score']}/100 ({vendor_risk['risk_level']})")
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| FAIR Institute | 定量风险分析 | https://www.fairinstitute.org/ |
| RiskLens | FAIR 平台 | https://www.risklens.com/ |
| Archer | GRC 平台 | https://www.archerirm.com/ |
| Grafana | 安全仪表盘 | https://grafana.com/ |
| Jira | 风险跟踪 | https://www.atlassian.com/software/jira |

## 参考资源

- [NIST SP 800-30 — Risk Assessment Guide](https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final)
- [FAIR Quantitative Risk Analysis](https://www.fairinstitute.org/what-is-fair)
- [Factor Analysis of Information Risk (FAIR) Model](https://www.riskmanagementstudio.com/fair-model)
- [CIS RAM (Risk Assessment Method)](https://www.cisecurity.org/insights/blog/cris-ram-risk-assessment-method)
- [SANS Security Metrics Guide](https://www.sans.org/white-papers/security-metrics/)
