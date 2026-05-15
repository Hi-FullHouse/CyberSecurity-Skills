---
id: 22-006
title: "📝 隐私影响评估(PIA) (Privacy Impact Assessment)"
category: 数据安全与隐私
category_en: "Data Security & Privacy"
difficulty: ★★★★
tools: "CNIL PIA Tool, OneTrust DPIA, PIA Template, DPIA Toolkit"
last_updated: 2025-07
tags: ["data-security", "privacy", "dlp", "gdpr", "encryption", "data-classification"]
subdomain: data-security-privacy
nist_csf: ["PR.DS-01", "PR.DS-02", "PR.DS-05", "ID.GV-03"]
mitre_attack: ["T1530", "T1048", "T1567"]
---
# 📝 隐私影响评估(PIA) (Privacy Impact Assessment)

## 概述

隐私影响评估（PIA）/ 数据保护影响评估（DPIA）是识别和降低个人数据处理活动隐私风险的系统性方法。GDPR Art.35 要求在高风险处理前必须进行DPIA。中国《个人信息保护法》第五十五条也要求在自动化决策、委托处理等场景进行影响评估。

## 核心技能

### 1. DPIA 触发条件判断

```python
def check_dpia_required(processing_activity):
    """判断是否需要开展DPIA"""
    high_risk_indicators = [
        processing_activity.get('systematic_profiling'),
        processing_activity.get('large_scale_sensitive_data'),
        processing_activity.get('public_area_monitoring'),
        processing_activity.get('vulnerable_data_subjects'),
        processing_activity.get('innovative_technology'),
        processing_activity.get('cross_border_transfer'),
        processing_activity.get('automated_decision_making')
    ]
    
    met_indicators = sum(1 for i in high_risk_indicators if i)
    
    if met_indicators >= 2:
        return True, f"满足{met_indicators}个高风险指标，必须开展DPIA"
    elif met_indicators == 1:
        return True, "建议开展DPIA"
    return False, "无需DPIA，但建议记录判断依据"

# EDPB Guidelines: DPIA必做清单
def dpia_mandatory_checklist():
    return {
        "员工监控系统": True,
        "大数据健康分析": True,
        "信用评分系统": True,
        "精准广告投放": True,
        "人脸识别系统": True,
        "位置轨迹追踪": True,
        "儿童数据处理": True
    }
```

### 2. 完整DPIA报告结构

```yaml
dpia_report:
  metadata:
    title: "行为分析平台DPIA报告"
    version: "1.0"
    date: "2025-07-01"
    status: "Final"
    
  section_1: "处理活动描述"
  section_2: "必要性与相称性评估"
  section_3: "风险评估"
  section_4: "风险处置措施"
  section_5: "数据主体参与"
  section_6: "结论与建议"

# DPIA 数据流图描述
data_flow:
  sources:
    - "Web前端 (用户行为埋点)"
    - "移动App SDK"
    - "线下POS系统"
  processing:
    - "数据清洗与去重"
    - "用户画像构建 (自动化决策)"
    - "实时推荐引擎"
  storage:
    - "ClickHouse (3个月热数据)"
    - "HDFS (2年冷数据)"
  recipients:
    - "推荐算法团队"
    - "BI分析团队"
  retention: "用户注销后30天删除"
```

### 3. 隐私风险评估矩阵

```python
#!/usr/bin/env python3
# 隐私风险评估系统

import json

class PrivacyRiskAssessment:
    def __init__(self):
        self.risks = []
    
    def add_risk(self, risk_id, description, likelihood, impact, data_subjects):
        """添加风险项
        likelihood/impact: 1-5 (极低-极高)
        """
        risk_level = likelihood * impact
        risk_rating = "低" if risk_level <= 6 else ("中" if risk_level <= 12 else "高")
        
        self.risks.append({
            "id": risk_id,
            "description": description,
            "likelihood": likelihood,
            "impact": impact,
            "risk_score": risk_level,
            "risk_rating": risk_rating,
            "affected_subjects": data_subjects,
            "mitigation": "",
            "residual_risk": ""
        })
    
    def add_mitigation(self, risk_id, mitigation, residual_likelihood, residual_impact):
        for risk in self.risks:
            if risk["id"] == risk_id:
                risk["mitigation"] = mitigation
                residual = residual_likelihood * residual_impact
                risk["residual_risk"] = "低" if residual <= 6 else ("中" if residual <= 12 else "高")
    
    def generate_report(self):
        report = {
            "risks": self.risks,
            "high_risks": [r for r in self.risks if r["risk_rating"] == "高"],
            "residual_high_risks": [r for r in self.risks 
                                     if r["residual_risk"] == "高" and r["mitigation"]],
            "summary": {
                "total_risks": len(self.risks),
                "high_risk": sum(1 for r in self.risks if r["risk_rating"] == "高"),
                "medium_risk": sum(1 for r in self.risks if r["risk_rating"] == "中"),
                "low_risk": sum(1 for r in self.risks if r["risk_rating"] == "低"),
                "residual_high": sum(1 for r in self.risks if r["residual_risk"] == "高")
            }
        }
        return report

# 使用示例
pia = PrivacyRiskAssessment()
pia.add_risk("R1", "用户画像披露导致歧视", 3, 5, "全体用户")
pia.add_risk("R2", "数据泄露导致身份冒用", 2, 5, "10万+用户")
pia.add_risk("R3", "未经同意的自动化决策", 4, 3, "活跃用户")

pia.add_mitigation("R1", "禁止敏感属性画像，人工审核机制", 2, 3)
pia.add_mitigation("R2", "数据加密、访问控制、安全审计", 1, 4)
pia.add_mitigation("R3", "用户可关闭个性化推荐", 2, 2)

report = pia.generate_report()
print(json.dumps(report["summary"], indent=2, ensure_ascii=False))
```

### 4. 数据保护设计(Data Protection by Design)

```python
# 隐私保护设计检查清单

dpb_design_checklist = {
    "数据最小化": [
        "仅收集业务必需字段",
        "设置合理的数据保留期限",
        "定期清理过期数据"
    ],
    "默认隐私": [
        "最严格的隐私设置作为默认值",
        "用户需主动选择开启数据共享",
        "选择性同意（Granular Consent）"
    ],
    "透明度": [
        "清晰易懂的隐私政策",
        "实时的数据使用说明",
        "数据访问与导出接口"
    ],
    "安全性": [
        "端到端加密",
        "假名化/匿名化处理",
        "访问日志与异常检测"
    ],
    "用户控制权": [
        "One-click 数据导出",
        "账户删除流程",
        "隐私偏好中心"
    ]
}

def privacy_by_design_audit(system_config):
    """执行隐私设计审计"""
    score = 0
    total = 0
    for category, items in dpb_design_checklist.items():
        for item in items:
            total += 1
            if item in system_config and system_config[item]:
                score += 1
                print(f"✅ [{category}] {item}")
            else:
                print(f"❌ [{category}] {item} - 未实施")
    
    compliance_rate = (score / total) * 100
    print(f"\n隐私设计合规率: {compliance_rate:.1f}%")
    return compliance_rate
```

### 5. DPIA 文档模板 (Markdown)

```markdown
# DPIA: [项目名称]

## 1. 处理活动描述
- **处理目的**：
- **数据类别**：
- **数据主体**：
- **处理方式**（自动化/半自动化）：
- **涉及的新技术**：

## 2. 必要性评估
| 评估项 | 说明 |
|:---|:---|
| 处理目的合法 | |
| 数据最小化 | |
| 存储期限合理 | |
| 替代方案 | |

## 3. 风险评估矩阵
| 风险ID | 风险描述 | 可能性(1-5) | 影响(1-5) | 风险等级 | 缓解措施 | 残余风险 |
|:---:|:---|:---:|:---:|:---:|:---|:---:|
| R01 | | | | | | |

## 4. 风险处置计划
| 优先级 | 风险 | 措施 | 负责人 | 截止日期 | 状态 |
|:---:|:---|:---|:---:|:---:|:---:|
| 🔴 高 | | | | | ⏳ |

## 5. 结论
**DPIA结论：** □ 可接受（残余风险在可接受范围内）
□ 不可接受（需向监管机构咨询）

**DPO签名：** ______ **日期：** ______
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| CNIL PIA Tool | 开源DPIA工具 | https://www.cnil.fr/en/open-source-pia-software |
| OneTrust DPIA | 企业级DPIA工作流 | https://www.onetrust.com/ |
| DPIA Template (ICO) | ICO官方模板 | https://ico.org.uk/for-organisations/dpia-template/ |
| EDPB DPIA Guidelines | DPIA指南 | https://edpb.europa.eu/ |

## 参考资源

- [EDPB Guidelines on DPIA](https://edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-data-protection-impact-assessment-dpia_en)
- [ICO DPIA Guidance](https://ico.org.uk/for-organisations/guide-to-data-protection/guide-to-the-general-data-protection-regulation-gdpr/data-protection-impact-assessments-dpias/)
- [中国个保法 — 影响评估义务](https://www.gov.cn/xinwen/2021-08/20/content_5632151.htm)
- [NIST Privacy Framework](https://www.nist.gov/privacy-framework)
- [ISO 29134 — Privacy Impact Assessment Guidelines](https://www.iso.org/standard/75250.html)
