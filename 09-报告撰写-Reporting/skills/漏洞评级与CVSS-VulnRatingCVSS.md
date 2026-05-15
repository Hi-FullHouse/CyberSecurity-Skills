---
id: 09-005
title: "📊 漏洞评级与CVSS评分 (Vulnerability Rating & CVSS Scoring)"
category: 报告撰写
category_en: Reporting
difficulty: ★★★
tools: "CVSS 3.1/4.0, DREAD, OWASP Risk Rating"
last_updated: 2025-07
tags: ["reporting", "documentation", "cvss", "pentest-report", "markdown"]
subdomain: reporting
nist_csf: ["ID.GV-01", "ID.SC-03"]
mitre_attack: []
---
# 📊 漏洞评级与CVSS评分 (Vulnerability Rating & CVSS Scoring)

## 概述
使用CVSS（Common Vulnerability Scoring System）标准和行业最佳实践对漏洞进行评级和严重性评估。

## 核心技能

### 1. CVSS 3.1评分体系

```python
# CVSS 3.1评分速查表

# Base Score Metrics (基础评分)
# 攻击向量 (AV):
#   Network (N) - 远程网络 - 0.85
#   Adjacent (A) - 相邻网络 - 0.62
#   Local (L) - 本地访问 - 0.55
#   Physical (P) - 物理接触 - 0.20

# 攻击复杂度 (AC):
#   Low (L) - 低复杂度 - 0.77
#   High (H) - 高复杂度 - 0.44

# 权限要求 (PR):
#   None (N) - 无需权限 - 0.85
#   Low (L) - 低权限 - 0.62 (Scope=U) / 0.68 (Scope=C)
#   High (H) - 高权限 - 0.27 (Scope=U) / 0.50 (Scope=C)

# 用户交互 (UI):
#   None (N) - 无需交互 - 0.85
#   Required (R) - 需要交互 - 0.62

# 影响范围 (S):
#   Unchanged (U) - 未变化
#   Changed (C) - 变化

# 机密性/完整性/可用性 (C/I/A):
#   High (H) - 高影响 - 0.56
#   Low (L) - 低影响 - 0.22
#   None (N) - 无影响 - 0.00

# 评分等级：
# Critical (严重): 9.0 - 10.0
# High (高危): 7.0 - 8.9
# Medium (中危): 4.0 - 6.9
# Low (低危): 0.1 - 3.9
# None (信息): 0.0
```

### 2. 常见漏洞类型评分参考

```python
# 常见漏洞CVSS 3.1评分参考

vuln_scoring_guide = {
    # 远程代码执行类
    "RCE - Remote Code Execution": {
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
        "severity": "Critical",
        "example": "Log4Shell, Struts2 RCE"
    },
    
    # SQL注入
    "SQL Injection": {
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
        "severity": "Critical",
        "example": "参数化查询缺失导致的注入"
    },
    
    # 文件上传
    "Unrestricted File Upload": {
        "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "score": 8.8,
        "severity": "High",
        "example": "上传WebShell"
    },
    
    # 反射型XSS
    "Reflected XSS": {
        "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "score": 6.1,
        "severity": "Medium",
        "example": "搜索框反射XSS"
    },
    
    # 存储型XSS
    "Stored XSS": {
        "vector": "AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N",
        "score": 7.6,
        "severity": "High",
        "example": "评论区存储XSS"
    },
    
    # CSRF
    "Cross-Site Request Forgery": {
        "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "score": 8.0,
        "severity": "High",
        "example": "缺少Token的敏感操作"
    },
    
    # SSRF
    "Server-Side Request Forgery": {
        "vector": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
        "score": 7.7,
        "severity": "High",
        "example": "内网元数据访问"
    },
    
    # 信息泄露
    "Information Disclosure": {
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "score": 5.3,
        "severity": "Medium",
        "example": "目录列表、错误信息泄露"
    },
    
    # 未授权访问
    "Unauthorized Access": {
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "score": 7.5,
        "severity": "High",
        "example": "未认证的API接口"
    },
    
    # 中间人攻击 (MITM)
    "Man-in-the-Middle": {
        "vector": "AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "score": 6.4,
        "severity": "Medium",
        "example": "HTTP明文传输"
    }
}
```

### 3. 风险等级矩阵

```python
# 风险等级 = 可能性 × 影响

risk_matrix = {
    "Likelihood (可能性)": {
        "Very High": {
            "description": "极可能发生",
            "score": 5,
            "examples": ["公开的PoC可用", "无需认证", "远程可执行"]
        },
        "High": {
            "description": "很可能发生",
            "score": 4,
            "examples": ["需要低权限", "局部条件满足"]
        },
        "Medium": {
            "description": "可能发生",
            "score": 3,
            "examples": ["需要用户交互", "特定配置"]
        },
        "Low": {
            "description": "不太可能发生",
            "score": 2,
            "examples": ["需要高权限", "特殊条件"]
        },
        "Very Low": {
            "description": "几乎不会发生",
            "score": 1,
            "examples": ["物理访问", "未知漏洞"]
        }
    },
    "Impact (影响)": {
        "Very High": {
            "description": "完全系统控制",
            "score": 5,
            "examples": ["RCE", "域控权限"]
        },
        "High": {
            "description": "重要数据泄露",
            "score": 4,
            "examples": ["数据库泄露", "管理员权限"]
        },
        "Medium": {
            "description": "部分数据泄露",
            "score": 3,
            "examples": ["用户信息泄露", "服务降级"]
        },
        "Low": {
            "description": "有限影响",
            "score": 2,
            "examples": ["服务重启", "信息枚举"]
        },
        "Very Low": {
            "description": "无实质影响",
            "score": 1,
            "examples": ["Banner泄露", "无效请求"]
        }
    }
}

# 风险等级 = Likelihood × Impact
# 16-25: Critical (严重)
# 10-15: High (高危)
# 6-9: Medium (中危)
# 3-5: Low (低危)
# 1-2: Info (信息)
```

### 4. CVSS 4.0更新

```python
# CVSS 4.0 主要变化 (2023年11月发布)

cvss40_changes = {
    "新增指标": [
        "Attack Requirements (AT): 攻击要求",
        "Safety (S): 人身安全影响",
        "Automatable (AU): 自动化程度",
        "Recovery (R): 恢复能力",
        "Value Density (VC/VI/VA): 价值密度",
        "Vulnerability Response Effort (RE): 响应工作量",
        "Provider Urgency (U): 供应商紧迫度"
    ],
    "主要改进": [
        "更细致的评分粒度",
        "增加对人身安全的考量",
        "考虑自动化攻击的可能性",
        "补充对AI/ML系统的评估",
        "更好的供应链风险评估"
    ],
    "与3.1的兼容性": "CVSS 4.0 可向前兼容3.1，使用CVSS-B前缀表示基础指标"
}

# CVSS 4.0 向量格式示例
# CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

### 5. 自定义风险评估模型

```python
#!/usr/bin/env python3
# custom_risk_assessment.py - 自定义风险评估

import json

class RiskAssessor:
    def __init__(self):
        self.factors = {}
    
    def add_factor(self, name, weight, score, description=""):
        """添加风险评估因素"""
        self.factors[name] = {
            'weight': weight,
            'score': score,
            'description': description,
            'weighted_score': weight * score
        }
    
    def calculate_risk(self):
        """计算加权风险总分"""
        if not self.factors:
            return 0
        
        total_weight = sum(f['weight'] for f in self.factors.values())
        total_weighted = sum(f['weighted_score'] for f in self.factors.values())
        
        if total_weight == 0:
            return 0
        
        return total_weighted / total_weight * 10  # 归一化到0-10
    
    def assess_vulnerability(self, vuln_data):
        """评估单个漏洞风险"""
        # 基于多个维度评估
        dimensions = {
            'exploitability': vuln_data.get('exploit_score', 5),
            'impact': vuln_data.get('impact_score', 5),
            'detection_difficulty': vuln_data.get('detection_score', 5),
            'asset_value': vuln_data.get('asset_value', 5),
            'exposure': vuln_data.get('exposure_level', 5)
        }
        
        for dim, score in dimensions.items():
            self.add_factor(dim, 1, score)
        
        return self.calculate_risk()
    
    def get_severity(self, score):
        """根据分数获取严重等级"""
        if score >= 9.0: return "Critical"
        elif score >= 7.0: return "High"
        elif score >= 4.0: return "Medium"
        elif score > 0: return "Low"
        else: return "Info"
    
    def generate_report(self, output_file="risk_report.json"):
        """生成风险评估报告"""
        report = {
            'total_risk_score': self.calculate_risk(),
            'severity': self.get_severity(self.calculate_risk()),
            'factors': self.factors,
            'recommendations': self._generate_recommendations()
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report
    
    def _generate_recommendations(self):
        """生成修复建议"""
        recs = []
        for name, factor in self.factors.items():
            if factor['score'] >= 7:
                recs.append(f"立即处理: {name} (评分: {factor['score']})")
            elif factor['score'] >= 4:
                recs.append(f"尽快处理: {name} (评分: {factor['score']})")
        return recs

# 使用示例
if __name__ == "__main__":
    assessor = RiskAssessor()
    
    vuln = {
        'exploit_score': 9,
        'impact_score': 9,
        'detection_score': 3,
        'asset_value': 9,
        'exposure_level': 8
    }
    
    score = assessor.assess_vulnerability(vuln)
    print(f"Risk Score: {score:.1f}")
    print(f"Severity: {assessor.get_severity(score)}")
```

### 6. 行业标准对比

```python
# 主流漏洞评级标准对比

rating_standards = {
    "CVSS 3.1": {
        "Critical": "9.0-10.0",
        "High": "7.0-8.9",
        "Medium": "4.0-6.9",
        "Low": "0.1-3.9",
        "Info": "0.0"
    },
    "OWASP Risk Rating": {
        "Critical": "Note: OWASP使用风险矩阵",
        "High": "Likelihood × Impact ≥ 6 (使用1-9分制)",
        "Medium": "Likelihood × Impact 3-5",
        "Low": "Likelihood × Impact 1-2",
        "Info": "无实际风险"
    },
    "DREAD (微软)": {
        "Critical": "15-25",
        "High": "11-14",
        "Medium": "5-10",
        "Low": "0-4",
        "Info": "不适用"
    },
    "Qualys": {
        "Critical": "5",
        "High": "4",
        "Medium": "3",
        "Low": "2",
        "Info": "1"
    }
}
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| NVD CVSS Calculator | 官方CVSS计算器 | https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator |
| FIRST CVSS | 在线评分计算 | https://www.first.org/cvss/calculator/3.1 |
| VulnDB | 漏洞数据库 | https://vulndb.cyberriskanalytics.com/ |
| Exploit-DB | Exploit数据库 | https://www.exploit-db.com/ |

## 参考资源
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3-1/)
- [CVSS v4.0 Specification](https://www.first.org/cvss/v4-0/)
- [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)
- [NVD Vulnerability Metrics](https://nvd.nist.gov/vuln-metrics/cvss)
- [FIRST CVSS SIG](https://www.first.org/cvss/)
