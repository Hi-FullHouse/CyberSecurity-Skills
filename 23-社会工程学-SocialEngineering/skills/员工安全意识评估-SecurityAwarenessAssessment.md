---
id: 23-005
title: "📊 员工安全意识评估 (Security Awareness Assessment)"
category: 社会工程学
category_en: "Social Engineering"
difficulty: ★★★
tools: "KnowBe4, Phish Insight, CyberArk, PhishLabs, Wizer"
last_updated: 2025-07
tags: ["social-engineering", "phishing", "vishing", "physical-security", "awareness"]
subdomain: social-engineering
nist_csf: ["PR.AT-01", "PR.AT-02"]
mitre_attack: ["T1566", "T1598", "T1204"]
---
# 📊 员工安全意识评估 (Security Awareness Assessment)

## 概述

员工安全意识评估通过钓鱼模拟、知识测试、行为分析等方法测量组织的安全文化成熟度，识别高风险人群，指导针对性培训。

## 核心技能

### 1. 意识评估体系设计

```python
# 安全意识评估框架

awareness_assessment_framework = {
    "assessment_types": {
        "phishing_simulation": {
            "频率": "季度",
            "目标": "测量识别和报告钓鱼邮件的能力",
            "指标": ["点击率", "报告率", "报告及时性"]
        },
        "knowledge_test": {
            "频率": "年度",
            "目标": "测量安全知识掌握程度",
            "指标": ["测试得分", "薄弱领域识别"]
        },
        "behavior_observation": {
            "频率": "持续",
            "目标": "观察日常安全行为",
            "指标": ["锁屏率", "密码复杂度", "数据分类执行率"]
        },
        "physical_testing": {
            "频率": "年度",
            "目标": "评估物理安全意识",
            "指标": ["尾随成功率", "访客登记率", "可疑行为报告率"]
        }
    },
    "risk_scoring": {
        "high_risk": "多次点击钓鱼邮件，多次违反安全策略",
        "medium_risk": "偶尔点击钓鱼邮件，基本安全知识欠缺",
        "low_risk": "极少违规，安全行为规范"
    }
}
```

### 2. 安全意识平台集成 (KnowBe4 API)

```python
#!/usr/bin/env python3
# KnowBe4 API 自动化管理

import requests
import json
import csv
from datetime import datetime, timedelta

class KnowBe4Manager:
    def __init__(self, api_key):
        self.base_url = "https://api.knowbe4.com/v1"
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json"
        }
    
    def get_users(self):
        """获取所有用户及其风险评分"""
        resp = requests.get(f"{self.base_url}/users", headers=self.headers)
        return resp.json()
    
    def get_phishing_results(self, days=90):
        """获取钓鱼模拟结果"""
        since = (datetime.now() - timedelta(days=days)).isoformat()
        resp = requests.get(
            f"{self.base_url}/phishing/security_tests",
            params={"since": since},
            headers=self.headers
        )
        return resp.json()
    
    def get_training_assignments(self):
        """获取培训分配情况"""
        resp = requests.get(
            f"{self.base_url}/training/enrollments",
            headers=self.headers
        )
        return resp.json()
    
    def assign_training(self, user_email, training_course):
        """为高风险用户分配培训"""
        payload = {
            "users": [{"email": user_email}],
            "training_course_id": training_course
        }
        resp = requests.post(
            f"{self.base_url}/training/enrollments",
            json=payload, headers=self.headers
        )
        return resp.json()
    
    def generate_risk_report(self):
        """生成风险报告"""
        users = self.get_users()
        results = self.get_phishing_results()
        
        high_risk = []
        for user in users:
            if user.get('risk_score', 0) >= 75:
                high_risk.append(user)
        
        print(f"高风险用户数量: {len(high_risk)}")
        print(f"总用户数量: {len(users)}")
        print(f"高风险比例: {(len(high_risk)/len(users))*100:.1f}%")
        
        return {"total": len(users), "high_risk": high_risk}

# 使用示例
manager = KnowBe4Manager("your-api-key-here")
report = manager.generate_risk_report()
```

### 3. 钓鱼测试数据统计分析

```python
# 钓鱼测试结果分析
import pandas as pd
import numpy as np

class PhishingAnalytics:
    def __init__(self, csv_file):
        self.df = pd.read_csv(csv_file)
    
    def department_analysis(self):
        """部门维度分析"""
        dept_stats = self.df.groupby('department').agg({
            'user_id': 'count',
            'phish_clicked': 'sum',
            'phish_reported': 'sum',
            'training_completed': 'mean'
        }).reset_index()
        
        dept_stats['click_rate'] = (dept_stats['phish_clicked'] / dept_stats['user_id']) * 100
        dept_stats['report_rate'] = (dept_stats['phish_reported'] / dept_stats['user_id']) * 100
        dept_stats['risk_level'] = pd.cut(
            dept_stats['click_rate'], 
            bins=[0, 5, 15, 100], 
            labels=['低风险', '中风险', '高风险']
        )
        
        print("=== 部门钓鱼风险分析 ===")
        for _, row in dept_stats.iterrows():
            print(f"{row['department']:20s} 点击率:{row['click_rate']:5.1f}% 报告率:{row['report_rate']:5.1f}% 风险:{row['risk_level']}")
        
        return dept_stats
    
    def repeat_offender_analysis(self):
        """重复违规者分析"""
        repeat_offenders = self.df[self.df['phish_clicked'] >= 3]
        print(f"\n重复违规者（≥3次点击）: {len(repeat_offenders)}人")
        
        # 培训效果分析
        trained = repeat_offenders[repeat_offenders['training_completed'] == True]
        untrained = repeat_offenders[repeat_offenders['training_completed'] == False]
        
        if len(trained) > 0 and len(untrained) > 0:
            trained_avg = trained['phish_clicked'].mean()
            untrained_avg = untrained['phish_clicked'].mean()
            print(f"培训后平均点击次数: {trained_avg:.1f}")
            print(f"未培训平均点击次数: {untrained_avg:.1f}")
        
        return repeat_offenders
    
    def time_trend_analysis(self):
        """时间趋势分析"""
        self.df['date'] = pd.to_datetime(self.df['test_date'])
        trend = self.df.groupby(self.df['date'].dt.quarter)['phish_clicked'].mean()
        
        print("\n=== 季度趋势 ===")
        for quarter, rate in trend.items():
            print(f"Q{quarter}: 平均点击率 {rate:.1f}%")
        
        # 判断趋势
        if len(trend) >= 4:
            if trend.iloc[-1] < trend.iloc[0]:
                print("✅ 安全意识呈持续改善趋势")
            elif trend.iloc[-1] > trend.iloc[0]:
                print("⚠️ 安全意识可能有下降趋势，需要关注")
    
    def generate_executive_summary(self):
        """生成管理层摘要"""
        stats = {
            "平均点击率": f"{self.df['phish_clicked'].mean():.1f}%",
            "平均报告率": f"{self.df['phish_reported'].mean():.1f}%",
            "最高风险部门": self.df.groupby('department')['phish_clicked'].mean().idxmax(),
            "最低风险部门": self.df.groupby('department')['phish_clicked'].mean().idxmin(),
            "培训完成率": f"{self.df['training_completed'].mean()*100:.1f}%",
            "高风险用户数": len(self.df[self.df['risk_score'] >= 75]),
            "总改善率": f"{(1 - self.df.iloc[0]['phish_clicked'] / self.df.iloc[-1]['phish_clicked']) * 100:.1f}%"
        }
        return stats
```

### 4. 培训课程设计与改进

```markdown
# 安全意识培训课程矩阵

## 基础培训（全员必修）
| 课程 | 时长 | 频率 | 考核方式 |
|:---|:---:|:---:|:---|
| 密码安全与MFA | 30min | 每年 | 知识测试 |
| 钓鱼邮件识别 | 45min | 半年 | 模拟测试 |
| 数据分类与处理 | 20min | 每年 | 场景判断 |
| 物理安全基础 | 15min | 每年 | 知识测试 |
| 事件报告流程 | 10min | 每年 | 情景演练 |

## 进阶培训（高风险人群）
| 课程 | 时长 | 频率 | 说明 |
|:---|:---:|:---:|:---|
| 高级钓鱼识别技术 | 60min | 季度 | 针对多次点击者 |
| 社交工程防御 | 45min | 半年 | 针对Vishing目标 |
| 安全编码基础 | 120min | 每年 | 针对开发人员 |

## 专项培训（特定角色）
| 角色 | 培训内容 | 频率 |
|:---|:---|:---:|
| IT管理员 | 安全运营、日志分析 | 季度 |
| 财务人员 | 商务邮件欺诈(BEC)防御 | 季度 |
| 高管 | 针对性攻击防御 | 半年 |
| 新员工 | 安全入职培训 | 入职30天内 |
```

### 5. 安全文化度量与改进

```python
# 安全文化成熟度模型

security_culture_maturity = {
    "level_1_reactive": {
        "score": 1,
        "characteristics": [
            "安全意识培训频率: 仅入职一次",
            "安全事件响应: 被动响应",
            "报告文化: 员工怕报告而不是主动报告",
            "钓鱼测试: 未开展"
        ]
    },
    "level_2_compliant": {
        "score": 2,
        "characteristics": [
            "安全意识培训: 年度合规培训",
            "钓鱼测试: 季度基础测试",
            "报告机制: 有已确认或的举报渠道",
            "安全考核: 纳入绩效评估"
        ]
    },
    "level_3_proactive": {
        "score": 3,
        "characteristics": [
            "持续安全宣传: 月度安全通讯",
            "钓鱼测试: 月度多样化测试",
            "即时奖励机制: 积极报告者即时奖励",
            "培训个性化: 基于风险评估的定制培训"
        ]
    },
    "level_4_sustained": {
        "score": 4,
        "characteristics": [
            "安全文化已融入日常: 员工主动识别并上报威胁",
            "社区驱动: 员工自发成立安全兴趣小组",
            "行业标杆: 安全文化被外部认可",
            "持续创新: 不断引入新的评估和培训方法"
        ]
    }
}
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| KnowBe4 | 安全意识培训平台 | https://www.knowbe4.com/ |
| Phish Insight | 钓鱼模拟平台 | https://www.phishinsight.com/ |
| CyberArk | 身份安全意识 | https://www.cyberark.com/ |
| Wizer | 安全培训平台 | https://www.wizer-training.com/ |
| PhishLabs | 钓鱼情报与分析 | https://www.phishlabs.com/ |

## 参考资源

- [NIST SP 800-50 — Building a Cybersecurity Awareness Program](https://csrc.nist.gov/publications/detail/sp/800-50/rev-1/draft)
- [SANS Security Awareness Report](https://www.sans.org/security-awareness-training/report/)
- [ENISA Cybersecurity Awareness](https://www.enisa.europa.eu/topics/cybersecurity-education)
- [CISA Phishing Awareness Program](https://www.cisa.gov/stopransomware)
