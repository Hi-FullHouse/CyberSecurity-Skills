---
id: 15-003
title: "📋 事件分类与优先级评估 (Incident Triage & Prioritization)"
category: 应急响应
category_en: "Incident Response"
difficulty: ★★★
tools: "事件管理平台, SIRP工具, TheHive"
last_updated: 2025-07
tags: ["incident-response", "forensics", "memory-forensics", "threat-hunting", "ransomware"]
subdomain: incident-response
nist_csf: ["RS.RP-01", "RS.CO-02", "RS.AN-01", "RS.MI-01"]
mitre_attack: ["T1486", "T1490", "T1485", "T1562"]
---
# 📋 事件分类与优先级评估 (Incident Triage & Prioritization)

## 概述
对安全事件进行快速分类和优先级评估，确保有限的安全资源聚焦于影响最大的事件。参照 **NIST SP 800-61** 的四阶段分类模型和 **FIRST CVSS** 评分体系，建立标准化的事件分级机制。

## 核心技能

### 1. 事件分类体系

根据 **NIST SP 800-61**，安全事件按类型分类：

| 事件类别 | 典型示例 | 严重程度 |
|:---|:---|:---:|
| 拒绝服务 (DoS/DDoS) | 流量攻击、应用层耗尽 | 中-高 |
| 恶意代码 | 勒索软件、蠕虫、木马 | 高-严重 |
| 未授权访问 | 撞库、越权操作、凭证泄露 | 高-严重 |
| 不当使用 | 数据泄露、内部威胁 | 中-高 |
| 侦察活动 | 端口扫描、漏洞探测 | 低-中 |
| 社会工程 | 钓鱼邮件、电话诈骗 | 中-高 |

### 2. 事件优先级矩阵

基于 **影响范围 × 紧急程度** 的四象限矩阵：

```text
                   紧急程度
                  低      高
         ┌────────┬────────┐
         │ Ⅲ类   │ Ⅰ类   │ 高
影响范围  │ 常规   │ 紧急   │
         ├────────┼────────┤
         │ Ⅳ类   │ Ⅱ类   │ 低
         │ 通知   │ 关注   │
         └────────┴────────┘
```

**优先级定义：**

| 等级 | 颜色 | SLA响应时间 | 描述 |
|:---:|:---:|:---:|:---|
| P1 — 严重 | 🔴 红色 | ≤15分钟 | 核心业务中断、大规模数据泄露 |
| P2 — 高 | 🟠 橙色 | ≤30分钟 | 重要系统受影响、敏感数据泄露 |
| P3 — 中 | 🟡 黄色 | ≤2小时 | 边缘系统受影响、疑似入侵 |
| P4 — 低 | 🟢 绿色 | ≤8小时 | 扫描探测、误报、合规通知 |

### 3. 事件评估模板

```text
=== 事件快速评估表单 ===

□ 事件发现时间:  ____-__-__ __:__ (UTC+8)
□ 报告来源: [SOC告警/用户报告/外部通知/自动化工具]
□ 事件类型: __________________
□ 影响系统: __________________
□ 影响用户数: ________________
□ 数据敏感性: [公开/内部/机密/绝密]
□ 是否涉及PII: [是/否]
□ 是否有合规通知义务: [是/否]
□ 初步定级: P[1-4]
□ 是否需要法务介入: [是/否]
```

### 4. 分级判定流程

```bash
# 伪代码 — 自动化分级逻辑
function classify_incident(alert):
    # 影响范围判定
    if alert.scope == "critical_business" or alert.users > 1000:
        impact = "high"
    elif alert.scope == "important_business" or alert.users > 100:
        impact = "medium"
    else:
        impact = "low"

    # 紧急程度判定
    if alert.type in ["ransomware", "data_breach", "active_exploit"]:
        urgency = "high"
    elif alert.type in ["malware", "unauthorized_access", "phishing"]:
        urgency = "medium"
    else:
        urgency = "low"

    # 矩阵定级
    if impact == "high" and urgency == "high":
        return "P1 - Critical"
    elif impact == "high" or urgency == "high":
        return "P2 - High"
    elif impact == "medium":
        return "P3 - Medium"
    else:
        return "P4 - Low"
```

### 5. 关键指标 (KPI) 定义

| 指标 | 定义 | 目标 |
|:---|:---|:---:|
| MTTR | 平均修复时间 (Mean Time to Respond) | < 1h (P1) |
| MTTD | 平均发现时间 (Mean Time to Detect) | < 1h |
| FPR | 误报率 (False Positive Rate) | < 5% |
| 闭环率 | 完成复盘的事件占比 | > 90% |

### 6. 常用工具

```bash
# TheHive — 开源SIRP平台
docker run -d --name thehive -p 9000:9000 thehiveproject/thehive:latest

# DFIR-IRIS — 事件响应案例管理
git clone https://github.com/dhondta/dfir-iris.git
cd dfir-iris && docker-compose up -d

# CERT/CC 工具包
# https://www.kb.cert.org/
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| TheHive | 开源事件响应平台 | https://thehive-project.org/ |
| DFIR-IRIS | 数字取证事件响应案例管理 | https://github.com/dhondta/dfir-iris |
| Shuffle | 开源SOAR（含Triage Workflow） | https://shuffler.io/ |
| CVSS Calculator | 通用漏洞评分 | https://www.first.org/cvss/calculator/3.1 |
| RTIR | 事件响应跟踪系统 | https://www.bestpractical.com/rtir/ |

## 参考资源

- [NIST SP 800-61 Rev 2 — Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [FIRST PSIRT — Incident Classification](https://www.first.org/standards/frameworks/psirts/)
- [SANS — Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)
- [ENISA — Incident Handling Template](https://www.enisa.europa.eu/)
