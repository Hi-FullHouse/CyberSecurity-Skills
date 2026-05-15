---
id: "28-001"
title: "威胁狩猎方法论与假设驱动 (Threat Hunting Methodology & Hypothesis)"
category: "威胁狩猎"
category_en: "Threat Hunting"
difficulty: "★★★★"
tools: "Splunk, Elastic, Jupyter, Sigma, ATT&CK Navigator"
last_updated: "2026-05"
tags: [threat-hunting, hypothesis, methodology, ioc, analytics]
subdomain: threat-hunting
nist_csf: [DE.AE-01, DE.AE-02, DE.DP-01]
mitre_attack: [T1046, T1057, T1082, T1087, T1482]
---

# 威胁狩猎方法论与假设驱动 (Threat Hunting Methodology & Hypothesis)

## 概述

威胁狩猎（Threat Hunting）是在传统检测规则触发之前，主动搜索网络中潜在威胁的过程。其核心是基于假设驱动（Hypothesis-Driven）的方法论，利用威胁情报、ATT&CK 框架、异常分析等技术，在攻击者造成实质性损害前发现其踪迹。本技能覆盖狩猎全流程：假设生成 → 数据采集 → 分析验证 → 闭环改进。

## 核心技能

### 1. 狩猎假设生成

```bash
# 基于 ATT&CK 技术生成狩猎假设的 4 种来源

# 来源 1: 威胁情报驱动
# 新发现 APT 组使用 T1055 进程注入 → 假设环境中存在类似行为

# 来源 2: 数据分析驱动
# 基线异常：DNS 查询量突然增长 300% → 假设存在 DNS 隧道

# 来源 3: 已知漏洞驱动
# Log4j 漏洞爆发 → 假设内网存在扫描和利用尝试

# 来源 4: 红队反馈驱动
# 红队成功通过 Kerberoasting 提权 → 假设真实攻击者也会使用
```

```python
# 狩猎假设文档模板
hunt_hypothesis = {
    "id": "HT-2026-001",
    "title": "检测异常 PowerShell 调用",
    "source": "threat_intel",  # threat_intel / data_driven / vuln / red_team
    "mitre_technique": ["T1059.001"],
    "hypothesis": "攻击者可能通过 PowerShell 下载执行恶意载荷",
    "data_sources": ["4688 (Process Creation)", "4104 (Script Block Logging)"],
    "indicators": [
        "powershell.exe -enc *",
        "IEX (New-Object Net.WebClient).DownloadString*",
        "powershell.exe -WindowStyle Hidden *"
    ],
    "validation": "search_siem",
    "status": "active"
}
```

### 2. 狩猎执行流程

```bash
# 狩猎流程 PDCA 循环

# Phase 1: 准备 (Plan)
# - 确定狩猎目标（如：横向移动技术）
# - 筛选数据源（Windows Event Logs, Network Logs, EDR Telemetry）
# - 定义 IOC 和狩猎指标

# Phase 2: 执行 (Do)
# 使用 Elastic EQL 搜索横向移动
curl -X POST "localhost:9200/_search" -H 'Content-Type: application/json' -d '{
  "query": {
    "bool": {
      "filter": [
        {"term": {"event.code": "4624"}},
        {"term": {"logon.type": "3"}},
        {"range": {"@timestamp": {"gte": "now-7d"}}}
      ]
    }
  }
}' | jq '.hits.hits[] | {user: .source_data.TargetUserName, ip: .source_data.IpAddress, time: ._source.@timestamp}'

# Phase 3: 分析 (Check)
# - 验证真阳性 vs 假阳性
# - 关联多个数据源
# - 时间线重建

# Phase 4: 改进 (Act)
# - 将确认的狩猎模式转化为检测规则
# - 更新 SIEM 告警
# - 生成狩猎报告
```

```splunk
# Splunk 狩猎搜索示例 — 检测异常 RDP 登录
index=windows EventCode=4624 LogonType=10
| stats count by Account_Name, WorkstationName, IpAddress
| where count > 10
| eval severity=if(count > 50, "critical", "high")
| sort -count

# 检测多个用户从同一 IP 登录
index=windows EventCode=4624
| stats dc(Account_Name) as user_count by IpAddress
| where user_count > 5
| eval alert="multiple_users_single_source"
```

### 3. 狩猎成熟度与度量

```bash
# 狩猎成熟度模型（Hunting Maturity Model - HMM）

# HMM 0: 初始级 — 仅依靠自动化告警
# HMM 1: 最小级 — 基于 IOC 的搜索
# HMM 2: 规程级 — 基于 TTP 的数据分析
# HMM 3: 创新级 — 自定义数据模型和分析
# HMM 4: 领先级 — 预测性狩猎和自动化

# 狩猎 KPI 指标
# - 狩猎循环时间：从假设到验证的时长
# - 真阳性率：每 10 小时狩猎发现的真实威胁数
# - 检测覆盖率：环境中 ATT&CK 技术的覆盖百分比
# - 狩猎转化率：狩猎结果 → 检测规则的比例

# 狩猎结果记录
cat > hunt_report_template.md << 'EOF'
# 威胁狩猎报告

## 狩猎信息
- 狩猎 ID: HT-2026-001
- 分析师:
- 日期范围: 2026-05-01 ~ 2026-05-07
- 假设: 
- ATT&CK 技术: 

## 方法论
- 数据源: [EDR, 网络流, DNS, 代理]
- 分析工具: [Splunk, Python, Kibana]
- 搜索查询:

## 发现

| 时间 | 主机 | 用户 | IOC | 可信度 | 操作 |
|------|------|------|-----|:-----:|------|
|      |      |      |     | 高/中/低 | 隔离/调查/忽略 |

## 结论
- 真阳性数: 
- 误报数: 
- 转化为检测规则的狩猎结果数: 
- 建议: 
EOF
```

### 4. 自动化狩猎与工具链

```python
#!/usr/bin/env python3
"""自动化狩猎脚本示例"""

import json
import requests
from datetime import datetime, timedelta

class ThreatHuntBot:
    def __init__(self, elastic_host="localhost:9200"):
        self.es = elastic_host
        self.hunts = []
    
    def run_hunt(self, hypothesis, query, time_range_hours=72):
        """执行单个狩猎任务"""
        since = (datetime.now() - timedelta(hours=time_range_hours)).isoformat()
        
        # 在 Elasticsearch 中执行
        resp = requests.post(f"http://{self.es}/_search", json={
            "query": {
                "bool": {
                    "must": query,
                    "filter": {"range": {"@timestamp": {"gte": since}}}
                }
            }
        })
        
        results = resp.json()
        hits = results.get("hits", {}).get("hits", [])
        
        self.hunts.append({
            "hypothesis": hypothesis,
            "timestamp": datetime.now().isoformat(),
            "total_hits": len(hits),
            "alerts": self._analyze(hits)
        })
        return self.hunts[-1]
    
    def _analyze(self, hits):
        """对匹配结果进行自动化分级"""
        alerts = []
        for hit in hits:
            source = hit.get("_source", {})
            score = hit.get("_score", 0)
            if score > 5:
                alerts.append({
                    "severity": "high",
                    "host": source.get("host"),
                    "user": source.get("user", {}).get("name"),
                    "action": "manual_review"
                })
        return alerts
    
    def generate_report(self):
        """生成狩猎概要报告"""
        return {
            "total_hunts": len(self.hunts),
            "total_alerts": sum(len(h["alerts"]) for h in self.hunts),
            "recommendations": [
                "高风险狩猎结果应立即转化为检测规则",
                "周期性狩猎应覆盖所有 ATT&CK 战术"
            ]
        }

# 使用示例
bot = ThreatHuntBot()
result = bot.run_hunt(
    hypothesis="攻击者可能使用 PowerShell 下载恶意文件",
    query={"match": {"process.name": "powershell.exe"}}
)
print(json.dumps(result, indent=2))
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| ATT&CK Navigator | 威胁狩猎覆盖度评估 | https://mitre-attack.github.io/attack-navigator/ |
| Sigma | 通用检测规则格式 | https://github.com/SigmaHQ/sigma |
| Elastic Stack | SIEM 与日志分析 | https://www.elastic.co/security |
| Splunk SPL | 安全搜索与查询 | https://www.splunk.com/ |
| Jupyter Notebook | 交互式数据分析 | https://jupyter.org/ |
| HELK | 狩猎 ELK 平台 | https://github.com/Cyb3rWard0g/HELK |

## 参考资源

- [SQRLL: Threat Hunting Maturity Model](https://www.threathunting.net/)
- [MITRE ATT&CK — Threat Hunting](https://attack.mitre.org/resources/threat-hunting/)
- [Hunting with Elastic — Elastic Guide](https://www.elastic.co/guide/en/security/current/hunting-with-elastic.html)
- [Sigma HQ — Sigma Detection Rules](https://github.com/SigmaHQ/sigma)
- [NIST SP 800-150 — Cyber Threat Hunting](https://csrc.nist.gov/publications/detail/sp/800-150/final)
- [威胁狩猎方法论 — 奇安信威胁情报中心](https://ti.qianxin.com/)
