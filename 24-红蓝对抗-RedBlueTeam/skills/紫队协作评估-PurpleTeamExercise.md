---
id: 24-003
title: "🟣 紫队协作评估 (Purple Team Exercise)"
category: 红蓝对抗
category_en: "Red/Blue Team"
difficulty: ★★★★★
tools: "CALDERA, SCYTHE, AttackIQ, Atomic Red Team, PurpleSharp"
last_updated: 2025-07
tags: ["red-team", "blue-team", "purple-team", "bas", "adversary-simulation"]
subdomain: red-blue-team
nist_csf: ["DE.AE-02", "RS.AN-01", "ID.RM-01"]
mitre_attack: ["T1595", "T1562"]
---
# 🟣 紫队协作评估 (Purple Team Exercise)

## 概述

紫队是红队和蓝队的协作机制，通过共同演练和验证安全控制有效性，实现防御能力的持续提升。紫队评估关注**检测覆盖验证**、**响应流程检验**和**防御能力度量**。

## 核心技能

### 1. 紫队评估框架

```python
# 紫队评估流程
purple_team_framework = {
    "pre_engagement": {
        "activities": [
            "选择MITRE ATT&CK技术",
            "定义检测验证目标",
            "准备检测工具和数据源",
            "建立基线指标"
        ]
    },
    "execution": {
        "activities": [
            "红队执行攻击技术",
            "蓝队实时监控检测",
            "记录检测时间和完整性",
            "识别检测盲区"
        ]
    },
    "evaluation": {
        "activities": [
            "验证检测覆盖率",
            "评估响应有效性",
            "识别检测缺口",
            "生成检测覆盖率矩阵"
        ]
    },
    "improvement": {
        "activities": [
            "创建新检测规则",
            "优化现有规则",
            "更新SOP",
            "建立持续验证机制"
        ]
    }
}

# 检测覆盖率矩阵
class DetectionCoverageMatrix:
    def __init__(self):
        self.tactics = {
            "initial_access": {"T1566.001": False, "T1078": False},
            "execution": {"T1059.001": False, "T1059.003": False, "T1204": False},
            "persistence": {"T1547.001": False, "T1053.005": False, "T1546.003": False},
            "privilege_escalation": {"T1068": False, "T1055": False},
            "defense_evasion": {"T1562.001": False, "T1070": False, "T1112": False},
            "credential_access": {"T1003.001": False, "T1003.002": False, "T1555": False},
            "discovery": {"T1087": False, "T1482": False, "T1069": False},
            "lateral_movement": {"T1021.001": False, "T1021.002": False, "T1550.002": False},
            "collection": {"T1114": False, "T1005": False},
            "command_and_control": {"T1071.001": False, "T1573": False},
            "exfiltration": {"T1048": False, "T1567": False}
        }
    
    def update_coverage(self, technique, detected):
        for tactic in self.tactics:
            if technique in self.tactics[tactic]:
                self.tactics[tactic][technique] = detected
    
    def coverage_report(self):
        total = sum(len(techs) for techs in self.tactics.values())
        detected = sum(
            sum(1 for d in techs.values() if d)
            for techs in self.tactics.values()
        )
        
        print(f"ATT&CK技术总数: {total}")
        print(f"已覆盖: {detected} ({detected/total*100:.1f}%)")
        print(f"未覆盖: {total - detected} ({(total-detected)/total*100:.1f}%)")
        
        return {
            "total": total,
            "detected": detected,
            "coverage_rate": f"{detected/total*100:.1f}%"
        }
```

### 2. Atomic Red Team 紫队验证

```powershell
# 紫队使用Atomic Red Team进行检测验证

# 安装Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -Force -Confirm:$false

# 验证检测 - 模拟PowerShell下载（T1059.001）
Invoke-AtomicTest T1059.001 -TestNumbers 1 -TimeoutSeconds 60

# 蓝队观察SIEM/EDR是否产生告警
# Splunk搜索验证
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational"
EventID=4103 ScriptBlockText="*Net.WebClient*" 

# 验证检测 - 模拟Mimikatz（T1003.001）
Invoke-AtomicTest T1003.001 -TestNumbers 1

# 验证检测 - 模拟计划任务持久化（T1053.005）
Invoke-AtomicTest T1053.005 -TestNumbers 1

# 批量执行ATT&CK技术矩阵
$technique_list = @(
    "T1059.001",  # PowerShell
    "T1566.001",  # Spearphishing Attachment
    "T1003.001",  # LSASS Memory
    "T1021.002",  # SMB/Admin Shares
    "T1550.002",  # Pass the Hash
    "T1070.004"   # Clear Event Log
)

foreach ($tech in $technique_list) {
    Write-Host "=== 测试: $tech ===" -ForegroundColor Yellow
    $result = Invoke-AtomicTest $tech -TestNumbers 1 -TimeoutSeconds 120
    Start-Sleep 5  # 等待检测系统处理日志
    # 蓝队在此检查检测系统是否产生告警
    Write-Host "检测结果: " -NoNewline
    # TODO: 查询SIEM确认检测状态
}
```

### 3. CALDERA 紫队自动化评估

```python
#!/usr/bin/env python3
# CALDERA API - 紫队自动化评估

import requests
import json
import time

class PurpleTeamAutomation:
    def __init__(self, server_url, api_key):
        self.base = f"{server_url}/api/v2"
        self.headers = {"KEY": api_key, "Content-Type": "application/json"}
    
    def create_assessment(self, name, adversary_id, objective_id, group="purple"):
        operation_data = {
            "name": name,
            "adversary": {"adversary_id": adversary_id},
            "objective": {"id": objective_id},
            "autonomous": 1,
            "group": group
        }
        resp = requests.post(
            f"{self.base}/operations",
            json=operation_data,
            headers=self.headers
        )
        return resp.json().get('id')
    
    def get_detection_results(self, operation_id):
        """获取每个攻击步骤的检测结果"""
        resp = requests.get(
            f"{self.base}/operations/{operation_id}",
            headers=self.headers
        )
        operation = resp.json()
        
        results = []
        for step in operation.get('chain', []):
            if step.get('status') == 0:  # 成功执行
                results.append({
                    'technique': step.get('ability', {}).get('technique_id'),
                    'name': step.get('ability', {}).get('name'),
                    'executed_at': step.get('finish'),
                    'detected': step.get('detected', False),
                    'detection_time': step.get('detection_time'),
                    'alerts': step.get('alerts', [])
                })
        return results
    
    def generate_coverage_report(self, operation_id):
        """生成检测覆盖率报告"""
        results = self.get_detection_results(operation_id)
        
        detected = sum(1 for r in results if r['detected'])
        missed = len(results) - detected
        
        print(f"\n=== 紫队评估报告 ===")
        print(f"执行技术数: {len(results)}")
        print(f"已检测: {detected}")
        print(f"未检测: {missed}")
        print(f"检测率: {detected/len(results)*100:.1f}%\n")
        
        if missed > 0:
            print("未检测到的技术:")
            for r in results:
                if not r['detected']:
                    print(f"  ❌ {r['technique']} - {r['name']}")
        
        return {"detected": detected, "missed": missed, "rate": f"{detected/len(results)*100:.1f}%"}

# 使用示例
# pt = PurpleTeamAutomation("http://localhost:8888", "admin")
# op_id = pt.create_assessment("Q3紫队评估", "adversary-APT29", "objective-e6b2f2")
# time.sleep(300)  # 等待执行完成
# report = pt.generate_coverage_report(op_id)
```

### 4. 检测工程 - 规则调优流程

```python
# 检测规则有效性评估
class RuleEffectiveness:
    def __init__(self):
        self.rules = {}
    
    def add_rule(self, name, tp=0, fp=0, fn=0):
        """TP=真阳性, FP=假阳性, FN=假阴性"""
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        self.rules[name] = {
            "tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1_score": round(f1, 3),
            "action": self._recommend_action(f1, fp/tp if tp > 0 else float('inf'))
        }
    
    def _recommend_action(self, f1, fp_ratio):
        if f1 < 0.5:
            return "需要重写"
        elif f1 < 0.8:
            return "需要优化"
        elif fp_ratio > 0.3:
            return "需降低误报"
        return "稳定"
    
    def optimization_report(self):
        print("=== 检测规则有效性报告 ===")
        print(f"{'规则名':30s} {'F1分数':8s} {'精确率':8s} {'召回率':8s} {'建议操作':12s}")
        print("-"*66)
        for name, stats in sorted(self.rules.items(), key=lambda x: x[1]['f1_score']):
            print(f"{name:30s} {stats['f1_score']:8.3f} {stats['precision']:8.3f} {stats['recall']:8.3f} {stats['action']:12s}")

# 使用示例
re = RuleEffectiveness()
re.add_rule("PowerShell Download", tp=45, fp=3, fn=2)
re.add_rule("Mimikatz Detection", tp=30, fp=1, fn=5)
re.add_rule("RDP Bruteforce", tp=100, fp=50, fn=10)
re.optimization_report()
```

### 5. 紫队成熟度评估

| 级别 | 名称 | 特征 | 检测率目标 |
|:---:|:---|:---|:---:|
| L1 | 初始级 | 无紫队流程，红蓝独立运营 | <30% |
| L2 | 合作级 | 定期紫队会议，手动验证 | 30-50% |
| L3 | 标准化 | 制度化紫队评估，检测矩阵管理 | 50-70% |
| L4 | 量化级 | 自动化验证，KPI驱动改进 | 70-85% |
| L5 | 优化级 | 持续验证，预测性防御 | >85% |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| CALDERA | 自动化紫队评估 | https://caldera.mitre.org/ |
| SCYTHE | 攻击模拟平台 | https://scythe.io/ |
| AttackIQ | 安全验证平台 | https://attackiq.com/ |
| PurpleSharp | Windows检测验证 | https://github.com/mvelazc0/PurpleSharp |
| Atomic Red Team | 免费原子测试 | https://atomicredteam.io/ |

## 参考资源

- [MITRE ATT&CK Detection Engineering](https://attack.mitre.org/resources/detection-engineering/)
- [Purple Team Exercise Methodology](https://www.sans.org/purple-team/)
- [NIST SP 800-115 — Technical Security Testing](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- [Detection Coverage Matrix Guide](https://detection-coverage.mitre.org/)
