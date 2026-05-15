---
id: 24-004
title: "⚡ BAS攻击模拟平台 (Breach & Attack Simulation)"
category: 红蓝对抗
category_en: "Red/Blue Team"
difficulty: ★★★★
tools: "Atomic Red Team, Stratus Red Team, CALDERA, AttackIQ, Picus Security"
last_updated: 2025-07
tags: ["red-team", "blue-team", "purple-team", "bas", "adversary-simulation"]
subdomain: red-blue-team
nist_csf: ["DE.AE-02", "RS.AN-01", "ID.RM-01"]
mitre_attack: ["T1595", "T1562"]
---
# ⚡ BAS攻击模拟平台 (Breach & Attack Simulation)

## 概述

BAS（入侵与攻击模拟）平台通过持续自动化地模拟真实攻击行为，验证安全控制（防火墙、EDR、SIEM、WAF等）的有效性。相比传统渗透测试，BAS提供**持续验证**、**闭环度量**和**量化风险降低**的能力。

## 核心技能

### 1. Atomic Red Team 部署与使用

```powershell
# Windows Atomic Red Team 安装
# 安装模块
Install-Module -Name AtomicRedTeam -Scope CurrentUser -Force
Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force

# 安装原子测试（本地执行）
Install-AtomicRedTeam -Force -Confirm:$false

# 列出所有可用的ATT&CK技术
Get-AtomicTechnique | Select-Object Technique, TechniqueName

# 执行特定技术及所有测试变体
Invoke-AtomicTest T1059.001

# 执行特定测试编号
Invoke-AtomicTest T1059.001 -TestNumbers 1,2,3

# 使用自定义执行时间
Invoke-AtomicTest T1003.001 -TimeoutSeconds 120

# 获取预备条件（确保测试环境就绪）
Invoke-AtomicTest T1003.001 -GetPrereqs

# 不清理测试痕迹（用于蓝队验证检测持久性）
Invoke-AtomicTest T1053.005 -NoCleanup

# 指定特定测试路径
Invoke-AtomicTest T1003.001 -Path "C:\AtomicRedTeam\atomics\"

# 导出测试结果
Invoke-AtomicTest T1059.001 -ShowDetails | Export-Csv -Path atomic_results.csv

# Linux Atomic Red Team
pip3 install atomic-operator
atomic-operator run T1059.004  # Unix Shell
atomic-operator run T1566.002  # Spearphishing Link

# $include 执行矩阵测试
$attack_matrix = @(
    @{technique="T1059.001"; tests=@(1,2,3)}, # PowerShell
    @{technique="T1566.001"; tests=@(1)},       # Phishing
    @{technique="T1003.001"; tests=@(1,2)},     # Credential Dumping
    @{technique="T1053.005"; tests=@(1,2,3,4)}  # Scheduled Task
)

foreach ($item in $attack_matrix) {
    Write-Host "Executing $($item.technique)..." -ForegroundColor Yellow
    Invoke-AtomicTest $item.technique -TestNumbers $item.tests -TimeoutSeconds 60
    Start-Sleep 10  # 等待安全设备处理日志
    # TODO: 在此查询SIEM/EDR确认检测
}
```

### 2. Stratus Red Team (云攻击模拟)

```bash
# Stratus Red Team - 云原生攻击模拟工具
# 安装
wget https://github.com/DataDog/stratus-red-team/releases/latest/download/stratus-red-team_Linux_x86_64.tar.gz
tar -xzf stratus-red-team_*.tar.gz
sudo mv stratus-red-team /usr/local/bin/

# 初始化
stratus-red-team init

# 列出所有可用的云攻击技术
stratus-red-team list --platform aws

# 冷启动（显示攻击命令但不执行）
stratus-red-team warmup aws.credential-access.iam-credential-exfiltration

# 执行攻击
stratus-red-team attack aws.credential-access.iam-credential-exfiltration

# 清理
stratus-red-team cleanup aws.credential-access.iam-credential-exfiltration

# AWS S3数据泄露模拟
stratus-red-team attack aws.exfiltration.s3-backup-inventory

# AWS IAM横向移动
stratus-red-team attack aws.lateral-movement.s3-access-key-iam-role

# EC2 SSM远程执行
stratus-red-team attack aws.execution.ssm-send-command

# Azure攻击模拟
stratus-red-team list --platform azure
stratus-red-team attack azure.privilege-escalation.miRBAC

# GCP攻击模拟
stratus-red-team list --platform gcp
stratus-red-team attack gcp.execution.gcloud-ssh-instance

# 批量执行与报告
stratus-red-team attack --detonate aws.execution.ssm-send-command \
  --detonate aws.credential-access.iam-credential-exfiltration \
  --detonate aws.persistence.iam-backdoor-role
```

### 3. CALDERA BAS 持续验证

```python
#!/usr/bin/env python3
# CALDERA BAS自动化 - 持续安全控制验证

import requests
import json
from datetime import datetime, timedelta
import time

class BASOrchestrator:
    def __init__(self, caldera_url, api_key):
        self.base = f"{caldera_url}/api/v2"
        self.headers = {
            "KEY": api_key,
            "Content-Type": "application/json"
        }
        self.results_history = []
    
    def run_weekly_assessment(self, adversary_ids, group="bas"):
        """每周基线评估"""
        results = []
        for adv_id in adversary_ids:
            operation = {
                "name": f"BAS-{datetime.now().strftime('%Y%m%d')}-{adv_id[:8]}",
                "adversary": {"adversary_id": adv_id},
                "autonomous": 1,
                "group": group
            }
            resp = requests.post(
                f"{self.base}/operations", 
                json=operation, headers=self.headers
            )
            op_id = resp.json().get('id')
            
            # 等待执行完成
            time.sleep(60)
            
            # 获取结果
            op_resp = requests.get(
                f"{self.base}/operations/{op_id}",
                headers=self.headers
            )
            op_data = op_resp.json()
            
            detected = sum(1 for s in op_data.get('chain', []) if s.get('detected'))
            total = len(op_data.get('chain', []))
            
            results.append({
                'adversary_id': adv_id,
                'total_steps': total,
                'detected': detected,
                'detection_rate': detected/total if total > 0 else 0
            })
        
        self.results_history.append({
            'date': datetime.now().isoformat(),
            'results': results
        })
        return results
    
    def trend_analysis(self):
        """检测率趋势分析"""
        if len(self.results_history) < 2:
            return "需要更多数据点（至少2次评估）"
        
        latest = sum(
            r['detection_rate'] for r in self.results_history[-1]['results']
        ) / len(self.results_history[-1]['results'])
        
        previous = sum(
            r['detection_rate'] for r in self.results_history[-2]['results']
        ) / len(self.results_history[-2]['results'])
        
        change = latest - previous
        trend = "🟢 改善" if change > 0 else ("🔴 下降" if change < 0 else "⚪ 持平")
        
        print(f"上次检测率: {previous:.1%}")
        print(f"当前检测率: {latest:.1%}")
        print(f"变化趋势: {trend} ({change:+.1%})")
        
        return {"previous": previous, "latest": latest, "trend": trend}
```

### 4. BAS结果与安全控制映射

```yaml
# BAS结果映射表
bas_findings_mapping:
  - technique: "T1059.001 (PowerShell)"
    security_controls:
      - type: "EDR"
        vendor: "Microsoft Defender for Endpoint"
        detected: true
        alert_id: "alert-12345"
        response_time_seconds: 45
      - type: "SIEM"
        vendor: "Splunk ES"
        detected: true
        rule_name: "PowerShell Remote Download"
        response_time_seconds: 120
      - type: "WAF"
        vendor: "Cloudflare"
        detected: false
        note: "WAF未覆盖内网流量"
    
  - technique: "T1003.001 (LSASS Dump)"
    security_controls:
      - type: "EDR"
        vendor: "CrowdStrike Falcon"
        detected: true
        alert_id: "alert-67890"
        response_time_seconds: 30
      - type: "Windows Defender"
        vendor: "Microsoft"
        detected: false
        note: "实时保护未检测到Mimikatz"

# BAS覆盖矩阵
bas_coverage_matrix:
  total_techniques: 125
  fully_covered: 85    # EDR/SIEM/WAF全部检测
  partially_covered: 30  # 至少一个控制检测到
  not_covered: 10        # 所有控制均未检测
  coverage_rate: "92%"
  
  gaps:
    - technique: "T1053.005 (计划任务)"
      gap: "Linux cron持久化未监控"
      recommendation: "部署Linux审计规则监控cron文件变更"
    - technique: "T1021.002 (SMB横向移动)"
      gap: "内网SMB流量未启用IDS检测"
      recommendation: "在核心交换机启用SMB协议深度检测"
```

### 5. BAS 实施架构

```markdown
# BAS 持续验证架构

## 组件
1. **BAS控制器** (CALDERA/AttackIQ)
   - 调度攻击模拟
   - 汇总检测结果
   - 生成覆盖率报告

2. **执行节点** 
   - Windows Agent: 原子测试执行
   - Linux Agent: 原子测试执行
   - 云Agent: Stratus Red Team

3. **检测层**
   - EDR端点检测 (CrowdStrike/Defender/SentinelOne)
   - SIEM日志分析 (Splunk/Elastic)
   - 网络检测 (Zeek/Suricata)
   - 云检测 (GuardDuty/Azure Sentinel)

## 部署频次建议
| 检测类型 | 执行频次 | 覆盖范围 |
|:---------|:--------:|:---------|
| 关键控制验证 | 每日 | 10个核心ATT&CK技术 |
| 全覆盖验证 | 每周 | 所有安全控制 |
| 深度验证 | 每月 | 完整ATT&CK技术矩阵 |
| 事件驱动验证 | 事件后 | 相关技术专项检测 |

## KPI目标
- 检测覆盖率 > 80%
- 平均检测时间 < 5分钟
- 误报率 < 20%
- MTTR < 1小时（高危事件）
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Atomic Red Team | 免费开源原子测试库 | https://atomicredteam.io/ |
| Stratus Red Team | 云攻击模拟 | https://stratus-red-team.cloud/ |
| CALDERA | 自动化攻击模拟 | https://caldera.mitre.org/ |
| AttackIQ | 商业BAS平台 | https://attackiq.com/ |
| Picus Security | BAS验证平台 | https://www.picussecurity.com/ |
| SCYTHE | 攻击模拟平台 | https://scythe.io/ |

## 参考资源

- [MITRE ATT&CK BAS Guide](https://attack.mitre.org/resources/breach-and-attack-simulation/)
- [Gartner BAS Market Guide](https://www.gartner.com/en/documents/3986494)
- [CISA Continuous Diagnostic & Mitigation](https://www.cisa.gov/cdm)
- [NIST SP 800-115 — Security Testing](https://csrc.nist.gov/publications/detail/sp/800-115/final)
