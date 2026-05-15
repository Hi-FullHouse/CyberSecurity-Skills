---
id: "28-003"
title: "基于ATT&CK的威胁狩猎 (MITRE ATT&CK Threat Hunting)"
category: "威胁狩猎"
category_en: "Threat Hunting"
difficulty: "★★★★★"
tools: "ATT&CK Navigator, Red Canary, Atomic Red Team, Caldera, MITRE ATT&CK"
last_updated: "2026-05"
tags: [mitre-attack, threat-hunting, coverage-gap, adversary-emulation]
subdomain: threat-hunting
nist_csf: [DE.AE-01, DE.AE-03, ID.GV-04]
mitre_attack: [all]
---

# 基于ATT&CK的威胁狩猎 (MITRE ATT&CK Threat Hunting)

## 概述

MITRE ATT&CK 是全球公认的对抗性战术和技术知识库，为威胁狩猎提供结构化框架。本技能基于 ATT&CK v15+，覆盖攻击路径分析、覆盖度评估、热力图生成、对抗模拟验证等核心技术。通过将 ATT&CK 作为狩猎的"脚手架"，安全团队可以系统化识别防御盲区。

## 核心技能

### 1. ATT&CK 覆盖度评估

```bash
# 使用 ATT&CK Navigator 评估覆盖度

# 步骤 1: 导出企业 ATT&CK 层
# Navigator 支持: https://mitre-attack.github.io/attack-navigator/

# 步骤 2: 标记已有检测规则覆盖的技术
# - 绿色: 有检测规则
# - 黄色: 部分覆盖  
# - 红色: 无覆盖

# 步骤 3: 生成覆盖度报告

# 命令行生成覆盖层
python3 << 'EOF'
import json

# 创建 ATT&CK Navigator 层
layer = {
    "name": "Detection Coverage v1.0",
    "version": "4.5",
    "domain": "enterprise-attack",
    "description": "Current detection coverage assessment",
    "techniques": [
        # 为每个 ATT&CK 技术添加评分（1-100）
        {
            "techniqueID": "T1059.001",
            "score": 85,  # 85% 覆盖
            "comment": "PowerShell monitoring active"
        },
        {
            "techniqueID": "T1003.001",
            "score": 90,
            "comment": "LSASS access auditing deployed"
        },
        {
            "techniqueID": "T1562",
            "score": 20,
            "comment": "Limited defense evasion detection"
        }
    ],
    "gradient": {
        "colors": [
            "#00ff00",  # 高覆盖
            "#ffff00",  # 部分覆盖
            "#ff0000"   # 无覆盖
        ]
    }
}

with open('detection_coverage.json', 'w') as f:
    json.dump(layer, f, indent=2)
print("ATT&CK Navigator layer saved")
EOF
```

```python
# 计算覆盖度指标
def calculate_coverage(layer_file):
    with open(layer_file, 'r') as f:
        layer = json.load(f)
    
    techniques = layer["techniques"]
    total = len(techniques)
    
    # 按分数分级
    high = sum(1 for t in techniques if t["score"] >= 70)
    partial = sum(1 for t in techniques if 30 <= t["score"] < 70)
    none = sum(1 for t in techniques if t["score"] < 30)
    
    print(f"ATT&CK 覆盖度报告")
    print(f"{'='*40}")
    print(f"总技术数: {total}")
    print(f"高覆盖 (>70%): {high} ({high/total*100:.1f}%)")
    print(f"部分覆盖: {partial} ({partial/total*100:.1f}%)")
    print(f"无覆盖: {none} ({none/total*100:.1f}%)")
    print(f"综合覆盖率: {(high+partial*0.5)/total*100:.1f}%")
    
    # 识别急需改进的战术
    print(f"\ntop 5 低覆盖技术:")
    low = sorted(techniques, key=lambda t: t["score"])[:5]
    for t in low:
        print(f"  - {t['techniqueID']}: {t['score']} ({t.get('comment','')})")

calculate_coverage('detection_coverage.json')
```

### 2. 对抗模拟验证

```bash
# 使用 Atomic Red Team 验证检测覆盖
# Atomic Red Team 是开源的 ATT&CK 测试库

# 安装
git clone https://github.com/redcanaryco/atomic-red-team.git
cd atomic-red-team
pip install -r requirements.txt

# 测试特定技术 (T1059.001 — PowerShell)
Invoke-AtomicTest T1059.001

# 列出可用测试
Invoke-AtomicTest T1059.001 -ShowDetails

# 测试整个战术（Execution）
Invoke-AtomicTest -Tactics TA0002

# 无风险模式（仅查看，不执行）
Invoke-AtomicTest T1003.001 -CheckPrereqs

# 清理测试痕迹
Invoke-AtomicTest T1059.001 -Cleanup
```

```bash
# 使用 Caldera 进行自动化对抗模拟
# 部署 Caldera 服务器
git clone https://github.com/mitre/caldera.git
cd caldera
pip install -r requirements.txt
python server.py --insecure

# API: 创建对抗模拟
curl -X POST http://localhost:8888/api/rest/operation \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Credential Access Assessment",
    "adversary_id": "apt",
    "planner_id": "atomic",
    "group": "red"
  }' \
  -k | jq .

# 使用 caldera-cli
caldera -server http://localhost:8888 -api-key admin123 \
  schedule -a APT_Group -g agents
```

### 3. 攻击路径分析

```bash
# 构建攻击路径图

# 场景: 分析钓鱼→执行→横向移动→数据窃取的路径
attack_path = """
Initial Access (T1566.001 Phishing)
  │
  ▼
Execution (T1204.001 User Execution)
  │
  ▼
Defense Evasion (T1055 Process Injection)
  │
  ▼
Credential Access (T1003.001 LSASS Dump)
  │
  ▼
Lateral Movement (T1021.006 PowerShell Remoting)
  │
  ▼
Collection (T1005 Data from Local System)
  │
  ▼
Exfiltration (T1041 Exfiltration Over C2)
"""
```

```python
# 攻击路径覆盖分析
attack_chain = {
    "TA0001: Initial Access": {
        "techniques": {
            "T1566.001": {"name": "Spearphishing Attachment", "covered": True},
            "T1190": {"name": "Exploit Public-Facing App", "covered": False}
        }
    },
    "TA0002: Execution": {
        "techniques": {
            "T1059.001": {"name": "PowerShell", "covered": True},
            "T1204": {"name": "User Execution", "covered": False}
        }
    },
    "TA0008: Lateral Movement": {
        "techniques": {
            "T1021.006": {"name": "PowerShell Remoting", "covered": False},
            "T1550.002": {"name": "Pass the Hash", "covered": True}
        }
    },
    "TA0010: Exfiltration": {
        "techniques": {
            "T1041": {"name": "C2 Channel", "covered": False},
            "T1567": {"name": "Web Service", "covered": False}
        }
    }
}

# 分析覆盖最大路径
def analyze_largest_gap(chain):
    uncovered_paths = []
    for tactic, data in chain.items():
        uncovered = [tid for tid, info in data["techniques"].items() 
                     if not info["covered"]]
        if uncovered:
            uncovered_paths.append((tactic, uncovered))
    
    # 找出现有检测最可能遗漏的攻击路径
    print("=== 覆盖缺口分析 ===")
    for tactic, ucs in uncovered_paths:
        print(f"[{tactic}]")
        for tid in ucs:
            tech = chain[tactic]["techniques"][tid]
            print(f"  未覆盖: {tid} - {tech['name']}")
    
    # 优先建议
    print("\n=== 狩猎优先级建议 ===")
    print("1. 覆盖 Execution 路径 — 用户执行是初始攻击后的关键步骤")
    print("2. 补充 PowerShell 远程管理检测 — 典型的横向移动通道")
    print("3. 加强数据外传检测 — C2 通道全覆盖")

analyze_largest_gap(attack_chain)
```

### 4. ATT&CK 驱动 SIEM 搜索

```splunk
# Splunk — 检测 T1059.001 (PowerShell)
index=windows EventCode=4104 ScriptBlockText=*Net.WebClient*
| stats count by host, UserName
| eval mitre_technique="T1059.001"
| outputlookup powershell_downloads.csv

# 检测 T1003.001 (LSASS Dump)
index=windows EventCode=4656 ObjectName=*lsass.exe AccessMask=0x705
| eval mitre_technique="T1003.001"
| table _time, host, SubjectUserName, ProcessName

# 检测 T1078 (Valid Accounts — Anomalous Login)
index=windows EventCode=4624
| where LogonType=10 AND Account_Name LIKE "admin%"
| stats values(IpAddress) as source_ips by Account_Name
| where mvcount(source_ips) > 5
| eval mitre_technique="T1078.002"
```

```kql
// KQL — 检测 T1055 (Process Injection)
DeviceProcessEvents
| where FileName in~ ("rundll32.exe", "regsvr32.exe", "mshta.exe", "cscript.exe")
| where ProcessCommandLine has_any ("http://", "https://", "ftp://")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| join kind=leftanti (
    DeviceProcessEvents
    | where FileName in~ ("rundll32.exe", "regsvr32.exe")
    | where ProcessCommandLine has "C:\\Windows\\System32\\"
) on DeviceName, FileName
| summarize by DeviceName, FileName
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| ATT&CK Navigator | 覆盖度热力图与可视化 | https://mitre-attack.github.io/attack-navigator/ |
| Atomic Red Team | ATT&CK 测试自动化 | https://github.com/redcanaryco/atomic-red-team |
| Caldera | 自动化对抗模拟平台 | https://github.com/mitre/caldera |
| Red Canary | ATT&CK 覆盖度评估 | https://redcanary.com/ |
| MITRE ATT&CK Workbench | ATT&CK 内容管理 | https://github.com/mitre-attack/workbench |

## 参考资源

- [MITRE ATT&CK v15 Documentation](https://attack.mitre.org/)
- [ATT&CK Navigator Documentation](https://github.com/mitre-attack/attack-navigator)
- [Atomic Red Team — Getting Started](https://atomicredteam.io/)
- [Caldera — Automated Adversary Emulation](https://caldera.mitre.org/)
- [ATT&CK Coverage Gap Analysis — Medium](https://medium.com/mitre-attack)
- [Mapping to ATT&ACK — SOC Prime](https://socprime.com/)
