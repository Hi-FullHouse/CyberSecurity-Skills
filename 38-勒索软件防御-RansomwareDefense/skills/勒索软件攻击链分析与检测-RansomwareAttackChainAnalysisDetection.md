---
id: "38-001"
title: "勒索软件攻击链分析与检测 (Ransomware Attack Chain Analysis & Detection)"
category: "勒索软件防御"
category_en: "Ransomware Defense"
difficulty: "★★★★"
tools: "YARA, Sigma, Elastic, Splunk, Any.Run, Joe Sandbox"
last_updated: "2026-05"
tags: [ransomware, detection, attack-chain, behavior-analysis, threat-hunting]
subdomain: ransomware-defense
nist_csf: [DE.AE-02, DE.CM-01, DE.CM-04, RS.AN-01]
mitre_attack: [T1486, T1490, T1485, T1561]
---

# 勒索软件攻击链分析与检测 (Ransomware Attack Chain Analysis & Detection)

## 概述

勒索软件（Ransomware）是最具破坏性的网络威胁之一。理解勒索软件的攻击链，在每个阶段建立检测能力，是有效防御的关键。本技能覆盖勒索软件攻击生命周期分析、行为检测指标、YARA 规则编写和早期预警。

## 核心技能

### 1. 勒索软件攻击链

```python
"""勒索软件攻击链分析"""

class RansomwareKillChain:
    """勒索软件杀伤链"""
    
    STAGES = {
        "1. 初始访问": {
            "techniques": ["钓鱼邮件", "RDP 暴力破解", "漏洞利用", "恶意广告"],
            "indicators": ["新进程 {winword.exe→powershell.exe}", "RDP 登录爆发", "Web Shell"],
            "detection": ["Event ID 4688 进程创建", "RDP 登录审计", "WAF 告警"]
        },
        "2. 执行": {
            "techniques": ["PowerShell 脚本", "MSHTA 执行", "WMI 远程执行"],
            "indicators": ["powershell -enc", "mshta http://", "wmic process call create"],
            "detection": ["ScriptBlock Logging 4104", "网络连接到未知域名"]
        },
        "3. 持久化": {
            "techniques": ["计划任务", "服务创建", "注册表 Run Keys"],
            "indicators": ["schtasks /create", "sc create", "Run Key 修改"],
            "detection": ["Event ID 4698 计划任务", "Event ID 7045 服务创建"]
        },
        "4. 防御绕过": {
            "techniques": ["禁用 Defender", "删除卷影副本", "AMSI 绕过"],
            "indicators": ["DisableAntiSpyware", "vssadmin delete shadows", "AmsiEnable=0"],
            "detection": ["注册表防护监控", "Event ID 33 卷影删除"]
        },
        "5. 凭据访问": {
            "techniques": ["Mimikatz", "LSASS dump", "浏览器凭据窃取"],
            "indicators": ["procdump lsass", "sekurlsa::logonpasswords"],
            "detection": ["Event ID 10 (ProcessAccess)", "LSASS 异常访问"]
        },
        "6. 横向移动": {
            "techniques": ["SMB/WMI 远程执行", "RDP 跳跃", "PsExec"],
            "indicators": ["$admin 共享连接", "服务创建到远程", "新 RDP 会话"],
            "detection": ["Event ID 5140 共享访问", "Event ID 4624 LogonType 3"]
        },
        "7. 加密与勒索": {
            "techniques": ["文件加密", "卷影删除", "勒索信息投放"],
            "indicators": ["大量文件重命名", "README.txt 创建", "vssadmin"],
            "detection": ["文件扩展名变更", "大规模文件写入", "加密进程高 CPU"]
        }
    }
    
    @classmethod
    def detect_ransomware_stage(cls, events):
        """检测当前所处的攻击阶段"""
        detected_stages = {}
        
        for event in events:
            for stage, info in cls.STAGES.items():
                for indicator in info["indicators"]:
                    if indicator.lower() in str(event).lower():
                        if stage not in detected_stages:
                            detected_stages[stage] = []
                        detected_stages[stage].append(event)
        
        # 判断攻击进度
        stage_order = list(cls.STAGES.keys())
        max_stage = -1
        for stage in detected_stages:
            idx = stage_order.index(stage)
            if idx > max_stage:
                max_stage = idx
        
        progress = round((max_stage + 1) / len(stage_order) * 100, 1)
        
        return {
            "detected_stages": list(detected_stages.keys()),
            "current_stage": stage_order[max_stage] if max_stage >= 0 else "none",
            "attack_progress": progress,
            "estimated_time_to_impact": max(0, 100 - progress) * 0.5  # 估计分钟
        }

# 使用示例
chain = RansomwareKillChain()
events = [
    "powershell -enc SQBFAFgAIAAoAE4AZQB3...",
    "vssadmin delete shadows /all /quiet",
    "schtasks /create /tn Updater /tr calc.exe",
]
result = chain.detect_ransomware_stage(events)
print(f"Current stage: {result['current_stage']}")
print(f"Attack progress: {result['attack_progress']}%")
```

### 2. 勒索软件行为检测

```python
"""勒索软件行为检测"""

import re
from datetime import datetime

class RansomwareBehaviorDetector:
    """勒索软件行为检测引擎"""
    
    # 勒索软件行为指纹
    BEHAVIOR_FINGERPRINTS = {
        "mass_file_rename": {
            "pattern": "大量文件重命名（加密后缀）",
            "threshold": 50,  # 每分钟50个以上
            "severity": "CRITICAL"
        },
        "shadow_copy_delete": {
            "pattern": "删除卷影副本 (vssadmin, wmic)",
            "threshold": 1,
            "severity": "CRITICAL"
        },
        "ransom_note_create": {
            "pattern": "创建勒索说明文件 (*.README*, *.txt in root)",
            "threshold": 3,
            "severity": "HIGH"
        },
        "mass_file_write": {
            "pattern": "大量文件写入（加密输出）",
            "threshold": 100,
            "severity": "HIGH"
        },
        "extension_change": {
            "pattern": "文件扩展名批量变更（.encrypted, .lockbit, .crypt）",
            "threshold": 20,
            "severity": "CRITICAL"
        },
        "backup_delete": {
            "pattern": "备份文件删除 (wbadmin, bcdedit)",
            "threshold": 1,
            "severity": "CRITICAL"
        }
    }
    
    def __init__(self):
        self.behavior_counters = {k: 0 for k in self.BEHAVIOR_FINGERPRINTS}
        self.detection_log = []
    
    def analyze_file_operations(self, file_events):
        """分析文件操作行为"""
        alerts = []
        rename_count = 0
        new_extensions = set()
        
        for event in file_events:
            # 统计重命名
            if event.get("action") == "rename":
                rename_count += 1
                new_ext = event.get("new_extension", "")
                if new_ext:
                    new_extensions.add(new_ext)
            
            # 检测勒索说明
            fname = event.get("file_name", "").lower()
            if any(kw in fname for kw in ["readme", "how_to", "decrypt", "help"]):
                alerts.append({
                    "type": "ransom_note_create",
                    "severity": "HIGH",
                    "detail": f"勒索说明文件创建: {fname}"
                })
        
        # 批量加密检测
        if rename_count > self.BEHAVIOR_FINGERPRINTS["mass_file_rename"]["threshold"]:
            alerts.append({
                "type": "mass_file_rename",
                "severity": "CRITICAL",
                "detail": f"检测到 {rename_count} 个文件重命名",
                "extensions": list(new_extensions)
            })
        
        return alerts
    
    def analyze_process_behavior(self, process_events):
        """分析进程行为"""
        alerts = []
        
        for event in process_events:
            cmdline = event.get("command_line", "").lower()
            
            # 卷影删除
            if "vssadmin" in cmdline and "delete" in cmdline:
                alerts.append({
                    "type": "shadow_copy_delete",
                    "severity": "CRITICAL",
                    "detail": "卷影副本删除命令执行"
                })
            
            # 备份删除
            if "wbadmin" in cmdline and "delete" in cmdline:
                alerts.append({
                    "type": "backup_delete",
                    "severity": "CRITICAL",
                    "detail": "备份删除命令执行"
                })
            
            # 启动配置修改
            if "bcdedit" in cmdline and "recoveryenabled" in cmdline:
                alerts.append({
                    "type": "boot_config_change",
                    "severity": "HIGH",
                    "detail": "启动恢复配置修改"
                })
        
        return alerts
    
    def assess_overall_risk(self, alerts):
        """评估整体风险"""
        score = 0
        for alert in alerts:
            if alert["severity"] == "CRITICAL":
                score += 40
            elif alert["severity"] == "HIGH":
                score += 20
            elif alert["severity"] == "MEDIUM":
                score += 10
        
        return {
            "risk_score": min(score, 100),
            "alert_count": len(alerts),
            "critical_count": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
            "verdict": "ransomware" if score >= 60 else "suspicious" if score >= 30 else "monitoring"
        }

# 使用示例
detector = RansomwareBehaviorDetector()
file_alerts = detector.analyze_file_operations([
    {"action": "rename", "file_name": "doc1.docx", "new_extension": ".encrypted"},
    {"action": "create", "file_name": "README_LOCKBIT.txt"},
])
proc_alerts = detector.analyze_process_behavior([
    {"command_line": "vssadmin delete shadows /all /quiet"},
])

all_alerts = file_alerts + proc_alerts
risk = detector.assess_overall_risk(all_alerts)
print(f"Risk: {risk['risk_score']}/100 — Verdict: {risk['verdict']}")
```

### 3. YARA 规则与检测

```yaml
# YARA 规则 — 勒索软件检测

# LockBit 3.0 检测
rule LockBit_Ransomware {
    meta:
        description = "Detect LockBit 3.0 ransomware"
        author = "CyberSecurity-Skills"
        date = "2026-05"
        reference = "https://attack.mitre.org/software/S1112/"
    strings:
        $mutex = "LockBit_3_" ascii wide nocase
        $note = "LockBit" ascii wide nocase
        $enc_ext = ".lockbit" ascii wide nocase
        $b1 = "bcrypt" ascii wide nocase
        $b2 = "BCrypt" ascii wide nocase
        $b3 = "NtSetInformationFile" wide
        $s1 = "\\!!\\" fullword
    condition:
        3 of ($mutex, $note, $enc_ext) or (2 of ($b*)) and $s1
}

# 勒索软件通用检测
rule Ransomware_Generic_Behavior {
    meta:
        description = "Generic ransomware behavioral detection"
        author = "CyberSecurity-Skills"
    strings:
        $vss = "vssadmin" nocase
        $bcd = "bcdedit" nocase
        $wbadmin = "wbadmin" nocase
        $shadow = "shadows" nocase
        $rec = "recoveryenabled" nocase
        $win_bin = "\\Windows\\" nocase
        $enc_ext1 = ".encrypted" nocase
        $enc_ext2 = ".crypt" nocase
        $enc_ext3 = ".lockbit" nocase
        $enc_ext4 = ".ryuk" nocase
    condition:
        ($vss or $bcd or $wbadmin) and
        ($shadow or $rec) and
        ($enc_ext1 or $enc_ext2 or $enc_ext3 or $enc_ext4)
        and $win_bin
}
```

```python
"""Sigma 规则 — 勒索软件检测"""

ransomware_sigma_rules = """
# 1. 卷影副本删除检测
title: Volume Shadow Copy Deletion
id: 12345678-1234-1234-1234-123456789001
status: production
description: Detects deletion of volume shadow copies
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'vssadmin delete shadows'
      - 'wmic shadowcopy delete'
      - 'vssadmin resize shadowstorage'
  condition: selection
level: critical

# 2. 批量文件扩展名变更检测
title: Mass File Extension Change
id: 12345678-1234-1234-1234-123456789002
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|endswith:
      - '.encrypted'
      - '.lockbit'
      - '.crypt'
      - '.ryuk'
      - '.enc'
  condition: selection | count() > 50 by ComputerName
level: high
"""
```

### 4. 勒索软件家族分析

```python
"""勒索软件家族知识库"""

class RansomwareFamilyDB:
    """勒索软件家族数据库"""
    
    FAMILIES = {
        "LockBit 3.0": {
            "type": "RaaS",
            "extensions": [".lockbit"],
            "notes": ["README_LOCKBIT.txt", "LockBit_Recovery.txt"],
            "c2_protocol": "HTTPS",
            "initial_access": ["Phishing", "RDP", "VPN"],
            "mitre_id": "S1112"
        },
        "BlackCat (ALPHV)": {
            "type": "RaaS (Rust)",
            "extensions": [".enc"],
            "notes": ["README.enc.txt"],
            "c2_protocol": "TOR + HTTPS",
            "initial_access": ["Phishing", "Exploit"],
            "mitre_id": "S1068"
        },
        "Clop": {
            "type": "RaaS",
            "extensions": [".clop"],
            "notes": ["ReadMe.txt"],
            "c2_protocol": "HTTPS",
            "initial_access": ["Exploit (SysAid, GoAnywhere)"],
            "mitre_id": "S1011"
        },
        "REvil (Sodinokibi)": {
            "type": "RaaS",
            "extensions": [".sodinokibi"],
            "notes": ["_readme.txt", "README.txt"],
            "c2_protocol": "TOR",
            "initial_access": ["Phishing", "Exploit"],
            "mitre_id": "S0496"
        },
        "Ryuk": {
            "type": "Targeted",
            "extensions": [".ryuk"],
            "notes": ["RyukReadMe.txt"],
            "c2_protocol": "HTTPS",
            "initial_access": ["Phishing → TrickBot → Ryuk"],
            "mitre_id": "S0446"
        },
        "Conti": {
            "type": "RaaS",
            "extensions": [".CONTI"],
            "notes": ["CONTIRECOVER.TXT", "CONTI_README.txt"],
            "c2_protocol": "HTTPS",
            "initial_access": ["Phishing", "RDP"],
            "mitre_id": "S0575"
        }
    }
    
    @classmethod
    def identify_family(cls, indicators):
        """基于指标识别勒索软件家族"""
        matches = []
        
        for family, info in cls.FAMILIES.items():
            score = 0
            
            # 文件扩展名匹配
            for ext in info["extensions"]:
                if ext in indicators.get("extensions", []):
                    score += 40
            
            # 勒索说明匹配
            for note in info["notes"]:
                if note.lower() in str(indicators.get("notes", [])).lower():
                    score += 30
            
            if score > 0:
                matches.append({
                    "family": family,
                    "confidence": min(score, 100),
                    "type": info["type"],
                    "c2": info["c2_protocol"]
                })
        
        return sorted(matches, key=lambda x: x["confidence"], reverse=True)

# 使用示例
matcher = RansomwareFamilyDB()
results = matcher.identify_family({
    "extensions": [".lockbit"],
    "notes": ["README_LOCKBIT.txt"]
})
for r in results:
    print(f"{r['family']}: {r['confidence']}% confidence")
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| YARA | 恶意软件模式匹配 | https://virustotal.github.io/yara/ |
| Any.Run | 交互式恶意软件分析 | https://any.run/ |
| Joe Sandbox | 深度恶意软件分析 | https://www.joesandbox.com/ |
| Ransomwhere | 勒索软件追踪 | https://ransomwhe.re/ |
| ID Ransomware | 勒索软件识别 | https://id-ransomware.malwarehunterteam.com/ |

## 参考资源

- [MITRE ATT&CK — Ransomware](https://attack.mitre.org/software/?domain=enterprise&q=ransomware)
- [SANS Ransomware Detection Guide](https://www.sans.org/white-papers/ransomware/)
- [CISA Ransomware Guide](https://www.cisa.gov/ransomware)
- [NoMoreRansom Project](https://www.nomoreransom.org/)
- [Ransomware Behavioral Detection — Elastic](https://www.elastic.co/security-labs/ransomware-behavioral-detection)
