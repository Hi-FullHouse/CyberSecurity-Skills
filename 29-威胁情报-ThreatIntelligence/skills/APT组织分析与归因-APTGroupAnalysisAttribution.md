---
id: "29-003"
title: "APT组织分析与归因 (APT Group Analysis & Attribution)"
category: "威胁情报"
category_en: "Threat Intelligence"
difficulty: "★★★★★"
tools: "ATT&CK Navigator, MISP, Malpedia, VirusTotal, PassiveTotal"
last_updated: "2026-05"
tags: [apt, attribution, threat-actor, intelligence, malware-analysis]
subdomain: threat-intelligence
nist_csf: [ID.RA-02, RS.AN-01, DE.AE-05]
mitre_attack: [T1587, T1588, T1593, T1594]
---

# APT组织分析与归因 (APT Group Analysis & Attribution)

## 概述

APT（高级持续威胁）组织分析是威胁情报的最高阶能力，涉及对手 TTP 分析、恶意软件关联、基础设施追踪和归因推理。本技能覆盖 APT 组织画像构建、攻击活动图谱分析、归因证据链和报告生成。参考 MITRE ATT&CK 的 140+ 个已知威胁行为体数据。

## 核心技能

### 1. APT 组织画像

```python
"""APT 组织画像构建"""

import json

class APTProfile:
    """APT 组织信息模型"""
    
    def __init__(self, group_name):
        self.group_name = group_name
        self.aliases = []
        self.origin = ""
        self.motivation = "espionage"
        self.targeted_sectors = []
        self.targeted_regions = []
        self.techniques = []
        self.tools = []
        self.malware = []
        self.known_ops = []
        self.timeline = {}
    
    @classmethod
    def from_mitre(cls, group_id):
        """从 MITRE ATT&CK 数据加载"""
        profile = cls(group_id)
        # 实际实现调用 MITRE CTI API
        # profile_data = mitre_api.get_group(group_id)
        return profile
    
    def to_misp_galaxy(self):
        """导出为 MISP Galaxy 格式"""
        return {
            "name": self.group_name,
            "meta": {
                "aliases": self.aliases,
                "country": self.origin,
                "motivation": self.motivation,
                "targeted_sectors": self.targeted_sectors,
                "targeted_countries": self.targeted_regions,
                "mitre_attack_id": self.techniques[:10],
                "tools": self.tools,
                "malware": self.malware
            }
        }
    
    def coverage_report(self):
        """生成 ATT&CK 覆盖报告"""
        tactics = set()
        for tech in self.techniques:
            tactics.add(tech.split('.')[0] if '.' in tech else tech)
        
        print(f"=== {self.group_name} 分析报告 ===")
        print(f"别号: {', '.join(self.aliases)}")
        print(f"起源: {self.origin}")
        print(f"动机: {self.motivation}")
        print(f"目标行业: {', '.join(self.targeted_sectors)}")
        print(f"使用技术: {len(self.techniques)} 个 ATT&CK 技术")
        print(f"覆盖战术: {len(tactics)} 个")
        print(f"使用工具: {len(self.tools)} 个")

# 示例: Lazarus Group
lazarus = APTProfile("Lazarus Group")
lazarus.aliases = ["HIDDEN COBRA", "ZINC", "Guardians of Peace"]
lazarus.origin = "North Korea"
lazarus.motivation = "financial-crime, espionage"
lazarus.targeted_sectors = ["finance", "cryptocurrency", "government", "media"]
lazarus.targeted_regions = ["Global", "South Korea", "US"]
lazarus.tools = ["Cobra Venom", "ELECTRICFISH", "Maui Ransomware"]
lazarus.malware = ["WannaCry", "Fallchill", "Bankshot"]
lazarus.coverage_report()
```

### 2. 攻击活动图谱分析

```python
"""攻击活动时间线构建"""

from datetime import datetime

class AttackCampaign:
    """攻击活动分析"""
    
    def __init__(self, name):
        self.name = name
        self.actor = ""
        self.timeline = []
        self.intrusion_set = []
        self.ttps = []
        self.victims = []
    
    def add_event(self, date, event_type, description, confidence="medium"):
        """添加时间线事件"""
        self.timeline.append({
            "date": date.isoformat() if isinstance(date, datetime) else date,
            "type": event_type,
            "description": description,
            "confidence": confidence
        })
    
    def kill_chain(self):
        """生成 Cyber Kill Chain 映射"""
        chain = {
            "Reconnaissance": [],
            "Weaponization": [],
            "Delivery": [],
            "Exploitation": [],
            "Installation": [],
            "C2": [],
            "Actions": []
        }
        
        for ttp in self.ttps:
            chain.get(ttp.get("phase", "Actions"), []).append(ttp)
        
        return chain
    
    def generate_report(self):
        """生成活动报告"""
        print(f"\n{'='*60}")
        print(f"攻击活动报告: {self.name}")
        print(f"行为体: {self.actor}")
        print(f"{'='*60}")
        
        print("\n时间线:")
        for event in sorted(self.timeline, key=lambda x: x["date"]):
            print(f"  [{event['date']}] {event['type']}: {event['description']}")
        
        print("\nTTP 覆盖:")
        for phase, ttps in self.kill_chain().items():
            if ttps:
                print(f"  {phase}: {len(ttps)} techniques")
        
        print("\n受影响组织:")
        for v in self.victims:
            print(f"  - {v}")

# 示例
campaign = AttackCampaign("Operation DreamJob")
campaign.actor = "Lazarus Group"
campaign.add_event("2025-06", "initial_access", "LinkedIn 钓鱼招聘信息投递")
campaign.add_event("2025-07", "execution", "诱导安装恶意 PDF 阅读器")
campaign.add_event("2025-08", "impact", "部署勒索软件并索要赎金")
campaign.victims = ["美国军工承包商", "韩国加密货币交易所"]
campaign.generate_report()
```

### 3. 归因证据链

```python
"""归因分析 — 多层次证据链"""

class AttributionAnalysis:
    """归因分析引擎"""
    
    def __init__(self):
        self.evidence = {
            "technical": {
                "malware_artifacts": [],
                "c2_infrastructure": [],
                "tool_overlap": [],
                "code_similarity": []
            },
            "operational": {
                "targeting": [],
                "temporal_patterns": [],
                "tradecraft": []
            },
            "strategic": {
                "motivation": [],
                "geopolitical_context": [],
                "victimology": []
            }
        }
    
    def add_technical_evidence(self, category, item, weight=1):
        self.evidence["technical"][category].append({"item": item, "weight": weight})
    
    def add_operational_evidence(self, category, item, weight=1):
        self.evidence["operational"][category].append({"item": item, "weight": weight})
    
    def confidence_score(self):
        """计算归因置信度"""
        scores = {"high": 0, "medium": 0, "low": 0}
        
        for category in self.evidence.values():
            for items in category.values():
                for item in items:
                    if item["weight"] >= 5:
                        scores["high"] += 1
                    elif item["weight"] >= 3:
                        scores["medium"] += 1
                    else:
                        scores["low"] += 1
        
        total = sum(scores.values())
        if total == 0:
            return 0
        
        weighted = (scores["high"] * 9 + scores["medium"] * 5 + scores["low"] * 2)
        max_possible = total * 9
        return round(weighted / max_possible * 100, 1)
    
    def summary(self):
        print(f"归因置信度: {self.confidence_score()}%")
        print("\n技术证据:")
        for cat, items in self.evidence["technical"].items():
            print(f"  {cat}: {len(items)} 件")
        print("\n运营证据:")
        for cat, items in self.evidence["operational"].items():
            print(f"  {cat}: {len(items)} 件")
        print("\n战略证据:")
        for cat, items in self.evidence["strategic"].items():
            print(f"  {cat}: {len(items)} 件")

attribution = AttributionAnalysis()
attribution.add_technical_evidence("malware_artifacts", "样本编译路径包含朝鲜语字符串", weight=5)
attribution.add_technical_evidence("c2_infrastructure", "C2 IP 归属朝鲜 IP 段", weight=5)
attribution.add_operational_evidence("targeting", "攻击时间与朝鲜工作时间一致 (UTC+9)", weight=3)
attribution.add_strategic_evidence("motivation", "攻击目标与朝鲜政治利益一致", weight=4)
attribution.summary()
```

### 4. 情报报告生成

```bash
# APT 报告框架（Markdown 格式）
cat > apt_report_template.md << 'EOF'
# APT 分析报告: [GROUP NAME]

## 基本信息
- **编号**: CSS-APT-2026-001
- **报告日期**: $(date +%Y-%m-%d)
- **TLP**: AMBER
- **分析等级**: [初步/中等/最终]

## 执行摘要
[1-2 段概述该 APT 组织及其威胁]

## 背景
- **起源**: 
- **活跃时间**: 
- **别号**: 
- **动机**: 

## TTP 分析
| ATT&CK 战术 | 技术 | 备注 |
|:-----------|:-----|:----|
| TA0001 | T1566.001 | 鱼叉式钓鱼附件 |
| TA0002 | T1059.001 | PowerShell 执行 |
| TA0005 | T1562.001 | 关闭 Windows Defender |

## 工具与恶意软件
| 名称 | 类型 | 功能 |
|:---|:----|:----|
| | Dropper | |
| | Backdoor | |

## 基础设施
| 类型 | 值 | 活跃时间 |
|:---|:---|:-------|
| C2 IP | | |
| 域名 | | |

## 归因证据
1. [证据 1]
2. [证据 2]

## 检测建议
- Sigma 规则:
- YARA 规则:
- IOCs:

## 来源
- MITRE ATT&CK
- 内部狩猎结果
- 情报共享伙伴
EOF

echo "APT 报告模板已生成"
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| ATT&CK Navigator | APT TTP 分析 | https://mitre-attack.github.io/attack-navigator/ |
| Malpedia | 恶意软件与 APT 关联 | https://malpedia.caad.fkie.fraunhofer.de/ |
| MISP Galaxy | APT 知识库 | https://github.com/MISP/misp-galaxy |
| VirusTotal | 样本关联分析 | https://www.virustotal.com/ |
| MITRE CTI | ATT&CK Python API | https://github.com/mitre/cti |

## 参考资源

- [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)
- [APT Notes — Threat Actor Profile](https://github.com/kbandla/APTnotes)
- [Diamond Model of Intrusion Analysis](https://www.activeresponse.org/diamond-model/)
- [NIST SP 800-150 — CTI](https://csrc.nist.gov/publications/detail/sp/800-150/final)
- [Cyber Kill Chain — Lockheed Martin](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
