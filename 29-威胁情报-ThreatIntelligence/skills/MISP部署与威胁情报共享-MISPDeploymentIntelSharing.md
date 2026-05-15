---
id: "29-002"
title: "MISP平台部署与威胁情报共享 (MISP Deployment & Threat Intel Sharing)"
category: "威胁情报"
category_en: "Threat Intelligence"
difficulty: "★★★★"
tools: "MISP, Docker, Cortex, MISP Galaxy, PyMISP"
last_updated: "2026-05"
tags: [misp, threat-intelligence, sharing, galaxy, cortex]
subdomain: threat-intelligence
nist_csf: [DE.AE-01, ID.RA-02, RS.CO-04]
mitre_attack: [T1583, T1597]
---

# MISP平台部署与威胁情报共享 (MISP Deployment & Threat Intel Sharing)

## 概述

MISP（Malware Information Sharing Platform）是目前全球应用最广泛的开源威胁情报共享平台。本技能覆盖 MISP 平台部署、事件管理、Galaxy 使用、自动化导入导出、Cortex 集成联动等技术。

## 核心技能

### 1. MISP 平台部署

```bash
# 使用 Docker 快速部署 MISP
git clone https://github.com/harvard-itsecurity/docker-misp.git
cd docker-misp
docker-compose up -d

# 查看部署状态
docker-compose ps
docker-compose logs -f

# 初始化配置
docker exec -it misp-server /init-db

# 访问 MISP Web 界面
# https://localhost/
# 默认账号: admin@admin.test
# 默认密码: admin

# 使用 CentOS 原生部署
sudo yum install epel-release
sudo yum install httpd mariadb-server php php-mysql python3
git clone https://github.com/MISP/MISP.git /var/www/MISP
cd /var/www/MISP
git submodule update --init --recursive

# 配置数据库
sudo mysql -u root -p
CREATE DATABASE misp;
CREATE USER 'misp'@'localhost' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON misp.* TO 'misp'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

```bash
# MISP 基础配置
# 管理员设置
# 系统设置 → MISP 基础配置
# - MISP.live: true
# - MISP.name: "CyberSecurity-Skills TI"
# - MISP.org: "CSS"

# 配置自动推送和拉取
# 同步设置 → 添加远程服务器

# 配置 API 密钥
# 用户管理 → 查看 API 密钥
# 应使用 40 字符以上的随机字符串
```

### 2. MISP 事件管理与 Galaxy

```python
"""使用 PyMISP 管理 MISP 事件"""

from pymisp import PyMISP, MISPEvent, MISPAttribute
import json

# 初始化 PyMISP 客户端
misp_url = "https://localhost"
misp_key = "YOUR_API_KEY"
misp = PyMISP(misp_url, misp_key, ssl=False)

# 创建新事件
event = MISPEvent()
event.info = "LockBit Ransomware Indicators - May 2026"
event.distribution = 1  # 0=Your Org, 1=Community, 2=Connected, 3=All
event.threat_level_id = 2  # 1=High, 2=Medium, 3=Low
event.analysis = 1  # 0=Initial, 1=Ongoing, 2=Completed
event.add_tag("ransomware")

# 添加 IOC 属性
event.add_attribute("ip-dst", "185.220.101.50", 
    comment="LockBit C2 Server",
    category="Network activity",
    to_ids=True)

event.add_attribute("domain", "lockbitxyz.onion",
    comment="LockBit Darknet Site",
    category="Network activity",
    to_ids=True)

event.add_attribute("md5", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    comment="LockBit sample hash",
    category="Payload delivery",
    to_ids=True)

# 创建事件
result = misp.add_event(event)
print(f"Event created: {result.get('Event', {}).get('id')}")

# 搜索事件
events = misp.search(controller="events", tags=["ransomware"])
print(f"Found {len(events)} ransomware events")

# 事件导出为 STIX
stix_output = misp.download_stix(events[0]['Event']['id'])
with open('misp_export.stix2.json', 'w') as f:
    json.dump(stix_output, f, indent=2)
```

```bash
# MISP Galaxy — 威胁行为体与活动活动
# 在 MISP UI 中使用 Galaxy 标记事件

# 安装 MISP Galaxy
cd /var/www/MISP/app/files
git clone https://github.com/MISP/misp-galaxy.git

# Galaxy 使用场景
# 1. 标记威胁行为体: galaxy-cluster="APT-XX"
# 2. 标记恶意软件: galaxy-cluster="LockBit"
# 3. 标记攻击技术: galaxy-cluster="T1059.001"
# 4. 标记行业: galaxy-cluster="finance"

# 命令行添加 Galaxy 标签
curl -X POST \
  -H "Authorization: YOUR_API_KEY" \
  -H "Accept: application/json" \
  -d '{"tag": "misp-galaxy:mitre-attack-pattern=\"T1059.001 - PowerShell\""}' \
  "https://misp.local/tags/addTagToObject"
```

### 3. 情报自动化导入与关联

```python
"""MISP 自动化工作流"""

import json
import requests
from pymisp import PyMISP

class MISPWorkflow:
    """MISP 自动化工作流引擎"""
    
    def __init__(self, url, api_key):
        self.misp = PyMISP(url, api_key, ssl=False)
    
    # 自动导入外部情报
    def import_alienvault_otx(self, api_key):
        """从 AlienVault OTX 导入情报到 MISP"""
        headers = {"X-OTX-API-KEY": api_key}
        resp = requests.get(
            "https://otx.alienvault.com/api/v1/indicators/export",
            headers=headers, timeout=60
        )
        pulses = resp.json().get("results", [])
        
        for pulse in pulses[:10]:  # 限制前 10 个 pulse
            event = self.misp.create_misp_event()
            event.info = f"OTX Pulse: {pulse['name']}"
            event.add_tag("alienvault-otx")
            
            for ioc in pulse.get("indicators", []):
                event.add_attribute(
                    ioc["type"],
                    ioc["indicator"],
                    comment=pulse.get("description", "")[:256]
                )
            
            self.misp.add_event(event)
            print(f"Imported: {pulse['name']}")
    
    # 事件关联分析
    def correlate_iocs(self, ioc_list):
        """将 IOC 列表与 MISP 中的所有事件关联"""
        results = {}
        for ioc in ioc_list:
            matches = self.misp.search(
                controller="attributes",
                value=ioc["value"],
                type_attribute=ioc["type"]
            )
            if matches:
                results[ioc["value"]] = {
                    "matched_events": len(matches),
                    "events": [m["Event"]["info"] for m in matches[:3]]
                }
        return results
    
    # 自动生成告警
    def create_alerts_for_sightings(self):
        """基于 sightings 生成告警"""
        sightings = self.misp.get_sightings_list()
        for sighting in sightings[:20]:
            print(f"Sighting: {sighting['attribute_uuid']}")
```

```bash
# MISP 告警推送集成

# 推送告警到 Slack
curl -X POST -H "Content-type: application/json" \
  -d '{
    "text": "🚨 MISP Alert: New ransomware event detected",
    "attachments": [{
      "fields": [
        {"title": "Event", "value": "LockBit Indicators"},
        {"title": "IOCs", "value": "5 IPs, 3 domains"},
        {"title": "TLP", "value": "AMBER"}
      ]
    }]
  }' \
  https://hooks.slack.com/services/YOUR/WEBHOOK

# MISP 与 Cortex 联动分析
curl -X POST \
  -H "Authorization: YOUR_MISP_API_KEY" \
  -d '{"attribute_ids": ["id1", "id2"], "type": "analyze"}' \
  https://misp.local/cortex/analyze
```

### 4. 情报质量评估与生命周期

```python
"""威胁情报质量评估"""

class IntelQualityAssessment:
    """评估威胁情报的质量指标"""
    
    @staticmethod
    def quality_score(ioc):
        """评估单个 IOC 的质量（0-100）"""
        score = 50  # 基础分
        
        # 1. 情报源可信度
        source_trust = {
            "misp": 80, "taxii": 75, "otx": 60,
            "threatbook": 70, "virustotal": 65,
            "community": 40, "unknown": 20
        }
        score += source_trust.get(ioc.get("source", "unknown"), 0) * 0.15
        
        # 2. 时间相关度
        from datetime import datetime, timezone
        from dateutil import parser
        
        last_seen = parser.parse(ioc.get("last_seen", datetime.now(timezone.utc).isoformat()))
        days_old = (datetime.now(timezone.utc) - last_seen).days
        time_score = max(0, 100 - days_old * 3)
        score += time_score * 0.2
        
        # 3. 标签丰富度
        tags = ioc.get("tags", [])
        tag_score = min(len(tags) * 10, 30)
        score += tag_score
        
        # 4. 上下文信息
        if ioc.get("description"):
            score += 10
        if ioc.get("mitre_attack"):
            score += 10
        
        return min(score, 100)
    
    @staticmethod
    def batch_assessment(ioc_list):
        """批量质量评估"""
        results = []
        for ioc in ioc_list:
            results.append({
                "indicator": ioc.get("value"),
                "type": ioc.get("type"),
                "quality_score": IntelQualityAssessment.quality_score(ioc),
                "action": "use" if IntelQualityAssessment.quality_score(ioc) >= 40 else "review"
            })
        return results

# 使用示例
iocs = [
    {"value": "185.220.101.50", "type": "ip", "source": "misp", 
     "tags": ["c2", "emotet"], "last_seen": "2026-05-01"},
    {"value": "1.1.1.1", "type": "ip", "source": "unknown", 
     "tags": [], "last_seen": "2025-01-01"}
]
qa = IntelQualityAssessment()
results = qa.batch_assessment(iocs)
for r in results:
    print(f"{r['indicator']}: {r['quality_score']}/100 -> {r['action']}")
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| MISP | 威胁情报共享平台 | https://www.misp-project.org/ |
| PyMISP | MISP Python API | https://github.com/MISP/PyMISP |
| MISP Galaxy | 威胁知识库 | https://github.com/MISP/misp-galaxy |
| Cortex | 分析引擎（与 MISP 联动） | https://github.com/TheHive-Project/Cortex |
| TheHive | SIEM 联动事件响应 | https://github.com/TheHive-Project/TheHive |

## 参考资源

- [MISP Official Documentation](https://www.misp-project.org/documentation/)
- [MISP Galaxy — MITRE ATT&CK Mapping](https://www.misp-project.org/galaxy.html)
- [Cortex Analyzers Integration](https://github.com/TheHive-Project/cortex-analyzers)
- [NIST SP 800-150 — CTI Sharing](https://csrc.nist.gov/publications/detail/sp/800-150/final)
- [CIRCL MISP 最佳实践](https://www.circl.lu/doc/misp/)
