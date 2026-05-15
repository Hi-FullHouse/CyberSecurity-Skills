---
id: "29-001"
title: "威胁情报馈入与TAXII/STIX管理 (Threat Intelligence Feeds & TAXII/STIX)"
category: "威胁情报"
category_en: "Threat Intelligence"
difficulty: "★★★"
tools: "TAXII, STIX, MISP, OpenCTI, MITRE CTI"
last_updated: "2026-05"
tags: [threat-intelligence, stix, taxii, cti, ioc, feed-management]
subdomain: threat-intelligence
nist_csf: [DE.AE-01, ID.RA-02, RS.AN-01]
mitre_attack: [T1583, T1584, T1595, T1597]
---

# 威胁情报馈入与TAXII/STIX管理 (Threat Intelligence Feeds & TAXII/STIX)

## 概述

威胁情报的自动化采集和消费是现代安全运营的基础。STIX（Structured Threat Information Expression）和 TAXII（Trusted Automated Exchange of Intelligence Resources）是业界标准的威胁情报交换格式和协议。本技能覆盖威胁情报馈入源管理、STIX 对象解析、TAXII 客户端配置、IOC 提取和情报质量评估。

## 核心技能

### 1. STIX 威胁情报对象

```python
#!/usr/bin/env python3
"""STIX 2.1 威胁情报对象处理"""

from stix2 import Indicator, Bundle, Malware, Relationship, TLP_AMBER
from stix2 import ThreatActor, ExternalReference, KillChainPhase
import json

# 创建 STIX 指标
indicator = Indicator(
    name="Malicious SHA256 Hash",
    indicator_types=["malicious-activity"],
    pattern="[file:hashes.'SHA-256' = 'ef537f25c895bfa782526529a9b63d97aa63164d24a2b3d2d10ce0e4b5c6d7e8']",
    pattern_type="stix",
    valid_from="2026-05-01T00:00:00Z",
    labels=["ransomware", "lockbit"],
    object_marking_refs=[TLP_AMBER]
)

# 创建恶意软件对象
malware = Malware(
    name="LockBit 3.0",
    malware_types=["ransomware"],
    is_family=True,
    aliases=["LockBitBlack"],
    kill_chain_phases=[
        KillChainPhase(kill_chain_name="mitre-attack", phase_name="execution"),
        KillChainPhase(kill_chain_name="mitre-attack", phase_name="defense-evasion")
    ]
)

# 创建威胁行为体
actor = ThreatActor(
    name="APT-XX",
    threat_actor_types=["nation-state"],
    aliases=["Group Y"],
    sophistication="expert",
    resource_level="government",
    primary_motivation="espionage"
)

# 关联所有对象
relationship = Relationship(
    relationship_type="indicates",
    source_ref=indicator.id,
    target_ref=malware.id
)

# 打包为 Bundle
bundle = Bundle(indicator, malware, actor, relationship)
print(json.dumps(json.loads(str(bundle)), indent=2))

# 保存 STIX bundle
with open('threat_intel_bundle.json', 'w') as f:
    f.write(str(bundle))
```

```python
# 从 STIX bundle 中提取 IOC
from stix2 import Bundle, parse
import re

def extract_iocs(stix_bundle_path):
    """从 STIX bundle 中提取 IOC"""
    with open(stix_bundle_path, 'r') as f:
        bundle = parse(f.read(), allow_custom=True)
    
    iocs = {
        "ipv4": [],
        "domain": [],
        "url": [],
        "hash": [],
        "email": []
    }
    
    for obj in bundle.objects:
        if hasattr(obj, 'pattern'):
            # 提取 IP
            ip_match = re.findall(r"\[ipv4-addr:value = '([^']+)'\]", obj.pattern)
            iocs["ipv4"].extend(ip_match)
            
            # 提取域名
            domain_match = re.findall(r"\[domain-name:value = '([^']+)'\]", obj.pattern)
            iocs["domain"].extend(domain_match)
            
            # 提取 URL
            url_match = re.findall(r"\[url:value = '([^']+)'\]", obj.pattern)
            iocs["url"].extend(url_match)
            
            # 提取 Hash
            hash_match = re.findall(r"\[file:hashes\..*?= '([^']+)'\]", obj.pattern)
            iocs["hash"].extend(hash_match)
    
    return iocs

iocs = extract_iocs('threat_intel_bundle.json')
for ioc_type, values in iocs.items():
    print(f"{ioc_type}: {len(values)}")
```

### 2. TAXII 客户端配置

```python
"""TAXII 2.1 客户端 — 采集威胁情报"""

from taxii2client.v21 import Server, Collection
import json

# TAXII 服务器连接
# 使用公开的 TAXII 服务器（Hail a TAXII）
server_url = "https://limo.anomali.com/api/v1/taxii2"
collection_url = "https://limo.anomali.com/api/v1/taxii2/collections/"

# 连接 TAXII 服务器
server = Server(server_url, user="guest", password="guest")

# 获取 API Root
api_root = server.api_roots[0]
print(f"API Root: {api_root.url}")
print(f"Title: {api_root.title}")

# 列出所有集合
print("\nAvailable Collections:")
for collection in api_root.collections:
    print(f"  - {collection.id}: {collection.title}")

# 从特定集合获取指标
collection_to_read = Collection(f"{collection_url}27_/objects/")

# 获取最近 100 个指标
indicators = collection_to_read.get_objects(limit=100)
print(f"\nRetrieved {len(indicators.get('objects', []))} STIX objects")

# 过滤 IP 指标
ip_indicators = [
    obj for obj in indicators.get('objects', [])
    if obj.get('type') == 'indicator' and 'ipv4' in str(obj.get('pattern', ''))
]
print(f"IP indicators: {len(ip_indicators)}")

# 将 TAXII 采集结果存为本地文件
with open('taxii_output.json', 'w') as f:
    json.dump(indicators, f, indent=2)
```

```bash
# 使用 TAXII CLI 工具（需安装）
pip install taxii2-client

# 列出 TAXII 服务器集合
python -c "
from taxii2client.v21 import Server
s = Server('https://limo.anomali.com/api/v1/taxii2', user='guest', password='guest')
for coll in s.api_roots[0].collections:
    print(f'{coll.id}: {coll.title}')
"

# 下载指定集合的指标
curl -s -u "guest:guest" \
  -H "Accept: application/taxii+json;version=2.1" \
  "https://limo.anomali.com/api/v1/taxii2/collections/27_/objects/" \
  | jq '.objects[] | select(.type=="indicator") | {pattern: .pattern, created: .created}' | head -20
```

### 3. 情报源管理与质量评估

```python
"""威胁情报源管理"""

import requests
import hashlib
from datetime import datetime

class ThreatFeedManager:
    """威胁情报源管理器"""
    
    def __init__(self):
        self.feeds = {
            "alienvault_otx": {
                "url": "https://otx.alienvault.com/api/v1/indicators/export",
                "api_key": "YOUR_OTX_KEY",
                "enabled": True,
                "interval_hours": 6
            },
            "abuseipdb": {
                "url": "https://api.abuseipdb.com/api/v2/blacklist",
                "api_key": "YOUR_ABUSEIPDB_KEY",
                "enabled": True,
                "interval_hours": 24
            },
            "feodo_tracker": {
                "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
                "enabled": True,
                "interval_hours": 1
            },
            "ci_bad_ips": {
                "url": "https://cinsscore.com/list/ci-badguys.txt",
                "enabled": True,
                "interval_hours": 12
            }
        }
        self.stats = {}
    
    def fetch_feed(self, name, config):
        """获取单个情报源"""
        start = datetime.now()
        try:
            headers = {}
            if "api_key" in config:
                headers["X-OTX-API-KEY"] = config.get("api_key", "")
            
            resp = requests.get(config["url"], headers=headers, timeout=30)
            resp.raise_for_status()
            
            # 计算哈希值用于去重
            content_hash = hashlib.md5(resp.text.encode()).hexdigest()
            
            elapsed = (datetime.now() - start).total_seconds()
            self.stats[name] = {
                "status": "success",
                "size": len(resp.text),
                "hash": content_hash,
                "elapsed_seconds": round(elapsed, 2),
                "timestamp": datetime.now().isoformat()
            }
            return resp.text
        except Exception as e:
            self.stats[name] = {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
            return None
    
    def deduplicate_and_merge(self, all_iocs):
        """去重合并 IOC"""
        seen = set()
        deduped = []
        for ioc in all_iocs:
            if ioc not in seen:
                seen.add(ioc)
                deduped.append(ioc)
        return deduped
    
    def get_quality_report(self):
        """生成情报源质量报告"""
        print("=" * 60)
        print("威胁情报源质量报告")
        print("=" * 60)
        for name, stat in self.stats.items():
            status_icon = "✓" if stat["status"] == "success" else "✗"
            print(f"\n[{status_icon}] {name}")
            if stat["status"] == "success":
                print(f"   大小: {stat['size']/1024:.1f} KB")
                print(f"   耗时: {stat['elapsed_seconds']}s")
            else:
                print(f"   错误: {stat.get('error')}")

# 使用示例
# manager = ThreatFeedManager()
# for name, config in manager.feeds.items():
#     if config['enabled']:
#         manager.fetch_feed(name, config)
# manager.get_quality_report()
```

### 4. IOC 生命周期管理

```bash
# IOC 生命周期：采集 → 标准化 → 去重 → 丰富 → 分发 → 退役

# IOC 自动化管道

# 1. IOC 标准化格式
ioc_record = """
{
    "type": "ipv4",
    "value": "185.220.101.X",
    "confidence": 85,
    "severity": "high",
    "tags": ["c2", "emotet"],
    "first_seen": "2026-04-01",
    "last_seen": "2026-05-01",
    "source": "feed-manager",
    "ttl_days": 30
}
"""

# 2. IOC 到期管理（自动退役超过 90 天未见的 IOC）
python3 -c "
iocs = {}  # 从数据库读取
from datetime import datetime, timedelta
threshold = datetime.now() - timedelta(days=90)
to_retire = [ioc for ioc in iocs if ioc['last_seen'] < threshold.isoformat()]
print(f'{len(to_retire)} expired IOCs to retire')
"
```

```bash
# 使用 MISP 进行威胁情报管理
# MISP 本地部署
docker run -d -p 443:443 \
  -v misp-db:/var/lib/mysql \
  -v misp-config:/var/www/MISP/app/Config \
  harvarditsecurity/misp

# 导入 STIX bundle
curl -X POST -H "Authorization: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d @threat_intel_bundle.json \
  https://misp.local/events/import

# 推送 IOC 到防火墙
curl -X POST -H "Authorization: YOUR_API_KEY" \
  -d '{"action": "block", "ips": ["1.2.3.4", "5.6.7.8"]}' \
  https://firewall-api.local/blocklist/update
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| TAXII 2 Client | STIX/TAXII 情报消费 | https://github.com/oasis-open/cti-taxii-client |
| MISP | 威胁情报共享平台 | https://www.misp-project.org/ |
| OpenCTI | 开源威胁情报平台 | https://github.com/OpenCTI-Platform/opencti |
| AlienVault OTX | 开源威胁情报社区 | https://otx.alienvault.com/ |
| MITRE CTI | STIX/TAXII Python 库 | https://github.com/mitre/cti |

## 参考资源

- [OASIS STIX 2.1 Documentation](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [OASIS TAXII 2.1 Specification](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)
- [MISP User Guide](https://www.circl.lu/doc/misp/)
- [MITRE ATT&CK — Threat Intelligence](https://attack.mitre.org/resources/threat-intelligence/)
- [FIRST TLP Specification](https://www.first.org/tlp/)
- [NIST SP 800-150 — Cyber Threat Intelligence](https://csrc.nist.gov/publications/detail/sp/800-150/final)
