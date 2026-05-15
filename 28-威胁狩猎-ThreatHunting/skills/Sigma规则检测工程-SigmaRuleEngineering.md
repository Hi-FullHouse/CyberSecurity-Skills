---
id: "28-002"
title: "基于Sigma规则的检测工程 (Sigma Rule Detection Engineering)"
category: "威胁狩猎"
category_en: "Threat Hunting"
difficulty: "★★★★"
tools: "Sigma, PySigma, sigma-cli, Elastic, Splunk, QRadar"
last_updated: "2026-05"
tags: [sigma, detection, rules, siem, yara, threat-hunting]
subdomain: threat-hunting
nist_csf: [DE.AE-02, DE.CM-01, DE.CM-04]
mitre_attack: [T1059, T1055, T1078, T1134, T1569]
---

# 基于Sigma规则的检测工程 (Sigma Rule Detection Engineering)

## 概述

Sigma 是开源的通用检测规则格式，类似 YARA 但面向日志事件。它允许安全团队编写一次检测规则，便可转换为 Splunk、Elasticsearch QL、KQL、ArcSight、QRadar 等 20+ 种 SIEM 平台的查询语言。本技能覆盖 Sigma 规则编写、转换、测试和部署的全流程。

## 核心技能

### 1. Sigma 规则语法

```yaml
# Sigma 规则结构
title: Suspicious PowerShell Download
id: 8b2c3a5e-1d4f-4a7b-9c8d-3e5f2a1b4c7d
status: experimental
description: Detects PowerShell downloading files from internet
author: threat-hunt-team
date: 2026-05-01
tags:
  - attack.t1059.001
  - attack.execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - 'Net.WebClient'
      - 'DownloadString'
      - 'DownloadFile'
      - 'IEX'
  condition: selection
falsepositives:
  - Administrative scripts
level: high
```

```yaml
# 进阶 Sigma 规则示例 — 检测 LSASS 凭证转储
title: LSASS Access from Non-System Process
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: production
description: Detects suspicious LSASS process access (potential credential dumping)
tags:
  - attack.t1003.001
  - attack.credential_access
logsource:
  product: windows
  service: security
  definition: Requires SACL on LSASS (Event ID 4656)
detection:
  selection:
    EventID: 4656
    ObjectName|endswith: '\lsass.exe'
    AccessMask: '0x705'  # PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
  filter_local:
    SubjectUserName|endswith: '$'
  filter_system:
    ProcessName|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Windows\SysWOW64\'
  condition: selection and not 1 of filter_*
falsepositives:
  - Antivirus scanners
  - Backup software
level: critical
```

### 2. Sigma 规则编写与转换

```bash
# 安装 Sigma CLI
pip install sigma-cli
pip install pySigma-backend-splunk
pip install pySigma-backend-elasticsearch

# 列出所有可用的后端
sigma list-backends

# 创建新规则
sigma create new-rule
# 交互式生成规则框架

# 将 Sigma 规则转换为 Splunk SPL
sigma convert -t splunk -f splunk_dm sigma_rules/suspicious_powershell.yml

# 转换为 Elasticsearch EQL
sigma convert -t elasticsearch -f eql sigma_rules/suspicious_powershell.yml

# 转换为 ELK Query DSL
sigma convert -t elasticsearch -f query_dsl sigma_rules/suspicious_powershell.yml

# 批量转换规则目录
sigma convert -t splunk -d converted_rules/ sigma_rules/

# 验证规则语法
sigma check sigma_rules/suspicious_powershell.yml

# 列出所有可用转换目标
sigma list-targets
```

```python
# 使用 PySigma 进行自动化转换
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.backends.elasticsearch import ElasticsearchQuerystringBackend

# 加载 Sigma 规则
rules = SigmaCollection.load_directory("./sigma_rules")

# 转换为 Splunk
splunk = SplunkBackend()
for rule in rules:
    splunk_query = splunk.convert(rule)
    print(f"[{rule.title}]")
    print(f"Splunk: {splunk_query}")
    print()

# 转换为 Elasticsearch
es = ElasticsearchQuerystringBackend()
for rule in rules:
    es_query = es.convert(rule)
    print(f"ES Query: {es_query}")
```

### 3. Sigma 规则分类与组织

```bash
# Sigma 规则目录结构（推荐）
sigma_rules/
├── builtin/                    # SigmaHQ 官方规则
│   ├── process_creation/
│   ├── file_event/
│   ├── network_connection/
│   └── registry_event/
├── custom/                     # 自定义规则
│   ├── threat_hunting/
│   ├── ransomware/
│   └── apt/
└── test/                       # 测试规则

# 按 ATT&CK 战术搜索规则
grep -rl "attack.t1003" sigma_rules/ --include="*.yml"

# 按级别搜索
grep -rl "level: critical" sigma_rules/ --include="*.yml"

# 统计规则覆盖的 ATT&CK 技术
grep "^  - attack\." sigma_rules/**/*.yml | sed 's/.*- //' | sort | uniq -c | sort -rn | head -20
```

### 4. Sigma 规则测试与调优

```python
#!/usr/bin/env python3
"""Sigma 规则测试工具"""

import yaml
import json
from pathlib import Path

def validate_sigma_rule(rule_path):
    """验证 Sigma 规则完整性"""
    with open(rule_path, 'r') as f:
        content = f.read()
    
    # 检查 YAML 格式
    try:
        rule = yaml.safe_load(content)
    except yaml.YAMLError as e:
        return {"valid": False, "error": f"YAML Error: {e}"}
    
    # 检查必需字段
    required = ['title', 'id', 'description', 'logsource', 'detection']
    missing = [f for f in required if f not in rule]
    if missing:
        return {"valid": False, "error": f"Missing fields: {missing}"}
    
    # 检查检测条件
    if 'condition' not in rule.get('detection', {}):
        return {"valid": False, "error": "Missing detection.condition"}
    
    # 检查字段引用
    detection = rule['detection']
    named_selections = {k: v for k, v in detection.items() if k != 'condition'}
    
    return {
        "valid": True,
        "title": rule.get('title'),
        "tags": rule.get('tags', []),
        "level": rule.get('level', 'medium'),
        "selections": len(named_selections),
        "file": str(rule_path)
    }

# 批量验证所有规则
rules_dir = Path("./sigma_rules")
results = [validate_sigma_rule(f) for f in rules_dir.rglob("*.yml")]
valid = [r for r in results if r.get("valid")]
invalid = [r for r in results if not r.get("valid")]

print(f"Total: {len(results)}, Valid: {len(valid)}, Invalid: {len(invalid)}")
```

```bash
# Rule Tuning — 降低误报率
# 方法 1: 添加过滤条件
# 在原规则的 detection 部分添加:
detection:
  selection:
    EventID: 4688
    CommandLine|contains: 'mimikatz'
  filter_siem:
    ProcessName: 'C:\Program Files\SecurityTool\scanner.exe'
  condition: selection and not filter_siem

# 方法 2: 使用通配符精确匹配
detection:
  keywords:
    CommandLine|contains|all:
      - 'sekurlsa'
      - 'logonPasswords'
  condition: keywords

# 方法 3: 频率阈值（通过 SIEM 层设置）
# Splunk 例: 30 分钟内出现 5 次以上才告警
index=windows sigma_rule="lsass_access"
| stats count by host, user
| where count > 5
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Sigma CLI | Sigma 规则管理转换 | https://github.com/SigmaHQ/sigma-cli |
| PySigma | Python Sigma 处理库 | https://github.com/SigmaHQ/pySigma |
| SigmaHQ Rules | 官方规则仓库 | https://github.com/SigmaHQ/sigma |
| Uncoder IO | 在线 SIEM 查询转换 | https://uncoder.io/ |
| sigma2splunk | 批量 Sigma → Splunk 工具 | https://github.com/unkn0wnuser/sigma2splunk |

## 参考资源

- [Sigma HQ — Official Documentation](https://github.com/SigmaHQ/sigma/wiki)
- [Sigma Rule Specification](https://github.com/SigmaHQ/sigma-specification)
- [MITRE ATT&CK — Detection Engineering](https://attack.mitre.org/resources/detection-engineering/)
- [Elastic Detection Rules](https://github.com/elastic/detection-rules)
- [Splunk Security Essentials](https://www.splunk.com/en_us/software/security-essentials.html)
- [Sigma 规则中文指南 — 安全内参](https://www.secrss.com/)
