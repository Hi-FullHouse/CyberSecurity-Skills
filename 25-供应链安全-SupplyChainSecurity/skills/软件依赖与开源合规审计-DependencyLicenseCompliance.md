---
id: 25-002
title: "🔍 软件依赖与开源合规审计 (Dependency License Compliance)"
category: 供应链安全
category_en: "Supply Chain Security"
difficulty: ★★★
tools: "FOSSA, Black Duck, Snyk, OWASP Dependency-Check, Scancode"
last_updated: 2025-07
tags: ["supply-chain-security", "sbom", "dependency-check", "container-image", "third-party-risk"]
subdomain: supply-chain-security
nist_csf: ["ID.SC-01", "ID.SC-02", "PR.DS-10"]
mitre_attack: ["T1195", "T1525"]
---
# 🔍 软件依赖与开源合规审计 (Dependency License Compliance)

## 概述

开源组件已成为软件的基石，但许可证合规风险也随之增加。本节涵盖许可证识别、合规检查、策略实施和自动化审计，确保开源使用符合法律要求。

## 核心技能

### 1. 许可证识别与分析

```python
#!/usr/bin/env python3
# 许可证自动识别

import re
import json

class LicenseIdentifier:
    def __init__(self):
        self.license_patterns = {
            "MIT": r"MIT License|Permission is hereby granted.*without restriction",
            "Apache-2.0": r"Apache License.*Version 2\.0|Licensed under the Apache License.*Version 2.0",
            "GPL-2.0": r"GNU GENERAL PUBLIC LICENSE.*Version 2",
            "GPL-3.0": r"GNU GENERAL PUBLIC LICENSE.*Version 3",
            "LGPL-2.1": r"GNU LESSER GENERAL PUBLIC LICENSE.*Version 2\.1",
            "BSD-3-Clause": r"Redistribution and use in source and binary forms.*following conditions",
            "BSD-2-Clause": r"Redistribution and use in source and binary forms.*following conditions:(?!.*3\.)",
            "ISC": r"ISC License|Permission to use, copy, modify, and/or distribute",
            "MPL-2.0": r"Mozilla Public License.*Version 2.0",
            "Unlicense": r"This is free and unencumbered software",
            "CC0-1.0": r"CC0 1.0 Universal|Creative Commons Zero v1.0 Universal",
        }
    
    def identify_license(self, file_content):
        matches = []
        for license_name, pattern in self.license_patterns.items():
            if re.search(pattern, file_content, re.IGNORECASE):
                matches.append(license_name)
        return matches
    
    def classify_risk(self, license_name):
        """许可证风险分类"""
        permissive = {"MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", 
                      "ISC", "Unlicense", "CC0-1.0", "MIT-0"}
        weak_copyleft = {"LGPL-2.1", "LGPL-3.0", "MPL-2.0", "CDDL-1.0", "EPL-2.0"}
        strong_copyleft = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "EUPL-1.2"}
        proprietary = {"BUSL-1.1", "SSPL-1.0", "Confluent Community License"}
        
        if license_name in permissive:
            return "低风险", "可自由使用，需保留版权声明"
        elif license_name in weak_copyleft:
            return "中风险", "使用后需按相同条款开源修改部分"
        elif license_name in strong_copyleft:
            return "高风险", "使用后整个软件需开源"
        elif license_name in proprietary:
            return "极高风险", "商业限制，需购买授权"
        return "未知", "手动审查许可证"
```

### 2. 依赖合规检查自动化

```bash
# OWASP Dependency-Check
# 安装
wget https://github.com/jeremylong/DependencyCheck/releases/latest/download/dependency-check-9.0.0-release.zip
unzip dependency-check-*.zip
cd dependency-check/bin

# 全面扫描
./dependency-check.sh --project my-app --scan /path/to/project \
  --format HTML --out /tmp/report.html \
  --suppression suppression.xml \
  --nvdApiKey your-nvd-api-key

# XML格式输出，用于CI集成
./dependency-check.sh --scan . -f XML -o depcheck-report.xml

# Java Maven集成 (pom.xml)
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>9.0.0</version>
    <configuration>
        <failBuildOnCVSS>7</failBuildOnCVSS>
        <suppressionFiles>
            <suppressionFile>dependency-check-suppression.xml</suppressionFile>
        </suppressionFiles>
    </configuration>
</plugin>

# Python Poetry集成
# 使用safety检查
pip install safety
safety check --full-report -r requirements.txt

# 忽略已知误报
safety check --ignore=12345,67890

# Node.js npm审计
npm audit --audit-level=high
npm audit fix --dry-run

# yarn审计
yarn audit --level high

# Go依赖检查
go list -m all > go-deps.txt
go vet ./...
nancy go-deps.txt  # Nancy漏洞扫描器
```

### 3. 许可证策略引擎

```yaml
# license-policy.yml - 许可证策略配置
policies:
  # 禁止的许可证
  forbidden:
    - "AGPL-3.0"
    - "BUSL-1.1"
    - "SSPL-1.0"
    - "Proprietary"
    - "Facebook-Plus"
    
  # 需审批的许可证
  require_approval:
    - "GPL-2.0"
    - "GPL-3.0"
    - "LGPL-3.0"
    
  # 允许的许可证
  allowed:
    - "MIT"
    - "Apache-2.0"
    - "BSD-2-Clause"
    - "BSD-3-Clause"
    - "ISC"
    - "Unlicense"
    - "CC0-1.0"
    - "0BSD"
    
  # 特定组件豁免（经过安全团队审批）
  exemptions:
    - component: "some-old-lib@1.2.3"
      license: "LGPL-2.1"
      reason: "已获法律部门批准，静态链接使用"
      approved_by: "legal@company.com"
      expiry: "2025-12-31"
```

### 4. 开源组件库存管理

```python
#!/usr/bin/env python3
# 开源组件库存与审计系统

import json
from datetime import datetime

class OpenSourceInventory:
    def __init__(self):
        self.components = {}
    
    def add_component(self, name, version, license_type, 
                      homepage, dependency_type):
        key = f"{name}@{version}"
        self.components[key] = {
            "name": name,
            "version": version,
            "license": license_type,
            "homepage": homepage,
            "type": dependency_type,
            "added_date": datetime.now().isoformat(),
            "last_reviewed": datetime.now().isoformat(),
            "status": "active"
        }
    
    def compliance_report(self, policy):
        violations = []
        for key, component in self.components.items():
            lic = component['license']
            if lic in policy.get('forbidden', []):
                violations.append({
                    'component': key,
                    'license': lic,
                    'severity': 'critical',
                    'action': 'remove'
                })
            elif lic in policy.get('require_approval', []):
                violations.append({
                    'component': key,
                    'license': lic,
                    'severity': 'high',
                    'action': 'legal_review'
                })
        
        print(f"总组件数: {len(self.components)}")
        print(f"合规组件: {len(self.components) - len(violations)}")
        print(f"违规组件: {len(violations)}")
        
        for v in violations:
            print(f"  [{v['severity'].upper()}] {v['component']} ({v['license']}) -> {v['action']}")
        
        return violations

# 使用示例
inv = OpenSourceInventory()
inv.add_component("lodash", "4.17.21", "MIT", "https://lodash.com/", "direct")
inv.add_component("log4j", "1.2.17", "Apache-2.0", "https://logging.apache.org/log4j/", "transitive")
policy = {"forbidden": ["AGPL-3.0", "SSPL-1.0"], "require_approval": ["GPL-2.0", "LGPL-2.1"]}
inv.compliance_report(policy)
```

### 5. CI/CD集成合规检查

```yaml
# GitHub Actions 开源合规审计
name: Open Source Compliance
on: [pull_request]

jobs:
  license-compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Dependency Review
        uses: actions/dependency-review-action@v3
        with:
          fail-on-severity: high
          deny-licenses: AGPL-3.0, SSPL-1.0, BUSL-1.1
          
      - name: FOSSA Scan
        run: |
          curl -H "Authorization: token ${{ secrets.FOSSA_API_KEY }}" \
            https://app.fossa.com/api/build/latest

      - name: Licenses Check
        run: |
          npm install --package-lock-only
          npx license-checker --failOn "AGPL-3.0;SSPL-1.0" --summary

      - name: OWASP Dependency Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: 'my-app'
          path: '.'
          format: 'HTML'
          args: >
            --failOnCVSS 7
            --suppression suppression.xml
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| FOSSA | 开源许可证管理平台 | https://fossa.com/ |
| Black Duck | 综合开源治理 | https://www.blackducksoftware.com/ |
| Snyk | 开源安全与合规 | https://snyk.io/ |
| OWASP DC | 依赖漏洞检查 | https://owasp.org/www-project-dependency-check/ |
| Scancode | 开源扫描工具 | https://scancode-toolkit.com/ |
| Licensee | GitHib许可证识别 | https://github.com/licensee/licensee |

## 参考资源

- [OpenSSF Best Practices for Open Source Developers](https://openssf.org/)
- [Linux Foundation Open Source Compliance](https://www.linuxfoundation.org/compliance/)
- [ISO 5230 — Open Source Compliance](https://www.iso.org/standard/81099.html)
- [CNCF Open Source License Compliance](https://www.cncf.io/reports/)
- [GitHub Open Source Guide](https://opensource.guide/)
