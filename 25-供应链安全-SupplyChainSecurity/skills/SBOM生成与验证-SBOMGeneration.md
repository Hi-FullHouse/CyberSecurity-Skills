---
id: 25-001
title: "📦 SBOM生成与验证 (SBOM Generation & Verification)"
category: 供应链安全
category_en: "Supply Chain Security"
difficulty: ★★★
tools: "Syft, CycloneDX, SPDX, Trivy, Dependency-Track, FOSSA"
last_updated: 2025-07
tags: ["supply-chain-security", "sbom", "dependency-check", "container-image", "third-party-risk"]
subdomain: supply-chain-security
nist_csf: ["ID.SC-01", "ID.SC-02", "PR.DS-10"]
mitre_attack: ["T1195", "T1525"]
---
# 📦 SBOM生成与验证 (SBOM Generation & Verification)

## 概述

SBOM（软件物料清单）是供应链安全的基石。通过生成和维护SBOM，组织可以清晰了解软件中包含的组件、依赖和许可证信息，快速响应漏洞事件。标准格式包括 **SPDX**、**CycloneDX** 和 **SWID**。

## 核心技能

### 1. SBOM生成工具

```bash
# Syft - 快速SBOM生成
# 安装
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# 生成容器镜像SBOM
syft alpine:latest -o cyclonedx-json > alpine-sbom.json
syft nginx:alpine -o spdx-json > nginx-sbom.spdx.json

# 生成项目SBOM
syft dir:/my/project -o cyclonedx > project-sbom.json

# 支持多格式输出
syft my-app:latest --scope all-layers -o table
syft my-app:latest -o cyclonedx-xml > sbom.xml
syft my-app:latest -o spdx-tag-value > sbom.spdx

# CycloneDX CLI
npm install -g @cyclonedx/cdxgen
cdxgen -o sbom.json -t npm
cdxgen -o sbom-python.json -t pip

# .Net项目
cdxgen -t nuget -o sbom.xml

# Java项目 (Maven/Gradle)
cdxgen -t maven -o sbom.json

# SPDX工具
# 使用go-spdx工具
go get github.com/spdx/tools-golang
spdx-tools convert --inFile input.spdx --outFile output.json

# 多项目聚合
cdxgen -o merged-sbom.json --deep --generate-key
```

### 2. SBOM验证与完整性检查

```bash
# SBOM签名与验证
# 使用GPG签名SBOM
gpg --detach-sign --armor sbom.json
gpg --verify sbom.json.asc sbom.json

# 使用cosign进行容器签名
cosign sign-blob --key cosign.key sbom.json > sbom.json.sig
cosign verify-blob --key cosign.pub --signature sbom.json.sig sbom.json

# SBOM格式验证
# CycloneDX验证
pip install cyclonedx-bom
cyclonedx validate --input-file sbom.json

# 使用Dependency-Check的SBOM分析
dependency-check --out . --scan sbom.json

# SPDX验证
pip install spdx-tools
spdx-tools validation validate sbom.spdx

# SBOM差异对比
python3 << 'EOF'
import json

def compare_sbom(old_sbom, new_sbom):
    with open(old_sbom) as f:
        old = json.load(f)
    with open(new_sbom) as f:
        new = json.load(f)
    
    old_components = {(c['name'], c['version']) for c in old.get('components', [])}
    new_components = {(c['name'], c['version']) for c in new.get('components', [])}
    
    added = new_components - old_components
    removed = old_components - new_components
    unchanged = old_components & new_components
    
    print(f"新增组件: {len(added)}")
    for name, ver in added:
        print(f"  + {name}@{ver}")
    
    print(f"移除组件: {len(removed)}")
    for name, ver in removed:
        print(f"  - {name}@{ver}")
    
    print(f"未变更组件: {len(unchanged)}")
    return {"added": added, "removed": removed}

compare_sbom("v1-sbom.json", "v2-sbom.json")
EOF
```

### 3. SBOM管理平台 (Dependency-Track)

```bash
# Dependency-Track 部署
# Docker Compose方式
cat << 'EOF' > docker-compose.yml
version: '3.8'
services:
  dtrack-apiserver:
    image: dependencytrack/apiserver:latest
    ports:
      - "8081:8080"
    environment:
      - ALPINE_DATABASE_MODE=external
      - ALPINE_DATABASE_URL=jdbc:postgresql://postgres:5432/dtrack
      - ALPINE_DATABASE_DRIVER=org.postgresql.Driver
      - ALPINE_DATABASE_USERNAME=dtrack
      - ALPINE_DATABASE_PASSWORD=dtrack
    volumes:
      - dtrack-data:/data
    restart: always

  dtrack-frontend:
    image: dependencytrack/frontend:latest
    ports:
      - "8080:8080"
    environment:
      - API_BASE_URL=http://localhost:8081
    restart: always

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=dtrack
      - POSTGRES_USER=dtrack
      - POSTGRES_PASSWORD=dtrack
    volumes:
      - postgres-data:/var/lib/postgresql/data
    restart: always

volumes:
  dtrack-data:
  postgres-data:
EOF

docker-compose up -d

# 上传SBOM到Dependency-Track
curl -X PUT -H "X-Api-Key: your-api-key" \
  -F "project=my-app" -F "bom=@sbom.json" \
  http://localhost:8081/api/v1/bom

# 查询项目漏洞
curl -H "X-Api-Key: your-api-key" \
  "http://localhost:8081/api/v1/vulnerability/project/uuid"
```

### 4. CI/CD集成SBOM

```yaml
# GitHub Actions SBOM集成
name: SBOM Generation
on:
  push:
    branches: [main, release/*]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          format: cyclonedx-json
          output-file: ./sbom.json

      - name: Sign SBOM
        run: |
          echo "${{ secrets.GPG_PRIVATE_KEY }}" | gpg --import
          gpg --detach-sign --armor sbom.json

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: |
            sbom.json
            sbom.json.asc

      - name: Publish to Dependency-Track
        run: |
          curl -X PUT -H "X-Api-Key: ${{ secrets.DTRACK_API_KEY }}" \
            -F "project=${{ github.repository }}" \
            -F "bom=@sbom.json" \
            ${{ secrets.DTRACK_URL }}/api/v1/bom

# GitLab CI SBOM
sbom-generation:
  stage: security
  image: alpine:latest
  script:
    - apk add curl
    - curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh
    - syft dir:. -o cyclonedx-json > sbom.json
    - |
      curl -X PUT -H "X-Api-Key: ${DTRACK_API_KEY}" \
        -F "project=${CI_PROJECT_NAME}" \
        -F "version=${CI_COMMIT_TAG:-latest}" \
        -F "bom=@sbom.json" \
        ${DTRACK_URL}/api/v1/bom
  artifacts:
    paths:
      - sbom.json
```

### 5. SBOM 策略与合规检查

```python
#!/usr/bin/env python3
# SBOM策略自动检查

import json
import sys

class SBOMPolicyEngine:
    def __init__(self, sbom_file):
        with open(sbom_file) as f:
            self.sbom = json.load(f)
        self.violations = []
    
    def check_license_compliance(self, allowed_licenses):
        """检查许可证合规性"""
        for component in self.sbom.get('components', []):
            licenses = component.get('licenses', [])
            for lic in licenses:
                license_id = lic.get('license', {}).get('id', 'unknown')
                if license_id not in allowed_licenses:
                    self.violations.append({
                        'type': 'license',
                        'component': f"{component['name']}@{component['version']}",
                        'license': license_id,
                        'severity': 'medium'
                    })
    
    def check_deprecated_components(self, deprecated_list):
        """检查废弃组件"""
        for component in self.sbom.get('components', []):
            key = f"{component['name']}@{component['version']}"
            if key in deprecated_list:
                self.violations.append({
                    'type': 'deprecated',
                    'component': key,
                    'severity': 'high'
                })
    
    def check_version_constraint(self, constraints):
        """检查版本约束"""
        for component in self.sbom.get('components', []):
            name = component['name']
            version = component.get('version', '0.0.0')
            if name in constraints:
                import re
                constraint = constraints[name]
                # 简单范围检查
                if '>=2.0' in constraint and version.startswith('1.'):
                    self.violations.append({
                        'type': 'version_constraint',
                        'component': f"{name}@{version}",
                        'constraint': constraint,
                        'severity': 'medium'
                    })
    
    def generate_report(self):
        print(f"=== SBOM合规检查报告 ===")
        print(f"总组件数: {len(self.sbom.get('components', []))}")
        print(f"违规数: {len(self.violations)}")
        
        for v in self.violations:
            print(f"  [{v['severity'].upper()}] {v['type']}: {v.get('component', '')}")
        
        if self.violations:
            sys.exit(1)  # CI流程失败

# 使用示例
engine = SBOMPolicyEngine("sbom.json")
engine.check_license_compliance({"MIT", "Apache-2.0", "BSD-3-Clause", "ISC"})
engine.check_deprecated_components({"log4j@1.2.17"})
engine.check_version_constraint({"spring-core": ">=5.3.0"})
engine.generate_report()
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Syft | SBOM生成工具 | https://github.com/anchore/syft |
| CycloneDX | 开源SBOM标准 | https://cyclonedx.org/ |
| Dependency-Track | SBOM管理平台 | https://dependencytrack.org/ |
| SPDX | SBOM标准格式 | https://spdx.dev/ |
| Trivy | 集成SBOM的漏洞扫描 | https://github.com/aquasecurity/trivy |
| FOSSA | 开源合规管理 | https://fossa.com/ |

## 参考资源

- [SPDX Specification 2.3](https://spdx.dev/specifications/)
- [CycloneDX BOM Standard](https://cyclonedx.org/specification/)
- [NTIA SBOM Minimum Elements](https://www.ntia.gov/sbom)
- [OpenSSF SBOM Everywhere](https://openssf.org/projects/sbom-everywhere/)
- [CISA SBOM Guidance](https://www.cisa.gov/sbom)
