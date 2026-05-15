---
id: 18-005
title: "🔗 软件供应链安全 (Software Supply Chain Security)"
category: 安全开发运维
category_en: DevSecOps
difficulty: ★★★★
tools: "Snyk, Dependabot, Trivy, SBOM, Sigstore, OWASP DC"
last_updated: 2025-07
tags: ["devsecops", "ci-cd", "sast", "dast", "iac-security", "supply-chain"]
subdomain: devsecops
nist_csf: ["PR.IP-12", "ID.RA-01", "DE.CM-08"]
mitre_attack: []
---
# 🔗 软件供应链安全 (Software Supply Chain Security)

## 概述
确保软件开发生命周期中所有组件的安全性和可追溯性，涵盖依赖漏洞管理、SBOM生成、制品签名、供应链威胁检测和SLSA合规。

## 核心技能

### 1. 依赖漏洞扫描

```bash
# 使用Snyk
# 安装
npm install -g snyk
snyk auth

# 扫描项目
snyk test --all-projects

# 持续监控
snyk monitor --all-projects

# Docker镜像扫描
snyk test --docker <image>

# 修复建议
snyk fix --all-projects

# 使用Trivy扫描
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd):/root/.cache/ aquasec/trivy:latest \
  fs --scanners vuln,secret,misconfig /root/.cache/

# 扫描容器镜像
trivy image node:18-alpine

# 扫描Git仓库
trivy repo https://github.com/vulnerable/project.git

# OWASP Dependency-Check
docker run --rm \
  -v $(pwd):/src \
  -v $(pwd)/odc-reports:/report \
  owasp/dependency-check:latest \
  --scan /src \
  --format HTML \
  --out /report
```

### 2. SBOM（软件物料清单）生成

```bash
# 使用Syft生成SBOM
docker run --rm -v $(pwd):/project anchore/syft:latest /project -o cyclonedx-json

# 扫描容器镜像
syft node:18-alpine -o spdx-json > sbom.spdx.json

# 扫描文件系统
syft /project -o cyclonedx > sbom.cdx.json

# 使用CycloneDX CLI
npm install -g @cyclonedx/bom
cyclonedx-bom -o bom.xml

# 使用SPDX工具
pip install spdx-tools
python -m spdx tools sbom /project

# SBOM格式比较
sbom format comparison:
- SPDX: ISO标准，侧重许可证合规
- CycloneDX: OWASP标准，侧重安全漏洞
- SWID: ISO标准，用于软件识别
```

### 3. 制品签名与验证

```bash
# 使用Sigstore/Cosign
# 安装Cosign
wget "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
mv cosign-linux-amd64 /usr/local/bin/cosign
chmod +x /usr/local/bin/cosign

# 密钥对生成
cosign generate-key-pair

# 签名容器镜像
cosign sign --key cosign.key <image>

# 验证签名
cosign verify --key cosign.pub <image>

# 使用无密钥签名（Keyless）
cosign sign <image>
cosign verify <image> \
  --certificate-identity <email> \
  --certificate-oidc-issuer https://accounts.google.com

# 签名SBOM
cosign attach sbom --sbom sbom.cdx.json <image>
cosign verify-attestation <image>

# SLSA验证
slsa-verifier verify-image \
  --source-uri github.com/org/repo \
  --source-tag v1.2.3 \
  <image>
```

### 4. 供应链攻击防御

```text
┌─ 常见供应链攻击类型 ────────────────────────┐
│                                              │
│ 1. 依赖混淆攻击                              │
│    - 攻击者上传同名恶意包到公共仓库            │
│    - 构建工具优先使用公共仓库的包              │
│    ✅ 防御: 使用resolutions锁定源仓库          │
│                                              │
│ 2. 恶意依赖植入                              │
│    - 合法包被注入恶意代码                      │
│    - event-stream, ua-parser-js等案例         │
│    ✅ 防御: 依赖锁文件审查 + 行为分析          │
│                                              │
│ 3. 类型混淆/拼写劫持                          │
│    - starfall/star-fall 等相似名称             │
│    ✅ 防御: 包名白名单 + 拼写检查CI检查         │
│                                              │
│ 4. CI/CD供应链投毒                            │
│    - 恶意CI Action/Plugin                     │
│    ✅ 防御: 锁定Action版本 + 最小权限           │
│                                              │
│ 5. 上游依赖沦陷                              │
│    - 多级依赖中的深层漏洞                      │
│    ✅ 防御: SBOM + 依赖深度扫描                │
│                                              │
└──────────────────────────────────────────────┘
```

### 5. SLSA合规等级

| 等级 | 要求 | 实施措施 | 认证工具 |
|:---:|:---|:---|:---:|
| SLSA 1 | 构建过程文档化 | CI/CD pipeline已配置 | — |
| SLSA 2 | 构建隔离 + 自动化 | 容器化构建 + 签名制品 | Cosign |
| SLSA 3 | 无篡改构建 + 可审计 | 非临时隔离构建 + 构建链验证 | Sigstore |
| SLSA 4 | 双审查 + 可重现 | 2人审查 + 重现性构建 | SLSA Verifier |

### 6. 供应链安全基线

```yaml
# package.json 安全配置
{
  "scripts": {
    "snyk-protect": "snyk protect",
    "sbom": "cyclonedx-bom -o bom.xml"
  },
  "snyk": true,
  "resolutions": {
    "**/**/tar": "6.1.4"   # 锁定传递依赖
  }
}

# npm配置
# .npmrc
registry=https://registry.npmjs.org/
@mycompany:registry=https://npm.mycompany.com/
# 避免依赖混淆
save-prefix=exact
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Snyk | 开源安全平台 | https://snyk.io/ |
| Trivy | 全面漏洞扫描 | https://github.com/aquasecurity/trivy |
| Syft | SBOM生成 | https://github.com/anchore/syft |
| Sigstore/Cosign | 代码签名 | https://www.sigstore.dev/ |
| OWASP DC | 依赖检查 | https://github.com/fabianishere/owasp-dependency-check |
| Dependabot | 自动依赖更新 | https://github.com/dependabot |
| Renovate | 自动依赖更新 | https://github.com/renovatebot/renovate |

## 参考资源
- [SLSA Framework](https://slsa.dev/)
- [CNCF Software Supply Chain Best Practices](https://www.cncf.io/reports/software-supply-chain-security/)
- [NIST SP 800-204D — Supply Chain Risk Management](https://csrc.nist.gov/publications/detail/sp/800-204d/final)
- [OpenSSF Scorecard](https://securityscorecards.dev/)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
