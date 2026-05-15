---
id: 18-001
title: "🔗 CI/CD管道安全审计 (CI/CD Pipeline Security)"
category: 安全开发运维
category_en: DevSecOps
difficulty: ★★★★
tools: "GitLab CI Security, Jenkins Security Scanner, GitGuardian, TruffleHog"
last_updated: 2025-07
tags: ["devsecops", "ci-cd", "sast", "dast", "iac-security", "supply-chain"]
subdomain: devsecops
nist_csf: ["PR.IP-12", "ID.RA-01", "DE.CM-08"]
mitre_attack: []
---
# 🔗 CI/CD管道安全审计 (CI/CD Pipeline Security)

## 概述
对CI/CD管道进行端到端安全审计，包括代码仓库安全、构建环境隔离、凭证管理、制品签名和部署安全管控。

## 核心技能

### 1. CI/CD配置安全基线

```yaml
# GitLab CI安全配置示例
variables:
  # ❌ 不良实践：硬编码密钥
  # API_KEY: "sk-xxx"
  
  # ✅ 良好实践：使用CI/CD变量（掩码）
  # 在Settings > CI/CD > Variables中配置，勾选Masked

# 安全job模板
.security-job:
  before_script:
    - echo "⚠️ 安全扫描阶段开始"
  after_script:
    - echo "✅ 扫描完成"
  only:
    - main
    - develop

# Jenkins Pipeline安全实践
// Jenkinsfile
pipeline {
  agent any
  environment {
    // ✅ 使用credentials插件
    DOCKER_CREDS = credentials('docker-hub-creds')
    // ❌ 避免：明文密码
  }
  stages {
    stage('Security Scan') {
      steps {
        // SAST扫描
        sh 'semgrep --config=auto .'
        // 密钥扫描
        sh 'trufflehog --no-update --exclude-paths=.exclude file://.'
      }
    }
  }
}
```

### 2. CI/CD凭证泄露检测

```bash
# 使用TruffleHog扫描代码仓库
docker run --rm -v "$(pwd):/project" trufflesecurity/trufflehog:latest \
  filesystem --directory=/project

# 扫描Git历史
trufflehog git --branch=main --since-commit HEAD~10 .

# 使用GitGuardian扫描
# 安装CLI
pip install ggshield
ggshield scan path . --show-secrets

# 扫描Git历史中的密钥
ggshield scan commit-range HEAD~10..HEAD

# 使用Gitleaks
docker run --rm -v $(pwd):/path zricethezav/gitleaks:latest detect --source="/path" --verbose

# 扫描CI/CD变量中的密钥
# GitLab: 检查masked变量
# Jenkins: 检查Credential Provider配置
```

### 3. 构建环境隔离评估

```bash
# 检查容器化构建的安全性
# Dockerfile安全实践
cat << 'DOCKERFILE' > Dockerfile.secure
# ✅ 使用指定版本镜像
FROM node:18-alpine AS builder

# ✅ 使用非root用户
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# ✅ 多阶段构建
COPY --chown=appuser:appuser package*.json ./
RUN npm ci --only=production
COPY --chown=appuser:appuser . .

# ✅ 最终镜像最小化
FROM node:18-alpine AS production
COPY --from=builder /app /app
USER appuser
CMD ["node", "app.js"]
DOCKERFILE

# 检查BuildKit安全配置
export DOCKER_BUILDKIT=1

# GitHub Actions安全实践
cat << 'YAML' > .github/workflows/secure.yml
name: Secure Build
on: [push]
jobs:
  secure-build:
    runs-on: ubuntu-latest
    permissions:
      contents: read  # 👈 最小权限
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - name: SAST扫描
        uses: github/codeql-action/analyze@v3
YAML
```

### 4. CI/CD安全控制清单

| # | 控制项 | 严重程度 | GitHub | GitLab | Jenkins |
|:---:|:---|:---:|:---:|:---:|:---:|
| 1 | 禁止密钥硬编码 | 🔴 严重 | Secret Scanning | Secret Detection | Credentials Plugin |
| 2 | 分支保护规则 | 🟠 高危 | Branch Protection | Protected Branches | Branch Restriction |
| 3 | 签名提交要求 | 🟡 中危 | GPG Signing | GPG Signing | Key Management |
| 4 | 构建容器化隔离 | 🟠 高危 | Actions Runner | Docker Runner | Kubernetes Agent |
| 5 | 最小权限CI_TOKEN | 🟠 高危 | Fine-grained PAT | Project Access Token | Credential Scoping |
| 6 | SBOM生成 | 🟡 中危 | Dependency Graph | CyclonedX | SPDX Plugin |
| 7 | 代码审查强制 | 🟡 中危 | Required Reviewers | Merge Request Approvals | Code Review |
| 8 | 制品签名 | 🟠 高危 | Sigstore/Cosign | Cosign | Sign Plugin |

### 5. CI/CD攻击路径分析

```text
┌─ CI/CD常见攻击路径 ───────────────────────────┐
│                                                 │
│ 1. 供应链投毒                                   │
│    ├─ 恶意NPM包 → 被CI/CD下载 → 植入后门       │
│    └─ 依赖混淆 → 私有包被公开包覆盖             │
│                                                 │
│ 2. CI/CD凭证泄露                                │
│    ├─ CI_JOB_TOKEN泄露 → 代码仓库被访问         │
│    ├─ 云凭据泄露 → 云环境被接管                  │
│    └─ SSH密钥泄露 → 服务器被入侵                │
│                                                 │
│ 3. 管道逻辑漏洞                                 │
│    ├─ 未授权的Merge Request → 触发生产部署      │
│    ├─ 条件判断绕过 → 跳过安全扫描阶段           │
│    └─ 缓存污染 → 使用恶意构建缓存               │
│                                                 │
│ 4. 第三方Action/Plugin滥用                       │
│    ├─ 未锁定版本 → Action被恶意更新              │
│    └─ 社区插件 → 权限过大                       │
│                                                 │
└─────────────────────────────────────────────────┘
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| TruffleHog | Git密钥扫描 | https://github.com/trufflesecurity/trufflehog |
| Gitleaks | Git密钥检测 | https://github.com/gitleaks/gitleaks |
| GitGuardian | 密钥泄露监控 | https://www.gitguardian.com/ |
| Sigstore/Cosign | 制品签名 | https://www.sigstore.dev/ |
| SLSA Framework | 供应链等级 | https://slsa.dev/ |
| OWASP WrongSecrets | CI/CD安全测试 | https://github.com/commjoen/wrongsecrets |

## 参考资源
- [OWASP CI/CD Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html)
- [GitLab CI/CD Security Best Practices](https://docs.gitlab.com/ee/ci/security/)
- [GitHub Security Best Practices for Actions](https://docs.github.com/actions/security-guides/security-hardening-for-github-actions)
- [CISA — Securing CI/CD Pipeline](https://www.cisa.gov/sites/default/files/publications/)
