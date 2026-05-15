---
id: "25-004"
title: "🐳 容器镜像安全扫描 (Container Image Security Scan)"
category: "供应链安全"
category_en: "Supply Chain Security"
difficulty: "★★★"
tools: "Trivy, Clair, Grype, Docker Scout, Anchore, Falco"
last_updated: "2025-07"
---

# 🐳 容器镜像安全扫描 (Container Image Security Scan)

## 概述

容器镜像安全扫描是确保云原生应用安全的关键环节。通过扫描操作系统包、应用依赖、配置弱点和恶意软件，识别镜像中的已知漏洞和不合规项，确保"安全可部署"。

## 核心技能

### 1. Trivy 全面扫描

```bash
# Trivy 安装与使用
# 安装
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# 扫描容器镜像
trivy image nginx:alpine

# 扫描并输出JSON（CI集成）
trivy image --severity CRITICAL,HIGH --format json -o report.json python:3.11

# 扫描本地文件系统
trivy filesystem --severity HIGH,CRITICAL /path/to/project

# 扫描Git仓库
trivy repository https://github.com/aquasecurity/trivy

# 扫描SBOM
trivy sbom sbom.json

# 扫描Kubernetes
trivy k8s --report=all cluster

# 配置阈值
trivy image --exit-code 0 --severity MEDIUM nginx:alpine  # 不因中危退出
trivy image --exit-code 1 --severity CRITICAL nginx:alpine # 高危导致CI失败

# 忽略特定的CVE
trivy image --ignorefile .trivyignore nginx:alpine
# .trivyignore 格式:
# CVE-2023-12345
# CVE-2023-67890

# 使用Trivy进行镜像授权策略检查
trivy image --scanners vuln,secret,misconfig nginx:alpine

# 离线扫描（下载数据库）
trivy image --download-db-only
trivy image --cache-dir /path/to/cache/ nginx:alpine
```

### 2. Dockerfile 安全分析

```dockerfile
# 安全的Dockerfile最佳实践
# ❌ 不安全示例
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl wget netcat
COPY . /app
RUN npm install --unsafe-perm
USER root
EXPOSE 3000
CMD ["node", "app.js"]

# ✅ 安全最佳实践
# 使用固定版本构建
FROM node:20.11.0-alpine3.19 AS builder

# 仅安装生产依赖
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production --ignore-scripts

# 复制源码
COPY . .

# 使用多阶段构建
FROM node:20.11.0-alpine3.19
RUN addgroup -g 1001 -S appgroup && \
    adduser -S appuser -u 1001 -G appgroup

# 从builder阶段复制
COPY --from=builder --chown=appuser:appgroup /app /app

# 非root用户运行
USER appuser
WORKDIR /app

# 只暴露必要端口
EXPOSE 3000

# 使用HEALTHCHECK
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# 使用exec格式
CMD ["node", "app.js"]
```

### 3. Docker Scout 集成

```bash
# Docker Scout 使用
# 启用Docker Scout
docker scout enable

# 快速分析
docker scout quickview nginx:latest

# 比较镜像版本
docker scout compare nginx:1.25 nginx:1.24

# 生成SBOM
docker scout sbom nginx:latest --format spdx

# 基于策略的建议
docker scout recommendations nginx:latest

# CI/CD集成
docker scout cves nginx:latest --only-severity critical,high --format sarif

# 查看修复建议
docker scout recommendations --filter base-image nginx:latest
```

### 4. CI/CD 集成容器扫描

```yaml
# GitHub Actions 容器安全扫描
name: Container Security Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  container-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Image
        run: docker build -t my-app:${{ github.sha }} .

      - name: Run Trivy Scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'my-app:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
          ignore-unfixed: true

      - name: Upload Trivy Results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-results.sarif'

      - name: Run Grype Scan
        uses: anchore/scan-action@v3
        with:
          image: 'my-app:${{ github.sha }}'
          severity-cutoff: high
          fail-build: true

# GitLab CI 容器扫描
container_scan:
  stage: test
  image:
    name: aquasec/trivy:latest
    entrypoint: [""]
  variables:
    TRIVY_USERNAME: "$CI_REGISTRY_USER"
    TRIVY_PASSWORD: "$CI_REGISTRY_PASSWORD"
  script:
    - trivy image --severity CRITICAL,HIGH --exit-code 1 $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  only:
    - main
```

### 5. 镜像授权控制与策略

```bash
# Kyverno 容器安全策略
# 禁止latest标签
cat << 'EOF' | kubectl apply -f -
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-latest-tag
spec:
  validationFailureAction: enforce
  rules:
  - name: require-image-tag
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "禁止使用latest标签"
      pattern:
        spec:
          containers:
          - image: "!*:latest"
EOF

# 强制扫描结果
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-vulnerability-scan
spec:
  validationFailureAction: audit
  rules:
  - name: check-trivy-scan
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "镜像必须经过Trivy扫描且无高危漏洞"
      anyPattern:
      - spec:
          containers:
          - image: "*-scanned-*"

# OPA Gatekeeper 策略
cat << 'EOF' > constraint.yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedImages
metadata:
  name: require-trusted-registry
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    trustedRegistries:
      - "harbor.company.com/*"
      - "gcr.io/my-project/*"
EOF
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Trivy | 综合容器扫描器 | https://github.com/aquasecurity/trivy |
| Clair | 开源容器漏洞扫描 | https://quay.io/repository/coreos/clair |
| Grype | 快速漏洞扫描器 | https://github.com/anchore/grype |
| Docker Scout | Docker原生安全 | https://docs.docker.com/scout/ |
| Falco | 运行时安全监控 | https://falco.org/ |
| Kyverno | Kubernetes安全策略 | https://kyverno.io/ |

## 参考资源

- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker/)
- [NSA Kubernetes Hardening Guide](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [CNCF Cloud Native Security Whitepaper](https://www.cncf.io/reports/)
