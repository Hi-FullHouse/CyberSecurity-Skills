---
id: "33-001"
title: "容器镜像安全与漏洞扫描 (Container Image Security & Scanning)"
category: "容器安全"
category_en: "Container Security"
difficulty: "★★★"
tools: "Trivy, Grype, Docker Scout, Clair, Cosign, Syft"
last_updated: "2026-05"
tags: [container-security, image-scanning, vulnerability, sbom, supply-chain]
subdomain: container-security
nist_csf: [ID.RA-01, PR.DS-03, PR.DS-06, DE.CM-08]
mitre_attack: [T1204, T1525, T1578, T1610]
---

# 容器镜像安全与漏洞扫描 (Container Image Security & Scanning)

## 概述

容器镜像安全是云原生安全的第一道防线。镜像中隐藏的漏洞、恶意软件和配置错误是攻击者进入容器环境的常见入口。本技能覆盖镜像漏洞扫描、Dockerfile 安全最佳实践、SBOM 生成、镜像签名和供应链安全。

## 核心技能

### 1. 镜像漏洞扫描

```bash
# Trivy — 全面镜像漏洞扫描
# 安装 Trivy
sudo apt-get install trivy
# 或
brew install trivy

# 扫描镜像
trivy image nginx:latest

# 按严重性过滤
trivy image --severity CRITICAL,HIGH nginx:latest

# 只输出修复建议
trivy image --ignore-unfixed nginx:latest

# 扫描并输出 JSON
trivy image --format json -o nginx_vulns.json nginx:latest

# 扫描 Dockerfile (IaC 安全)
trivy config Dockerfile

# 扫描容器文件系统
trivy fs /path/to/project

# 扫描私有仓库镜像
trivy image --username admin --password pass registry.company.com/app:1.0

# 扫描归档文件
trivy image --input alpine.tar

# 持续集成 (CI) 集成退出码
trivy image --exit-code 1 --severity CRITICAL,HIGH python:3.9-slim
```

```bash
# Grype — 快速镜像扫描
# 安装 Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# 扫描镜像
grype nginx:latest

# 按严重性过滤
grype nginx:latest --only-fixed

# 输出 JSON
grype nginx:latest -o json > grype_results.json

# 生成 CycloneDX SBOM
grype nginx:latest -o cyclonedx > sbom.json

# Syft — 生成 SBOM
syft nginx:latest -o spdx-json > nginx.spdx.json

# SBOM 格式支持:
# - SPDX (ISO standard)
# - CycloneDX (OWASP standard)
# - Syft JSON

# Docker Scout — Docker 官方镜像分析
docker scout quickview nginx:latest
docker scout recommendations nginx:latest

# Docker Scout 策略评估
docker scout policy nginx:latest --platform linux/amd64
```

### 2. Dockerfile 安全最佳实践

```dockerfile
# Dockerfile 安全最佳实践

# 1. 使用官方签名基础镜像
FROM python:3.11-slim AS builder

# 2. 设置 LABEL 维护者信息
LABEL maintainer="security@company.com" \
      version="1.0.0" \
      description="Secure Python Application"

# 3. 使用非 root 用户运行
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

# 4. 多阶段构建 — 分离构建与运行环境
# 构建阶段
FROM python:3.11-slim AS build
COPY requirements.txt .
RUN pip install --user -r requirements.txt

# 运行阶段
FROM python:3.11-slim
COPY --from=build /root/.local /root/.local

# 5. 最小化安装包
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# 6. 复制文件并设置权限
COPY --chown=appuser:appgroup app/ /app/
WORKDIR /app

# 7. 切换到非 root 用户
USER appuser

# 8. 设置只读根文件系统
# (需要在容器运行时配置 --read-only)
# docker run --read-only --tmpfs /tmp ...

# 9. 设置 HEALTHCHECK
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:8080/health || exit 1

# 10. 使用 exec 格式的 CMD
CMD ["python", "app.py"]
```

### 3. 镜像签名与供应链安全

```bash
# Cosign — 镜像签名与验证
# 安装 Cosign
wget https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
chmod +x /usr/local/bin/cosign

# 生成密钥对
cosign generate-key-pair

# 签名镜像
cosign sign --key cosign.key registry.company.com/app:1.0

# 验证签名
cosign verify --key cosign.pub registry.company.com/app:1.0

# 使用密钥less 签名 (OIDC)
cosign sign registry.company.com/app:1.0

# 镜像完整性策略
# cosign verify 确保:
# 1. 镜像来自可信构建管道
# 2. 镜像未被篡改
# 3. 镜像签名者身份可验证

# Notary — Docker 内容信任
# 启用 Docker 内容信任
export DOCKER_CONTENT_TRUST=1

# 签名推送
docker push registry.company.com/app:1.0
# 只推送带签名的镜像

# 只拉取带签名的镜像
DOCKER_CONTENT_TRUST=1 docker pull registry.company.com/app:1.0

# SLSA 供应链安全级别
# SLSA 1: 构建过程文档化
# SLSA 2: 构建过程完整 + 签名
# SLSA 3: 隔离构建 + 无外部影响
# SLSA 4: 完全可审计 + 双重审查
```

### 4. 镜像安全策略自动化

```python
"""镜像安全策略引擎"""

class ImageSecurityPolicy:
    """容器镜像安全策略"""
    
    def __init__(self):
        self.vulnerability_threshold = {
            "CRITICAL": 0,    # 不允许任何严重漏洞
            "HIGH": 2,        # 最多 2 个高危
            "MEDIUM": 10      # 最多 10 个中危
        }
        self.allowed_base_images = [
            "python:3.11-slim", "node:20-alpine",
            "alpine:3.19", "nginx:alpine"
        ]
        self.denied_packages = [
            "telnet", "netcat", "curl", "wget"
        ]
    
    def evaluate_image(self, scan_result, image_name):
        """评估镜像是否通过安全策略"""
        violations = []
        
        # 1. 检查基础镜像白名单
        if not any(base in image_name for base in self.allowed_base_images):
            violations.append({
                "type": "base_image",
                "severity": "HIGH",
                "message": f"镜像 {image_name} 不在允许的基础镜像列表中"
            })
        
        # 2. 检查漏洞阈值
        vulns = scan_result.get("vulnerabilities", [])
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
        for vuln in vulns:
            sev = vuln.get("Severity", "UNKNOWN")
            if sev in severity_count:
                severity_count[sev] += 1
        
        for sev, count in severity_count.items():
            threshold = self.vulnerability_threshold.get(sev, 999)
            if count > threshold:
                violations.append({
                    "type": "vulnerability",
                    "severity": sev,
                    "message": f"{sev} 漏洞 {count} 个，超过阈值 {threshold}"
                })
        
        # 3. 检查危险包
        for vuln in vulns:
            pkg = vuln.get("PkgName", "")
            if pkg in self.denied_packages:
                violations.append({
                    "type": "denied_package",
                    "severity": "HIGH",
                    "message": f"镜像包含危险包: {pkg}"
                })
        
        passed = len(violations) == 0
        return {
            "image": image_name,
            "passed": passed,
            "violations": violations,
            "vulnerability_summary": severity_count
        }

# 使用示例
policy = ImageSecurityPolicy()
result = policy.evaluate_image({
    "vulnerabilities": [
        {"Severity": "CRITICAL", "PkgName": "libssl", "VulnerabilityID": "CVE-2026-1234"},
    ]
}, "python:3.11-slim")
print(f"Policy passed: {result['passed']}")
for v in result['violations']:
    print(f"  [!] {v['message']}")
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Trivy | 镜像漏洞扫描 | https://github.com/aquasecurity/trivy |
| Grype | 快速镜像扫描 | https://github.com/anchore/grype |
| Cosign | 镜像签名 | https://github.com/sigstore/cosign |
| Syft | SBOM 生成 | https://github.com/anchore/syft |
| Docker Scout | Docker 镜像分析 | https://docs.docker.com/scout/ |

## 参考资源

- [Dockerfile Security Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [NIST SP 800-190 — Container Security](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Sigstore / Supply Chain Security](https://www.sigstore.dev/)
- [SLSA Framework](https://slsa.dev/)
