---
id: 18-002
title: "📦 IaC安全扫描 (Infrastructure as Code Security)"
category: 安全开发运维
category_en: DevSecOps
difficulty: ★★★
tools: "Checkov, Terrascan, tfsec, KICS, cfn-nag, kube-lint"
last_updated: 2025-07
tags: ["devsecops", "ci-cd", "sast", "dast", "iac-security", "supply-chain"]
subdomain: devsecops
nist_csf: ["PR.IP-12", "ID.RA-01", "DE.CM-08"]
mitre_attack: []
---
# 📦 IaC安全扫描 (Infrastructure as Code Security)

## 概述
对Terraform、CloudFormation、ARM、Kubernetes manifests等基础设施即代码进行安全配置扫描，发现错误配置、安全基线偏离和合规违规。

## 核心技能

### 1. Terraform安全扫描

```bash
# 使用Checkov扫描Terraform
pip install checkov

# 扫描目录
checkov -d .

# 指定框架
checkov -d . --framework terraform

# 输出格式
checkov -d . -o json > checkov-report.json
checkov -d . -o junitxml > checkov-report.xml

# 跳过特定检查
checkov -d . --skip-check CKV_AWS_123

# 使用配置文件
cat << 'YAML' > .checkov.yml
directory: .
framework:
  - terraform
  - kubernetes
skip-check:
  - CKV_AWS_1
compact: true
YAML

# 使用tfsec扫描
brew install tfsec  # 或下载二进制
tfsec .
tfsec --no-colour --format json > tfsec-report.json
```

### 2. 常见Terraform安全配置

```hcl
# ❌ 不良实践
resource "aws_s3_bucket" "bad" {
  bucket = "my-bucket"
  # 未配置：acl, versioning, encryption, logging
}

resource "aws_security_group" "bad_sg" {
  name = "bad-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # ❌ 开放SSH到公网
  }
}

# ✅ 良好实践
resource "aws_s3_bucket" "good" {
  bucket = "my-secure-bucket"
  
  versioning {
    enabled = true
  }
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
  
  logging {
    target_bucket = aws_s3_bucket.logs.id
    target_prefix = "s3-access/"
  }
}

resource "aws_s3_bucket_public_access_block" "good" {
  bucket = aws_s3_bucket.good.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "good_sg" {
  name = "good-sg"
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # ✅ 限制内网
  }
}

# 使用变量避免硬编码
variable "allowed_ssh_cidrs" {
  type        = list(string)
  description = "允许SSH访问的CIDR列表"
  default     = ["10.0.0.0/8"]
}
```

### 3. Kubernetes Manifest安全扫描

```bash
# 使用KICS扫描
docker run --rm -v $(pwd):/path checkmarx/kics:latest scan -p /path

# 使用kube-lint
kube-lint manifests/

# 使用polaris
polaris audit --audit-path ./k8s/

# 使用conftest (OPA策略)
conftest test deployment.yaml -p policy/

# 使用kubesec
docker run --rm -i kubesec/kubesec:latest scan /dev/stdin < deployment.yaml
```

```yaml
# ❌ 不良实践的K8s Deployment
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: latest  # ❌ 使用latest标签
        securityContext:
          privileged: true  # ❌ 特权容器
        env:
        - name: DB_PASSWORD
          value: "password123"  # ❌ 明文密钥
        ports:
        - containerPort: 3000

# ✅ 良好实践的K8s Deployment
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: myapp:v1.2.3  # ✅ 固定版本
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
          readOnlyRootFilesystem: true
        env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
```

### 4. IaC安全基线检查清单

| # | 检查项 | 工具 | 严重程度 |
|:---:|:---|:---|:---:|
| 1 | S3桶公共访问阻止 | Checkov CKV_AWS_53 | 🔴 严重 |
| 2 | 安全组不开放SSH/RDP到公网 | Checkov CKV_AWS_24 | 🔴 严重 |
| 3 | 启用EBS/RDS加密 | Checkov CKV_AWS_116 | 🟠 高危 |
| 4 | 容器禁止特权模式 | Checkov CKV_K8S_13 | 🔴 严重 |
| 5 | 容器以非root运行 | Checkov CKV_K8S_22 | 🟠 高危 |
| 6 | 不使用latest标签 | Checkov CKV_K8S_18 | 🟡 中危 |
| 7 | 密钥使用Secret/SecretsManager | Checkov CKV_AWS_41 | 🔴 严重 |
| 8 | 启用CloudTrail | Checkov CKV_AWS_36 | 🟠 高危 |
| 9 | VPC流日志启用 | Checkov CKV_AWS_48 | 🟡 中危 |
| 10 | 数据库不公开访问 | Checkov CKV_AWS_88 | 🔴 严重 |

### 5. CI/CD集成示例

```yaml
# GitHub Actions IaC安全扫描
name: IaC Security Scan
on: [push, pull_request]
jobs:
  iac-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Checkov IaC Scan
        id: checkov
        uses: bridgecrewio/checkov-action@master
        with:
          directory: terraform/
          framework: terraform
          output_format: sarif
          soft_fail: false
          skip_check: CKV_AWS_1
      
      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
      
      - name: tfsec
        uses: aquasecurity/tfsec-action@v1.0.0
        with:
          working_directory: terraform/
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Checkov | IaC安全扫描 | https://github.com/bridgecrewio/checkov |
| tfsec | Terraform安全扫描 | https://github.com/aquasecurity/tfsec |
| Terrascan | IaC扫描 | https://github.com/tenable/terrascan |
| KICS | IaC安全扫描 | https://github.com/Checkmarx/kics |
| cfn-nag | CloudFormation扫描 | https://github.com/stelligent/cfn_nag |
| conftest | OPA策略测试 | https://github.com/open-policy-agent/conftest |

## 参考资源
- [Bridgecrew — IaC Security Best Practices](https://www.bridgecrew.io/blog/infrastructure-as-code-security-best-practices)
- [Terraform Security Guide](https://developer.hashicorp.com/terraform/cloud-docs/workspaces/settings)
- [OWASP Infrastructure as Code Security](https://owasp.org/www-project-kubernetes-security/)
- [CIS Infrastructure as Code Benchmarks](https://www.cisecurity.org/benchmark/infrastructure-as-code/)
