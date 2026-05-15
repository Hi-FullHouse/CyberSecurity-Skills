---
id: 17-008
title: "🔄 多云安全策略评估 (Multi-Cloud Security Strategy)"
category: 云安全
category_en: "Cloud Security"
difficulty: ★★★★★
tools: "Prisma Cloud, Wiz, Orca Security, Lacework, Aqua Security"
last_updated: 2025-07
tags: ["cloud-security", "aws", "azure", "gcp", "cloud-iam", "cloud-network"]
subdomain: cloud-security
nist_csf: ["PR.AC-01", "PR.DS-05", "PR.PT-01"]
mitre_attack: ["T1525", "T1613", "T1537"]
---
# 🔄 多云安全策略评估 (Multi-Cloud Security Strategy)

## 概述
评估跨多云/混合云环境的整体安全策略，包括统一身份管理、合规一致性、安全工具集成、数据主权和云治理框架。

## 核心技能

### 1. 多云安全治理框架

```text
多云安全治理矩阵
┌───────────────────────────────────────────────────────────┐
│            │   AWS          │   Azure       │   GCP       │
├────────────┼────────────────┼───────────────┼─────────────┤
│ 统一IAM    │ IAM + SSO     │ AD + MFA      │ Cloud IAM   │
│ 日志聚合   │ Security Hub  │ Sentinel      │ SCC          │
│ 合规基线   │ Config Rules  │ Policy        │ Forseti      │
│ 密钥管理   │ KMS           │ KeyVault      │ CKM          │
│ WAF        │ WAF + Shield  │ Front Door    │ Cloud Armor │
│ CSPM       │ GuardDuty     │ Defender      │ SCC          │
└───────────────────────────────────────────────────────────┘
```

### 2. CSPM云安全态势管理

```bash
# Prisma Cloud (Palo Alto Networks)
# 自动发现多云资产
# 合规基线检查（CIS, NIST, PCI, SOC2）
# 威胁检测和事件响应

# Wiz (Agentless CNAPP)
# 全栈云安全态势管理
# 漏洞优先级分析
# Kubernetes安全态势

# Orca Security (SideScanning)
# SideScanning无代理扫描
# 深度上下文关联分析
# 跨云统一视图

# 开源替代方案
# ScoutSuite - 多云审计
pip install scoutsuite

# 同时审计多个云
scout aws --profile default
scout azure --tenant-id <id> --subscriptions <sub>
scout gcp --project-id <project>
```

### 3. 跨云统一身份管理评估

```bash
# 检查SSO配置
# AWS IAM Identity Center (SSO)
aws sso-admin list-instances

# Azure AD Connect
# 检查AD同步配置
az ad connect status

# GCP Workforce Identity Federation
gcloud iam workforce-pools list

# 检查跨云角色的信任策略
# AWS角色信任Azure AD
aws iam get-role --role-name <cross-account-role> --query 'Role.AssumeRolePolicyDocument'
```

### 4. 多云合规一致性

| 合规框架 | AWS | Azure | GCP | 关键要求 |
|:---|:---:|:---:|:---:|:---|
| CIS Benchmark | ✅ | ✅ | ✅ | 基线配置检查 |
| ISO 27001 | ✅ | ✅ | ✅ | 全栈管控 |
| PCI DSS | ✅ | ✅ | ✅ | 敏感数据保护 |
| SOC 2 | ✅ | ✅ | ✅ | 安全控制 |
| HIPAA | ✅ | ✅ | ✅ | 医疗数据 |
| FedRAMP | ✅ | ✅ | ✅ | 政府云 |

### 5. 数据主权与地理分布

```bash
# 检查数据驻留策略
# AWS
aws s3api get-bucket-location --bucket <bucket>
aws dynamodb list-tables --region <region>

# Azure
az storage account list --query "[].{name:name, primaryLocation:primaryLocation, secondaryLocation:secondaryLocation}"

# GCP
gcloud compute instances list --format="table(name,zone)"

# 检查跨区域数据复制
aws s3api get-bucket-replication --bucket <bucket>
gcloud storage buckets describe gs://<bucket> --format="json(versioning,encryption)"

# 检查合规边界（GCP VPC-SC）
gcloud access-context-manager perimeters list --policy=<policy-id>
```

### 6. 多云安全成熟度评估

| 成熟度等级 | 特征 | 具体措施 |
|:---:|:---|:---|
| 🟢 初始级 | 单云安全，各自为政 | 基本合规，独立工具 |
| 🟡 重复级 | 多云独立管控 | 统一凭证管理，独立监控 |
| 🟠 定义级 | 统一安全策略 | CSPM工具，基线标准化 |
| 🔵 管理级 | 自动化安全运营 | IaC安全分析，自动化修复 |
| 🟣 优化级 | 预测性安全 | AI威胁预测，自适应策略 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Prisma Cloud | 多云CSPM/CNAPP | https://www.paloaltonetworks.com/prisma/cloud |
| Wiz | 全栈云安全 | https://www.wiz.io/ |
| Orca Security | 无代理云安全 | https://orca.security/ |
| Lacework | 云原生安全 | https://www.lacework.com/ |
| Aqua Security | 云原生应用保护 | https://www.aquasec.com/ |
| ScoutSuite | 开源多云审计 | https://github.com/nccgroup/ScoutSuite |

## 参考资源
- [CSA Cloud Controls Matrix v4](https://cloudsecurityalliance.org/research/cloud-controls-matrix/)
- [NIST SP 500-299 — Cloud Security Architecture](https://csrc.nist.gov/publications/detail/sp/500-299/final)
- [AWS Multi-account Security Strategy](https://docs.aws.amazon.com/whitepapers/latest/multi-account-security-strategy/)
- [Azure Cloud Adoption Framework — Security](https://learn.microsoft.com/azure/cloud-adoption-framework/strategy/security-strategy)
- [GCP Multi-Cloud Security Patterns](https://cloud.google.com/architecture/multi-cloud-security)
