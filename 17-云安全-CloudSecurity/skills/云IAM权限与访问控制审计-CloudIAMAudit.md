---
id: 17-004
title: "🔑 云IAM权限与访问控制审计 (Cloud IAM Audit)"
category: 云安全
category_en: "Cloud Security"
difficulty: ★★★
tools: "AWS IAM Access Analyzer, Azure AD, gcloud IAM, Principal Mapper, Cloudsplaining"
last_updated: 2025-07
tags: ["cloud-security", "aws", "azure", "gcp", "cloud-iam", "cloud-network"]
subdomain: cloud-security
nist_csf: ["PR.AC-01", "PR.DS-05", "PR.PT-01"]
mitre_attack: ["T1525", "T1613", "T1537"]
---
# 🔑 云IAM权限与访问控制审计 (Cloud IAM Audit)

## 概述
跨云平台的身份与访问管理审计方法论，识别过度授权的IAM角色/用户、权限提升路径、闲置凭证和不合规的信任策略。

## 核心技能

### 1. AWS IAM权限审计

```bash
# 使用Cloudsplaining检测IAM权限滥用
pip install cloudsplaining

# 生成IAM授权报告
cloudsplaining download --profile default

# 分析IAM策略中的权限过度配置
cloudsplaining scan --policy-file ./default.json

# 生成HTML报告
cloudsplaining scan --policy-file ./default.json --output ./report

# 使用Principal Mapper分析权限路径
pip install principalmapper
pmapper --profile default graph
pmapper --profile default query "preset=privesc"
pmapper --profile default query "preset=exfiltration"

# 检查IAM Access Analyzer发现
aws accessanalyzer list-findings --analyzer-arn <arn>
```

### 2. Azure RBAC审计

```bash
# 使用Azure CLI审计RBAC
# 查看角色分配
az role assignment list --all --output table

# 列出所有自定义角色及其权限
az role definition list --custom-role-only true --output table

# 检查特权角色下的所有成员
az role assignment list --query "[?roleDefinitionName=='Contributor' || roleDefinitionName=='Owner' || roleDefinitionName=='User Access Administrator']"

# 使用Azure AD Privileged Identity Management (PIM)
az rest --method GET --uri "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess"

# 检查服务主体权限
az ad sp list --all --query "[?appOwnerOrganizationId!=null].{name:displayName, appId:appId, type:appType}" -o table
```

### 3. GCP IAM审计

```bash
# 使用Policy Analyzer
gcloud beta asset analyze-iam-policy --project=<project-id> --identity=<identity>

# 检查服务账号提权路径
gcloud beta asset search-all-resources --asset-types=iam.googleapis.com/ServiceAccount --scope=projects/<project-id>

# 使用Policy Troubleshooter
gcloud beta policy-troubleshoot \
    --principal=<identity> \
    --resource=//cloudresourcemanager.googleapis.com/projects/<project-id> \
    --permission=resourcemanager.projects.get

# 检查服务账号密钥使用期限
gcloud iam service-accounts keys list --iam-account <sa-email> --managed-by=user
```

### 4. 权限提权路径分析

```text
┌─ AWS 提权路径 ─────────────────────────────────────┐
│ 1. iam:PassRole + ec2:RunInstances → 启动特权实例    │
│ 2. iam:CreateAccessKey → 创建其他用户的访问密钥        │
│ 3. iam:CreateLoginProfile → 创建控制台密码            │
│ 4. iam:UpdateAssumeRolePolicy → 修改信任策略          │
│ 5. lambda:CreateFunction + iam:PassRole → 执行函数     │
└─────────────────────────────────────────────────────┘

┌─ Azure 提权路径 ────────────────────────────────────┐
│ 1. 拥有Managed Contributor → 创建KeyVault → 读取密钥  │
│ 2. 拥有User Access Administrator → 提升自己为Owner    │
│ 3. 拥有AAD Global Admin → 全局权限扩展                  │
│ 4. 拥有虚拟机Contributor → 运行自定义脚本获取Vault凭证  │
└─────────────────────────────────────────────────────┘

┌─ GCP 提权路径 ──────────────────────────────────────┐
│ 1. iam.serviceAccounts.getAccessToken → 模拟服务账号  │
│ 2. iam.serviceAccounts.implicitDelegation → 提权     │
│ 3. iam.roles.update → 修改角色权限                     │
│ 4. compute.instances.setServiceAccount → 修改VM服务账号│
└─────────────────────────────────────────────────────┘
```

### 5. IAM合规基线

| 检查项 | AWS | Azure | GCP |
|:---|:---|:---|:---|
| 禁用根用户访问密钥 | ✅ 必查 | ✅ 必查 | ✅ 必查 |
| 最小权限原则 | IAM Access Analyzer | PIM | IAM Recommender |
| 定期凭证轮换 | 90天密钥轮换 | 证书自动轮换 | 服务账号密钥管理 |
| 多因素认证(MFA) | AWS MFA强制 | Azure AD CA策略 | 两步验证 |
| 条件访问 | SCP + Permission Boundary | Conditional Access | VPC Service Controls |
| 资源级权限 | 资源级策略 | 管理组作用域 | 自定义角色 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Cloudsplaining | AWS IAM权限分析 | https://github.com/salesforce/cloudsplaining |
| Principal Mapper | AWS IAM权限路径分析 | https://github.com/nccgroup/PMapper |
| Azure AD PIM | Azure特权身份管理 | https://learn.microsoft.com/azure/active-directory/privileged-identity-management/ |
| GCP IAM Recommender | GCP IAM建议 | https://cloud.google.com/recommender/docs/iam |
| SCP Explorer | AWS SCP策略可视化 | https://github.com/amzn/scp-explorer |
| SkyArk | Azure特权账号审计 | https://github.com/cyberark/SkyArk |

## 参考资源
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Azure RBAC Best Practices](https://learn.microsoft.com/azure/role-based-access-control/best-practices)
- [GCP IAM Security Best Practices](https://cloud.google.com/iam/docs/using-iam-securely)
- [MITRE ATT&CK — T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/)
