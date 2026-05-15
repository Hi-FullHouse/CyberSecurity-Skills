---
id: "32-003"
title: "云IAM与联邦认证 (Cloud IAM & Federation)"
category: "身份与访问管理"
category_en: "Identity & Access Management"
difficulty: "★★★★"
tools: "AWS IAM, GCP IAM, Azure RBAC, Okta, Terraform"
last_updated: "2026-05"
tags: [cloud-iam, federation, aws-iam, gcp-iam, azure-rbac, oidc]
subdomain: identity-access-management
nist_csf: [PR.AC-01, PR.AC-04, PR.AC-06, PR.AC-07]
mitre_attack: [T1078, T1528, T1550, T1613]
---

# 云IAM与联邦认证 (Cloud IAM & Federation)

## 概述

云环境中的 IAM 是多云安全的基础。不同云厂商的 IAM 模型各有特点，需要统一管理和联邦集成。本技能覆盖 AWS IAM、GCP IAM、Azure RBAC 的策略编写、跨云联邦认证和基础设施即代码（IaC）管理。

## 核心技能

### 1. AWS IAM 策略

```python
"""AWS IAM 策略生成与分析"""

import json

class AWSIAMPolicy:
    """AWS IAM 策略构建器"""
    
    @staticmethod
    def allow_policy(actions, resources, conditions=None):
        """创建允许策略"""
        statement = {
            "Effect": "Allow",
            "Action": actions if isinstance(actions, list) else [actions],
            "Resource": resources if isinstance(resources, list) else [resources]
        }
        if conditions:
            statement["Condition"] = conditions
        
        return {
            "Version": "2012-10-17",
            "Statement": [statement]
        }
    
    @staticmethod
    def deny_policy(actions, resources):
        """创建显式拒绝策略"""
        return {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Action": actions if isinstance(actions, list) else [actions],
                "Resource": resources if isinstance(resources, list) else [resources]
            }]
        }
    
    @staticmethod
    def managed_policy_example():
        """托管策略示例"""
        # 最小权限 S3 访问策略
        return AWSIAMPolicy.allow_policy(
            actions=["s3:GetObject", "s3:ListBucket"],
            resources=[
                "arn:aws:s3:::company-data",
                "arn:aws:s3:::company-data/*"
            ],
            conditions={
                "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},
                "Bool": {"aws:SecureTransport": "true"}
            }
        )
    
    @staticmethod
    def trust_policy_for_federation():
        """联邦信任策略"""
        return {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": "accounts.google.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        "accounts.google.com:sub": "123456789012345678901"
                    }
                }
            }]
        }
    
    @staticmethod
    def analyze_policy(policy):
        """分析策略风险"""
        risks = []
        for stmt in policy.get("Statement", []):
            # 检查通配符
            if "*" in str(stmt.get("Resource", "")):
                risks.append("通配符资源: 策略影响范围过大")
            if "*" in str(stmt.get("Action", "")):
                risks.append("通配符操作: 建议限制具体操作")
            if stmt.get("Effect") == "Allow" and \
               "*" in str(stmt.get("Action", "")) and \
               "*" in str(stmt.get("Resource", "")):
                risks.append("CRITICAL: 完全通配策略 (Action=*, Resource=*)")
        return risks

# 使用示例
policy = AWSIAMPolicy.managed_policy_example()
print(json.dumps(policy, indent=2))
risks = AWSIAMPolicy.analyze_policy(policy)
for r in risks:
    print(f"[!] {r}")
```

```bash
# AWS IAM CLI 操作

# 创建 IAM 用户
aws iam create-user --user-name alice

# 创建 IAM 组
aws iam create-group --group-name security-engineers

# 将用户加入组
aws iam add-user-to-group --user-name alice --group-name security-engineers

# 创建自定义策略
aws iam create-policy \
  --policy-name SecurityReadOnly \
  --policy-document file://security-readonly.json

# 附加策略到组
aws iam attach-group-policy \
  --group-name security-engineers \
  --policy-arn arn:aws:iam::123456789012:policy/SecurityReadOnly

# 创建角色（跨账号访问）
aws iam create-role \
  --role-name SecurityAuditRole \
  --assume-role-policy-document file://trust-policy.json

# IAM 访问报告
aws iam generate-credential-report
aws iam get-credential-report --output text

# 检查未使用的 IAM 用户
aws iam list-users | jq -r '.Users[] | select(.PasswordLastUsed == null) | .UserName'

# IAM Access Analyzer
aws accessanalyzer create-analyzer --analyzer-name console-analyzer --type ACCOUNT
aws accessanalyzer list-findings --analyzer-name console-analyzer
```

### 2. GCP IAM 策略

```bash
# GCP IAM 基础

# 查看 IAM 策略
gcloud projects get-iam-policy <project-id>

# 添加 IAM 策略绑定
gcloud projects add-iam-policy-binding <project-id> \
  --member="user:alice@company.com" \
  --role="roles/compute.admin"

# 创建自定义角色
gcloud iam roles create SecurityViewer \
  --project=<project-id> \
  --title="Security Viewer" \
  --description="Read-only security access" \
  --permissions=securitycenter.findings.list,securitycenter.assets.list \
  --stage=GA

# 服务账号管理
gcloud iam service-accounts create security-sa \
  --display-name="Security Service Account"

# 服务账号密钥管理
gcloud iam service-accounts keys create sa-key.json \
  --iam-account=security-sa@<project-id>.iam.gserviceaccount.com

# 条件 IAM 策略（基于上下文）
cat > conditional_policy.yaml << 'EOF'
bindings:
- members:
  - user:alice@company.com
  role: roles/storage.objectAdmin
  condition:
    title: office_hours_only
    expression: request.time.getHours("America/New_York") >= 9 
                && request.time.getHours("America/New_York") <= 17
EOF

gcloud projects set-iam-policy <project-id> conditional_policy.yaml
```

### 3. Azure RBAC 与条件访问

```bash
# Azure RBAC 管理

# 查看角色分配
az role assignment list --all

# 创建自定义角色
cat > custom_role.json << 'EOF'
{
  "Name": "Security Reader",
  "Description": "Read security configurations",
  "Actions": [
    "Microsoft.Security/*/read",
    "Microsoft.Storage/*/read",
    "Microsoft.Network/*/read"
  ],
  "NotActions": [],
  "AssignableScopes": ["/subscriptions/<sub-id>"]
}
EOF

az role definition create --role-definition custom_role.json

# 分配角色
az role assignment create \
  --assignee "alice@company.com" \
  --role "Security Reader" \
  --scope "/subscriptions/<sub-id>"

# Azure AD 条件访问策略
# 位置: Azure AD → 安全性 → 条件访问

# 条件访问策略示例:
# 策略1: 所有管理员账号需要 MFA
# 策略2: 外网访问需要 MFA + 合规设备
# 策略3: 从非信任位置登录需要 MFA + 密码更改

# 使用 Azure CLI 配置条件访问
# (需要 Azure AD Premium P1/P2)
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

# Azure 托管身份（Managed Identity）
# 为 VM 启用托管身份
az vm identity assign --resource-group my-rg --name my-vm

# 为托管身份分配权限
az role assignment create \
  --assignee $(az vm show -g my-rg -n my-vm --query identity.principalId -o tsv) \
  --role "Reader" \
  --scope "/subscriptions/<sub-id>/resourceGroups/my-rg"
```

### 4. 联邦身份集成

```yaml
# Terraform — 跨云 IAM 基础设施即代码

# AWS IAM 角色与 OIDC 联邦
resource "aws_iam_role" "github_actions_role" {
  name = "github-actions-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "accounts.google.com"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "accounts.google.com:aud": "github-actions"
          }
        }
      }
    ]
  })
}

# Azure AD 应用注册与 OIDC
resource "azuread_application" "sso_app" {
  display_name = "Enterprise SSO Application"
  
  single_page_application {
    redirect_uris = ["https://app.company.com/auth/callback"]
  }
  
  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
    resource_access {
      id   = "e1fe6dd8-ba31-4d61-898e-88685b0c7e7d"  # User.Read
      type = "Scope"
    }
  }
}

# GCP 跨项目 IAM
resource "google_project_iam_member" "cross_project" {
  project = "target-project"
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:security-sa@shared-project.iam.gserviceaccount.com"
  
  condition {
    title       = "limited_access"
    description = "Only allow during business hours"
    expression  = "request.time.getHours('America/New_York') >= 9 && request.time.getHours('America/New_York') <= 17"
  }
}
```

```python
"""联邦身份认证验证"""

import jwt
import requests
from datetime import datetime

class FederationValidator:
    """联邦身份认证验证器"""
    
    WELL_KNOWN_URLS = {
        "google": "https://accounts.google.com/.well-known/openid-configuration",
        "azure": "https://login.microsoftonline.com/common/.well-known/openid-configuration",
        "okta": "https://{org}.okta.com/.well-known/openid-configuration"
    }
    
    @staticmethod
    def verify_oidc_token(token, expected_issuer, expected_audience):
        """验证 OIDC token"""
        try:
            # 获取 OIDC 配置
            # config = requests.get(FederationValidator.WELL_KNOWN_URLS["google"]).json()
            # keys = requests.get(config["jwks_uri"]).json()
            
            # 验证 JWT 签名（生产中使用 JWKS）
            decoded = jwt.decode(
                token,
                options={"verify_signature": False},  # 生产必须验证签名
                audience=expected_audience,
                issuer=expected_issuer
            )
            
            # 检查过期
            exp = decoded.get("exp", 0)
            if datetime.fromtimestamp(exp) < datetime.now():
                return {"valid": False, "reason": "Token expired"}
            
            return {
                "valid": True,
                "claims": {
                    "sub": decoded.get("sub"),
                    "email": decoded.get("email"),
                    "name": decoded.get("name"),
                    "issuer": decoded.get("iss"),
                    "expires": datetime.fromtimestamp(exp).isoformat()
                }
            }
        except Exception as e:
            return {"valid": False, "reason": str(e)}
    
    @staticmethod
    def assume_role_with_web_identity(token, role_arn, session_name):
        """使用 Web Identity 切换角色 (AWS STS)"""
        import boto3
        
        sts = boto3.client("sts")
        response = sts.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            WebIdentityToken=token,
            DurationSeconds=3600
        )
        
        return {
            "access_key_id": response["Credentials"]["AccessKeyId"],
            "secret_access_key": response["Credentials"]["SecretAccessKey"],
            "session_token": response["Credentials"]["SessionToken"],
            "expiration": response["Credentials"]["Expiration"].isoformat()
        }

# 使用示例
validator = FederationValidator()
print("OIDC 验证器就绪 (生产环境需配置 JWKS)")
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| AWS IAM | AWS 访问管理 | https://aws.amazon.com/iam/ |
| GCP IAM | Google Cloud IAM | https://cloud.google.com/iam |
| Azure RBAC | Azure 角色管理 | https://learn.microsoft.com/en-us/azure/role-based-access-control/ |
| Okta | 联邦身份平台 | https://www.okta.com/ |
| Terraform | IaC IAM 管理 | https://www.terraform.io/ |

## 参考资源

- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [GCP IAM Documentation](https://cloud.google.com/iam/docs)
- [Azure Identity Management](https://learn.microsoft.com/en-us/azure/security/fundamentals/identity-management-overview)
- [OIDC Federation — AWS](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)
- [NIST SP 800-63 — Digital Identity](https://csrc.nist.gov/publications/detail/sp/800-63/3/final)
