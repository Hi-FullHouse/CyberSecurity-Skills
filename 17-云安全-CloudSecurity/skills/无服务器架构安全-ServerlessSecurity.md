---
id: 17-007
title: "⚡ 无服务器架构安全 (Serverless Security)"
category: 云安全
category_en: "Cloud Security"
difficulty: ★★★★
tools: "AWS Lambda Check, Serverless Framework, PureSec, Snyk"
last_updated: 2025-07
tags: ["cloud-security", "aws", "azure", "gcp", "cloud-iam", "cloud-network"]
subdomain: cloud-security
nist_csf: ["PR.AC-01", "PR.DS-05", "PR.PT-01"]
mitre_attack: ["T1525", "T1613", "T1537"]
---
# ⚡ 无服务器架构安全 (Serverless Security)

## 概述
评估AWS Lambda、Azure Functions、GCP Cloud Functions等无服务器计算环境的安全性，涵盖函数权限配置、事件源安全、依赖漏洞和环境变量保护。

## 核心技能

### 1. AWS Lambda安全审计

```bash
# 检查Lambda函数权限
aws lambda list-functions --query "Functions[*].[FunctionName,Handler,Runtime]"

# 检查函数IAM角色
aws lambda get-function-configuration --function-name <name> --query 'Role'

# 检查函数环境变量（不要包含明文密钥）
aws lambda get-function-configuration --function-name <name> --query 'Environment'

# 检查函数是否具有VPC配置
aws lambda get-function-configuration --function-name <name> --query 'VpcConfig'

# 检查函数URL配置（公开访问）
aws lambda list-function-url-configs --function-name <name>

# 检查函数并发限制
aws lambda get-function-concurrency --function-name <name>

# 检查函数代码签名
aws lambda get-function --function-name <name> --query 'CodeSigningConfig'

# 检查函数事件源映射
aws lambda list-event-source-mappings --function-name <name>
```

### 2. 函数权限与资源策略

```bash
# 检查Lambda资源策略（跨账号调用）
aws lambda get-policy --function-name <name> 2>/dev/null

# 检查函数是否允许公共调用
aws lambda get-function-url-config --function-name <name>

# 检查执行角色的托管策略
aws iam list-attached-role-policies --role-name <lambda-exec-role>
aws iam list-role-policies --role-name <lambda-exec-role>

# 检查执行角色是否配置了最小权限
# 不良实践：使用AdministratorAccess
# 良好实践：仅授予函数所需的特定权限

# 检查死信队列(DLQ)配置
aws lambda get-function-configuration --function-name <name> --query 'DeadLetterConfig'
```

### 3. Azure Functions安全审计

```bash
# 检查函数应用配置
az functionapp show --name <name> --resource-group <rg>

# 检查HTTPS仅配置
az functionapp show --name <name> --query "httpsOnly"

# 检查认证设置
az functionapp auth show --name <name> --resource-group <rg>

# 检查CORS配置
az functionapp cors show --name <name> --resource-group <rg>

# 检查应用程序设置中的密钥
az functionapp config appsettings list --name <name> --resource-group <rg>

# 检查客户端证书
az functionapp show --name <name> --query "clientCertEnabled"
```

### 4. GCP Cloud Functions安全审计

```bash
# 列出所有Cloud Functions
gcloud functions list

# 检查函数配置
gcloud functions describe <name> --region=<region> --format=json

# 检查入口权限（是否允许未经身份验证的调用）
gcloud functions get-iam-policy <name> --region=<region>

# 检查环境变量
gcloud functions describe <name> --region=<region> --format="table(eventTrigger,httpsTrigger)"

# 检查VPC连接
gcloud functions describe <name> --region=<region> --format="table(serviceConfig.vpcConnector)"

# 检查函数超时和内存配置
gcloud functions describe <name> --region=<region> --format="table(serviceConfig.timeoutSeconds,serviceConfig.availableMemoryMb)"
```

### 5. 无服务器安全基线

| # | 检查项 | AWS Lambda | Azure Functions | GCP Cloud Functions |
|:---:|:---|:---:|:---:|:---:|
| 1 | 最小权限IAM角色 | ✅ 必查 | ✅ 必查 | ✅ 必查 |
| 2 | 环境变量加密 | ✅ KMS加密 | ✅ KeyVault引用 | ✅ Secret Manager |
| 3 | 依赖漏洞扫描 | ✅ Snyk/Lambda层 | ✅ OWASP DC | ✅ Snyk |
| 4 | 函数超时限制 | ✅ 建议 < 5分钟 | ✅ 建议 < 5分钟 | ✅ 建议 < 5分钟 |
| 5 | VPC部署 | ✅ 推荐 | ✅ 推荐 | ✅ 推荐 |
| 6 | 禁止公开URL | ✅ 如无必要 | ✅ 如无必要 | ✅ 如无必要 |
| 7 | 启用日志监控 | ✅ CloudWatch | ✅ App Insights | ✅ Cloud Logging |
| 8 | 代码签名 | ✅ 推荐 | ✅ 推荐 | ✅ 推荐 |

### 6. 常见漏洞与加固

```python
# 不良实践：环境变量中存储明文密钥
import os

# ❌ 不良实践
API_KEY = os.environ['API_KEY']  # 明文存在于明文环境变量

# ✅ 良好实践 - 使用KMS/Secret Manager解密
import boto3
from base64 import b64decode
kms = boto3.client('kms')
encrypted_key = os.environ['ENCRYPTED_API_KEY']
API_KEY = kms.decrypt(CiphertextBlob=b64decode(encrypted_key))['Plaintext']

# 不良实践：无输入验证
def handler(event, context):
    # ❌ 直接反序列化未验证的输入
    user_input = event['body']
    # ✅ 应进行输入验证和白名单过滤

# 不良实践：过大的函数权限
# ❌ Lambda执行角色带有S3:*和DynamoDB:*
# ✅ 仅授予函数实际访问的特定资源和操作
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| AWS Lambda Check | Lambda安全扫描 | https://github.com/1v1d/lambda-check |
| PureSec | 无服务器安全平台 | https://www.puresec.io/ |
| Snyk | 依赖漏洞扫描 | https://snyk.io/ |
| Serverless Framework | 无服务器框架 | https://www.serverless.com/ |
| Aqua Security | Serverless安全 | https://www.aquasec.com/ |

## 参考资源
- [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/)
- [AWS Lambda Security Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/security-best-practices.html)
- [Azure Functions Security](https://learn.microsoft.com/azure/azure-functions/security-concepts)
- [GCP Cloud Functions Security](https://cloud.google.com/functions/docs/securing)
