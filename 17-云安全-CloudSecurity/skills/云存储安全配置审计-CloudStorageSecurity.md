---
id: 17-005
title: "💾 云存储安全配置审计 (Cloud Storage Security)"
category: 云安全
category_en: "Cloud Security"
difficulty: ★★★
tools: "S3 Scanner, CloudSploit, gsutil, Azure Storage Explorer"
last_updated: 2025-07
tags: ["cloud-security", "aws", "azure", "gcp", "cloud-iam", "cloud-network"]
subdomain: cloud-security
nist_csf: ["PR.AC-01", "PR.DS-05", "PR.PT-01"]
mitre_attack: ["T1525", "T1613", "T1537"]
---
# 💾 云存储安全配置审计 (Cloud Storage Security)

## 概述
全面审计三大云平台的存储服务安全配置，包括AWS S3、Azure Blob Storage和GCP Cloud Storage的公开访问、加密、版本管理和访问日志检查。

## 核心技能

### 1. AWS S3存储桶审计

```bash
# 使用S3 Scanner批量审计
git clone https://github.com/sa7mon/S3Scanner.git
cd S3Scanner && pip install -r requirements.txt

# 扫描所有公开存储桶
python s3scanner.py --buckets-file buckets.txt --dump

# 使用AWS CLI审计
# 检查公共访问阻止
aws s3api get-public-access-block --bucket <bucket> 2>/dev/null || echo "未配置"

# 检查存储桶策略
aws s3api get-bucket-policy --bucket <bucket> 2>/dev/null | jq '.Policy | fromjson'

# 检查跨域配置(CORS)
aws s3api get-bucket-cors --bucket <bucket> 2>/dev/null

# 检查生命周期策略
aws s3api get-bucket-lifecycle-configuration --bucket <bucket> 2>/dev/null

# 检查静态网站配置
aws s3api get-bucket-website --bucket <bucket> 2>/dev/null

# 检查默认加密
aws s3api get-bucket-encryption --bucket <bucket> 2>/dev/null || echo "默认加密未启用"
```

### 2. Azure Blob Storage审计

```bash
# 检查容器公开访问级别
az storage container list --account-name <account> --query "[].{name:name, publicAccess:properties.publicAccess}"

# 检查存储账户的HTTPS强制
az storage account show --name <account> --query properties.enableHttpsTrafficOnly

# 检查存储账户防火墙
az storage account show --name <account> --query properties.networkRules

# 检查软删除策略
az storage account blob-service-properties show --name <account> --query deleteRetentionPolicy

# 检查不可变策略
az storage container immutability-policy show --account-name <account> --container-name <container>

# 检查共享访问签名(SAS)
# 列出存储账户密钥
az storage account keys list --account-name <account>

# 使用Azure Storage Explorer从GUI审计
```

### 3. GCP Cloud Storage审计

```bash
# 检查公共访问配置
gsutil iam get gs://<bucket> | grep -E "allUsers|allAuthenticatedUsers"

# 检查统一存储桶级别访问
gsutil pap get gs://<bucket>

# 检查对象保留策略
gsutil retention get gs://<bucket>

# 检查默认加密
gsutil kms encryption gs://<bucket>

# 检查存储桶标签
gsutil label get gs://<bucket>

# 检查审计日志配置
gcloud logging buckets describe <bucket-name> --location=global

# 检查CORS配置
gsutil cors get gs://<bucket>

# 检查对象版本控制
gsutil versioning get gs://<bucket>
```

### 4. 存储安全基线检查清单

| # | 检查项 | AWS S3 | Azure Blob | GCP Cloud Storage |
|:---:|:---|:---:|:---:|:---:|
| 1 | 禁止公开读 | 必查 | 必查 | 必查 |
| 2 | 禁止公开写 | 必查 | 必查 | 必查 |
| 3 | 启用默认加密 | 推荐(SSE-S3/KMS) | 推荐 | 推荐 |
| 4 | 启用HTTPS强制 | 策略配置 | 默认 | 默认 |
| 5 | 启用对象版本控制 | 推荐 | 可选 | 推荐 |
| 6 | 启用访问日志 | 推荐 | 推荐 | 推荐 |
| 7 | 限制跨域访问(CORS) | 推荐 | 推荐 | 推荐 |
| 8 | 启用软删除 | 开启 | 开启(推荐) | 目标保留策略 |
| 9 | 最小权限IAM | 必查 | 必查 | 必查 |
| 10 | 网络限制 | VPC Endpoint | 防火墙和虚拟网络 | VPC-SC |

### 5. 数据泄露风险评估

```bash
# 使用CloudSploit云安全扫描
npm install -g cloudsploit
cloudsploit --config ./config.js

# 配置示例
# config.js 内容:
# module.exports = {
#   credentials: {
#     aws: { access_key: '', secret_access_key: '' },
#     azure: { application_id: '', key_value: '', directory_id: '', subscription_id: '' },
#     gcp: { project_id: '', keyfile_path: '' }
#   }
# };

# 扫描S3开放存储桶
cloudsploit --plugin s3BucketPublicACL
cloudsploit --plugin s3BucketPublicPolicy

# 使用Buckets越权检测
# https://github.com/initstring/cloud_enum
python3 cloud_enum.py -k <domain>
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| S3Scanner | S3公开存储桶扫描 | https://github.com/sa7mon/S3Scanner |
| CloudSploit | 多云存储安全扫描 | https://github.com/aquasecurity/cloudsploit |
| Cloud_enum | 云存储资源枚举 | https://github.com/initstring/cloud_enum |
| Azure Storage Explorer | Azure存储管理 | https://azure.microsoft.com/products/storage/storage-explorer/ |
| gsutil | GCP存储CLI | https://cloud.google.com/storage/docs/gsutil |

## 参考资源
- [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [Azure Storage Security Guide](https://learn.microsoft.com/azure/storage/blobs/security-recommendations)
- [GCP Cloud Storage Security](https://cloud.google.com/storage/docs/security-bulletins)
- [OWASP Cloud Storage Security](https://owasp.org/www-project-cloud-security/)
