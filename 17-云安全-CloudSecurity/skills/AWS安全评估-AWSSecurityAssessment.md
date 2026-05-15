---
id: 17-001
title: "☁️ AWS安全评估 (AWS Security Assessment)"
category: 云安全
category_en: "Cloud Security"
difficulty: ★★★★
tools: "Prowler, ScoutSuite, AWS Config, Security Hub, PacBot"
last_updated: 2025-07
tags: ["cloud-security", "aws", "azure", "gcp", "cloud-iam", "cloud-network"]
subdomain: cloud-security
nist_csf: ["PR.AC-01", "PR.DS-05", "PR.PT-01"]
mitre_attack: ["T1525", "T1613", "T1537"]
---
# ☁️ AWS安全评估 (AWS Security Assessment)

## 概述
对AWS云环境进行全面的安全评估，包括身份与访问管理（IAM）、S3存储桶权限、安全组配置、CloudTrail审计日志、KMS密钥管理和合规基线检查。

## 核心技能

### 1. IAM身份与访问管理审计

```bash
# 使用AWS CLI审计IAM配置
# 列出所有IAM用户及其最后使用时间
aws iam list-users --query 'Users[*].[UserName,CreateDate,PasswordLastUsed]' --output table

# 检查未使用的IAM用户和凭证
aws iam list-users | jq -r '.Users[] | select(.PasswordLastUsed==null) | .UserName'

# 检查IAM策略权限越界
aws iam list-policies --scope Local --only-attached

# 检查IAM角色信任策略
aws iam get-role --role-name <role-name> --query 'Role.AssumeRolePolicyDocument'

# 检查IAM用户是否拥有管理员权限
aws iam list-attached-user-policies --user-name <user>

# 检查内联策略
aws iam list-user-policies --user-name <user>

# 检查IAM密码策略
aws iam get-account-password-policy
```

### 2. S3存储桶安全审计

```bash
# 列出所有S3存储桶并检查公共访问
aws s3api list-buckets --query 'Buckets[*].Name'

# 检查存储桶公共访问配置
aws s3api get-public-access-block --bucket <bucket-name>

# 检查存储桶ACL
aws s3api get-bucket-acl --bucket <bucket-name>

# 检查存储桶策略（是否存在公开读写）
aws s3api get-bucket-policy --bucket <bucket-name>
aws s3api get-bucket-policy-status --bucket <bucket-name>

# 批量检查所有存储桶
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  echo "=== $bucket ==="
  aws s3api get-bucket-acl --bucket $bucket --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers`]'
done

# 检查存储桶加密配置
aws s3api get-bucket-encryption --bucket <bucket-name>

# 检查存储桶日志记录
aws s3api get-bucket-logging --bucket <bucket-name>
```

### 3. 安全组与网络审计

```bash
# 列出所有安全组及入站规则
aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupName,GroupId,IpPermissions]'

# 查找开放到0.0.0.0/0的安全组
aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0

# 查找开放高危端口的安全组
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?FromPort==`22`||FromPort==`3389`||FromPort==`3306`||FromPort==`6379`]].[GroupName,IpPermissions]'

# 检查VPC流日志是否启用
aws ec2 describe-flow-logs

# 检测未受保护的子网
aws ec2 describe-subnets --query 'Subnets[?MapPublicIpOnBroadcast==`true`]'

# 检查网络ACL
aws ec2 describe-network-acls
```

### 4. 审计日志与监控

```bash
# 检查CloudTrail是否启用
aws cloudtrail describe-trails

# 检查CloudTrail日志文件完整性
aws cloudtrail get-trail-status --name <trail-name>

# 检查CloudTrail是否跨区域
aws cloudtrail describe-trails --query 'trailList[?IsMultiRegionTrail==`true`]'

# 检查Config服务是否启用
aws configservice describe-configuration-recorders

# 检查GuardDuty是否启用
aws guardduty list-detectors

# 检查Security Hub状态
aws securityhub get-enabled-standards
```

### 5. 加密与密钥管理

```bash
# 列出所有KMS密钥
aws kms list-keys

# 检查KMS密钥轮换策略
aws kms get-key-rotation-status --key-id <key-id>

# 检查未加密的EBS卷
aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`].[VolumeId,Size,AvailabilityZone]'

# 检查未加密的RDS实例
aws rds describe-db-instances --query 'DBInstances[?StorageEncrypted==`false`].[DBInstanceIdentifier,Engine]'

# 检查未加密的SQS/SNS
aws sqs list-queues
```

### 6. Prowler自动化审计

```bash
# 安装Prowler
pip install prowler
# 或使用Docker
docker run --rm -v ~/.aws:/root/.aws toniblyx/prowler:latest

# 基础审计
prowler aws

# 指定合规标准审计
prowler aws --compliance cis_1.4_aws
prowler aws --compliance nist_800_53_rev4
prowler aws --compliance soc2
prowler aws --compliance pci_3.2

# 指定服务审计
prowler aws --services s3,iam,ec2

# 输出HTML报告
prowler aws -M html

# 输出CSV供分析
prowler aws -M csv
```

### 7. 常见高风险配置

| # | 风险项 | 风险等级 | 修复建议 |
|:---:|:---|:---:|:---|
| 1 | IAM用户拥有AdministratorAccess | 🔴 严重 | 使用最小权限原则创建自定义策略 |
| 2 | S3存储桶公开读/写 | 🔴 严重 | 启用公共访问阻止，使用预签名URL |
| 3 | 安全组开放22/3389到0.0.0.0/0 | 🔴 严重 | 限制来源IP，使用堡垒机/SSM |
| 4 | CloudTrail未启用 | 🟠 高危 | 启用跨区域CloudTrail并开启日志文件验证 |
| 5 | EBS/RDS未加密 | 🟡 中危 | 启用默认加密，对现有卷创建快照后迁移 |
| 6 | KMS密钥未自动轮换 | 🟡 中危 | 启用自动轮换（每年一次） |
| 7 | ECR仓库公开访问 | 🟠 高危 | 限制仓库权限，使用私有仓库 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Prowler | AWS安全基线审计 | https://github.com/prowler-cloud/prowler |
| ScoutSuite | 多云安全审计 | https://github.com/nccgroup/ScoutSuite |
| AWS Config | AWS资源配置审计 | https://aws.amazon.com/config/ |
| Security Hub | AWS安全中心 | https://aws.amazon.com/security-hub/ |
| PacBot | 策略即代码 | https://github.com/tmobile/pacbot |
| CloudSploit | 云安全扫描 | https://github.com/aquasecurity/cloudsploit |

## 参考资源
- [AWS Well-Architected Framework — Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services/)
- [AWS Security Audit Guidelines](https://docs.aws.amazon.com/config/latest/developerguide/operational-checks.html)
- [Prowler Documentation](https://docs.prowler.com/)
- [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)
