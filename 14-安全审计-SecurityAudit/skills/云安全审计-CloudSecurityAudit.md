---
id: 14-002
title: "☁️ 云安全审计 (Cloud Security Audit)"
category: 安全审计
category_en: "Security Audit"
difficulty: ★★★★
tools: "ScoutSuite, Prowler, CloudSploit, Pacu"
last_updated: 2025-07
tags: ["security-audit", "compliance", "cloud-audit", "container-audit", "network-audit"]
subdomain: security-audit
nist_csf: ["ID.GV-01", "ID.RM-01", "ID.SC-01"]
mitre_attack: []
---
# ☁️ 云安全审计 (Cloud Security Audit)

## 概述
对云基础设施（AWS、Azure、阿里云等）进行安全配置审计，检查云资源的访问控制、数据加密、日志审计、网络安全组等配置是否符合安全最佳实践。

## 核心技能

### 1. 云安全责任共担模型

```text
┌─────────────────────────────────┐
│        客户负责                  │
│  ├─ 数据分类与加密              │
│  ├─ 操作系统配置                │
│  ├─ 网络与防火墙规则            │
│  ├─ IAM策略配置                 │
│  └─ 应用安全                    │
├─────────────────────────────────┤
│        云厂商负责                │
│  ├─ 物理安全                    │
│  ├─ 虚拟化基础设施              │
│  ├─ 网络基础设施                │
│  └─ 存储基础设施                │
└─────────────────────────────────┘
```

### 2. AWS安全审计

**使用ScoutSuite（全平台云审计）：**
```bash
# AWS审计
pip install scoutsuite
scout aws --access-key-id AKIA... --secret-access-key ...

# 生成审计报告
scout aws --report-dir ./aws-report
```

**Prowler - AWS CIS Benchmark检查：**
```bash
# 安装
pip install prowler

# 运行全量检查
prowler aws

# 指定检查项
prowler aws --group iam                          # IAM检查
prowler aws --group s3                           # S3检查
prowler aws --checks s3_bucket_public_access     # S3公开访问检查

# 生成HTML报告
prowler aws -M html
```

**关键审计项：**
```bash
# S3公开访问审计
aws s3api get-public-access-block --bucket example-bucket
aws s3 ls s3://bucket-name --no-sign-request     # 测试匿名访问

# IAM审计
aws iam list-users
aws iam list-attached-user-policies --user-name admin
aws iam get-account-password-policy

# CloudTrail审计
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name default

# 安全组审计
aws ec2 describe-security-groups
aws ec2 describe-security-group-rules
```

### 3. Azure安全审计

```bash
# 安装Azure CLI
az login
az account show

# 使用Azure Policy审计
az policy assignment list
az policy state list

# NSG审计
az network nsg list --query "[].{Name:name, Rules:securityRules[].{Name:name, Direction:direction, Access:access, Priority:priority, Source:sourceAddressPrefix, Dest:destinationAddressPrefix, Port:destinationPortRange}}"

# 角色分配审计
az role assignment list --all

# 使用Azucar审计工具
git clone https://github.com/nccgroup/azucar
cd Azucar
.\Azucar.ps1 -ExportTo EXCEL
```

### 4. 阿里云安全审计

```bash
# 安装阿里云CLI
aliyun configure

# RAM用户审计
aliyun ram ListUsers
aliyun ram ListPoliciesForUser --UserName admin

# OSS Bucket审计
aliyun oss ls
aliyun oss get-bucket-acl oss://bucket-name

# 安全组审计
aliyun ecs DescribeSecurityGroups
aliyun ecs DescribeSecurityGroupAttribute --SecurityGroupId sg-xxx

# 使用CIS检查工具
git clone https://github.com/alibabacloud/well-architected-framework
```

### 5. 容器与K8s云环境审计

```bash
# K8s安全审计（kube-bench）
kube-bench run --targets master,node

# K8s配置审计（kube-hunter）
kube-hunter --remote https://your-cluster.com

# Trivy - 容器镜像漏洞扫描
trivy image nginx:latest
trivy repo https://github.com/org/repo
trivy filesystem --severity HIGH,CRITICAL /

# Falco - 运行时安全
falco
falco --help
```

### 6. 云安全审计Checklist

```text
□ IAM最小权限原则
  - 是否使用角色替代长期访问密钥
  - 是否有未使用的IAM用户
  - 管理员权限是否合理分配

□ 数据加密
  - 存储桶是否默认加密
  - 数据库是否启用TDE
  - 传输过程是否使用TLS 1.2+

□ 日志与监控
  - 是否启用CloudTrail/操作审计
  - 日志是否保存到独立账号
  - 是否有异常告警配置

□ 网络安全
  - 是否开放不必要的端口(22,3389)
  - VPC/Security Group是否最小化
  - 是否有公网访问的私密服务

□ 合规认证
  - ISO 27001 / SOC 2 / PCI DSS
  - 区域合规（GDPR、等保）
  - 数据驻留要求
```

## 常用工具
| 工具 | 用途 | 链接 |
|:---|:---|:---|
| ScoutSuite | 多云审计框架 | https://github.com/nccgroup/ScoutSuite |
| Prowler | AWS CIS基准检查 | https://github.com/prowler-cloud/prowler |
| kube-bench | K8s CIS基准检查 | https://github.com/aquasecurity/kube-bench |
| Trivy | 容器漏洞扫描 | https://github.com/aquasecurity/trivy |
| CloudSploit | 云安全扫描 | https://github.com/aquasecurity/cloudsploit |
| Azucar | Azure安全审计 | https://github.com/nccgroup/azucar |

## 参考资源
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services/)
- [CIS Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure/)
- [CIS Alibaba Cloud Foundation Benchmark](https://www.cisecurity.org/benchmark/alibaba_cloud/)
- [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)
- [Cloud Security Alliance (CSA)](https://cloudsecurityalliance.org/)
