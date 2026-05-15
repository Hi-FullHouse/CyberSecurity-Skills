---
id: 17-003
title: "🟢 GCP安全评估 (GCP Security Assessment)"
category: 云安全
category_en: "Cloud Security"
difficulty: ★★★★
tools: "Forseti Security, GCP Inspector, ScoutSuite, gcloud CLI"
last_updated: 2025-07
tags: ["cloud-security", "aws", "azure", "gcp", "cloud-iam", "cloud-network"]
subdomain: cloud-security
nist_csf: ["PR.AC-01", "PR.DS-05", "PR.PT-01"]
mitre_attack: ["T1525", "T1613", "T1537"]
---
# 🟢 GCP安全评估 (GCP Security Assessment)

## 概述
对Google Cloud Platform环境进行全面安全评估，涵盖IAM权限审计、Cloud Storage存储桶加固、GKE集群安全、VPC防火墙规则和合规基线检查。

## 核心技能

### 1. IAM与资源管理审计

```bash
# 使用gcloud审计IAM
# 列出所有项目及其IAM策略
gcloud projects list
gcloud projects get-iam-policy <project-id> --format=json

# 检查拥有Owner角色的用户
gcloud projects get-iam-policy <project-id> --format="table(bindings.role,bindings.members)" | grep roles/owner

# 检查服务账号权限
gcloud iam service-accounts list --project <project-id>
gcloud iam service-accounts get-iam-policy <sa-email>

# 检查服务账号密钥
gcloud iam service-accounts keys list --iam-account <sa-email>

# 检查原始权限（Primitive Roles）使用情况
gcloud projects get-iam-policy <project-id> --flatten="bindings[].members" --format="table(bindings.role)" | grep -E "roles/editor|roles/owner|roles/viewer"

# 推荐使用IAM Recommender
gcloud recommender insights list --insight-type=google.iam.policy.Insight --project=<project-id>
```

### 2. Cloud Storage安全审计

```bash
# 列出所有存储桶并检查公共访问
gsutil ls -p <project-id>

# 检查存储桶IAM策略
gsutil iam get gs://<bucket-name>

# 检查是否允许公开访问（allUsers/allAuthenticatedUsers）
gsutil iam get gs://<bucket-name> | grep -E "allUsers|allAuthenticatedUsers"

# 检查对象访问权限
gsutil ls -L gs://<bucket-name>

# 启用对象版本控制
gsutil versioning get gs://<bucket-name>

# 检查存储桶加密
gsutil kms encryption gs://<bucket-name>

# 检查保留策略
gsutil retention get gs://<bucket-name>

# 检查日志导出
gsutil logging get gs://<bucket-name>
```

### 3. GKE集群安全审计

```bash
# 列出所有GKE集群
gcloud container clusters list

# 检查集群配置
gcloud container clusters describe <cluster-name> --region=<region>

# 检查是否启用了私有集群
gcloud container clusters describe <cluster-name> --format="table(privateClusterConfig.enablePrivateNodes)"

# 检查集群的网络策略
gcloud container clusters describe <cluster-name> --format="table(addonsConfig.networkPolicyConfig)"

# 检查节点自动升级
gcloud container node-pools list --cluster=<cluster-name>

# 检查Workload Identity配置
gcloud container clusters describe <cluster-name> --format="table(workloadIdentityConfig)"

# 检查二进制授权
gcloud container binauthz policy export

# 检查屏蔽实例
gcloud container clusters describe <cluster-name> --format="table(shieldedInstanceConfig)"
```

### 4. VPC防火墙审计

```bash
# 列出所有VPC防火墙规则
gcloud compute firewall-rules list

# 查找开放到0.0.0.0/0的规则
gcloud compute firewall-rules list --filter="sourceRanges=0.0.0.0/0"

# 检查开放高危端口的规则
gcloud compute firewall-rules list --filter="ALLOW AND (22 OR 3389 OR 3306 OR 6379)"

# 检查默认VPC中的规则
gcloud compute firewall-rules list --filter="network=default"

# 检查VPC流日志
gcloud compute networks list --format="table(name, routingConfig.routingMode, subnetworks.len())"

# 检查Cloud NAT配置
gcloud compute routers nats list --router=<router-name>
```

### 5. 使用Forseti Security和ScoutSuite

```bash
# 部署Forseti Security
git clone https://github.com/forseti-security/forseti-security.git
cd forseti-security
# 按照文档部署Forseti Server和Forseti Client

# Forseti常用命令
# 库存扫描
forseti inventory create --project=<project-id>

# IAM策略扫描
forseti model create --inventory_index=<index>
forseti scanner run --model=<model-id>

# 违规查看
forseti notifier run --model=<model-id>

# 使用ScoutSuite
pip install scoutsuite
scout gcp --project-id <project-id> # 需要在bash中设置GOOGLE_APPLICATION_CREDENTIALS
```

### 6. 常见高风险配置

| # | 风险项 | 风险等级 | 修复建议 |
|:---:|:---|:---:|:---|
| 1 | IAM原始角色（Owner/Editor）滥用 | 🔴 严重 | 替换为预定义或自定义角色 |
| 2 | Cloud Storage公开访问 | 🔴 严重 | 移除allUsers/allAuthenticatedUsers |
| 3 | 服务账号密钥未轮换 | 🟠 高危 | 使用Workload Identity替代密钥 |
| 4 | GKE集群允许公网访问 | 🔴 严重 | 启用私有集群和Master授权网络 |
| 5 | VPC防火墙开放SSH到公网 | 🟠 高危 | 限制来源IP，使用IAP隧道 |
| 6 | 未启用审计日志 | 🟠 高危 | 启用Cloud Audit Logs和Data Access日志 |
| 7 | VM未屏蔽（Shielded VM） | 🟡 中危 | 启用Shielded VM和安全启动 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Forseti Security | GCP安全治理 | https://forsetisecurity.org/ |
| ScoutSuite | 多云安全审计 | https://github.com/nccgroup/ScoutSuite |
| Google Cloud Compliance Manager | GCP合规管理 | https://cloud.google.com/compliance |
| Security Command Center | GCP安全中心 | https://cloud.google.com/security-command-center |
| gcloud CLI | GCP命令行工具 | https://cloud.google.com/sdk/gcloud |

## 参考资源
- [CIS Google Cloud Platform Foundation Benchmark](https://www.cisecurity.org/benchmark/google_cloud_computing_platform/)
- [GCP Security Best Practices Center](https://cloud.google.com/security/best-practices)
- [Google Cloud Architecture Framework — Security](https://cloud.google.com/architecture/framework/security)
- [Forseti Security Documentation](https://forsetisecurity.org/docs/latest/)
