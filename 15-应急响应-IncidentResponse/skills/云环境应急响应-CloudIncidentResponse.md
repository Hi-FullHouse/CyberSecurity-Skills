---
id: 15-006
title: "☁️ 云环境应急响应 (Cloud Incident Response)"
category: 应急响应
category_en: "Incident Response"
difficulty: ★★★★
tools: "AWS GuardDuty, Azure Sentinel, GCP Security"
last_updated: 2025-07
tags: ["incident-response", "forensics", "memory-forensics", "threat-hunting", "ransomware"]
subdomain: incident-response
nist_csf: ["RS.RP-01", "RS.CO-02", "RS.AN-01", "RS.MI-01"]
mitre_attack: ["T1486", "T1490", "T1485", "T1562"]
---
# ☁️ 云环境应急响应 (Cloud Incident Response)

## 概述
云环境的安全事件响应与传统IT存在显著差异：共享责任模型、API驱动的控制平面、短暂的云资源、以及需要云原生取证技术。参照 **AWS IR Guide**、**Azure Sentinel IR Playbooks** 和 **GCP IR Framework** 最佳实践。

## 核心技能

### 1. 云安全责任共担与IR

```text
┌──────────────────────────────────────────────────────┐
│      客户责任（无论部署模型）                            │
│  ├─ 用户身份与权限管理                                  │
│  ├─ 应用安全配置                                       │
│  ├─ 数据分类与加密                                     │
│  ├─ 操作系统配置（IaaS）                               │
│  ├─ 网络防火墙规则                                     │
│  └─ 事件应急响应（客户侧）                              │
├──────────────────────────────────────────────────────┤
│      云厂商责任                                         │
│  ├─ 物理基础设施安全                                   │
│  ├─ 虚拟化基础设施                                     │
│  ├─ 网络基础设施                                       │
│  ├─ 托管服务安全性                                     │
│  └─ 云平台侧事件检测和响应                              │
└──────────────────────────────────────────────────────┘
```

### 2. AWS 应急响应

#### 事件检测
```bash
# 使用AWS GuardDuty检测威胁
aws guardduty list-findings --detector-id <ID>
aws guardduty get-findings --detector-id <ID> --finding-ids <IDS>

# 使用CloudTrail调查API调用
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=<INSTANCE_ID>

# 查看CloudWatch告警
aws cloudwatch describe-alarms --state-value ALARM
```

#### 事件响应 — 遏制操作
```bash
# 隔离EC2实例（更改安全组为限制性策略）
aws ec2 modify-instance-attribute --instance-id i-xxxxxxxx --groups sg-isolated

# 终止可疑EC2实例
aws ec2 terminate-instances --instance-ids i-xxxxxxxx

# 创建AMI快照（取证保留）
aws ec2 create-image --instance-id i-xxxxxxxx --name "forensics-snapshot-YYYYMMDD" --no-reboot

# 禁用IAM用户
aws iam update-user --user-name compromised_user
aws iam create-access-key --user-name compromised_user
# 注意：先创建新AK/SK，再禁用旧的

# 挂起IAM用户密钥
aws iam update-access-key --access-key-id AKIAxxxx --status Inactive --user-name compromised_user

# 撤销IAM权限
aws iam delete-user-policy --user-name compromised_user --policy-name malicious-policy
aws iam detach-user-policy --user-name compromised_user --policy-arn arn:aws:iam::xxx:policy/malicious

# S3桶访问阻断（防止数据泄露）
aws s3api put-bucket-policy --bucket compromised-bucket --policy file://deny-all-policy.json

# 禁用AWS Organizations成员帐户
# Organizations管理账号操作
aws organizations remove-account-from-organization --account-id <ID>
```

#### 日志导出与取证
```bash
# 导出CloudTrail日志到S3
aws s3 sync s3://my-cloudtrail-logs/AWSLogs/<ACCOUNT-ID>/CloudTrail/ ./forensics-logs/

# 导出VPC Flow Logs
aws ec2 describe-flow-logs
aws s3 sync s3://vpc-flow-log-bucket/ ./flow-logs/

# 调查EC2内存取证（需要先获取SSM）
aws ssm send-command --instance-ids i-xxxxxxxx --document-name "AWS-RunShellScript" --parameters commands=["sudo dd if=/dev/mem of=/tmp/mem.dmp bs=1M count=1024"]

# 创建EBS快照取证
aws ec2 create-snapshot --volume-id vol-xxxxxxxx --description "Forensics_EBS_$(date +%Y%m%d)"
```

### 3. Azure 应急响应

```powershell
# 连接到Azure
Connect-AzAccount

# 事件检测 — 使用Azure Sentinel
# KQL查询示例在威胁狩猎技能中

# 遏制动作为 — 锁定NSG
$nsg = Get-AzNetworkSecurityGroup -Name "my-nsg" -ResourceGroupName "RG-Prod"
$nsg.SecurityRules = @()
$blockRule = New-AzNetworkSecurityRuleConfig -Name "BlockAll" -Access Deny -Direction Inbound -Protocol * -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange * -Priority 100
$nsg.SecurityRules += $blockRule
Set-AzNetworkSecurityGroup -NetworkSecurityGroup $nsg

# 终止Azure VM
Stop-AzVM -Name "compromised-vm" -ResourceGroupName "RG-Prod" -Force
Remove-AzVM -Name "compromised-vm" -ResourceGroupName "RG-Prod" -Force

# 禁用Azure AD用户
Disable-AzureADUser -ObjectId "user@domain.com"

# 撤销所有会话令牌
Revoke-AzureADUserAllRefreshToken -ObjectId "user@domain.com"
Revoke-AzureADSignedInUserAllRefreshToken

# 提取VM磁盘取证
Stop-AzVM -Name "compromised-vm" -ResourceGroupName "RG-Prod"
$vm = Get-AzVM -Name "compromised-vm" -ResourceGroupName "RG-Prod"
$disk = Get-AzDisk -ResourceGroupName $vm.ResourceGroupName -DiskName $vm.StorageProfile.OsDisk.Name
# 快照
$snapshot = New-AzSnapshotConfig -SourceUri $disk.Id -CreateOption Copy -Location $disk.Location
New-AzSnapshot -Snapshot $snapshot -SnapshotName "forensics-snapshot" -ResourceGroupName "RG-Forensics"
```

### 4. GCP 应急响应

```bash
# 切换到项目
gcloud config set project compromised-project

# 识别异常API使用
gcloud logging read 'protoPayload.methodName="SetIamPolicy" AND severity>=WARNING' --project=compromised-project

# 停止GCE实例
gcloud compute instances stop compromised-vm --zone=us-central1-a

# 创建磁盘快照（取证）
gcloud compute disks snapshot compromised-vm-disk --snapshot-names=forensics-$(date +%Y%m%d) --zone=us-central1-a

# 撤销服务账号密钥
gcloud iam service-accounts keys list --iam-account=sa@project.iam.gserviceaccount.com
gcloud iam service-accounts keys delete <KEY-ID> --iam-account=sa@project.iam.gserviceaccount.com

# 禁用IAM绑定
gcloud projects get-iam-policy compromised-project --format=json > iam_backup.json
gcloud projects remove-iam-policy-binding compromised-project --member=user:compromised@domain.com --role=roles/owner
```

### 5. 云环境关键攻击场景

| 攻击场景 | 检测指标 | 遏制操作 | 取证来源 |
|:---|:---|:---|:---|
| IAM密钥泄露 | 异常API调用地理/时间 | 禁用密钥+轮换 | CloudTrail |
| 存储桶公开访问 | 匿名下载流量飙升 | 关闭公开访问+分析访问日志 | S3访问日志 |
| 加密货币挖矿 | CPU持续100%/异常网络出站 | 终止实例+加固镜像 | CloudWatch+VPC Flow |
| 凭证窃取 | 异常Console登录 | 禁用用户+重置所有密钥 | CloudTrail登录事件 |
| K8s集群入侵 | 异常Pod创建/权限提升 | 禁用kubeconfig+隔离命名空间 | Audit Logs |
| 供应链投毒 | CI/CD管道异常提交 | 回滚+轮换CI密钥 | GitHub Audit+CloudBuild |

### 6. 云取证关键考虑

```bash
# 云临时资源问题：
# ● 自动伸缩组（ASG）会销毁和重建实例
# ● Lambda执行环境是短暂的
# ● Container/Pod随时可能被调度器移除

# 云取证建议：
# 1. 优先使用快照而非实时取证
# 2. 启用所有API日志记录的Capture并配置长期保留
# 3. 使用基础设施即代码（IaC）快速重建隔离分析环境
# 4. 区分控制平面（API日志）和数据平面（OS日志）证据

# 推荐取证工具
# ● AWS: AWS Forensic Toolkit by EC2 Rescue
# ● Azure: Azure Forensics Toolkit
# ● GCP: Forseti Security

# 云取证工作流
# 1. 使用快照/备份创建隔离副本
# 2. 在独立的云账号或本地环境中挂载分析
# 3. 运行Sleuth Kit/Autopsy进行文件系统分析
# 4. 使用Volatility分析内存快照
# 5. 交叉关联CloudTrail/Activity Logs
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| AWS GuardDuty | 威胁检测 | https://aws.amazon.com/guardduty/ |
| Azure Sentinel | SIEM+SOC | https://azure.microsoft.com/sentinel/ |
| Google Chronicle | 安全分析 | https://chronicle.security/ |
| Falco | 云原生运行时安全 | https://falco.org/ |
| Prowler | AWS安全审计 | https://github.com/prowler-cloud/prowler |
| ScoutSuite | 多云安全审计 | https://github.com/nccgroup/ScoutSuite |
| CloudSploit | 云安全扫描 | https://github.com/aquasecurity/cloudsploit |

## 参考资源

- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/)
- [Azure: Cloud Incident Response](https://learn.microsoft.com/security/incident-response)
- [GCP Incident Response Guide](https://cloud.google.com/security/incident-response)
- [CIS — Cloud Incident Response Benchmarks](https://www.cisecurity.org/benchmark/cloud_incident_response/)
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
