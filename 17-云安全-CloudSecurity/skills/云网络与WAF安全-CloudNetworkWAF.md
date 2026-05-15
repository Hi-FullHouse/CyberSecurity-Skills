---
id: 17-006
title: "🌐 云网络与WAF安全 (Cloud Network & WAF Security)"
category: 云安全
category_en: "Cloud Security"
difficulty: ★★★★
tools: "AWS WAF, Azure WAF, Cloud Armor, Security Groups, CloudSploit"
last_updated: 2025-07
tags: ["cloud-security", "aws", "azure", "gcp", "cloud-iam", "cloud-network"]
subdomain: cloud-security
nist_csf: ["PR.AC-01", "PR.DS-05", "PR.PT-01"]
mitre_attack: ["T1525", "T1613", "T1537"]
---
# 🌐 云网络与WAF安全 (Cloud Network & WAF Security)

## 概述
评估云平台网络层面的安全控制，包括VPC网络分段、安全组与防火墙规则审查、WAF策略配置审计、DDoS防护和私有连接安全。

## 核心技能

### 1. VPC与网络架构审计

```bash
# AWS VPC审计
# 检查VPC数量及默认VPC使用情况
aws ec2 describe-vpcs --query "Vpcs[?IsDefault==`true`]"

# 检查VPC对等连接
aws ec2 describe-vpc-peering-connections --query "VpcPeeringConnections[?Status.Code=='active']"

# 检查子网路由表
aws ec2 describe-route-tables --query "RouteTables[?Routes[?DestinationCidrBlock=='0.0.0.0/0' && GatewayId!='local']]"

# 检查NAT网关配置
aws ec2 describe-nat-gateways

# 检查VPC端点
aws ec2 describe-vpc-endpoints --query "VpcEndpoints[?VpcEndpointType=='Interface']"

# Azure VNet审计
az network vnet list --query "[].{name:name, addressSpace:addressSpace.addressPrefixes}"
az network vnet peering list --resource-group <rg> --vnet-name <vnet>
az network vnet subnet list --resource-group <rg> --vnet-name <vnet>

# GCP VPC审计
gcloud compute networks list
gcloud compute networks subnets list --filter="purpose=PRIVATE"
```

### 2. WAF策略配置审计

```bash
# AWS WAF审计
# 列出所有Web ACL
aws wafv2 list-web-acls --scope REGIONAL

# 检查Web ACL规则
aws wafv2 get-web-acl --name <acl-name> --scope REGIONAL --id <acl-id>

# 检查托管规则集
aws wafv2 get-managed-rule-set --name AWSManagedRulesCommonRuleSet --scope REGIONAL

# 检查速率限制规则
aws wafv2 get-web-acl --name <acl-name> --query 'WebACL.Rules[?Action.Count!=null]'

# 检查WAF日志配置
aws wafv2 get-web-acl --name <acl-name> --query 'WebACL.VisibilityConfig'

# 关联资源检查
aws wafv2 list-resources-for-web-acl --web-acl-arn <arn>

# Azure WAF (Application Gateway) 审计
az network application-gateway waf-policy list --query "[].{name:name, mode:properties.policySettings.mode}"

# GCP Cloud Armor审计
gcloud compute security-policies list
gcloud compute security-policies describe <policy-name>
```

### 3. DDoS防护配置审计

```bash
# AWS Shield Advanced
aws shield list-protections
aws shield describe-protection --protection-id <id>
aws shield list-attacks

# AWS Shield Standard (默认启用，无需配置)

# Azure DDoS Protection
az network ddos-protection list --query "[].{name:name, virtualNetworks:virtualNetworks}"

# GCP Cloud Armor DDoS防护
gcloud compute security-policies list --filter="(type=CLOUD_ARMOR)"
gcloud compute security-policies describe <policy>
```

### 4. 安全组与NACL基线检查

```bash
# AWS安全组基线
# 查找过于宽松的安全组
aws ec2 describe-security-groups --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']]]" --output table

# 检查未使用的安全组
aws ec2 describe-security-groups --query "SecurityGroups[?length(NetworkInterfaceIds)==`0`]"

# 检查NACL
aws ec2 describe-network-acls --query "NetworkAcls[?Entries[?CidrBlock=='0.0.0.0/0' && RuleAction=='allow']]"

# 检查安全组基线分数
# AWS Security Hub -> Security Group Findings

# Azure NSG基线
az network nsg list --query "[].{name:name, rules:securityRules[?access=='Allow' && sourceAddressPrefix=='*' || sourceAddressPrefix=='Internet']}"

# GCP VPC防火墙基线
gcloud compute firewall-rules list --filter="disabled=False AND direction=INGRESS AND sourceRanges=0.0.0.0/0"
```

### 5. 云网络安全基线

| 检查项 | 严重程度 | 修复建议 |
|:---|:---:|:---|
| 默认VPC正在使用 | 🟡 中危 | 创建并迁移到自定义VPC |
| 安全组开放22/3389到公网 | 🔴 严重 | 使用SSM Session Manager、堡垒机或IAP |
| 无WAF保护 | 🟠 高危 | 为面向公网的负载均衡器启用WAF |
| 未启用VPC流日志 | 🟡 中危 | 启用流日志到S3/CloudWatch |
| 跨账号对等连接无限制 | 🟠 高危 | 仅允许必要的路由和端口 |
| 无DDoS保护 | 🟠 高危 | 企业级启用Shield Advanced/DDoS Protection |
| 负载均衡器允许HTTP | 🟡 中危 | 重定向到HTTPS，禁用HTTP |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| CloudSploit | 云网络配置审计 | https://github.com/aquasecurity/cloudsploit |
| PacBot | 策略合规检查 | https://github.com/tmobile/pacbot |
| Terraform Compliance | IaC网络合规 | https://terraform-compliance.com/ |
| VPC Flow Logs | AWS网络流量日志 | https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html |
| Cloud Armor | GCP WAF/DDoS | https://cloud.google.com/armor |

## 参考资源
- [AWS Network Security Best Practices](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
- [Azure Network Security Best Practices](https://learn.microsoft.com/azure/security/fundamentals/network-best-practices)
- [GCP Network Security Best Practices](https://cloud.google.com/architecture/framework/security/network-security)
- [OWASP Cloud Network Security](https://owasp.org/www-project-cloud-security/)
