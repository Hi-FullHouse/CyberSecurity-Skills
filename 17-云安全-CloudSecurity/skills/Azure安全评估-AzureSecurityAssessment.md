---
id: 17-002
title: "🌤️ Azure安全评估 (Azure Security Assessment)"
category: 云安全
category_en: "Cloud Security"
difficulty: ★★★★
tools: "Azucar, ScoutSuite, Azure Security Center, Microsoft Defender for Cloud"
last_updated: 2025-07
tags: ["cloud-security", "aws", "azure", "gcp", "cloud-iam", "cloud-network"]
subdomain: cloud-security
nist_csf: ["PR.AC-01", "PR.DS-05", "PR.PT-01"]
mitre_attack: ["T1525", "T1613", "T1537"]
---
# 🌤️ Azure安全评估 (Azure Security Assessment)

## 概述
对Microsoft Azure云环境进行安全评估，涵盖Azure RBAC权限审计、KeyVault密钥管理、NSG网络安全组配置、Azure AD安全、存储账户加密和合规基线检查。

## 核心技能

### 1. Azure AD与RBAC审计

```bash
# 使用Azure CLI审计Azure AD
# 列出所有全局管理员
az role assignment list --all --query "[?roleDefinitionName=='Global Administrator']"

# 列出订阅级别的所有者
az role assignment list --all --query "[?roleDefinitionName=='Owner' && scope!=null]"

# 检查条件访问策略
az rest --method GET --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

# 检查服务主体权限
az ad sp list --all --query "[].{displayName:displayName, appId:appId}"

# 检查托管身份
az identity list --query "[].{name:name, clientId:clientId}"

# 检查MFA状态
az rest --method GET --uri "https://graph.microsoft.com/v1.0/users?`$select=displayName,userPrincipalName,strongAuthenticationRequirements"
```

### 2. 存储账户安全

```bash
# 列出所有存储账户
az storage account list --query "[].{name:name, kind:kind, location:location}"

# 检查HTTPS是否强制
az storage account show --name <storage-name> --query properties.enableHttpsTrafficOnly

# 检查公共网络访问
az storage account show --name <storage-name> --query properties.publicNetworkAccess

# 检查存储账户防火墙规则
az storage account show --name <storage-name> --query properties.networkRules

# 检查存储加密
az storage account show --name <storage-name> --query properties.encryption

# 检查软删除是否启用
az storage account blob-service-properties show --account-name <storage-name> --query deleteRetentionPolicy

# 检查SAS令牌
az storage account show --name <storage-name> --query "keyPermissions"
```

### 3. 网络安全组审计

```bash
# 列出所有NSG
az network nsg list --query "[].{name:name, location:location}"

# 检查开放到Internet的端口
az network nsg list --query "[].{name:name, rules:securityRules[?access=='Allow' && sourceAddressPrefix=='*' || sourceAddressPrefix=='Internet']}"

# 查找高危端口
az network nsg list --query "[?securityRules[?destinationPortRange=='22' || destinationPortRange=='3389' || destinationPortRange=='3306']]"

# 检查流日志
az network watcher flow-log list --query "[].{name:name, enabled:enabled}"

# 检查Azure Bastion部署
az network bastion list --query "[].{name:name, dnsName:dnsName}"
```

### 4. KeyVault密钥管理审计

```bash
# 列出所有KeyVault
az keyvault list --query "[].{name:name, vaultUri:vaultUri}"

# 检查KeyVault防火墙配置
az keyvault show --name <vault-name> --query properties.networkAcls

# 检查密钥轮换策略
az keyvault key list --vault-name <vault-name> --query "[].{name:name, keyType:keyType}"

# 检查KeyVault日志记录
az monitor diagnostic-settings list --resource <vault-id> --query "[].{name:name, logs:logs}"

# 检查RBAC对KeyVault的访问权限
az role assignment list --scope <vault-id> --query "[].{principalName:principalName, roleDefinitionName:roleDefinitionName}"
```

### 5. 使用Azucar自动化审计

```bash
# 安装Azucar
git clone https://github.com/nccgroup/azucar.git
cd azucar
pip install -r requirements.txt

# 执行审计
python azucar.py --tenant-id <tenant-id> --subscription-id <sub-id>

# 指定审计模块
python azucar.py --modules identity,storage,network,encryption

# 导出HTML报告
python azucar.py --html

# 使用ScoutSuite
pip install scoutsuite
scout azure --tenant-id <tenant-id> --subscriptions <sub-id>
```

### 6. 常见高风险配置

| # | 风险项 | 风险等级 | 修复建议 |
|:---:|:---|:---:|:---|
| 1 | 全局管理员数量过多 | 🔴 严重 | 限制为2-4名紧急访问账户，启用PIM |
| 2 | 存储账户允许公共访问 | 🔴 严重 | 启用防火墙和虚拟网络规则 |
| 3 | 网络安全组开放RDP/SSH到公网 | 🔴 严重 | 使用Azure Bastion或Just-In-Time访问 |
| 4 | KeyVault允许公共网络访问 | 🟠 高危 | 启用KeyVault防火墙和私有端点 |
| 5 | 未启用MFA | 🟠 高危 | 启用条件访问策略要求MFA |
| 6 | SQL Server启用AD认证 | 🟡 中危 | 启用Azure AD认证 |
| 7 | 诊断日志未启用 | 🟡 中危 | 启用诊断设置至Log Analytics |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Azucar | Azure安全审计 | https://github.com/nccgroup/azucar |
| ScoutSuite | 多云安全审计 | https://github.com/nccgroup/ScoutSuite |
| Microsoft Defender for Cloud | Azure安全中心 | https://azure.microsoft.com/products/defender-for-cloud/ |
| Azure Policy | Azure合规策略 | https://learn.microsoft.com/azure/governance/policy/ |
| AzSK (Secure DevOps Kit) | Azure安全开发工具 | https://github.com/azsk/DevOpsKit |

## 参考资源
- [CIS Microsoft Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure/)
- [Microsoft Cloud Security Benchmark](https://learn.microsoft.com/security/benchmark/azure/)
- [Azure Security Best Practices](https://learn.microsoft.com/azure/security/)
- [Azucar Auditing Guide](https://github.com/nccgroup/azucar/wiki)
