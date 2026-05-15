---
id: 14-003
title: "🏗️ 安全架构审计 (Security Architecture Audit)"
category: 安全审计
category_en: "Security Audit"
difficulty: ★★★★
tools: "威胁建模工具, Archi, draw.io, STRIDE"
last_updated: 2025-07
tags: ["security-audit", "compliance", "cloud-audit", "container-audit", "network-audit"]
subdomain: security-audit
nist_csf: ["ID.GV-01", "ID.RM-01", "ID.SC-01"]
mitre_attack: []
---
# 🏗️ 安全架构审计 (Security Architecture Audit)

## 概述
对组织整体安全架构进行系统性审计评估，包括网络架构、零信任架构、身份与访问管理架构、数据安全架构等，识别架构层面的安全设计缺陷。

## 核心技能

### 1. 网络架构安全审计

**网络区域划分检查：**
```text
┌────────────────────────────────────────────────┐
│                  互联网                           │
└──────────┬──────────────────┬──────────────────-─┘
           │                  │
    ┌──────▼──────┐    ┌─────▼──────┐
    │  DMZ区域     │    │ WAF/IPS    │
    │ Web/API/DNS  │    │ 清洗中心    │
    └──────┬──────┘    └─────┬──────┘
           │                  │
    ┌──────▼──────────────────▼──────┐
    │        核心业务区                 │
    │    App / DB / Cache / MQ        │
    └──────────────┬───────────────────┘
                   │
    ┌──────────────▼───────────────────┐
    │        管理区 / 堡垒机             │
    └──────────────────────────────────┘
```

**审计要点：**
- 区域隔离措施（防火墙策略、ACL）
- 东西向流量管控（微隔离）
- 网络冗余设计（HA、负载均衡）
- 加密传输（TLS 1.2+、IPSec VPN）

### 2. 零信任架构评估

**NIST SP 800-207 零信任核心原则：**

| 原则 | 审计验证方法 |
|:---|:---|
| 所有资源默认不可信 | 检查是否所有访问都经过认证 |
| 最小权限原则 | 检查RBAC/ABAC策略配置 |
| 持续验证 | 检查会话连续性检测机制 |
| 动态策略 | 检查基于风险的条件访问策略 |
| 全链路加密 | 检查mTLS/IPSec配置 |

```bash
# 检查微隔离配置（以Calico为例）
calicoctl get networkpolicy --all-namespaces
calicoctl get profiles

# 检查服务网格mTLS（以Istio为例）
istioctl authz check <pod-name>
istioctl experimental describe pod <pod-name>
```

### 3. 身份与访问管理（IAM）审计

**认证架构检查：**
- SSO/OIDC/SAML配置安全性
- MFA强制策略覆盖率
- 会话管理（超时、刷新、吊销）
- 密码策略（复杂度、历史、过期）

**授权架构检查：**
```bash
# Active Directory审计
Get-ADGroupMember -Identity "Domain Admins"      # 检查组
Get-ADUser -Filter * -Properties MemberOf         # 用户所属组
Get-ADOrganizationalUnit -Filter *                # OU结构

# AWS IAM审计（使用Prowler）
prowler aws --group iam
aws iam simulate-principal-policy
```

### 4. 数据安全架构审计

**数据分类与保护：**
| 数据等级 | 示例 | 保护要求 |
|:---|:---|:---|
| L1 公开 | 官网内容 | 完整性保护 |
| L2 内部 | 组织架构 | 访问控制+传输加密 |
| L3 敏感 | 客户信息 | 加密存储+脱敏展示 |
| L4 机密 | 密钥/财务 | 硬件加密+严格审计 |

**数据流安全审计：**
```text
审计要点：
□ 数据分类标签是否完善
□ 数据加密范围（传输/存储/备份）
□ DLP策略是否覆盖关键数据
□ 数据生命周期管理（留存/销毁）
□ API数据泄露风险
```

### 5. 威胁建模与架构风险评估

```text
STRIDE威胁建模：
S - Spoofing（身份欺骗）
T - Tampering（篡改）
R - Repudiation（抵赖）
I - Information Disclosure（信息泄露）
D - Denial of Service（拒绝服务）
E - Elevation of Privilege（权限提升）
```

**PASTA威胁建模流程：**
```text
1. 定义目标 → 2. 定义技术范围 → 3. 分解应用
4. 威胁分析 → 5. 漏洞分析 → 6. 风险评估 → 7. 对策
```

### 6. 安全架构审计工具

```bash
# 网络拓扑发现
nmap -sP 10.0.0.0/24
nmap -sS -O 10.0.0.0/24

# 安全控制评估
nikto -h https://target.com
testssl.sh https://target.com

# 架构文档审计
# 检查网络拓扑图、数据流图、信任边界
# 检查变更管理记录、设计文档、架构决策记录(ADR)
```

## 常用工具
| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Archi | 企业架构建模 | https://www.archimatetool.com/ |
| draw.io | 架构图绘制 | https://app.diagrams.net/ |
| Microsoft Threat Modeling Tool | 微软威胁建模 | https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool |
| OWASP Threat Dragon | OWASP威胁建模 | https://owasp.org/www-project-threat-dragon/ |
| Prowler | AWS安全审计 | https://github.com/prowler-cloud/prowler |

## 参考资源
- [NIST SP 800-207 零信任架构](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [OWASP Application Security Architecture](https://owasp.org/www-project-application-security-architecture/)
- [SABSA - 安全架构框架](https://sabsa.org/)
- [TOGAF - 企业架构框架](https://www.opengroup.org/togaf)
