---
id: "36-001"
title: "零信任架构设计与实施 (Zero Trust Architecture Design & Implementation)"
category: "零信任架构"
category_en: "Zero Trust Architecture"
difficulty: "★★★★"
tools: "Google BeyondCorp, AWS Verified Access, Azure AD, Cloudflare Access"
last_updated: "2026-05"
tags: [zero-trust, architecture, beyondcorp, never-trust-always-verify, microsegmentation]
subdomain: zero-trust
nist_csf: [PR.AC-01, PR.AC-04, PR.AC-05, PR.AC-06]
mitre_attack: [T1078, T1550, T1557]
---

# 零信任架构设计与实施 (Zero Trust Architecture Design & Implementation)

## 概述

零信任（Zero Trust）以"永不信任，始终验证"为核心理念，要求无论请求来自内网还是外网，都需要持续验证。本技能覆盖零信任架构模型、NIST ZTA 框架、策略决策和 Google BeyondCorp/ AWS Verified Access 实施。

## 核心技能

### 1. 零信任架构模型

```python
"""零信任架构核心模型"""

class ZeroTrustModel:
    """零信任架构模型"""
    
    # NIST SP 800-207 七大原则
    PRINCIPLES = [
        "所有数据源和计算服务都被视为资源",
        "无论网络位置，所有通信都必须加密",
        "每个资源的访问都按会话粒度授权",
        "基于动态策略（用户、设备、环境上下文）决策",
        "监控所有资产并执行持续安全评估",
        "认证和授权在访问前强制执行",
        "收集尽可能多的信息来改进安全态势"
    ]
    
    # 零信任组件
    COMPONENTS = {
        "PEP": "Policy Enforcement Point — 策略执行点（网关/代理）",
        "PDP": "Policy Decision Point — 策略决策点（策略引擎）",
        "PA": "Policy Administrator — 策略管理员（生成凭证）",
        "PIP": "Policy Information Point — 策略信息点（上下文数据源）"
    }
    
    @staticmethod
    def access_decision_model():
        """访问决策模型"""
        return {
            "身份": {
                "user_id": "",
                "group_membership": [],
                "authentication_strength": "mfa",
                "risk_score": 0
            },
            "设备": {
                "device_id": "",
                "compliance": False,
                "disk_encrypted": True,
                "os_patched": True,
                "certificate_valid": True
            },
            "网络": {
                "source_ip": "",
                "location": "office/vpn/public",
                "network_segment": ""
            },
            "请求": {
                "resource": "",
                "action": "read/write/admin",
                "protocol": "",
                "time": ""
            }
        }
    
    @staticmethod
    def evaluate_policy(context):
        """零信任策略评估"""
        score = 0
        
        # 身份评估
        if context.get("auth_strength") == "mfa":
            score += 30
        elif context.get("auth_strength") == "password":
            score += 10
        
        # 设备评估
        device = context.get("device", {})
        if device.get("compliant"):
            score += 30
        if device.get("disk_encrypted"):
            score += 10
        if device.get("patched"):
            score += 10
        
        # 上下文评估
        if context.get("location") == "office":
            score += 10
        elif context.get("location") == "vpn":
            score += 5
        else:
            score -= 10
        
        # 风险评估
        risk = context.get("risk_score", 0)
        score -= risk * 2
        
        # 决策
        if score >= 70:
            return "allowed"
        elif score >= 40:
            return "allowed_with_restrictions"
        else:
            return "denied"

# 使用示例
model = ZeroTrustModel()
print("Zero Trust Principles:")
for i, p in enumerate(model.PRINCIPLES, 1):
    print(f"  {i}. {p}")
```

### 2. NIST ZTA 实施

```yaml
# NIST SP 800-207 零信任架构实施策略

# 场景1: 增强型 IAM
# - 所有访问必须 MFA
# - 动态权限基于角色+上下文
# - 持续会话验证

# 场景2: 微隔离
# - 东西向流量全加密
# - 应用级分段
# - 默认拒绝策略

# 场景3: 网络基础设施现代化
# - 加密所有内部流量 (mTLS)
# - 网络微分段
# - 消除隐式信任

# 实施路径
implementation_roadmap = {
    "Phase 1 — 评估与规划": {
        "duration": "1-3个月",
        "tasks": [
            "识别关键资产和数据流",
            "绘制当前网络架构图",
            "识别隐式信任区域",
            "制定零信任策略"
        ]
    },
    "Phase 2 — IAM 加固": {
        "duration": "2-4个月",
        "tasks": [
            "部署 MFA",
            "实施 JIT/JEA 权限",
            "集成身份提供商",
            "配置条件访问策略"
        ]
    },
    "Phase 3 — 网络分段": {
        "duration": "3-6个月",
        "tasks": [
            "实施微隔离",
            "部署应用网关",
            "配置 mTLS",
            "迁移到 SDP/ZTNA"
        ]
    },
    "Phase 4 — 持续监控": {
        "duration": "持续",
        "tasks": [
            "部署 UEBA",
            "配置持续合规检查",
            "自动化响应",
            "安全态势仪表盘"
        ]
    }
}

# 零信任成熟度模型
zt_maturity = {
    "Level 1 — 传统": "基于边界的信任，内网默认可信",
    "Level 2 — 初步": "VPN + MFA，基本的条件访问",
    "Level 3 — 进阶": "应用级访问控制，微隔离初步",
    "Level 4 — 成熟": "持续验证，自适应策略，全量加密",
    "Level 5 — 优化": "AI驱动的动态策略，零摩擦安全"
}
```

### 3. Google BeyondCorp / AWS Verified Access

```bash
# Google BeyondCorp Enterprise
# 1. 配置身份感知代理 (IAP)

# 启用 IAP
gcloud services enable iap.googleapis.com

# 配置 OAuth 同意屏幕
gcloud alpha iap oauth-clients create projects/<project-id>/brands/<brand-id> \
  --display_name="Internal App Access"

# 配置 IAP 访问策略
cat > iap_policy.yaml << 'EOF'
access_settings:
  gcip_settings:
    tenant_ids:
    - <tenant-id>
  cors_settings:
    allow_origins:
    - https://app.company.com
EOF

# 启用 IAP 保护
gcloud iap web enable \
  --resource-type=app-engine \
  --oauth2-client-id=<client-id> \
  --oauth2-client-secret=<secret>

# 创建 IAP 访问策略
gcloud resource-manager org-policies set-policy \
  --organization=<org-id> iap_policy.yaml

# AWS Verified Access
# 创建信任提供商
aws verifiedaccess create-trust-provider \
  --policy-reference-name "company-idp" \
  --trust-provider-type "user" \
  --user-trust-provider-configuration file://trust-config.json

# 创建 Verified Access 实例
aws verifiedaccess create-instance \
  --description "Company internal apps"

# 创建端点
aws verifiedaccess create-endpoint \
  --verified-access-instance-id <instance-id> \
  --application-domain "app.company.com" \
  --endpoint-type "load-balancer" \
  --load-balancer-options file://lb-config.json

# 配置访问策略
{
  "Version": "2021-05-01",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"user": ["alice@company.com"]},
    "Action": ["verified-access:AllowAccess"],
    "Condition": {
      "Bool": {"verified-access:deviceCompliant": "true"},
      "IpAddress": {"verified-access:sourceIp": "10.0.0.0/8"},
      "NumericLessThan": {"verified-access:userRiskScore": 50}
    }
  }]
}

# Cloudflare Access — ZTNA 示例
# 配置 Access 策略
# 在 Cloudflare Dashboard → Access → Applications → Add Application
# 策略:
#   - 用户: alice@company.com AND
#   - 国家: CN OR US AND
#   - 设备: 托管设备 AND
#   - 认证: MFA
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| BeyondCorp Enterprise | Google ZTNA | https://cloud.google.com/beyondcorp |
| AWS Verified Access | AWS ZTNA | https://aws.amazon.com/verified-access/ |
| Cloudflare Access | ZTNA 代理 | https://www.cloudflare.com/products/zero-trust/access/ |
| Azure AD Conditional Access | 条件访问 | https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/ |
| Tailscale | 简单安全的网络 | https://tailscale.com/ |

## 参考资源

- [NIST SP 800-207 — Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [Google BeyondCorp Paper](https://research.google/pubs/pub43231/)
- [CISA Zero Trust Maturity Model](https://www.cisa.gov/zero-trust-maturity-model)
- [Forrester Zero Trust Framework](https://www.forrester.com/report/zero-trust-extended-ecosystem/)
- [NSA Zero Trust Guidance](https://media.defense.gov/2021/Feb/25/2002588479/-1/-1/0/CSI_EMBRACING_ZT_SECURITY_MODEL_UOO115131-21.PDF)
