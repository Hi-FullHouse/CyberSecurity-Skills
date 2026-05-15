---
id: "37-004"
title: "移动设备安全与MDM (Mobile Device Security & MDM)"
category: "端点安全"
category_en: "Endpoint Security"
difficulty: "★★★★"
tools: "Intune, Jamf, MaaS360, MobileIron, Workspace ONE"
last_updated: "2026-05"
tags: [mobile-security, mdm, ios, android, byod, device-compliance]
subdomain: endpoint-security
nist_csf: [PR.AC-01, PR.DS-03, PR.PT-01, DE.CM-01]
mitre_attack: [T1204, T1475, T1514, T1529]
---

# 移动设备安全与MDM (Mobile Device Security & MDM)

## 概述

移动设备已成为企业办公的必需品，但也带来了新的安全风险。MDM（移动设备管理）帮助企业管理和保护移动设备。本技能覆盖 MDM 策略配置、设备合规、应用管理和移动威胁防御。

## 核心技能

### 1. MDM 策略配置

```python
"""MDM 策略配置引擎"""

class MDMPolicy:
    """MDM 策略"""
    
    def __init__(self, platform="ios"):
        self.platform = platform
        self.policies = {}
    
    def set_password_policy(self, min_length=6, require_alpha=True, 
                            require_special=False, max_attempts=10):
        """设置密码策略"""
        self.policies["password"] = {
            "min_length": min_length,
            "require_alpha": require_alpha,
            "require_special": require_special,
            "max_attempts": max_attempts,
            "auto_lock_seconds": 300,  # 5分钟自动锁定
        }
        return self.policies["password"]
    
    def set_encryption_policy(self, require_encryption=True):
        """设置加密策略"""
        self.policies["encryption"] = {
            "require_device_encryption": require_encryption,
            "require_remote_wipe": True,
            "require_jailbreak_detection": True
        }
        return self.policies["encryption"]
    
    def set_network_policy(self, block_vpn=False, require_https=True):
        """设置网络策略"""
        self.policies["network"] = {
            "block_vpn": block_vpn,
            "require_https": require_https,
            "wifi_whitelist": ["corp-wifi"],
            "block_hotspot": True
        }
        return self.policies["network"]
    
    def set_app_policy(self, allowed_apps=None, blocked_apps=None):
        """设置应用策略"""
        self.policies["applications"] = {
            "allow_app_store": True,
            "require_app_approval": True,
            "allowed_apps": allowed_apps or [],
            "blocked_apps": blocked_apps or [],
            "block_sideloading": True
        }
        return self.policies["applications"]
    
    def generate_intune_config(self):
        """生成 Intune 配置策略"""
        return {
            "displayName": f"Security Policy - {self.platform}",
            "platform": self.platform,
            "password": self.policies.get("password", {}),
            "encryption": self.policies.get("encryption", {}),
            "network": self.policies.get("network", {}),
            "applications": self.policies.get("applications", {}),
            "compliance": {
                "require_compliance": True,
                "non_compliance_action": "block_access",
                "grace_period_days": 7
            }
        }
    
    def compliance_check(self, device_status):
        """检查设备合规性"""
        violations = []
        
        # 检查越狱/Root
        if device_status.get("jailbroken"):
            violations.append({
                "policy": "jailbreak_detection",
                "status": "violated",
                "action": "block"
            })
        
        # 检查加密
        if not device_status.get("encrypted"):
            violations.append({
                "policy": "encryption",
                "status": "violated",
                "action": "warn"
            })
        
        # 检查密码
        if device_status.get("passcode_set") == False:
            violations.append({
                "policy": "password",
                "status": "violated",
                "action": "block"
            })
        
        # 检查 OS 版本
        min_version = "15.0" if self.platform == "ios" else "12.0"
        if device_status.get("os_version", "0.0") < min_version:
            violations.append({
                "policy": "os_version",
                "status": "violated",
                "action": "warn"
            })
        
        return {
            "compliant": len(violations) == 0,
            "violations": violations,
            "device_id": device_status.get("device_id")
        }

# 使用示例
mdm = MDMPolicy("ios")
mdm.set_password_policy(min_length=8, max_attempts=10)
mdm.set_encryption_policy(True)
config = mdm.generate_intune_config()
print(f"MDM Policy: {config['displayName']}")

status = mdm.compliance_check({
    "device_id": "iphone-001",
    "jailbroken": False,
    "encrypted": True,
    "passcode_set": True,
    "os_version": "17.0"
})
print(f"Compliant: {status['compliant']}")
```

### 2. 移动威胁防御

```bash
# 移动威胁检测策略

# iOS 安全加固 (通过 MDM 配置)
# 1. 限制 USB 配件连接 (DFU 保护)
# 2. 禁用 USB 受信连接
# 3. 要求所有应用来自 App Store
# 4. 启用 Lockdown 模式
# 5. 启用 VPN 始终开启

# Android 安全加固 (通过 MDM 配置)
# 1. 要求 Google Play Protect 启用
# 2. 禁用未知来源安装
# 3. 启用安全启动验证
# 4. 要求加密存储
# 5. 禁用开发者模式

# Microsoft Intune — 合规策略示例
# 创建 iOS 合规策略
az rest --method PUT \
  --uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies" \
  --body '{
    "@odata.type": "#microsoft.graph.iosCompliancePolicy",
    "displayName": "iOS Security Baseline",
    "passcodeRequired": true,
    "passcodeMinimumLength": 8,
    "passcodeRequiredType": "numericComplex",
    "osMinimumVersion": "16.0",
    "securityBlockJailbrokenDevices": true,
    "deviceThreatProtectionEnabled": true,
    "deviceThreatProtectionRequiredSecurityLevel": "high",
    "storageRequireEncryption": true
  }'

# Jamf Pro — macOS/iOS 管理
# 创建配置策略
curl -X POST "https://company.jamfcloud.com/JSSResource/computergroups/name/0" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
  <computer_group>
    <name>Security Baseline</name>
    <computers>
      <computer><name>All Managed Macs</name></computer>
    </computers>
  </computer_group>'

# Mobile Threat Defense (MTD) 集成
# 1. Microsoft Defender for Endpoint on iOS/Android
# 2. Lookout for Enterprise
# 3. Zimperium zIPS
# 4. Sophos Mobile Security

# MTD 检测指标
# - 网络钓鱼检测 (URL 分析)
# - 恶意应用检测 (行为分析)
# - 网络攻击检测 (MITM)
# - 操作系统漏洞检测
# - 异常行为检测
```

### 3. BYOD 安全策略

```python
"""BYOD 安全策略管理"""

class BYODPolicy:
    """BYOD 安全管理"""
    
    BYOD_MODELS = {
        "intune_app_protection": "应用保护策略（不管理设备，只管理应用）",
        "intune_device_compliance": "设备合规检查 + 应用保护",
        "corporate_owned": "企业所有设备，完全管理",
        "cyberlab": "工作资料/容器方案（Android Work Profile / iOS User Enrollment）"
    }
    
    def __init__(self):
        self.policies = {}
    
    def app_protection_policy(self):
        """应用保护策略（最轻量 BYOD）"""
        return {
            "policy_type": "app_protection",
            "data_protection": {
                "block_copy_paste": True,
                "block_print": True,
                "block_save_as": True,
                "require_encrypted_storage": True,
                "data_transfer_to_other_apps": "block",
                "data_transfer_from_other_apps": "allow_policy_managed"
            },
            "access_requirements": {
                "require_pin": True,
                "pin_length": 6,
                "require_jailbreak_detection": True,
                "require_device_encryption": True,
                "max_pin_attempts": 5,
                "offline_grace_period_hours": 720
            },
            "conditional_launch": {
                "min_os_version": "15.0",
                "min_app_version": "3.0",
                "max_device_threat_level": "low"
            }
        }
    
    def device_compliance_policy(self):
        """设备合规策略（中等 BYOD）"""
        return {
            "policy_type": "device_compliance",
            "device_health": {
                "require_jailbreak_detection": True,
                "require_device_encryption": True,
                "min_threat_level": "low"
            },
            "os_requirements": {
                "ios_min_version": "16.0",
                "android_min_version": "12.0",
                "require_latest_patches": True
            },
            "actions_for_noncompliance": [
                {"action": "block_access", "grace_period_days": 0},
                {"action": "wipe_company_data", "grace_period_days": 14}
            ]
        }
    
    def generate_user_agreement(self):
        """生成用户同意书"""
        return {
            "title": "BYOD 安全协议",
            "sections": [
                "企业有权远程擦除设备中的企业数据",
                "企业不监控个人数据（照片、短信、通话）",
                "设备必须启用加密和锁屏密码",
                "设备不能越狱/Root",
                "企业应用内的数据受 MDM 策略管理",
                "离职时企业数据将从设备移除"
            ]
        }

# 使用示例
byod = BYODPolicy()
app_policy = byod.app_protection_policy()
print(f"APP Policy: {app_policy['policy_type']}")
print(f"Access: PIN required ({app_policy['access_requirements']['pin_length']} digits)")
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Microsoft Intune | MDM/MAM 平台 | https://learn.microsoft.com/en-us/mem/intune/ |
| Jamf Pro | Apple 设备管理 | https://www.jamf.com/ |
| VMware Workspace ONE | 统一端点管理 | https://www.vmware.com/products/workspace-one.html |
| Lookout | 移动威胁防御 | https://www.lookout.com/ |
| Zimperium | 移动安全防御 | https://www.zimperium.com/ |

## 参考资源

- [NIST SP 1800-22 — Mobile Device Security](https://www.nccoe.nist.gov/projects/mobile-device-security)
- [CIS Mobile Device Security Guide](https://www.cisecurity.org/insights/blog/cis-controls-mobile-device-security)
- [Microsoft Intune Documentation](https://learn.microsoft.com/en-us/mem/intune/)
- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [BYOD Security — SANS](https://www.sans.org/white-papers/byod-security/)
