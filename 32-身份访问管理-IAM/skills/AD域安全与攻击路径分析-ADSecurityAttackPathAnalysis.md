---
id: "32-004"
title: "AD域安全与攻击路径分析 (AD Security & Attack Path Analysis)"
category: "身份与访问管理"
category_en: "Identity & Access Management"
difficulty: "★★★★★"
tools: "BloodHound, PingCastle, Purple Knight, AD Explorer, PowerView"
last_updated: "2026-05"
tags: [active-directory, domain-security, attack-path, bloodhound, acl-abuse]
subdomain: identity-access-management
nist_csf: [DE.AE-02, DE.AE-05, PR.AC-01, PR.AC-05]
mitre_attack: [T1003, T1207, T1484, T1550, T1611]
---

# AD域安全与攻击路径分析 (AD Security & Attack Path Analysis)

## 概述

Active Directory 是企业身份认证的核心，也是攻击者横向移动的关键目标。AD 中的权限配置错误和信任关系常被利用来提升权限。本技能覆盖 AD 安全评估工具使用、攻击路径分析、ACL 滥用检测和域安全加固。

## 核心技能

### 1. BloodHound 攻击路径分析

```bash
# BloodHound 部署
# 安装 Neo4j 数据库
# https://neo4j.com/download/

# 启动 Neo4j
sudo neo4j start

# BloodHound 数据采集
# 在域内机器上运行 SharpHound

# SharpHound — PowerShell 采集器
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Domain corp.company.com

# SharpHound — 可执行文件
SharpHound.exe -c All -d corp.company.com

# 采集方法说明:
# - All: 全部数据（ACL、Group、Session、Trust）
# - ACL: 访问控制列表
# - Group: 组成员关系
# - Session: 用户会话
# - Trust: 域信任关系
# - ObjectProps: 对象属性

# 上传数据到 BloodHound
# 拖拽 JSON 文件到 BloodHound UI

# 常用 BloodHound 查询 (Cypher)

# 查找 Domain Admin 路径
MATCH p = shortestPath((g:Group)-[:MemberOf*1..]->(da:Group {name:"DOMAIN ADMINS@CORP.COMPANY.COM"}))
RETURN p LIMIT 10

# 查找拥有域管理员权限的非特权用户
MATCH p = (u:User)-[:MemberOf|AdminTo|GenericAll|Owns|WriteOwner|WriteDacl*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.COMPANY.COM"})
WHERE NOT u.name STARTS WITH "ADMIN"
RETURN p

# 查找所有可被攻击者控制的计算机
MATCH (u:User)-[:CanRDP|SQLAdmin|ExecuteDCOM*]->(c:Computer)
RETURN u.name, c.name

# 查找 Kerberoastable 账户
MATCH (u:User {hasspn: true})
RETURN u.name, u.samaccountname

# 查找 AS-REP Roastable 账户 (不需要预认证)
MATCH (u:User {dontreqpreauth: true})
RETURN u.name

# 查找出站信任关系
MATCH (d:Domain)-[:TrustedBy]->(t:Domain)
RETURN d.name, t.name
```

### 2. AD 安全评估

```bash
# PingCastle — AD 安全评估
# 下载: https://www.pingcastle.com/

# 运行 PingCastle 评估
PingCastle.exe --healthcheck --server dc.company.com --level Full

# 输出 HTML 报告
# 包含:
# - 全局评分 (0-100, 分数越低越安全)
# - 风险指标 (高/中/低)
# - 规则违反列表 (~60+ 安全规则)
# - 趋势图（多次评估对比）

# PingCastle 风险评分解释
# 0-20: 非常安全
# 20-35: 安全
# 35-50: 有风险
# 50-70: 高风险
# 70+: 立即行动

# Purple Knight — 免费 AD 安全评估
# 下载: https://www.purple-knight.com/

# 运行评估
PurpleKnightCmd.exe --domain corp.company.com

# AD 安全基线检查
# 1. 发现未使用的管理员账户
# 2. 检测过度的委派权限
# 3. 检查 SIDHistory 滥用
# 4. 检测 Kerberos 委派配置问题
# 5. 检查 LDAP 签名是否强制
# 6. 检测弱密码策略
```

### 3. ACL 滥用检测

```python
"""AD ACL 滥用检测"""

class ADAnalyzer:
    """AD 安全分析"""
    
    # 危险的 ACL 权限
    DANGEROUS_ACLS = [
        "GenericAll",      # 完全控制
        "GenericWrite",    # 写入所有属性
        "WriteOwner",      # 修改所有者
        "WriteDacl",       # 修改 ACL
        "AllExtendedRights", # 所有扩展权限
        "ForceChangePassword", # 强制改密码
        "AddMember",       # 添加组成员
        "AddAllowedToAct", # 添加 Kerberos 委派
    ]
    
    @staticmethod
    def check_privileged_acl(acl_entries):
        """检查高危 ACL"""
        findings = []
        for entry in acl_entries:
            if entry.get("right") in ADAnalyzer.DANGEROUS_ACLS:
                findings.append({
                    "principal": entry.get("principal"),
                    "right": entry.get("right"),
                    "target": entry.get("target"),
                    "risk": "high",
                    "recommendation": f"Remove {entry['right']} from {entry['principal']}"
                })
        return findings
    
    @staticmethod
    def analyze_delegation(users):
        """分析 Kerberos 委派配置"""
        vulnerable = []
        for user in users:
            if user.get("unconstrained_delegation"):
                vulnerable.append({
                    "user": user["name"],
                    "type": "Unconstrained Delegation",
                    "risk": "critical",
                    "impact": "可以模拟任意用户访问任意服务"
                })
            if user.get("constrained_delegation"):
                vulnerable.append({
                    "user": user["name"],
                    "type": "Constrained Delegation",
                    "risk": "high",
                    "impact": f"可以模拟用户访问: {user.get('delegated_services', [])}"
                })
        return vulnerable

# 使用示例
analyzer = ADAnalyzer()
findings = analyzer.check_privileged_acl([
    {"principal": "domain_users", "right": "GenericAll", "target": "OU=Servers"}
])
for f in findings:
    print(f"[{f['risk']}] {f['principal']} has {f['right']} on {f['target']}")
```

```bash
# PowerView — AD 枚举与分析
# 加载 PowerView
Import-Module PowerView.ps1

# 枚举域管理员
Get-NetGroup -GroupName "Domain Admins" | Get-NetGroupMember

# 查找非服务账户的 SPN (Kerberoast 目标)
Get-NetUser -SPN | Where-Object {$_.samaccountname -notlike "*svc_*"}

# 查找约束委派
Get-NetUser -TrustedToAuth | fl name,msds-allowedtodelegateto

# 查找不需要预认证的账户 (AS-REP Roast)
Get-DomainUser -PreauthNotRequired

# 枚举 ACL
Get-ObjectAcl -ResolveGUIDs -SamAccountName "Domain Admins"

# 查找所有用户的 GenericAll 权限
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs |
  Where-Object {$_.ActiveDirectoryRights -eq "GenericAll"} |
  ForEach-Object {Convert-ADName -IdentityObject $_.SecurityIdentifier}

# 查找 GPO 滥用
Get-NetGPO | Get-ObjectAcl -ResolveGUIDs |
  Where-Object {$_.ActiveDirectoryRights -match "Write|Create|Modify"}

# 枚举域信任
Get-NetDomainTrust -API

# 查找本地管理员组中的域用户
Get-NetLocalGroup -ComputerName dc01 -ListGroups | ForEach-Object {
  Get-NetLocalGroupMember -ComputerName dc01 -GroupName $_ -API
}
```

### 4. AD 安全加固

```powershell
# AD 安全加固策略

# 1. 启用高级审计策略
auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable

# 2. 启用 LDAP 签名和通道绑定
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
  -Name "LDAPServerIntegrity" -Value 2 -PropertyType DWORD
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
  -Name "LdapEnforceChannelBinding" -Value 2 -PropertyType DWORD

# 3. 禁用 NTLM v1
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
  -Name "NtlmMinClientSec" -Value 537395200 -PropertyType DWORD
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
  -Name "NtlmMinServerSec" -Value 537395200 -PropertyType DWORD

# 4. 防护 Kerberoast 攻击
# 为服务账号设置复杂密码并定期轮换
# 使用组托管服务账号 (gMSA)

# 5. 防护 DCSync 攻击
# 移除非必要账户的 DS-Replication-Get-Changes 权限
Get-ObjectAcl -DistinguishedName "dc=corp,dc=company" -ResolveGUIDs |
  Where-Object {$_.ObjectAceType -eq "DS-Replication-Get-Changes"}

# 6. 配置受保护用户组
# 将高权限账户移入 "Protected Users" 组
Add-ADGroupMember -Identity "Protected Users" -Members "admin_alice", "admin_bob"

# 7. 禁用 RC4 加密（防止 Kerberoast）
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" `
  -Name "Enabled" -Value 0 -PropertyType DWORD

# 8. 最小化域管理员组成员
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| BloodHound | AD 攻击路径分析 | https://github.com/BloodHoundAD/BloodHound |
| PingCastle | AD 安全评估 | https://www.pingcastle.com/ |
| Purple Knight | AD 安全基线检查 | https://www.purple-knight.com/ |
| PowerView | AD 枚举脚本 | https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon |
| AD Explorer | Sysinternals AD 查看 | https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer |

## 参考资源

- [BloodHound Cypher Cheat Sheet](https://hausec.com/2019/09/15/bloodhound-cypher-cheatsheet/)
- [Active Directory Security — Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices)
- [AD Attack Paths — SpecterOps](https://posts.specterops.io/the-attacker-side-of-active-directory-1a0e3e86898c)
- [PingCastle Rules Reference](https://www.pingcastle.com/documentation/)
- [NIST SP 800-77 — AD Security Guide](https://csrc.nist.gov/publications/detail/sp/800-77/rev-1/final)
