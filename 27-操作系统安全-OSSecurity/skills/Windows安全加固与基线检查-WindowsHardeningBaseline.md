---
id: 27-001
title: "Windows安全加固与基线检查 (Windows Hardening & Baseline)"
category: 操作系统安全
category_en: "OS Security"
difficulty: ★★★
tools: "CIS Benchmarks, 等保2.0, GPO, LGPO, Microsoft Security Compliance Toolkit, Windows Defender"
last_updated: 2026-05
tags: ["os-security", "windows-hardening", "linux-hardening", "macos", "privilege-escalation"]
subdomain: os-security
nist_csf: ["PR.AC-01", "PR.DS-07", "PR.PT-01"]
mitre_attack: ["T1548", "T1552", "T1562"]
---
# Windows安全加固与基线检查 (Windows Hardening & Baseline)

## 概述

Windows 系统安全加固是保障企业环境安全的基础。本技能以 CIS Microsoft Windows Server Benchmarks、等保2.0 三级安全要求、Microsoft 安全基线为参考，系统覆盖 Windows 系统安全配置、组策略加固、用户权限管理、服务加固、安全功能配置等核心领域，帮助安全运维人员建立标准化的 Windows 安全加固体系。

## 核心技能

### 1. 安全基线评估与合规检查

使用 Microsoft Security Compliance Toolkit 和 LGPO 工具进行基线检查：

```powershell
# 下载并导入安全基线
# Microsoft Security Compliance Toolkit 1.0
Invoke-WebRequest -Uri "https://download.microsoft.com/download/.../Windows-Security-Baseline.zip" -OutFile "baseline.zip"
Expand-Archive -Path "baseline.zip" -DestinationPath ".\baseline"

# 使用 LGPO 导入安全策略
.\LGPO.exe /s .\baseline\GPOs\MSFT-Windows-10-1809-v4-FINAL\DomainSysvol\GPO\Machine\registry.pol

# 使用 PolicyAnalyzer 对比当前策略与基线
.\PolicyAnalyzer.exe /Compare ^
  /Source "Current Policy" ^
  /Target ".\baseline\GPOs\MSFT-Windows-10-1809-v4-FINAL" ^
  /Report ".\compliance-report.html"

# 使用 Local Group Policy Object 工具导出当前策略
secedit /export /cfg "C:\Windows\security\current_policy.inf"
```

```powershell
# CIS-CAT 合规评估（需要 CIS-CAT Pro）
.\CIS-CAT.bat ^
  -a assessment ^
  -t "Windows 10 Enterprise" ^
  -p "CIS_Microsoft_Windows_10_Enterprise_Benchmark_v2.0.0" ^
  -o ".\cis-report.html"

# 等保2.0 三级合规检查项
# 身份鉴别（三级要求）
# a) 应对登录的用户进行身份标识和鉴别
secedit /export /cfg secpol.cfg
Select-String "PasswordComplexity" secpol.cfg          # 应=1
Select-String "MinimumPasswordLength" secpol.cfg       # 应≥8
Select-String "LockoutBadCount" secpol.cfg             # 应≤5
Select-String "ResetLockoutCount" secpol.cfg           # 应≥15
Select-String "LockoutDuration" secpol.cfg             # 应≥15

# b) 应启用登录失败处理功能
secedit /export /cfg secpol.cfg | Select-String "ForceLogoffWhenHourExpire"
```

### 2. 用户权限与账户安全

```powershell
# 检查本地管理员组成员
net localgroup Administrators
Get-LocalGroupMember -Group "Administrators"

# 配置密码策略
net accounts /minpwlen:14 /maxpwage:90 /minpwage:1 /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30

# 查询并审核特权用户
# 查找所有域管理员
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName

# 查找服务账号是否具有交互登录权限
# 通过 secedit 导出用户权限分配
secedit /export /cfg "C:\Windows\security\user_rights.inf"
Select-String -Path "C:\Windows\security\user_rights.inf" -Pattern "SeDenyInteractiveLogonRight"
Select-String -Path "C:\Windows\security\user_rights.inf" -Pattern "SeServiceLogonRight"

# UAC 配置（推荐级别：Always Notify）
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2

# 删除不必要的本地用户
$unusedUsers = @("Guest", "DefaultAccount")
foreach ($user in $unusedUsers) {
    $u = Get-LocalUser -Name $user -ErrorAction SilentlyContinue
    if ($u -and $u.Enabled) { Disable-LocalUser -Name $user }
}
```

### 3. 组策略安全加固

```powershell
# 通过 GPO 配置安全选项（域环境）

# 网络安全：LAN Manager 身份验证级别 → 仅发送 NTLMv2
Set-GPRegistryValue -Name "Windows Hardening Policy" ^
  -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" ^
  -ValueName "LmCompatibilityLevel" -Type DWord -Value 5

# 网络安全：最小化会话安全
Set-GPRegistryValue -Name "Windows Hardening Policy" ^
  -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" ^
  -ValueName "NTLMMinClientSec" -Type DWord -Value 537395200
Set-GPRegistryValue -Name "Windows Hardening Policy" ^
  -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" ^
  -ValueName "NTLMMinServerSec" -Type DWord -Value 537395200

# 关闭 SMBv1（消除永恒之蓝类漏洞风险）
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-GPRegistryValue -Name "Windows Hardening Policy" ^
  -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" ^
  -ValueName "SMB1" -Type DWord -Value 0

# 限制空链接匿名访问
Set-GPRegistryValue -Name "Windows Hardening Policy" ^
  -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" ^
  -ValueName "RestrictAnonymous" -Type DWord -Value 2
Set-GPRegistryValue -Name "Windows Hardening Policy" ^
  -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" ^
  -ValueName "RestrictAnonymousSAM" -Type DWord -Value 1
Set-GPRegistryValue -Name "Windows Hardening Policy" ^
  -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" ^
  -ValueName "RestrictRemoteSAM" -Type String -Value "O:BAG:BAD:(A;;RC;;;BA)"
```

### 4. 安全功能配置

```powershell
# Windows Defender 配置
# 启用实时保护
Set-MpPreference -DisableRealtimeMonitoring $false
# 启用云保护
Set-MpPreference -EnableControlledFolderAccess Enabled
# 配置 ASR 规则（Attack Surface Reduction）
Add-MpPreference -AttackSurfaceReductionRulesIds ^
  "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" -AttackSurfaceReductionRulesActions Enabled
Add-MpPreference -AttackSurfaceReductionRulesIds ^
  "3b576869-a4ec-4529-8536-b80a7765e899" -AttackSurfaceReductionRulesActions Enabled
# 计划扫描
Set-MpPreference -ScanScheduleDay 1 -ScanScheduleQuickScanTime 09:00

# BitLocker 加密配置
# 启用 BitLocker（系统盘）
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector
# 检查 BitLocker 状态
Get-BitLockerVolume -MountPoint "C:" | fl

# Windows 防火墙配置
# 开启所有配置文件防火墙
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
# 禁止 ICMP 重定向
Set-NetFirewallSetting -AllowICMPRedirect $false

# Credential Guard 启用（需硬件虚拟化支持）
# 通过组策略：计算机配置 → 管理模板 → 系统 → Device Guard → 打开基于虚拟化的安全
# 或通过注册表
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -Value 1
```

### 5. 日志审计与安全监控

```powershell
# 启用高级审计策略
auditpol /set /subcategory:"用户帐户管理" /success:enable /failure:enable
auditpol /set /subcategory:"安全组管理" /success:enable /failure:enable
auditpol /set /subcategory:"进程创建" /success:enable /failure:enable
auditpol /set /subcategory:"帐户登录" /success:enable /failure:enable
auditpol /set /subcategory:"登录" /success:enable /failure:enable
auditpol /set /subcategory:"注册表" /success:enable /failure:enable
auditpol /set /subcategory:"文件系统" /success:enable /failure:enable

# 查看当前审计策略
auditpol /get /category:*
auditpol /get /subcategory:"进程创建"

# 配置日志大小
# 安全日志（至少 1GB）
wevtutil sl Security /ms:1073741824 /rt:true /ab:true
# 系统日志
wevtutil sl System /ms:536870912 /rt:true /ab:true
# PowerShell 操作日志
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1073741824 /rt:true /ab:true

# 配置 Windows 事件转发 (WEF)
# 在收集器上创建订阅
wecutil cs "C:\subscription.xml"

# Sysmon 部署（系统监控）
# 安装 Sysmon 并加载配置
.\Sysmon64.exe -accepteula -i sysmon-config.xml

# 检查 Sysmon 运行状态
Get-Service -Name Sysmon
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; StartTime=(Get-Date).AddHours(-1)} | Group-Object EventID
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Microsoft Security Compliance Toolkit | 微软官方安全基线管理 | https://www.microsoft.com/en-us/download/details.aspx?id=55319 |
| LGPO | 本地组策略对象管理工具 | https://www.microsoft.com/en-us/download/details.aspx?id=55319 |
| CIS-CAT Pro | CIS 合规评估工具 | https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro |
| Sysmon | 系统活动监控驱动 | https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon |
| Windows Event Forwarding | 事件转发集中收集 | https://docs.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding |
| OpenSCAP | 开源合规扫描器（支持 Windows） | https://www.open-scap.org/ |
| 等保2.0 自查工具 | 等保三级自动检查脚本 | https://github.com/ |

## 参考资源

- [CIS Microsoft Windows Server Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_server)
- [CIS Microsoft Windows Desktop Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [GB/T 22239-2019 信息安全技术 网络安全等级保护基本要求](https://openstd.samr.gov.cn/)
- [Microsoft Security Baselines Blog](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/bg-p/M365-Security-Baselines)
- [Windows Defender Security Center](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-security-center)
- [MITRE ATT&CK — TA0005 Defense Evasion](https://attack.mitre.org/tactics/TA0005/)
- [NIST SP 800-53 Rev 5 — AC Access Control](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [Windows Hardening — HackTricks](https://book.hacktricks.xyz/windows-hardening)
