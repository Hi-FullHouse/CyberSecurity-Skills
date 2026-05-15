---
id: 15-013
title: "🌐 网络流量分析 (Network Traffic Analysis)"
category: 应急响应
category_en: "Incident Response"
difficulty: ★★★★
tools: "Wireshark, Zeek, Suricata, tcpdump"
last_updated: 2025-07
tags: ["incident-response", "forensics", "memory-forensics", "threat-hunting", "ransomware"]
subdomain: incident-response
nist_csf: ["RS.RP-01", "RS.CO-02", "RS.AN-01", "RS.MI-01"]
mitre_attack: ["T1486", "T1490", "T1485", "T1562"]
---
# 🌐 网络流量分析 (Network Traffic Analysis)

## 概述
通过对网络流量进行捕获和分析，发现恶意通信模式、提取入侵指标（IoC）、还原攻击路径。是应急响应中确定C2通信、数据外传、横向移动等行为的关键技术。

## 核心技能

### 1. 流量捕获

```bash
# 全流量捕获（取证场景）
sudo tcpdump -i eth0 -s 0 -C 1000 -W 10 -w capture.pcap

# 参数说明：
# -s 0       : 捕获完整数据包（不截断）
# -C 1000    : 每1000MB分割文件
# -W 10      : 最多保留10个文件
# -w capture.pcap : 输出文件名

# 指定BPF过滤器（减少无关流量）
sudo tcpdump -i eth0 -w malicious.pcap -s 0 \
    "host 185.xxx.xxx.xxx or port 4444 or port 8888"

# 无盘模式（高IO场景推荐）
sudo dumpcap -i eth0 -b filesize:1000000 -b files:20 -w /mnt/evidence/traffic.pcapng

# 使用n2disk（工业级全流量存储）
# https://www.ntop.org/products/traffic-collection/n2disk/
```

### 2. Wireshark/TShark 分析

```bash
# 使用TShark命令行分析（适合脚本化）

# 查看会话统计
tshark -r capture.pcap -z conv,tcp
tshark -r capture.pcap -z conv,udp

# 查看HTTP统计
tshark -r capture.pcap -z http,tree

# 查找特定协议的数据包
tshark -r capture.pcap -Y "dns"
tshark -r capture.pcap -Y "http.request"
tshark -r capture.pcap -Y "tls.handshake.type==1"

# 提取HTTP中的文件
tshark -r capture.pcap --export-objects "http,/extracted_files/"

# ICMP数据分析（检测ICMP隧道）
tshark -r capture.pcap -Y "icmp and icmp.type==8 and data.len>64"

# DNS查询分析（检测DNS隧道）
tshark -r capture.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name | sort | uniq -c | sort -nr | head -20
```

### 3. 关键IoC分析技术

#### 识别C2通信
```bash
# 检测Beaconing（周期性心跳包）
tshark -r capture.pcap -Y "tcp.flags.syn==1 and tcp.flags.ack==0" -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.time_delta | awk '{print $1,$2,$5}' | sort

# 检测JA3指纹（TLS客户端指纹识别恶意工具）
tshark -r capture.pcap -Y "tls.handshake.type==1" -T fields -e tls.handshake.ja3

# 检测SLAAC/MD5等异常TLS特征
tshark -r capture.pcap -Y "tls.handshake.version==0x0300 or tls.handshake.version==0x0301"

# 检测异常用户代理
tshark -r capture.pcap -Y "http.request" -T fields -e http.user_agent | sort | uniq -c | sort -nr
```

#### 检测数据外传
```bash
# 大流量外传检测
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e frame.len | awk '{sum[$1","$2]+=$3} END{for(k in sum) print k","sum[k]}' | sort -t, -k3 -nr | head -20

# DNS TXT查询异常（数据外传）
tshark -r capture.pcap -Y "dns.qry.type==16" -T fields -e dns.qry.name | awk -F. '{if(length($1)>50) print}'

# HTTP POST请求体过大
tshark -r capture.pcap -Y "http.request.method==POST" -T fields -e http.content_length -e http.request.uri | awk '$1>1000000'
```

#### 检测横向移动
```bash
# 大量SMB连接（Pass-the-Hash/WMI横向移动）
tshark -r capture.pcap -Y "smb2.cmd==0x03" -T fields -e ip.src -e ip.dst -e smb2.sessionid | sort | uniq -c | sort -nr

# RDP连接日志
tshark -r capture.pcap -Y "tcp.port==3389 and tcp.flags.syn==1" -T fields -e ip.src -e ip.dst

# PsExec特征（服务创建+管道通信）
tshark -r capture.pcap -Y "smb.named_pipe and smb.named_pipe contains psexec"
```

### 4. Zeek (Bro) 日志分析

```bash
# Zeek自动生成结构化日志
zeek -r capture.pcap

# 输出文件:
# conn.log     — 所有连接记录
# dns.log      — DNS查询日志
# http.log     — HTTP请求日志
# ssl.log      — TLS证书信息
# smb.log      — SMB协议日志
# files.log    — 文件提取信息
# notice.log   — 异常行为告警

# 分析Zeek日志

# 连接统计
cat conn.log | zeek-cut ts id.orig_h id.resp_h proto service duration | sort -nr

# HTTP请求分析
cat http.log | zeek-cut host uri user_agent status_code

# TLS证书指纹（用于IoC匹配）
cat ssl.log | zeek-cut server_name certificate.subject ja3 fingerprint

# DNS分析 — 检测DGA域名
cat dns.log | zeek-cut query | awk -F. '{if(length($1)>15) print}'
```

### 5. Suricata IDS 规则匹配

```bash
# 使用Suricata对pcap进行重放分析
suricata -r capture.pcap -l suricata_output/

# 查看告警统计
cat suricata_output/fast.log | cut -d'[' -f2 | cut -d']' -f1 | sort | uniq -c | sort -nr

# 查看Eve JSON告警详情
cat suricata_output/eve.json | jq 'select(.event_type=="alert") | {sig:.alert.signature, src:.src_ip, dst:.dest_ip, proto:.proto}'
```

### 6. 威胁情报关联

```bash
# 提取所有IP进行威胁情报查询
tshark -r capture.pcap -T fields -e ip.dst | sort -u | grep -v "^$" > ips.txt

# 批量查询VirusTotal
for ip in $(cat ips.txt); do
    result=$(curl -s "https://www.virustotal.com/api/v3/ip_addresses/$ip" -H "x-apikey: $VT_API_KEY" | jq '.data.attributes.last_analysis_stats.malicious')
    echo "$ip: $result malicious"
done

# MISP威胁情报平台集成
misp-cli search-threat actor:<查询>
```

### 7. 流量中提取文件

```bash
# 从HTTP流量中提取文件
foremost -t all -i capture.pcap -o extracted/

# 从SMB流量提取文件（Zeek自动提取）
# 查看files.log中提取的文件
cat files.log | zeek-cut tx_hosts rx_hosts filename extracted

# 使用NetworkMiner（Windows GUI）
# NetworkMiner.exe — 自动解析和提取

# curl从http流提取单个文件
tshark -r capture.pcap -Y "http.request.uri contains /malware.exe" -T fields -e http.host -e http.request.uri
```

### 8. 流量取证时间线

```bash
# 构建网络时间线
tshark -r capture.pcap -T fields -e frame.time_epoch -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info -E separator=| | sort -t| -k1 > timeline.csv

# 使用elasticdump导入ELK进行可视化分析
elasticdump --input=capture.pcap --output=http://localhost:9200/packets
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Wireshark/TShark | 全流量分析 | https://www.wireshark.org/ |
| Zeek | 网络流量元数据分析 | https://zeek.org/ |
| Suricata | IDS/IPS规则匹配 | https://suricata.io/ |
| tcpdump | 命令行抓包 | https://www.tcpdump.org/ |
| NetworkMiner | 网络取证分析工具 | https://www.netresec.com/?page=NetworkMiner |
| Moloch/Arkime | 全流量搜索索引 | https://arkime.com/ |
| CapLoader | 超大pcap快速处理 | https://www.netresec.com/?page=CapLoader |
| ntopng | 流量可视化监控 | https://www.ntop.org/ |

## 参考资源

- [SANS FOR572 — Advanced Network Forensics](https://www.sans.org/for572/)
- [Wireshark Display Filters 参考](https://www.wireshark.org/docs/dfref/)
- [Zeek Quick Start Guide](https://docs.zeek.org/en/current/quickstart.html)
- [Chris Sanders — Practical Packet Analysis](https://www.practicalpacketanalysis.com/)
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)
