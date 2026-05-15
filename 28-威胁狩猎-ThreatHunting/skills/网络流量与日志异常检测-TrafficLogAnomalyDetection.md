---
id: "28-004"
title: "网络流量与日志异常检测 (Network Traffic & Log Anomaly Detection)"
category: "威胁狩猎"
category_en: "Threat Hunting"
difficulty: "★★★★"
tools: "Zeek, Suricata, tcpdump, Elastic, Splunk, Jupyter"
last_updated: "2026-05"
tags: [anomaly-detection, network-traffic, dns, beaconing, log-analysis]
subdomain: threat-hunting
nist_csf: [DE.AE-02, DE.AE-04, DE.CM-01]
mitre_attack: [T1041, T1071, T1095, T1571, T1572]
---

# 网络流量与日志异常检测 (Network Traffic & Log Anomaly Detection)

## 概述

网络流量异常检测是威胁狩猎的核心能力之一，常用于发现 DNS 隧道、C2 通信、数据外传等隐蔽行为。本技能覆盖流量层面（Zeek/包分析）和日志层面（Windows Event/EDR/代理日志）的异常检测技术，结合统计分析和机器学习方法识别偏离基线的行为。

## 核心技能

### 1. DNS 隧道与 C2 检测

```python
#!/usr/bin/env python3
"""DNS 隧道检测 — 基于子域名熵分析"""

import numpy as np
import pandas as pd
from collections import Counter
import math

def calculate_entropy(data):
    """计算字符串的信息熵"""
    if not data:
        return 0
    entropy = 0
    length = len(data)
    for count in Counter(data).values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def detect_dns_tunneling(dns_log_file):
    """检测 DNS 隧道流量"""
    df = pd.read_csv(dns_log_file)
    
    results = []
    for _, row in df.iterrows():
        query = row.get('query', '')
        subdomain = query.split('.')[0] if '.' in query else query
        
        # 特征 1: 子域名熵
        entropy = calculate_entropy(subdomain)
        
        # 特征 2: 子域名长度
        length = len(subdomain)
        
        # 特征 3: 查询频率（每秒查询数）
        # 特征 4: TXT 记录查询（常用于 C2 数据传递）
        qtype = row.get('query_type', '')
        
        is_suspicious = False
        reasons = []
        
        if entropy > 3.5:
            reasons.append(f"高熵子域名: {entropy:.2f}")
            is_suspicious = True
        
        if length > 30:
            reasons.append(f"长子域名: {length} 字符")
            is_suspicious = True
        
        if qtype == 'TXT':
            reasons.append("TXT 记录查询（可能的数据传递）")
            is_suspicious = True
        
        if is_suspicious:
            results.append({
                'query': query,
                'entropy': round(entropy, 2),
                'length': length,
                'qtype': qtype,
                'reasons': '; '.join(reasons),
                'timestamp': row.get('timestamp', '')
            })
    
    return pd.DataFrame(results)

# 使用示例
# df = detect_dns_tunneling('dns_queries.csv')
# df.to_csv('dns_tunnel_candidates.csv', index=False)

# 高熵阈值参考:
# - 正常域名: 1.5 - 2.5 (如 google.com)
# - DGA 域名: 3.0 - 4.0 (如 jf8d2s9f.example.com)
# - Base64 编码: 4.0 - 5.0 (隧道流量)
```

```bash
# Zeek + DNS 分析
# 安装 Zeek
sudo apt-get install zeek

# 捕获 DNS 日志
zeek -i eth0 -C dns

# 分析 DNS 日志中的异常
cd /var/log/zeek/current/

# 查找 TXT 记录查询（C2 常用）
grep "TXT" dns.log | awk '{print $10, $11}' | sort | uniq -c | sort -rn | head -10

# 查找长子域名（> 30 字符）
cat dns.log | zeek-cut query | awk -F'.' '{print $1}' | awk 'length($0)>30 {print}' | head -20

# 查找高频 DNS 查询（信标检测）
cat dns.log | zeek-cut query ts | awk '{print $1}' | sort | uniq -c | sort -rn | head -20

# Zeek 检测 DGA 域名（使用 zeek-dga 插件）
zeek -r capture.pcap dga
```

### 2. 网络信标与 C2 通信检测

```python
"""C2 信标（Beaconing）检测 — 基于时间间隔分析"""

import numpy as np
import pandas as pd
from datetime import datetime

def detect_beaconing(flow_log_file, threshold_cv=0.5):
    """
    基于时间间隔变异系数检测网络信标
    CV < 0.5 表示周期性强（可疑）
    """
    df = pd.read_csv(flow_log_file)
    
    # 按目标 IP 分组，分析连接间隔
    beacons = []
    for ip, group in df.groupby('dest_ip'):
        if len(group) < 5:
            continue
        
        timestamps = sorted(pd.to_datetime(group['timestamp']))
        intervals = [(timestamps[i+1] - timestamps[i]).total_seconds()
                     for i in range(len(timestamps)-1)]
        
        if not intervals:
            continue
        
        # 计算变异系数 (CV = std/mean)
        mean_int = np.mean(intervals)
        std_int = np.std(intervals)
        cv = std_int / mean_int if mean_int > 0 else float('inf')
        
        if cv < threshold_cv and mean_int > 0.5:
            beacons.append({
                'dest_ip': ip,
                'avg_interval': round(mean_int, 2),
                'std_interval': round(std_int, 2),
                'cv': round(cv, 2),
                'total_connections': len(group),
                'total_bytes': group['bytes'].sum(),
                'suspicious': 'YES' if cv < 0.3 else 'POSSIBLE'
            })
    
    result = pd.DataFrame(beacons)
    return result.sort_values('cv')

# 使用示例
# beacons = detect_beaconing('netflow.csv')
# beacons.to_csv('beacon_candidates.csv', index=False)
# print(beacons[beacons['suspicious'] == 'YES'])
```

```bash
# Suricata 检测 C2 通信
# 安装 Suricata
sudo apt-get install suricata

# 配置 C2 检测规则
cat > /etc/suricata/rules/c2-detection.rules << 'EOF'
# 检测高频 HTTP GET 请求（信标）
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Potential C2 Beacon - Regular HTTP GET";
  flow:to_server; method:"GET";
  threshold: type both, track by_src, count 50, seconds 300;
  classtype:trojan-activity; sid:1000001; rev:1;
)

# 检测 DNS TXT 响应过大的数据传递
alert dns $HOME_NET any -> any 53 (
  msg:"DNS TXT Response Oversize - Possible C2";
  dns.rrtype:TXT; dns.rcode:NOERROR;
  content:"|0A|"; dns.resp_len:>100;
  classtype:command-and-control; sid:1000002; rev:1;
)
EOF

# 加载规则测试
suricata -T -c /etc/suricata/suricata.yaml

# 实时检测
suricata -i eth0 -c /etc/suricata/suricata.yaml
```

### 3. Windows 日志异常检测

```powershell
# 检测异常登录行为

# 1. 非工作时间登录
$non_work_hours = Get-WinEvent -FilterHashtable @{
    LogName='Security'; ID=4624; StartTime=(Get-Date).AddDays(-7)
} | Where-Object {
    $_.TimeCreated.Hour -lt 7 -or $_.TimeCreated.Hour -gt 19
}

# 2. 从 N 个不同 IP 登录的用户
$multi_ip_logins = Get-WinEvent -FilterHashtable @{
    LogName='Security'; ID=4624
} | Group-Object @{e={$_.Properties[5].Value}} | Where-Object Count -gt 5

# 3. 服务账号交互式登录（异常）
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} |
Where-Object { $_.Properties[5].Value -match 'svc_|sa_|backup_' } |
Select-Object TimeCreated, @{n='Account';e={$_.Properties[5].Value}},
    @{n='LogonType';e={$_.Properties[8].Value}} |
Where-Object { $_.LogonType -ne 5 }
```

```bash
# 结合 EDR 与网络日志的关联分析
# 场景: 检测进程外连异常

# 步骤 1: 收集进程网络连接
# 在 EDR 中查询过去 1 小时所有出站连接

# 步骤 2: 建立基线
# 列出每个进程的正常外部连接目标

# 步骤 3: 异常识别
# 从未见过的进程→IP 连接

# 使用 osquery 查询进程连接
osqueryi "
SELECT p.name, p.pid, c.remote_address, c.remote_port, c.state
FROM process_open_sockets c
JOIN processes p ON c.pid = p.pid
WHERE c.remote_address NOT IN (
  '127.0.0.1', '0.0.0.0', '::1'
) AND c.remote_port != 443 AND c.remote_port != 80
ORDER BY p.name;
"
```

### 4. 基于基线的异常检测

```python
"""建立网络流量基线并检测异常"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta

class BaselineAnomalyDetector:
    """基于统计基线的异常检测器"""
    
    def __init__(self, window_days=30):
        self.window = timedelta(days=window_days)
        self.metrics = {}
    
    def build_baseline(self, historical_data):
        """构建流量基线"""
        df = pd.DataFrame(historical_data)
        
        self.metrics = {
            'dns_queries_per_hour': {
                'mean': df.groupby(df['timestamp'].dt.hour)['dns_count'].mean().to_dict(),
                'std': df.groupby(df['timestamp'].dt.hour)['dns_count'].std().to_dict()
            },
            'bytes_per_connection': {
                'mean': df['bytes'].mean(),
                'std': df['bytes'].std()
            },
            'unique_external_ips': {
                'mean': df.groupby(df['timestamp'].dt.date)['dest_ip'].nunique().mean(),
                'std': df.groupby(df['timestamp'].dt.date)['dest_ip'].nunique().std()
            }
        }
        return self.metrics
    
    def detect_anomalies(self, current_data):
        """对比基线检测异常"""
        alerts = []
        
        # 检查 DNS 频率
        hour = current_data['timestamp'].hour
        dns_mean = self.metrics['dns_queries_per_hour']['mean'].get(hour, 0)
        dns_std = self.metrics['dns_queries_per_hour']['std'].get(hour, 1)
        
        dns_zscore = (current_data['dns_count'] - dns_mean) / max(dns_std, 1)
        if dns_zscore > 3:
            alerts.append({
                'type': 'dns_anomaly',
                'message': f"DNS 查询量异常 (z-score: {dns_zscore:.2f})",
                'severity': 'high'
            })
        
        # 检查连接字节数
        byte_zscore = (current_data['bytes'] - self.metrics['bytes_per_connection']['mean']) / max(self.metrics['bytes_per_connection']['std'], 1)
        if byte_zscore > 3:
            alerts.append({
                'type': 'bandwidth_anomaly',
                'message': f"连接大小异常 (z-score: {byte_zscore:.2f})",
                'severity': 'medium'
            })
        
        return alerts

# 使用示例
detector = BaselineAnomalyDetector()
# detector.build_baseline(historical_netflow)
# alerts = detector.detect_anomalies(current_flow)
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Zeek | 网络安全监控框架 | https://zeek.org/ |
| Suricata | IDS/IPS 引擎 | https://suricata.io/ |
| tcpdump | 数据包捕获分析 | https://www.tcpdump.org/ |
| Elastic Stack | 日志存储与分析 | https://www.elastic.co/elastic-stack |
| Wireshark | 协议分析器 | https://www.wireshark.org/ |
| RITA | 信标检测框架 | https://github.com/activecm/rita |

## 参考资源

- [Zeek Network Security Monitoring](https://docs.zeek.org/en/current/)
- [DNS Tunneling Detection — SANS](https://www.sans.org/white-papers/dns-tunneling/)
- [Detecting C2 Beacons with RITA](https://github.com/activecm/rita)
- [Network Anomaly Detection — Elastic Security](https://www.elastic.co/guide/en/security/current/network-anomaly-detection.html)
- [Hunting for C2 — Palantir Blog](https://blog.palantir.com/hunting-for-c2-communications-with-network-traffic-analysis/)
