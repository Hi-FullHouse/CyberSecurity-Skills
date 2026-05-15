---
id: 19-001
title: "⚙️ SCADA系统安全评估 (SCADA System Security Assessment)"
category: 工控安全
category_en: "ICS/OT Security"
difficulty: ★★★★
tools: "PLCScan, Modbus/TCP Scanner, Shodan, Nmap NSE, Wireshark"
last_updated: 2025-07
tags: ["ics-security", "ot-security", "scada", "plc", "iec-62443", "industrial-security"]
subdomain: ics-ot-security
nist_csf: ["PR.AC-01", "PR.DS-07", "PR.PT-01"]
mitre_attack: ["T0843", "T0839", "T0881", "T0855"]
---
# ⚙️ SCADA系统安全评估 (SCADA System Security Assessment)

## 概述
对SCADA(监控与数据采集)系统进行安全评估，涵盖Modbus、DNP3、S7等工业协议的安全性测试、PLC设备发现、固件版本核查和网络隔离审查。

## 核心技能

### 1. 工控设备发现与识别

```bash
# 使用Nmap工控脚本扫描
nmap -sV -p 502,102,20000,44818,2404,1911,2222 <target> --script modbus-discover

# Modbus TCP设备发现
nmap -p 502 --script modbus-discover <target-range>
nmap -p 502 --script modbus-discover -sV --script-args modbus-discover.aggressive=true

# S7协议(Siemens PLC)发现
nmap -p 102 --script s7-info <target>
nmap -p 102 --script s7-enumerate <target-range>

# BACnet协议发现
nmap -p 47808 --script bacnet-info <target>

# DNP3协议发现
nmap -p 20000 --script dnp3-info <target>

# 使用PLCScan专业扫描
git clone https://github.com/me easily/PLCScan.git
python PLCScan.py --target 192.168.1.100 --timeout 10
python PLCScan.py --range 192.168.1.0/24 --verbose
```

### 2. Modbus协议安全测试

```bash
# Modbus协议基础测试
# 使用Modbus客户端读取数据
pip install modbus-tk pymodbus

# Python Modbus安全测试
python3 << 'EOF'
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('192.168.1.100', port=502)
client.connect()

# 读取线圈状态 (功能码01)
coils = client.read_coils(0, 10, unit=1)
print(f"Coils: {coils.bits}")

# 读取离散输入 (功能码02)
discrete = client.read_discrete_inputs(0, 10, unit=1)
print(f"Discrete inputs: {discrete.bits}")

# 读取保持寄存器 (功能码03)
holding = client.read_holding_registers(0, 10, unit=1)
print(f"Holding registers: {holding.registers}")

# 读取输入寄存器 (功能码04)
input_regs = client.read_input_registers(0, 10, unit=1)
print(f"Input registers: {input_regs.registers}")

# ⚠️ 写入测试 - 仅在授权后进行
# 写入单个线圈 (功能码05)
client.write_coil(0, True, unit=1)

# 写入单个寄存器 (功能码06)
client.write_register(0, 100, unit=1)

client.close()
EOF

# 使用nmap Modbus枚举
nmap -p 502 --script modbus-enum <target>
```

### 3. 工控网络流量分析

```bash
# 使用Wireshark/TShark分析工控协议
# 捕获Modbus TCP流量
tshark -i eth0 -Y "modbus" -T fields -e modbus.func_code -e modbus.unit_id

# 分析DNP3流量
tshark -i eth0 -Y "dnp3" -T fields -e dnp3.function_code -e dnp3.object_type

# 分析S7comm流量
tshark -i eth0 -Y "s7comm" -T fields -e s7comm.param.func

# 分析EtherNet/IP流量
tshark -i eth0 -Y "cip" -T fields -e cip.service

# 分析PROFINET流量
tshark -i eth0 -Y "pn_rt" -T fields -e pn_rt.frame_id

# 使用Scapy解析工控协议
python3 << 'EOF'
from scapy.all import *

def analyze_modbus(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].dport == 502:
        print(f"Modbus pkt: {pkt[IP].src} -> {pkt[IP].dst}")
        print(f"Unit ID: {pkt[Raw].load[6]}")
        print(f"Func Code: {pkt[Raw].load[7]}")

sniff(filter="tcp port 502", prn=analyze_modbus, count=10)
EOF
```

### 4. 工控安全基线

| 检查项 | 严重程度 | 典型配置 |
|:---|:---:|:---|
| 使用默认密码 | 🔴 严重 | admin/admin, 空密码 |
| Modbus无认证 | 🔴 严重 | 协议本身无认证机制 |
| DNP3安全模式未启用 | 🟠 高危 | Secure Authentication (SAv5) |
| PLC固件未更新 | 🟠 高危 | 厂商安全公告未应用 |
| 工程站安装无关软件 | 🟠 高危 | 如浏览器、Office等 |
| 网络分段不足(PLC直连公司网) | 🔴 严重 | 缺少Purdue级别隔离 |
| 远程访问未加固 | 🟠 高危 | 未使用Jump Box/VPN |
| 无线工控网络未加密 | 🟠 高危 | WiFi未使用WPA3 |
| HMI/SCADA服务器未加固 | 🟡 中危 | 多余端口开放 |
| 日志审计未启用 | 🟡 中危 | 无法追踪异常操作 |
| 无备用/冗余控制 | 🟡 中危 | 单点故障风险 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| PLCScan | PLC设备扫描 | https://github.com/neohapsis/PLCScan |
| Modbus CLI | Modbus协议测试 | https://github.com/tallakt/modbus-cli |
| Wireshark | 工业协议分析 | https://www.wireshark.org/ |
| Nmap NSE | 工控脚本扫描 | https://nmap.org/nsedoc/ |
| OpenPLC | PLC模拟器/测试 | https://www.openplcproject.com/ |

## 参考资源
- [NIST SP 800-82 Rev. 3 — Guide to ICS Security](https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final)
- [ICS-CERT Alerts & Advisories](https://www.cisa.gov/ics)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/techniques/ics/)
- [SANS ICS Security](https://www.sans.org/ics-security/)
- [IEC 62443 Security Standards](https://www.iec.ch/standards/62443)
