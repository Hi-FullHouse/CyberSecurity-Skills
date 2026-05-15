---
id: 21-003
title: "🌐 物联网通信协议安全 (IoT Communication Security)"
category: 物联网安全
category_en: "IoT Security"
difficulty: ★★★★
tools: "MQTT Pwn, MQTTSA, Wireshark, nmap, MQTTCheck"
last_updated: 2025-07
tags: ["iot-security", "firmware", "embedded", "ble", "zigbee", "hardware-security"]
subdomain: iot-security
nist_csf: ["PR.AC-01", "PR.DS-03", "PR.PT-01"]
mitre_attack: ["T1465", "T1559", "T1524"]
---
# 🌐 物联网通信协议安全 (IoT Communication Security)

## 概述
评估物联网通信协议的安全性，包括MQTT、CoAP、HTTP/2、AMQP、LoRaWAN等IoT协议的安全配置和漏洞识别。

## 核心技能

### 1. MQTT协议安全评估

```bash
# MQTT安全扫描
# 使用MQTT PWN框架
git clone https://github.com/akamai/mqtt-pwn.git
cd mqtt-pwn
pip install -r requirements.txt

# 扫描MQTT Broker
python mqtt-pwn.py --host 192.168.1.100 --scan
# 检查开放端口、TLS支持、匿名访问

# 使用mosquitto_sub测试匿名访问
mosquitto_sub -h 192.168.1.100 -t "#" -v  # 订阅所有主题
mosquitto_sub -h 192.168.1.100 -t "$SYS/#" -v  # 系统主题

# 使用MQTTSA (MQTT Security Assistant)
git clone https://github.com/akamai/MQTTSA.git
cd MQTTSA
pip install -r requirements.txt
python MQTTSA.py --host 192.168.1.100 --port 1883

# MQTT安全基线
# 1. 禁用匿名访问 (allow_anonymous false)
# 2. 启用TLS (listener 8883)
# 3. 配置ACL规则
# 4. 禁用$SYS主题的外部访问
# 5. 设置客户端ID白名单
# 6. 启用持久会话限制

# MQTT ACL配置
cat << 'ACL' > mosquitto.acl
# 用户级别ACL
user sensor01
topic read sensors/+/temperature
topic write sensors/sensor01/status

user admin
topic readwrite #
topic read $SYS/#

# 模式匹配ACL
pattern read sensors/%u/#
pattern write sensors/%u/status
ACL

# Mosquitto安全配置
cat << 'CONF' > mosquitto.conf
listener 1883 127.0.0.1  # 内部监听仅本地
listener 8883             # TLS端口
certfile /etc/mosquitto/certs/server.crt
keyfile /etc/mosquitto/certs/server.key
cafile /etc/mosquitto/certs/ca.crt
tls_version tlsv1.2

allow_anonymous false
password_file /etc/mosquitto/passwd
acl_file /etc/mosquitto/acl

max_connections 1000
persistent_client_expiration 14d
CONF
```

### 2. CoAP协议安全评估

```bash
# CoAP (Constrained Application Protocol)
# 默认端口: UDP 5683 (不加密), UDP 5684 (DTLS加密)

# CoAP扫描
pip install aiocoap

# 使用aiocoap-client
aiocoap-client coap://192.168.1.100/.well-known/core

# CoAP资源发现
python3 << 'EOF'
import asyncio
from aiocoap import *

async def discover():
    protocol = await Context.create_client_context()
    request = Message(code=GET, uri='coap://192.168.1.100/.well-known/core')
    response = await protocol.request(request).response
    print(f"发现资源: {response.payload.decode()}")

asyncio.run(discover())
EOF

# CoAP安全基线
# 1. 使用DTLS加密 (coaps://)
# 2. 启用访问控制
# 3. 限制资源发现
# 4. 避免敏感信息在URI中
# 5. 实施速率限制
```

### 3. LoRaWAN安全评估

```bash
# LoRaWAN安全架构
# 两层加密:
# 1. Network Session Key (NwkSKey) - 网络层
# 2. Application Session Key (AppSKey) - 应用层

# LoRaWAN安全检查
# 1. OTAA vs ABP
#    OTAA (Over-the-Air Activation): ✅ 更安全
#    ABP (Activation by Personalization): ❌ 密钥静态

# 2. 检查Join-EUI和Dev-EUI
# 3. 检查AppKey生成
# 4. 检查帧计数器 (Frame Counter)

# LoRaWAN安全基线
# ✅ 使用OTAA activation
# ✅ 使用随机生成的AppKey (至少16字节)
# ✅ 启用帧计数器验证
# ✅ 使用加密自适应数据速率 (ADR)
# ❌ 避免使用ABP方式
# ❌ 避免使用默认AppKey
```

### 4. IoT协议安全对比

| 协议 | 传输层 | 加密 | 认证 | 默认端口 | 安全等级 |
|:---|:---:|:---:|:---:|:---:|:---:|
| MQTT 3.1.1 | TCP | TLS | Username/Password, Cert | 1883/8883 | ⭐⭐⭐ |
| MQTT 5.0 | TCP | TLS+ | Enhanced Auth | 1883/8883 | ⭐⭐⭐⭐ |
| CoAP | UDP | DTLS | Pre-Shared Key, Cert | 5683/5684 | ⭐⭐⭐ |
| HTTP/2 | TCP | TLS | OAuth, JWT | 443 | ⭐⭐⭐⭐ |
| AMQP | TCP | TLS | SASL, X.509 | 5671/5672 | ⭐⭐⭐⭐ |
| LoRaWAN | LoRa | AES-128 | AppKey | N/A | ⭐⭐⭐ |
| Zigbee | 802.15.4 | AES-128-CCM | Trust Center | N/A | ⭐⭐⭐ |
| Thread | 6LoWPAN | AES-128-CCM | DTLS | N/A | ⭐⭐⭐⭐ |

### 5. IoT通信安全基线清单

| # | 检查项 | 严重程度 | 验证方法 |
|:---:|:---|:---:|:---|
| 1 | MQTT匿名访问是否禁用 | 🔴 严重 | 尝试无密码连接 |
| 2 | TLS是否启用 | 🔴 严重 | 尝试非加密连接 |
| 3 | 默认凭证是否修改 | 🔴 严重 | 尝试admin/admin |
| 4 | MQTT ACL是否配置 | 🟠 高危 | 尝试订阅受限主题 |
| 5 | CoAP资源发现是否限制 | 🟠 高危 | 请求.well-known/core |
| 6 | MQTT $SYS主题是否保护 | 🟠 高危 | 尝试订阅$SYS |
| 7 | 客户端ID是否验证 | 🟡 中危 | 使用伪造client ID |
| 8 | 帧计数器是否启用 | 🟠 高危 | 发送重放消息 |
| 9 | 会话超时是否配置 | 🟡 中危 | 检查配置 |
| 10 | 速率限制是否启用 | 🟡 中危 | 压力测试 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| MQTT PWN | MQTT安全测试框架 | https://github.com/akamai/mqtt-pwn |
| MQTTSA | MQTT安全助手 | https://github.com/akamai/MQTTSA |
| aiocoap | CoAP Python库 | https://github.com/chrysn/aiocoap |
| Mosquitto | MQTT Broker | https://mosquitto.org/ |
| Wireshark | 协议分析 | https://www.wireshark.org/ |
| ChirpStack | LoRaWAN网络服务器 | https://www.chirpstack.io/ |

## 参考资源
- [MQTT Security Best Practices](https://www.hivemq.com/blog/mqtt-security-fundamentals/)
- [CoAP Security (RFC 7252)](https://datatracker.ietf.org/doc/html/rfc7252)
- [LoRaWAN Security](https://lora-alliance.org/about-lorawan/)
- [OWASP IoT Top 10](https://owasp.org/www-project-iot-top-10/)
- [NIST IR 8259 — IoT Device Cybersecurity Guidance](https://csrc.nist.gov/publications/detail/ir/8259/final)
