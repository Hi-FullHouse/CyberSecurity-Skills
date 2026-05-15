---
id: 21-006
title: "🏠 智能家居与车联网安全 (Smart Home & Connected Vehicle Security)"
category: 物联网安全
category_en: "IoT Security"
difficulty: ★★★★
tools: "Home Assistant, CANtact, UDSim, ICSim, OpenVehicles"
last_updated: 2025-07
tags: ["iot-security", "firmware", "embedded", "ble", "zigbee", "hardware-security"]
subdomain: iot-security
nist_csf: ["PR.AC-01", "PR.DS-03", "PR.PT-01"]
mitre_attack: ["T1465", "T1559", "T1524"]
---
# 🏠 智能家居与车联网安全 (Smart Home & Connected Vehicle Security)

## 概述
评估智能家居生态系统和车联网系统的安全性，包括智能家电漏洞分析、Matter协议安全、CAN总线测试和OBD-II安全评估。

## 核心技能

### 1. 智能家居安全评估

```bash
# 智能家居攻击面
# 1. 本地网络: 智能设备扫描
nmap -sn 192.168.1.0/24  # 发现设备
nmap -sV -T4 -A 192.168.1.50-100  # 服务扫描
sudo arp-scan --local  # ARP扫描

# 2. UPnP发现
# 扫描UPnP服务
pip install upnpclient
python3 << 'EOF'
import upnpclient
devices = upnpclient.discover()
for dev in devices:
    print(f"Device: {dev.friendly_name}")
    print(f"  Services: {[s.name for s in dev.services]}")
EOF

# 3. 智能音箱监听
# 检查智能音箱的Web服务器
nmap -p 80,443,8000,8080,8443 <smart-speaker-ip>
# 检查mDNS服务
sudo avahi-browse -all

# 4. Zigbee/Z-Wave集线器检查
# 集线器通常运行嵌入式Linux
# 尝试默认SSH凭证 (root/root, admin/admin)
ssh root@<hub-ip>
```

### 2. Matter协议安全

```text
Matter (原CHIP) 安全架构
┌──────────────────────────────────────────────────────┐
│ 安全层      │ 说明                    │ 机制          │
├─────────────┼─────────────────────────┼──────────────┤
│ 设备认证     │ 认证设备合法性          │ DAC (Device    │
│             │                          │ Attestation   │
│             │                          │ Certificate)  │
├─────────────┼─────────────────────────┼──────────────┤
│ 通信加密     │ 数据加密传输            │ CASE (Cert    │
│             │                          │ Auth Session  │
│             │                          │ Establishment)│
├─────────────┼─────────────────────────┼──────────────┤
│ 访问控制     │ 细粒度权限控制          │ ACL (Access   │
│             │                          │ Control List) │
├─────────────┼─────────────────────────┼──────────────┤
│ 固件更新     │ 安全OTA                │ 代码签名验证  │
└──────────────────────────────────────────────────────┘

Matter安全检查清单:
[ ] 使用Test-Event安全证书 (非生产)
[ ] Matter DAC未过期
[ ] ACL配置正确 (最小权限)
[ ] Thread网络密钥非默认
[ ] 调试模式在生产设备禁用
[ ] mDNS服务信息过滤
```

### 3. CAN总线安全测试

```bash
# 车辆CAN总线测试
# 硬件: CANtact, USBtin, etc.

# 使用SocketCAN (Linux)
sudo modprobe can
sudo modprobe can-raw
sudo ip link set can0 type can bitrate 500000
sudo ip link set can0 up

# 使用can-utils
# 监听CAN总线
candump can0

# 发送CAN帧
cansend can0 7DF#02010C0000000000  # OBD-II请求

# 过滤特定ID
candump can0,0x7E8:0xFFF  # 仅接收响应

# 使用Python
pip install python-can

python3 << 'EOF'
import can

bus = can.interface.Bus(channel='can0', bustype='socketcan')

# 发送诊断请求
msg = can.Message(
    arbitration_id=0x7DF,
    data=[0x02, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00],  # RPM请求
    is_extended_id=False
)
bus.send(msg)

# 监听响应
for msg in bus:
    if msg.arbitration_id == 0x7E8:
        print(f"Response: {msg.data.hex()}")
EOF

# 使用ICSim模拟CAN总线
git clone https://github.com/zombieCraig/ICSim.git
cd ICSim
make
./icsim vcan0  # 启动仪表盘模拟
./controls vcan0  # 控制模拟

# CAN总线攻击模拟
# 1. 伪造车速显示
cansend vcan0 0x244#032F000000000000  # 设置速度

# 2. 伪造仪表盘指示灯
cansend vcan0 0x245#0100000000000000  # 开启检查引擎灯
```

### 4. OBD-II安全评估

```bash
# OBD-II接口安全风险
# 1. OBD-II dongle不安全的蓝牙连接
# 2. OBD-II设备的固定PIN码
# 3. 通过OBD-II的CAN总线攻击

# 蓝牙OBD-II扫描
sudo hcitool scan  # 发现OBD-II蓝牙设备
# 常见OBD-II蓝牙: "OBDII", "ELM327", "Vgate"

# 尝试默认连接PIN
# 1234, 0000, 6789 (ELM327常见默认)

# 蓝牙OBD-II连接测试
sudo rfcomm connect 0 <MAC> 1 &
# 成功后: /dev/rfcomm0

# 连接到OBD-II
picocom /dev/rfcomm0 -b 38400
# 发送AT命令
# ATZ - 重置
# ATSP0 - 自动选择协议
# 010C - 请求RPM

# OBD-II WiFi扫描
nmap -p 35000 192.168.0.0/24  # ELM327 WiFi设备
# 默认IP通常为 192.168.0.10
```

### 5. 车联网安全基线

| # | 安全项 | 严重程度 | 修复建议 |
|:---:|:---|:---:|:---:|
| 1 | OBD-II端口未加锁 | 🔴 严重 | 使用OBD-II锁或安全盖 |
| 2 | CAN总线无认证 | 🔴 严重 | 实施CAN-FD安全消息认证 |
| 3 | 蓝牙OBD-II默认PIN | 🟠 高危 | 修改为随机PIN |
| 4 | 远程解锁漏洞 | 🔴 严重 | 实施端到端加密+挑战-响应 |
| 5 | 智能家居设备默认密码 | 🔴 严重 | 强制修改默认密码 |
| 6 | Matter设备使用测试证书 | 🟠 高危 | 使用生产PCA签发的DAC |
| 7 | UPnP端口暴露 | 🟡 中危 | 禁用WAN端UPnP |
| 8 | 本地API未授权 | 🔴 严重 | 实施本地认证 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| ICSim | CAN总线模拟器 | https://github.com/zombieCraig/ICSim |
| CANtact | CAN总线工具 | https://cantact.io/ |
| can-utils | CAN工具集 | https://github.com/linux-can/can-utils |
| Home Assistant | 智能家居平台 | https://www.home-assistant.io/ |
| OpenVehicles | 电动车监控 | https://openvehicles.com/ |
| UDSim | UDS协议模拟 | https://github.com/akira215/uds-c |

## 参考资源
- [Matter Security Fundamentals](https://csa-iot.org/all-solutions/matter/)
- [CAN bus Security Research](https://labs.f-secure.com/blog/)
- [Car Hacking: Defense in Depth](https://www.sans.org/white-papers/)
- [OWASP IoT Smart Home Security](https://owasp.org/www-project-iot-security-testing-guide/)
- [SAE J3061 — Automotive Cybersecurity](https://www.sae.org/standards/content/j3061_201601/)
