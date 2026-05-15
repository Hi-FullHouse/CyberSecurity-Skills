---
id: 21-002
title: "📶 BLE/Zigbee/Z-Wave无线安全测试 (Wireless Protocol Security Testing)"
category: 物联网安全
category_en: "IoT Security"
difficulty: ★★★★
tools: "BLEAH, GATTool, Z3sec, HackRF, BetterCAP, Ubertooth"
last_updated: 2025-07
tags: ["iot-security", "firmware", "embedded", "ble", "zigbee", "hardware-security"]
subdomain: iot-security
nist_csf: ["PR.AC-01", "PR.DS-03", "PR.PT-01"]
mitre_attack: ["T1465", "T1559", "T1524"]
---
# 📶 BLE/Zigbee/Z-Wave无线安全测试 (Wireless Protocol Security Testing)

## 概述
对物联网设备最常用的三种无线协议（BLE、Zigbee、Z-Wave）进行全面的安全测试和评估。

## 核心技能

### 1. BLE (Bluetooth Low Energy) 安全测试

```bash
# 使用BLEAH进行BLE设备侦察
pip install bleson bluepy

# 扫描BLE设备
sudo hcitool lescan
# 或使用BLEAH
sudo python3 -m blescan

# 使用GATTool连接和枚举服务
gatttool -b <MAC> -t random -I
# [CONNECTED]
# primary  # 列出主要服务
# characteristics  # 列出特征值

# 使用BlueZ工具
bluetoothctl
# scan on
# devices
# connect <MAC>
# menu gatt
# list-attributes
# select-attribute <handle>

# 读取未保护的特性
gatttool -b <MAC> -t random --char-read -a 0x0003

# BLE嗅探
# 使用Ubertooth One
ubertooth-btle -f -c capture.pcap

# 使用Wireshark分析
wireshark -r capture.pcap

# 使用BTLEJack进行BLE劫持
git clone https://github.com/virtualabs/btlejack.git
cd btlejack
pip install -r requirements.txt

# 扫描BLE连接
sudo btlejack -s

# 嗅探BLE连接
sudo btlejack -f -c <access_address> -d
```

### 2. Zigbee安全测试

```bash
# Zigbee协议基础
# 频段: 2.4GHz (全球), 915MHz (美国), 868MHz (欧洲)
# 安全: AES-128-CCM * 默认安全
# 信任中心: 网络密钥分发

# 使用Z3sec Zigbee安全测试
git clone https://github.com/attify/z3sec.git
cd z3sec
pip install -r requirements.txt

# 扫描Zigbee网络
python z3sec.py -sniff -c 11 -o capture.pcap

# Zigbee密钥提取
python z3sec.py -extract-keys -c capture.pcap

# 使用KillerBee框架
git clone https://github.com/riverloopsec/killerbee.git
cd killerbee
pip install -r requirements.txt

# ZB适配器扫描
sudo zbid

# 网络发现
sudo zbstumbler -c 11

# 包捕获
sudo zbdump -c 11 -w zigbee_capture.pcap

# 解析捕获
zbreplay -f zigbee_capture.pcap -l | grep -i "key\|password\|token"

# Zigbee安全检查
# 检查是否使用默认网络密钥
# Zigbee默认key: ZLL (Zigbee Light Link): 全零
#                          HA (Home Automation): 厂商自定义
```

### 3. Z-Wave安全测试

```bash
# Z-Wave协议基础
# 频段: 908.42MHz (US), 868.42MHz (EU)
# 安全: S0, S2 (Security 2 更安全)
# 拓扑: Mesh网络

# Z-Wave PC Controller
# Windows: Z-Wave PC Controller

# Z-Wave S0 vs S2对比
# S0: 单钥匙加密, 节点间共享
# S2: 双向认证, 每节点单独密钥

# Z-Wave S0攻击 (已知漏洞)
# 1. 捕获网络包含过程
# 2. 提取网络密钥(支持TrueZT)
# 3. 解密所有通信

# 使用HackRF捕获Z-Wave
hackrf_transfer -r zwave_capture.iq -f 908420000 -s 2000000

# 使用GnuRadio解调
# ... (参考gnuradio Z-Wave解调教程)
```

### 4. 无线协议安全对比

| 特性 | BLE | Zigbee | Z-Wave | Wi-Fi (IoT) |
|:---|:---:|:---:|:---:|:---:|
| 加密 | AES-128-CCM | AES-128-CCM | AES-128-GCM/S0/S2 | WPA2/WPA3 |
| 认证 | Pairing Bonding | Trust Center | S2认证 | WPA-PSK/EAP |
| 默认安全等级 | 低(Join Without Auth) | 中(Network Key) | 中(S0) →高(S2) | 高(WPA3) |
| 已知攻击 | MITM, Eavesdrop | Key Extraction | Key Extraction | 暴力破解 |
| 配对安全 | Just Works(弱) | Out-of-Band | PIN输入 | QR/按钮 |
| 嗅探距离 | ~100m | ~100m | ~100m | ~300m |
| 重放攻击防护 | 随机地址 | Frame Counter | Nonce | 802.11w |

### 5. 无线攻击防护建议

| 攻击类型 | 防护建议 | 优先级 |
|:---|:---|:---:|
| BLE Just Works配对劫持 | 使用OOB或Passkey Entry配对 | 🔴 紧急 |
| Zigbee默认网络密钥 | 修改为随机生成的网络密钥 | 🔴 紧急 |
| Z-Wave S0密钥提取 | 升级支持S2的设备 | 🟠 重要 |
| Sniffing嗅探 | 所有无线通信必须AES-128加密 | 🔴 紧急 |
| Replay重放攻击 | 使nonce/frame counter | 🔴 紧急 |
| Deauth攻击 | 使用802.11w管理帧保护(Wi-Fi) | 🟡 推荐 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| BLEAH | BLE安全测试框架 | https://github.com/BAH-LE/BLEAH |
| Ubertooth | BLE嗅探器 | https://github.com/greatscottgadgets/ubertooth |
| Z3sec | Zigbee安全测试 | https://github.com/attify/z3sec |
| KillerBee | Zigbee攻击框架 | https://github.com/riverloopsec/killerbee |
| HackRF | SDR平台 | https://greatscottgadgets.com/hackrf/ |
| BetterCAP | 网络攻击框架 | https://www.bettercap.org/ |

## 参考资源
- [BLE Security Best Practices](https://www.bluetooth.com/specifications/specs/core-specification/)
- [Zigbee Security Specification](https://csa-iot.org/all-solutions/zigbee/)
- [Z-Wave Security Specification](https://www.z-wave.com/security)
- [MITRE ATT&CK — IoT & Embedded](https://attack.mitre.org/matrices/enterprise/ics/)
- [OWASP IoT Testing Guide — Wireless](https://owasp.org/www-project-iot-security-testing-guide/)
