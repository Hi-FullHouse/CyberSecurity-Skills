---
id: 21-004
title: "⚙️ 嵌入式设备硬件安全测试 (Embedded Hardware Security)"
category: 物联网安全
category_en: "IoT Security"
difficulty: ★★★★★
tools: "JTAGulator, OpenOCD, Saleae Logic, Bus Pirate, ChipWhisperer"
last_updated: 2025-07
tags: ["iot-security", "firmware", "embedded", "ble", "zigbee", "hardware-security"]
subdomain: iot-security
nist_csf: ["PR.AC-01", "PR.DS-03", "PR.PT-01"]
mitre_attack: ["T1465", "T1559", "T1524"]
---
# ⚙️ 嵌入式设备硬件安全测试 (Embedded Hardware Security)

## 概述
对物联网嵌入式硬件进行物理安全评估，涵盖JTAG/SWD调试接口测试、UART串口攻击、SPI/I2C总线窃听和侧信道攻击分析。

## 核心技能

### 1. 硬件接口识别与攻击

```text
常见硬件调试接口
┌──────────────────────────────────────────────────────┐
│ 接口    │ 电压  │ 协议           │ 用途               │
├─────────┼───────┼────────────────┼───────────────────┤
│ JTAG    │ 3.3V  │ IEEE 1149.1   │ CPU调试/编程       │
│ SWD     │ 3.3V  │ ARM Serial Wire│ ARM调试            │
│ UART    │ 3.3V  │串行(115200,8N1)│ 控制台/Bootloader  │
│ SPI     │ 3.3V  │同步串行        │ Flash/传感器       │
│ I2C     │ 3.3V  │ I2C总线        │ 传感器/EEPROM      │
│ USB     │ 5V    │ USB 2.0/3.0   │ 固件更新/数据     │
└──────────────────────────────────────────────────────┘

JTAG引脚识别
┌───────────────────────────────────────────┐
│ 引脚  │ 信号        │ 颜色(常见)          │
├───────┼─────────────┼────────────────────┤
│ 1     │ VREF (3.3V) │ 红色/橙色          │
│ 2     │ GND         │ 黑色               │
│ 3     │ TMS/SWDIO   │ 黄色               │
│ 4     │ TCK/SWCLK   │ 蓝色               │
│ 5     │ TDO/SWO     │ 绿色               │
│ 6     │ TDI         │ 紫色               │
│ 7-20  │ GND         │ 黑色               │
└───────────────────────────────────────────┘
```

### 2. JTAG/SWD调试接口测试

```bash
# 使用JTAGulator识别JTAG引脚
# 连接JTAGulator到目标设备
# 通过串口连接到JTAGulator
screen /dev/ttyUSB0 115200

# JTAGulator菜单
# 1. 选择电压 (3.3V)
# 2. IDCODE扫描 - 识别JTAG TAP
# 3. BYPASS扫描 - 确认TCK连接
# 4. Pin映射

# 使用OpenOCD访问JTAG
# openocd.cfg
cat << 'OCD' > openocd.cfg
source [find interface/jlink.cfg]
transport select jtag
source [find target/stm32f4x.cfg]

# JTAG安全操作
# 1. 尝试halt CPU
# 2. 读取Flash内容
# 3. 读取option bytes
# 4. 解除Flash读保护
OCD

# 运行OpenOCD
openocd -f openocd.cfg

# 在telnet中操作
telnet localhost 4444
# halt
# flash read_bank 0 firmware.bin
# flash protect 0 0 0 off
# flash erase_address 0x08000000 0x10000
```

### 3. UART串口攻击

```bash
# UART引脚识别
# 使用逻辑分析仪 (Saleae Logic)
# 连接通道到UART引脚
# 采样率: 1MHz+
# 触发: 检测UART启动位

# 使用Bus Pirate
# 连接到Bus Pirate
screen /dev/ttyUSB0 115200

# Bus Pirate命令
# m  # 选择模式
# 3  # UART模式
# 115200  # 波特率
# 8  # 数据位
# 1  # 停止位
# n  # 无校验
# (3) # 接收数据

# 常见波特率枚举
for baud in 9600 19200 38400 57600 115200 230400 460800 921600; do
    stty -F /dev/ttyUSB0 $baud cs8 -cstopb -parenb
    echo -n "$baud: "
    timeout 1 cat /dev/ttyUSB0 2>/dev/null
    echo
done

# 使用UART进入Bootloader
# 通常: 上电时按住某个按键会进入Bootloader
# 或发送特定break信号

# Bootloader提取固件
# 使用xmodem/ymodem传输
# 或通过UART console导出
```

### 4. 侧信道攻击

```bash
# 使用ChipWhisperer进行侧信道分析
pip install chipwhisperer

# 简单功率分析 (SPA)
import chipwhisperer as cw
scope = cw.scope()
target = cw.target(scope, cw.targets.SimpleSerial)

# 捕获功率轨迹
scope.adc.samples = 10000
scope.clock.clkgen_freq = 7.37e6
scope.trigger.triggers = "rising"
scope.trigger.triggers = "tio4"

# 捕获AES加密的功率轨迹
target.simpleserial_write('k', key)
target.simpleserial_write('p', plaintext)
ret = scope.capture()
trace = scope.adc.read()

# 差分功率分析 (DPA)
# 需要多次捕获
traces = []
for i in range(1000):
    plaintext = random_bytes(16)
    target.simpleserial_write('p', plaintext)
    scope.capture()
    traces.append(scope.adc.read())

# 使用Pyside进行电磁攻击
# 需要: 电磁探头 + 放大器
# 使用示波器或ADC采集电磁信号
```

### 5. 硬件安全加固基线

| # | 防护措施 | 效果 | 实施难度 |
|:---:|:---|:---:|:---:|
| 1 | JTAG/SWD熔丝编程(读保护) | ✅ 禁止调试接口读取Flash | 低(烧录时设置) |
| 2 | Flash加密存储 | ✅ 即使读出也无法解析 | 中(需要BootROM支持) |
| 3 | 禁用UART控制台 | ✅ 防止串口入侵 | 低(kernel config) |
| 4 | 移除调试焊盘 | ✅ 物理防护 | 高(PCB redesign) |
| 5 | 安装防篡改检测 | ✅ 打开即擦除密钥 | 高(硬件设计) |
| 6 | BGA封装(替代QFP) | ✅ 增加探测难度 | 高(制造成本) |
| 7 | 环氧树脂封装 | ✅ 保护芯片/线 | 中(生产工序) |
| 8 | Secure Boot | ✅ 验证启动代码 | 中(需ROM支持) |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| JTAGulator | JTAG引脚识别 | https://www.adafruit.com/product/1554 |
| OpenOCD | JTAG/SWD调试器 | https://openocd.org/ |
| Saleae Logic | 逻辑分析仪 | https://www.saleae.com/ |
| Bus Pirate | 多协议硬件工具 | https://buspirate.com/ |
| ChipWhisperer | 侧信道分析平台 | https://chipwhisperer.io/ |
| GlitchKit | 故障注入工具 | https://glitchkit.io/ |

## 参考资源
- [Hardware Hacking Handbook](https://nostarch.com/hardwarehacking)
- [JTAG Explained](https://blog.senr.io/apps/jtag.html)
- [OWASP IoT Testing Guide — Hardware](https://owasp.org/www-project-iot-security-testing-guide/)
- [NIST SP 800-193 — Platform Firmware Resiliency](https://csrc.nist.gov/publications/detail/sp/800-193/final)
- [Embedded Security — ChipWhisperer Docs](https://chipwhisperer.readthedocs.io/)
