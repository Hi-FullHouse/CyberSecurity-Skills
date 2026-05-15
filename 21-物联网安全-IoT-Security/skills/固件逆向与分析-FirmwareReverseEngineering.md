---
id: 21-001
title: "🔧 固件逆向与分析 (Firmware Reverse Engineering)"
category: 物联网安全
category_en: "IoT Security"
difficulty: ★★★★★
tools: "Binwalk, Firmadyne, Ghidra, QEMU, GDB, JTAGulator"
last_updated: 2025-07
tags: ["iot-security", "firmware", "embedded", "ble", "zigbee", "hardware-security"]
subdomain: iot-security
nist_csf: ["PR.AC-01", "PR.DS-03", "PR.PT-01"]
mitre_attack: ["T1465", "T1559", "T1524"]
---
# 🔧 固件逆向与分析 (Firmware Reverse Engineering)

## 概述
系统化地对物联网设备固件进行逆向分析，包括固件提取、文件系统分析、架构识别、漏洞发现和后门检测。

## 核心技能

### 1. 固件提取与分析

```bash
# 使用Binwalk分析固件
binwalk firmware.bin  # 扫描文件签名
binwalk -Me firmware.bin  # 递归解包
binwalk -D 'png:raw' firmware.bin  # 提取特定类型

# 详细分析
binwalk -B firmware.bin  # 字节熵分析
binwalk -A firmware.bin  # CPU架构识别
binwalk -W firmware.bin  # 文件类型统计

# 使用Firmadyne进行固件仿真
git clone https://github.com/firmadyne/firmadyne.git
cd firmadyne
./setup.sh

# 添加固件并提取文件系统
./scripts/extract.sh firmware.bin <firmware-id>
# 创建网络配置
./scripts/makeNetwork.py -i <firmware-id>
# 运行仿真
./scripts/run.sh <firmware-id>

# 使用QEMU仿真特定架构固件
# ARM
qemu-system-arm -M virt -kernel vmlinuz -initrd initrd.img -append "console=ttyAMA0" -nographic

# MIPS
qemu-system-mips -M malta -kernel vmlinux -initrd initrd.img -append "console=ttyS0" -nographic
```

### 2. 固件漏洞分析

```bash
# 硬编码凭证检测
grep -r "password" extracted_fs/
grep -r "secret" extracted_fs/
grep -rP "[A-Za-z0-9+/]{20,}={0,2}" extracted_fs/  # Base64

# 检查后端URL/api端点
grep -r "http" extracted_fs/ | grep -v "http_parser\|mhttpd\|libhttp"

# 检查证书和私钥
find extracted_fs/ -name "*.pem" -o -name "*.key" -o -name "*.cert" -o -name "*.p12"

# 检查调试接口
grep -r "debug\|telnet\|gdb\|gdbserver" extracted_fs/

# 检查配置文件
find extracted_fs/ -name "*.conf" -o -name "*.cfg" -o -name "*.ini"

# 检查初始化脚本
ls extracted_fs/etc/init.d/
cat extracted_fs/etc/inittab

# 检查Web界面漏洞
# 检查硬编码会话密钥
grep -r "session\|token\|secret" extracted_fs/www/

# 使用Ghidra进行深度逆向
# 1. 导入固件 (选择CPU架构)
# 2. 定位entry函数
# 3. 分析密码验证逻辑
# 4. 查找backdoor函数
```

### 3. 固件安全基线

| # | 检查项 | 严重程度 | 修复建议 |
|:---:|:---|:---:|:---|
| 1 | 硬编码凭证(密码/令牌) | 🔴 严重 | 移除硬编码,使用配置文件或HSM |
| 2 | 未加密固件存储 | 🟠 高危 | 固件加密存储+签名验证 |
| 3 | 调试接口(GDB/telnet)开放 | 🔴 严重 | 生产固件禁用调试接口 |
| 4 | 嵌入式私钥/证书 | 🟠 高危 | 使用TPM/SE存储私钥 |
| 5 | 硬编码API端点/密钥 | 🟠 高危 | 使用OTA更新配置 |
| 6 | 未签名固件更新 | 🔴 严重 | 实现固件签名+验证 |
| 7 | 敏感信息在日志中 | 🟡 中危 | 日志过滤敏感信息 |
| 8 | 缓冲区溢出漏洞 | 🔴 严重 | 使用安全编译选项(-fstack-protector) |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Binwalk | 固件分析工具 | https://github.com/ReFirmLabs/binwalk |
| Firmadyne | 固件仿真平台 | https://github.com/firmadyne/firmadyne |
| Ghidra | 逆向工程框架 | https://ghidra-sre.org/ |
| QEMU | 全系统仿真器 | https://www.qemu.org/ |
| Firmwalker | 固件扫描脚本 | https://github.com/craigz28/firmwalker |

## 参考资源
- [Embedded Security CTF Challenges](https://microcorruption.com/)
- [NIST SP 800-193 — Platform Firmware Resiliency](https://csrc.nist.gov/publications/detail/sp/800-193/final)
- [OWASP IoT Firmware Security](https://owasp.org/www-project-iot-security-testing-guide/)
- [Attify — IoT Security Training](https://www.attify.com/)
