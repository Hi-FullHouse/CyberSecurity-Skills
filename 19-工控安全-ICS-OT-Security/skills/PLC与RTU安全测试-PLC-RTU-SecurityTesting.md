---
id: 19-002
title: "🔧 PLC与RTU安全测试 (PLC & RTU Security Testing)"
category: 工控安全
category_en: "ICS/OT Security"
difficulty: ★★★★★
tools: "ISF (ICS Exploitation Framework), Metasploit, Industrial Exploitation Suite, C0br4.sh"
last_updated: 2025-07
tags: ["ics-security", "ot-security", "scada", "plc", "iec-62443", "industrial-security"]
subdomain: ics-ot-security
nist_csf: ["PR.AC-01", "PR.DS-07", "PR.PT-01"]
mitre_attack: ["T0843", "T0839", "T0881", "T0855"]
---
# 🔧 PLC与RTU安全测试 (PLC & RTU Security Testing)

## 概述
对可编程逻辑控制器(PLC)和远程终端单元(RTU)进行深入安全测试，包括固件分析、逻辑注入、Ladder Logic安全审查和物理接口安全评估。

## 核心技能

### 1. ICS Exploitation Framework (ISF)

```bash
# 安装ISF
git clone https://github.com/dark-labs/ISF.git
cd ISF
pip install -r requirements.txt

# 探索可用模块
python isf.py
# isf > show exploits
# isf > show scanners

# 扫描Siemens S7 PLC
python isf.py
# 使用扫描模块
use scanners/siemens_s7_scanner
set target 192.168.1.100
run

# S7-1200/1500漏洞利用
use exploits/siemens/s7_plc
set target 192.168.1.100
set slot 1
check
# ⚠️ 仅在授权环境下执行
run

# Modbus从站扫描
use scanner/modbus_scanner
set target 192.168.1.0/24
run
```

### 2. PLC固件分析

```bash
# 固件提取与解包
binwalk -e firmware.bin
binwalk -Me firmware.bin  # 递归扫描

# 分析固件中的文件系统
firmware-mod-kit/extract-firmware.sh firmware.bin

# 检查固件中的硬编码凭证
strings firmware.bin | grep -iE "password|secret|key|admin|user"
strings firmware.bin | grep -iE "pass|pwd|login"

# 检查固件版本和已知漏洞
strings firmware.bin | grep -iE "version|firmware|build"
# 对比CVE数据库

# 使用Ghidra进行固件逆向
# 1. 导入固件为原始二进制
# 2. 识别处理器架构 (通常为ARM/ARC/MIPS)
# 3. 查找安全关键函数 (访问控制、密码验证)

# 使用Firmadyne仿真
git clone https://github.com/firmadyne/firmadyne.git
cd firmadyne
./setup.sh
./run.sh -i firmware.bin -q
```

### 3. Ladder Logic安全审查

```bash
# 连接PLC读取逻辑
# Siemens TIA Portal - 在线访问
# 使用s7client读取S7 PLC块
pip install python-snap7

python3 << 'EOF'
import snap7

plc = snap7.client.Client()
plc.connect('192.168.1.100', 0, 2)  # IP, rack, slot

# 读取DB块
db_data = plc.db_read(1, 0, 100)  # DB1, 偏移0, 长度100
print(f"DB1 Data: {db_data}")

# 读取系统信息
cpu_info = plc.get_cpu_info()
print(f"CPU Info: {cpu_info.ModuleTypeName}")

# 检查保护级别
protection = plc.get_protection()
print(f"Protection: {protection}")

# 检查CPU状态
cpu_status = plc.get_cpu_state()
print(f"CPU State: {cpu_status}")

plc.disconnect()
EOF

# Ladder Logic审计清单
# ✅ 是否使用安全功能块(如西门子Safety Matrix)
# ✅ 紧急停止逻辑是否硬件触发
# ✅ 关键输出是否有互锁条件
# ❌ 是否存在可远程触发的危险操作
# ❌ 是否存在未保护的在线修改通道
```

### 4. 物理接口攻击面

```text
PLC/RTU物理接口安全
┌─────────────────────────────────────────────┐
│ 接口类型     │ 攻击面               │ 防护  │
├──────────────┼──────────────────────┼───────┤
│ Ethernet     │ Modbus/DNP3未认证    │ 网络隔离│
│ Serial(RS232)│ 控制台访问           │ 物理锁 │
│ USB端口      │ 固件上传/逻辑注入    │ 禁用   │
│ SD卡槽       │ 固件替换             │ 密封   │
│ 调试接口(JTAG)│ 固件提取/逆向        │ 禁用JTAG│
│ 数字I/O      │ 物理信号注入         │ 光隔离 │
│ 拨码开关     │ 配置篡改             │ 密封保护│
└─────────────────────────────────────────────┘
```

### 5. 常见PLC漏洞类型

| 漏洞类型 | 受影响PLC | CVE示例 | CVSS评分 |
|:---|:---|:---:|:---:|
| 硬编码凭证 | Allen-Bradley ControlLogix | CVE-2020-6995 | 9.8 |
| 拒绝服务 | Siemens S7-1200 | CVE-2021-31800 | 7.5 |
| 认证绕过 | Schneider Modicon | CVE-2021-22776 | 8.1 |
| 远程代码执行 | Rockwell MicroLogix | CVE-2020-6994 | 9.8 |
| 信息泄露 | Omron NJ/NX | CVE-2021-27504 | 5.3 |
| 逻辑篡改 | Mitsubishi MELSEC | CVE-2020-16862 | 7.5 |
| 固件降级 | Delta DVP | CVE-2021-22818 | 6.5 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| ISF (ICS Exploitation Framework) | 工控漏洞利用框架 | https://github.com/dark-labs/ISF |
| Metasploit (ICS模块) | 通用利用框架 | https://github.com/rapid7/metasploit-framework |
| python-snap7 | S7协议客户端 | https://github.com/gijzelaerr/python-snap7 |
| Binwalk | 固件分析 | https://github.com/ReFirmLabs/binwalk |
| Firmadyne | 固件仿真 | https://github.com/firmadyne/firmadyne |
| OpenPLC | PLC测试平台 | https://www.openplcproject.com/ |

## 参考资源
- [IEC 62443-4-2 — Component Security](https://www.iec.ch/standards/62443)
- [ICS-CERT Advisories](https://www.cisa.gov/ics)
- [Kaspersky ICS CERT](https://ics-cert.kaspersky.com/)
- [Dragos ICS Vulnerability Database](https://www.dragos.com/vulnerability-database/)
- [SANS ICS Defense Resources](https://www.sans.org/ics-security/)
