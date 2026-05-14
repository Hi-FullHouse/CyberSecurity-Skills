---
id: "15-007"
title: "🧠 内存取证分析 (Memory Forensics)"
category: "应急响应"
category_en: "Incident Response"
difficulty: "★★★★★"
tools: "Volatility, Rekall, LiME, Avml"
last_updated: "2025-07"
---
# 🧠 内存取证分析 (Memory Forensics)

## 概述
内存取证（Memory Forensics）是应急响应中最核心的技术之一。通过分析系统内存（RAM）中的运行进程、网络连接、加载模块和加密密钥等关键信息，发现无文件攻击（Fileless Malware）、Rootkit等传统磁盘取证难以检测的威胁。

## 核心技能

### 1. 内存获取

**⚠️ 重要原则：** 内存获取必须在系统运行状态下进行，获取后立即对镜像文件进行哈希校验以确保证据链完整。

#### Windows
```bash
# FTK Imager — 图形化工具，支持Live RAM捕获
# 下载: https://www.exterro.com/ftk-imager
# 操作: File → Capture Memory → 选择保存路径

# DumpIt — 简洁命令行工具
DumpIt.exe /Outfile=C:\incident\memory.dmp

# WinPmem — 开源内存采集
winpmem_mini_x64_rc2.exe C:\incident\memory.raw

# Magnet RAM Capture — 微软推荐
MagnetRAMCapture.exe C:\incident\memory.raw

# 计算哈希（取证链）
certutil -hashfile C:\incident\memory.raw SHA256 > C:\incident\memory.sha256
```

#### Linux
```bash
# LiME (Linux Memory Extractor) — 推荐使用
# 编译并加载内核模块
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src
make
insmod lime.ko "path=/tmp/mem.lime format=lime"

# FMEM — 另一种内存获取方式
insmod fmem.ko
dd if=/dev/fmem of=/tmp/memory.dd bs=1M

# 使用AVML (Microsoft开源)
./avml /tmp/memory.raw
```

### 2. Volatility 基础操作

```bash
# 安装 Volatility 3 (Python3版)
pip install volatility3

# 确认镜像信息（自动识别OS和Profile）
vol -f memory.raw windows.info

# Volatility 2 (传统版)
volatility -f memory.raw imageinfo  # 先识别建议Profile
```

### 3. 进程分析

```bash
# 列出进程（识别可疑进程）
# Volatility 3
vol -f memory.raw windows.pslist
vol -f memory.raw windows.psscan     # 含已终止和隐藏进程
vol -f memory.raw windows.pstree     # 树形显示进程关系

# Volatility 2
volatility -f memory.raw --profile=Win10x64 pslist
volatility -f memory.raw --profile=Win10x64 psscan
volatility -f memory.raw --profile=Win10x64 pstree

# 可疑进程识别要点：
# ● 父进程异常（如explorer.exe为svchost.exe父进程）
# ● 无父进程的进程
# ● 名称伪装（如svch0st.exe代替svchost.exe）
# ● 从临时目录运行的进程

# 查看进程命令行参数
vol -f memory.raw windows.cmdline

# 查看进程环境变量（含临时路径、恶意DLL搜索路径）
vol -f memory.raw windows.envars

# 检测进程注入（Cross Process Injection）
vol -f memory.raw windows.malfind
```

### 4. DLL与模块分析

```bash
# 列出进程加载的DLL
vol -f memory.raw windows.dlllist

# 检测隐藏/未链接的DLL
vol -f memory.raw windows.ldrmodules

# 检查DLL劫持
vol -f memory.raw windows.modscan  # 扫描所有内核模块

# 关注点：
# ● 从用户目录加载的DLL (%TEMP%, %APPDATA%)
# ● 伪装系统DLL名称但路径不对
# ● 签名信息异常（未签名/签名无效）
# ● 与正常基址偏移不一致
```

### 5. 网络连接分析

```bash
# 列出网络连接（活跃和已关闭）
vol -f memory.raw windows.netscan

# Volatility 2
volatility -f memory.raw --profile=Win10x64 netscan

# 常见指标：
# ● 通往已知恶意IP的C2连接
# ● 异常端口监听（如非标准端口上的Shell）
# ● 大量对外连接（数据外传）
# ● 使用Tor/I2P等匿名网络的连接

# 提取原始套接字信息
vol -f memory.raw windows.sockets
vol -f memory.raw windows.connections
```

### 6. 注册表分析

```bash
# 从内存中提取注册表信息
# 列出注册表hive
vol -f memory.raw windows.hivelist

# 提取特定注册表项
# 自动运行项（用于持久化分析）
vol -f memory.raw windows.printkey --key "Microsoft\Windows\CurrentVersion\Run"

vol -f memory.raw windows.printkey --key "Microsoft\Windows\CurrentVersion\RunOnce"

# 服务项分析
vol -f memory.raw windows.printkey --key "System\CurrentControlSet\Services"

# Shell启动项
vol -f memory.raw windows.printkey --key "Microsoft\Windows NT\CurrentVersion\Winlogon"
```

### 7. 恶意代码检测技术

```bash
# 1. malfind — 检测注入代码
vol -f memory.raw windows.malfind --dump

# 2. yarascan — YARA规则扫描
vol -f memory.raw windows.yarascan --yara-rules /path/to/rules.yar

# 3. 检测钩子
vol -f memory.raw windows.ssdt  # SSDT钩子（Rootkit）
vol -f memory.raw windows.idt   # IDT钩子

# 4. 检测内核模块
vol -f memory.raw windows.modscan | grep -i "rootkit\|hook\|hide"

# 5. 检测APC注入
vol -f memory.raw windows.apihooks  # API钩子检测

# 6. 提取可疑进程内存
vol -f memory.raw windows.memdump --pid <PID> --dump
```

### 8. Linux内存取证

```bash
# Linux特定Volatility插件
vol -f linux.mem linux.pslist
vol -f linux.mem linux.pstree
vol -f linux.mem linux.bash          # Bash历史记录
vol -f linux.mem linux.check_syslog  # 系统日志
vol -f linux.mem linux.check_afinfo  # 网络协议钩子
vol -f linux.mem linux.dmesg         # Dmesg输出

# 检测内核模块
vol -f linux.mem linux.lsmod

# 检测隐藏进程
vol -f linux.mem linux.psxview

# 网络连接
vol -f linux.mem linux.netstat
```

### 9. 取证时间线

```bash
# 构建事件时间线
vol -f memory.raw windows.timeliner

# 输出格式化（可选CSV/SQLite便于分析）
vol -f memory.raw windows.timeliner --output=csv > timeline.csv
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Volatility 3 | 内存取证框架 | https://github.com/volatilityfoundation/volatility3 |
| Volatility 2 | 内存取证（传统版） | https://github.com/volatilityfoundation/volatility |
| LiME | Linux内存获取 | https://github.com/504ensicsLabs/LiME |
| WinPmem | Windows内存获取 | https://github.com/Velocidex/WinPmem |
| Rekall | 内存取证（Google分支） | https://github.com/google/rekall |
| MemProcFS | 以文件系统形式查看内存 | https://github.com/ufrisk/MemProcFS |
| Redline | FireEye内存分析（免费） | https://fireeye.com/services/freeware/redline/ |

## 参考资源

- [Volatility 3 官方文档](https://volatility3.readthedocs.io/)
- [SANS FOR572 — Advanced Memory Forensics](https://www.sans.org/for572/)
- [13Cubed — Memory Forensics 视频教程](https://www.youtube.com/c/13Cubed)
- [The Art of Memory Forensics (书籍)](https://www.amazon.com/Art-Memory-Forensics-Detecting-Malware/dp/1118825098)
