---
id: "30-002"
title: "内存取证分析 (Memory Forensics with Volatility)"
category: "数字取证"
category_en: "Digital Forensics"
difficulty: "★★★★"
tools: "Volatility 3, Volatility 2, LiME, WinPmem, FTK Imager, Rekall, YARA"
last_updated: "2026-05"
tags: [forensics, memory-analysis, volatility, ram, malware-analysis]
subdomain: digital-forensics
nist_csf: [DE.AE-02, DE.AE-05, RS.AN-01]
mitre_attack: [T1003, T1055, T1071, T1564]
---

# 内存取证分析 (Memory Forensics with Volatility)

## 概述

内存取证是数字取证和事件响应（DFIR）的核心技术。攻击者留下的恶意代码和证据通常在内存中，而不会写入磁盘。本技能覆盖内存获取、Volatility 插件使用、进程分析、网络连接恢复、Rootkit 检测和恶意代码提取。

## 核心技能

### 1. 内存获取

**⚠️ 重要原则：** 内存获取必须在系统运行状态下进行，获取后立即对镜像文件进行哈希校验以确保证据链完整。

```bash
# LiME — Linux 内存获取
# 编译 LiME 内核模块
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src
make
# 输出: lime-$(uname -r).ko

# 获取内存并保存为 raw 格式
sudo insmod lime-$(uname -r).ko \
  "path=/evidence/memory.lime format=raw"

# LiME 格式选项
# format=raw: 原始内存转储（Volatility 推荐）
# format=lime: 压缩格式（带元数据）
# format=padded: 对齐填充格式

# FMEM — 另一种 Linux 内存获取方式
sudo insmod fmem.ko
sudo dd if=/dev/fmem of=/tmp/memory.dd bs=1M

# AVML (Microsoft 开源)
sudo ./avml /tmp/memory.raw
```

```bash
# Windows 内存获取 — WinPmem
# 下载 WinPmem
# https://github.com/veler/winpmem

# 获取内存（AFF4 格式）
winpmem_mini.exe C:\Evidence\memory.raw

# 获取内存（原始格式）
winpmem_mini.exe --format raw -o C:\Evidence\memory.raw

# 使用无文件获取（避免写入磁盘）
winpmem_mini.exe --format raw | nc forensic-server 9999

# FTK Imager — 图形化工具，支持 Live RAM 捕获
# 操作: File → Capture Memory → 选择保存路径

# DumpIt — 简洁命令行工具
DumpIt.exe /Outfile=C:\incident\memory.dmp

# Magnet RAM Capture — 微软推荐
MagnetRAMCapture.exe C:\incident\memory.raw

# 计算哈希（取证链）
certutil -hashfile C:\incident\memory.raw SHA256 > C:\incident\memory.sha256
```

```bash
# 虚拟机内存获取
# VMware: 挂起虚拟机时 .vmem 文件
# Hyper-V: .bin 和 .vmrs 文件
# VirtualBox: .sav 和 .vmem 文件
```

### 2. Volatility 基础使用

```bash
# Volatility 3 安装
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install

# Volatility 2 安装
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python2 setup.py install

# Volatility 3 — 基本信息
python3 vol.py -f memory.raw windows.info

# Volatility 2 — 基本信息
python2 vol.py -f memory.raw imageinfo
# 建议: 首先运行 imageinfo 确定 OS/Profile

# 设置 Profile（Volatility 2）
python2 vol.py -f memory.raw --profile=Win10x64_19041 [plugin]

# Volatility 3 自动检测操作系统（无需指定 profile）
python3 vol.py -f memory.raw windows.info
```

### 3. 进程分析

```bash
# 列出进程（Volatility 3）
python3 vol.py -f memory.raw windows.pslist

# 列出进程（Volatility 2）
python2 vol.py -f memory.raw --profile=Win10x64 pslist

# 进程树（检测父进程异常）
python3 vol.py -f memory.raw windows.pstree

# Volatility 2 进程树
python2 vol.py -f memory.raw --profile=Win10x64 pstree

# 隐藏进程检测
python3 vol.py -f memory.raw windows.psxview
python2 vol.py -f memory.raw --profile=Win10x64 psxview

# 进程命令行参数
python3 vol.py -f memory.raw windows.cmdline

# 查看进程环境变量（含临时路径、恶意DLL搜索路径）
python3 vol.py -f memory.raw windows.envars

# DLL 列表
python3 vol.py -f memory.raw windows.dlllist --pid 1234

# 进程内存转储
python3 vol.py -f memory.raw windows.dumpfiles --pid 1234
python2 vol.py -f memory.raw --profile=Win10x64 memdmp --pid 1234 -D processes/

# 恶意进程检测特征
# 1. 无父进程的进程
# 2. 从临时目录运行的进程
# 3. 可疑的进程名（svch0st.exe vs svchost.exe）
# 4. 隐藏进程（pslist 看不到但 psxview 看到）
# 5. 没有对应可执行文件的进程
# 6. 父进程异常（如 explorer.exe 为 svchost.exe 父进程）
```

### 4. 网络与注册表分析

```bash
# 网络连接（Volatility 3）
python3 vol.py -f memory.raw windows.netscan

# 网络连接（Volatility 2）
python2 vol.py -f memory.raw --profile=Win10x64 netscan
# netscan 适用于 Win 7+，XP 使用 connscan

# 列出 socket
python2 vol.py -f memory.raw --profile=Win10x64 sockets

# 提取原始套接字信息
python3 vol.py -f memory.raw windows.sockets
python3 vol.py -f memory.raw windows.connections

# 常见指标：
# ● 通往已知恶意IP的C2连接
# ● 异常端口监听（如非标准端口上的Shell）
# ● 大量对外连接（数据外传）
# ● 使用Tor/I2P等匿名网络的连接

# 注册表分析
# 注册表 hive 列表
python2 vol.py -f memory.raw --profile=Win10x64 hivelist

# 打印注册表键值
python2 vol.py -f memory.raw --profile=Win10x64 printkey -K "ControlSet001\\Control\\ComputerName\\ComputerName"

# 获取 SAM 哈希（用户密码哈希）
python2 vol.py -f memory.raw --profile=Win10x64 hashdump

# 检测自动启动项
python2 vol.py -f memory.raw --profile=Win10x64 autorunsc

# 用户凭据
python2 vol.py -f memory.raw --profile=Win10x64 lsadump

# 注册表变化检测
python2 vol.py -f memory.raw --profile=Win10x64 shellbags

# Volatility 3 注册表操作
python3 vol.py -f memory.raw windows.hivelist
python3 vol.py -f memory.raw windows.printkey --key "Microsoft\Windows\CurrentVersion\Run"
python3 vol.py -f memory.raw windows.printkey --key "Microsoft\Windows\CurrentVersion\RunOnce"
python3 vol.py -f memory.raw windows.printkey --key "System\CurrentControlSet\Services"
python3 vol.py -f memory.raw windows.printkey --key "Microsoft\Windows NT\CurrentVersion\Winlogon"
```

### 5. DLL与模块分析

```bash
# 列出进程加载的DLL
python3 vol.py -f memory.raw windows.dlllist

# 检测隐藏/未链接的DLL
python3 vol.py -f memory.raw windows.ldrmodules

# 扫描所有内核模块
python3 vol.py -f memory.raw windows.modscan

# 检查DLL劫持关注点：
# ● 从用户目录加载的DLL (%TEMP%, %APPDATA%)
# ● 伪装系统DLL名称但路径不对
# ● 签名信息异常（未签名/签名无效）
# ● 与正常基址偏移不一致
```

### 6. 恶意代码与 Rootkit 检测

```bash
# MFT 解析（列出文件）
python2 vol.py -f memory.raw --profile=Win10x64 mftparser
python2 vol.py -f memory.raw --profile=Win10x64 filescan

# 检测内核模块
python2 vol.py -f memory.raw --profile=Win10x64 modules
python2 vol.py -f memory.raw --profile=Win10x64 modscan

# 检测内核挂钩
python2 vol.py -f memory.raw --profile=Win10x64 ssdt
python2 vol.py -f memory.raw --profile=Win10x64 idt
python2 vol.py -f memory.raw --profile=Win10x64 driverirp

# 检测注入代码
python2 vol.py -f memory.raw --profile=Win10x64 malfind
python2 vol.py -f memory.raw --profile=Win10x64 apihooks
python2 vol.py -f memory.raw --profile=Win10x64 ldrmodules

# Volatility 3 检测注入
python3 vol.py -f memory.raw windows.malfind --dump

# 检测APC注入
python3 vol.py -f memory.raw windows.apihooks

# YARA 规则扫描
python3 vol.py -f memory.raw windows.yarascan --yara-rules /path/to/rules.yar

# 提取执行过的命令
python2 vol.py -f memory.raw --profile=Win10x64 cmdline
python2 vol.py -f memory.raw --profile=Win10x64 consoles
python2 vol.py -f memory.raw --profile=Win10x64 cmdscan

# 剪贴板内容
python2 vol.py -f memory.raw --profile=Win10x64 clipboard

# 提取内存中的可执行文件
python2 vol.py -f memory.raw --profile=Win10x64 procdump -p 1234 -D extracted/
python2 vol.py -f memory.raw --profile=Win10x64 dlldump -p 1234 -b -D extracted/
```

### 7. Linux 内存取证

```bash
# Linux 特定 Volatility 插件
python3 vol.py -f linux.mem linux.pslist
python3 vol.py -f linux.mem linux.pstree
python3 vol.py -f linux.mem linux.bash          # Bash历史记录
python3 vol.py -f linux.mem linux.check_syslog  # 系统日志
python3 vol.py -f linux.mem linux.check_afinfo  # 网络协议钩子
python3 vol.py -f linux.mem linux.dmesg         # Dmesg输出

# 检测内核模块
python3 vol.py -f linux.mem linux.lsmod

# 检测隐藏进程
python3 vol.py -f linux.mem linux.psxview

# 网络连接
python3 vol.py -f linux.mem linux.netstat
```

### 8. 取证时间线

```bash
# 构建事件时间线
python3 vol.py -f memory.raw windows.timeliner

# 输出格式化（可选CSV/SQLite便于分析）
python3 vol.py -f memory.raw windows.timeliner --output=csv > timeline.csv
```

```python
"""自动化内存取证分析"""

import subprocess
import json

class MemoryForensics:
    """内存取证自动化"""
    
    def __init__(self, memory_path, vol_path="python3"):
        self.memory = memory_path
        self.vol = vol_path
        self.results = {}
    
    def run_vol3_plugin(self, plugin, args=""):
        """运行 Volatility 3 插件"""
        cmd = f"{self.vol} vol.py -f {self.memory} {plugin} {args}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return {"stdout": result.stdout, "stderr": result.stderr}
    
    def quick_scan(self):
        """快速扫描 — 收集关键证据"""
        plugins = [
            "windows.pstree",
            "windows.netscan",
            "windows.dlllist",
            "windows.cmdline",
            "windows.malfind"
        ]
        
        for plugin in plugins:
            self.results[plugin] = self.run_vol3_plugin(plugin)
        
        # 筛选可疑进程
        suspicious = []
        ps_output = self.results.get("windows.pstree", {}).get("stdout", "")
        for line in ps_output.split("\n"):
            # 检测常见恶意进程特征
            if any(kw in line.lower() for kw in 
                   ["temp", "powershell", "rundll32", "regsvr32"]):
                suspicious.append(line.strip())
        
        return {
            "scan_complete": True,
            "suspicious_findings": suspicious,
            "total_artifacts": len(self.results)
        }
    
    def extract_malware_sample(self, pid, output_dir):
        """提取可疑进程的内存"""
        plugin = f"windows.dumpfiles --pid {pid}"
        return self.run_vol3_plugin(plugin, f"--dump-dir {output_dir}")

# 使用示例
analyzer = MemoryForensics("/evidence/memory.raw")
findings = analyzer.quick_scan()
print(f"Suspicious items: {len(findings['suspicious_findings'])}")
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Volatility 3 | 内存取证框架 | https://github.com/volatilityfoundation/volatility3 |
| Volatility 2 | 内存取证（传统版） | https://github.com/volatilityfoundation/volatility |
| LiME | Linux 内存获取 | https://github.com/504ensicsLabs/LiME |
| WinPmem | Windows 内存获取 | https://github.com/veler/winpmem |
| FTK Imager | 图形化内存/磁盘获取 | https://www.exterro.com/ftk-imager |
| Rekall | 内存取证工具 | https://github.com/google/rekall |
| MemProcFS | 文件系统式内存分析 | https://github.com/ufrisk/MemProcFS |
| Redline | FireEye内存分析（免费） | https://fireeye.com/services/freeware/redline/ |
| AVML | Linux内存获取（Microsoft） | https://github.com/microsoft/avml |

## 参考资源

- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [SANS Memory Forensics Cheat Sheet](https://www.sans.org/blog/memory-forensics-cheat-sheet/)
- [Malware Unicorns — Memory Forensics](https://malwareunicorn.org/#/memory-forensics)
- [SANS FOR572 — Advanced Memory Forensics](https://www.sans.org/for572/)
- [13Cubed — Memory Forensics 视频教程](https://www.youtube.com/c/13Cubed)
- [The Art of Memory Forensics (书籍)](https://www.amazon.com/Art-Memory-Forensics-Detecting-Malware/dp/1118825098)
