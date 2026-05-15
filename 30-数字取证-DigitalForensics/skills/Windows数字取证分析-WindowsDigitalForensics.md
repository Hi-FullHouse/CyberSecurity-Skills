---
id: "30-003"
title: "Windows数字取证分析 (Windows Digital Forensics)"
category: "数字取证"
category_en: "Digital Forensics"
difficulty: "★★★★"
tools: "KAPE, Hayabusa, Eric Zimmerman Tools, Plaso, Event Log Explorer"
last_updated: "2026-05"
tags: [forensics, windows, artifacts, event-logs, timeline-analysis]
subdomain: digital-forensics
nist_csf: [DE.AE-02, DE.CM-04, RS.AN-01]
mitre_attack: [T1003, T1070, T1071, T1546, T1564]
---

# Windows数字取证分析 (Windows Digital Forensics)

## 概述

Windows 操作系统在运行过程中会产生大量的取证痕迹，包括文件系统元数据、注册表、事件日志和各类应用痕迹。本技能覆盖 Windows 核心取证痕迹的提取与分析，包括 MFT、USN Journal、Event Logs、Prefetch、Shimcache、Amcache、SRUM 等。

## 核心技能

### 1. 文件系统取证 (MFT & USN Journal)

```bash
# MFT (Master File Table) — 每个文件的元数据记录
# MFT 位置: C:\$MFT

# 使用 MFTECmd (Eric Zimmerman 工具)
MFTECmd.exe -f "C:\Evidence\C\$MFT" --csv "C:\Output"

# 提取重点:
# - 已删除文件（Flag 包含 0x02）
# - 时间戳变化（创建/修改/MFT修改/访问）
# - 文件大小与簇信息
# - 文件名（短文件名 + 长文件名）

# 使用 analyzeMFT (Python)
python3 analyzeMFT.py -f "C:\Evidence\C\$MFT" -o mft_parsed.csv

# 使用 MFT 检测时间戳欺骗
# 正常: $STANDARD_INFORMATION ≈ $FILE_NAME 时间
# 异常: 两者时间差 > 几秒 → 可能存在 Timestomping

# USN Journal — 文件变更记录
# 位置: C:\$Extend\$UsnJrnl:$J

# 使用 USNJournal2CSV
USNJournal2CSV.exe -m -c \\.\C: -o usn_journal.csv
```

```powershell
# PowerShell 获取 USN Journal 记录
$usn = Get-Item "C:\$Extend\$UsnJrnl\$J"
Write-Host "USN Journal Size: $($usn.Length / 1MB) MB"

# 查找近期删除的文件
# 在 USN Journal 中搜索 USN_REASON_DELETE (0x80000100)
```

### 2. 事件日志分析

```bash
# Windows 事件日志位置
# Security: C:\Windows\System32\winevt\Logs\Security.evtx
# System: C:\Windows\System32\winevt\Logs\System.evtx
# Application: C:\Windows\System32\winevt\Logs\Application.evtx
# PowerShell: C:\Windows\System32\winevt\Logs\Windows PowerShell.evtx

# 使用 Hayabusa（快速事件日志分析工具）
# 下载: https://github.com/Yamato-Security/hayabusa

# 分析事件日志目录
hayabusa.exe csv-timeline -d "C:\Evidence\Logs" -o timeline.csv

# 检测关键安全事件
hayabusa.exe hunt -d "C:\Evidence\Logs" -o hunt_results.csv

# 检测横向移动
hayabusa.exe hunting -r rules/hunting/ -d "C:\Evidence\Logs"

# 使用 EvtxeCmd
EvtxeCmd.exe -f "C:\Evidence\Security.evtx" --csv "C:\Output"

# 关键安全事件 ID
# 4624: 登录成功
# 4625: 登录失败
# 4672: 特殊权限登录
# 4688: 进程创建
# 4648: 显式凭据登录（RunAs）
# 4698: 计划任务创建
# 4103: PowerShell 管道执行
# 4104: PowerShell 脚本块记录
```

```python
"""Windows 事件日志分析"""

import xml.etree.ElementTree as ET
from datetime import datetime

class WindowsEventAnalyzer:
    """Windows 事件日志分析器"""
    
    def __init__(self):
        self.suspicious_events = []
    
    def analyze_security_log(self, evtx_file):
        """分析安全日志"""
        # 使用 Python-evtx 解析
        # pip install python-evtx
        import subprocess
        import json
        
        # 转换为 CSV（调用工具）
        cmd = f"EvtxeCmd.exe -f {evtx_file} --csv output/"
        subprocess.run(cmd, shell=True)
        
        return {"status": "analyzed", "file": evtx_file}
    
    def detect_brute_force(self, log_entries):
        """检测暴力破解（大量 4625 事件）"""
        failed_logins = [
            entry for entry in log_entries
            if entry.get("EventID") == 4625
        ]
        
        # 按来源 IP 聚合
        from collections import Counter
        ip_counts = Counter(
            entry.get("IpAddress", "") for entry in failed_logins
        )
        
        return [
            {"ip": ip, "failed_count": count}
            for ip, count in ip_counts.items()
            if count > 10
        ]
    
    def detect_lateral_movement(self, log_entries):
        """检测横向移动 — 网络登录(3) + 非预期主机"""
        network_logons = [
            entry for entry in log_entries
            if entry.get("EventID") == 4624 
            and entry.get("LogonType") == 3
            and not entry.get("IpAddress", "").startswith("192.168.1")
        ]
        return network_logons

    def detect_powershell_abuse(self, log_entries):
        """检测 PowerShell 滥用"""
        ps_events = [
            entry for entry in log_entries
            if entry.get("EventID") in [4103, 4104]
        ]
        suspicious = []
        for evt in ps_entries:
            script = evt.get("ScriptBlockText", "")
            if any(kw in script.lower() for kw in 
                   ["downloadstring", "invoke-", "iex", 
                    "-enc ", "base64", "bypass"]):
                suspicious.append(evt)
        return suspicious
```

### 3. 执行痕迹分析

```bash
# Prefetch — 应用程序执行记录
# 位置: C:\Windows\Prefetch\*.pf
# 包含: 执行次数、时间戳、文件路径

# 使用 PECmd
PECmd.exe -f "C:\Evidence\C\Windows\Prefetch\*.pf" --csv "C:\Output"

# 重点关注:
# - 首次执行时间
# - 最后执行时间
# - 执行次数（运行频率）
# - 加载的 DLL 和文件

# Shimcache (AppCompatCache) — 程序兼容性缓存
# 位置: SYTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
# 包含: 文件名、最后修改时间

# 使用 AppCompatCacheParser
AppCompatCacheParser.exe --csv "C:\Output" -f "C:\Evidence\C\Windows\System32\config\SYSTEM"

# Amcache — 应用程序缓存
# 位置: C:\Windows\AppCompat\Programs\Amcache.hve
# 包含: 已安装程序、执行过的文件、驱动程序

# 使用 AmcacheParser
AmcacheParser.exe -f "C:\Evidence\C\Windows\AppCompat\Programs\Amcache.hve" --csv "C:\Output"

# SRUM — 系统资源使用监控
# 位置: C:\Windows\System32\sru\SRUDB.dat
# 包含: 网络连接、CPU使用、能耗、数据流量

# 使用 SrumECmd
SrumECmd.exe -f "C:\Evidence\C\Windows\System32\sru\SRUDB.dat" --csv "C:\Output"
```

### 4. 用户活动痕迹

```powershell
# ShellBags — 文件夹视图设置（位置历史）
# 位置: USRCLASS.DAT 和 NTUSER.DAT 注册表

# Jump Lists — 最近打开的文件
# 位置: C:\Users\%USER%\AppData\Roaming\Microsoft\Windows\Recent

# LNK 文件分析
# 使用 LECmd
LECmd.exe -f "C:\Evidence\Users\*\Recent\*.lnk" --csv "C:\Output"

# LNK 文件包含:
# - 目标文件路径（含原始路径）
# - 创建/访问时间
# - 目标文件序列号
# - 网络位置（如果来自网络）

# 浏览器历史
# Chrome: C:\Users\%USER%\AppData\Local\Google\Chrome\User Data\Default\History
# Edge: C:\Users\%USER%\AppData\Local\Microsoft\Edge\User Data\Default\History
# Firefox: C:\Users\%USER%\AppData\Roaming\Mozilla\Firefox\Profiles\

# 回收站记录
# $Recycle.Bin\$I<ID> — 元数据文件
# $Recycle.Bin\$R<ID> — 原始文件

# 使用 RBCmd
RBCmd.exe -f "C:\Evidence\C\$Recycle.Bin\S-1-5-21-XXXX\$IXXXXX" --csv "C:\Output"
```

### 5. 时间线分析

```bash
# 使用 Plaso (log2timeline) 创建超级时间线
# 安装
pip install plaso

# 创建时间线
log2timeline.py --storage-file evidence.plaso "C:\Evidence\C"

# 查看处理状态
psort.py -o null evidence.plaso

# 导出时间线 CSV
psort.py -o l2tcsv -w timeline.csv evidence.plaso

# 按时间范围过滤
psort.py -o l2tcsv -w timeline.csv \
  -q "date > '2026-05-01 00:00:00' AND date < '2026-05-15 23:59:59'" \
  evidence.plaso

# 生成超级时间线
# 关键时间线分析技术:
# 1. 时间线拼接 — 合并 MFT + EVTX + Prefetch + 注册表
# 2. 时间窗口分析 — 聚焦攻击时间窗口
# 3. 活动序列重建 — 用户操作的时间顺序
```

```python
"""Windows 取证自动化 — KAPE 集成"""

import subprocess

class KAPEWrapper:
    """KAPE 取证获取与处理"""
    
    def __init__(self, kape_path, output_dir):
        self.kape = kape_path
        self.output = output_dir
    
    def collect_targets(self, source):
        """KAPE 目标收集（Evidence of Execution）"""
        cmd = (
            f"{self.kape} --tsource {source} "
            f"--tdest {self.output} "
            f"--target !SANS_Triage "
            f"--gui 0"
        )
        subprocess.run(cmd, shell=True)
    
    def collect_all(self, source):
        """KAPE 全面收集"""
        cmd = (
            f"{self.kape} --tsource {source} "
            f"--tdest {self.output} "
            f"--target !CUSTOM_KAPE_All "
            f"--gui 0"
        )
        subprocess.run(cmd, shell=True)
    
    def process_with_hayabusa(self, log_path):
        """调用 Hayabusa 处理事件日志"""
        cmd = (
            f"hayabusa.exe csv-timeline "
            f"-d {log_path} "
            f"-o {self.output}/hayabusa_timeline.csv "
            f"-q"
        )
        subprocess.run(cmd, shell=True)

# 使用示例
kape = KAPEWrapper(r"C:\Tools\kape\kape.exe", r"C:\Output")
kape.collect_targets(r"C:\Evidence\C")
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| KAPE | 取证工件收集 | https://www.kroll.com/en/services/cyber-security/incident-response-tools/kape |
| Hayabusa | 事件日志分析 | https://github.com/Yamato-Security/hayabusa |
| Eric Zimmerman Tools | Windows 取证工具集 | https://ericzimmerman.github.io/ |
| Plaso | 超级时间线生成 | https://github.com/log2timeline/plaso |
| Velociraptor | 端点取证采集 | https://github.com/Velocidex/velociraptor |

## 参考资源

- [SANS Windows Forensics Cheat Sheet](https://www.sans.org/blog/windows-forensic-analysis/)
- [Windows Forensic Artifacts — 13Cubed](https://www.13cubed.com/windows-forensic-artifacts)
- [DFIR Training — Windows Forensics](https://www.dfir.training/windows-forensics)
- [Forensic Artifacts — Google](https://forensicartifacts.com/)
- [KAPE Documentation](https://kape.li/)
