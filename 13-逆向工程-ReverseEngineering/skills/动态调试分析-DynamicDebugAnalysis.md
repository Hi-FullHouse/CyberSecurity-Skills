---
id: 13-001
title: "⚙️ 动态调试分析 (Dynamic Debug Analysis)"
category: 逆向工程
category_en: "Reverse Engineering"
difficulty: ★★★★
tools: "x64dbg, OllyDbg, GDB, WinDbg, Immunity"
last_updated: 2025-07
tags: ["reverse-engineering", "malware-analysis", "debugging", "static-analysis"]
subdomain: reverse-engineering
nist_csf: ["DE.CM-04", "DE.AE-02"]
mitre_attack: ["T1204", "T1036"]
---
# ⚙️ 动态调试分析 (Dynamic Debug Analysis)

## 概述
通过运行和调试目标程序，实时观察执行流程、内存状态和行为特征，分析程序逻辑和漏洞。

## 核心技能

### 1. GDB调试

```bash
# 基础调试
gdb ./target
gdb -q ./target        # 静默模式
gdb -p PID             # 附加到进程
gdb -batch -ex "run" -ex "bt" ./target  # 无交互运行

# 断点设置
(gdb) break main           # 函数断点
(gdb) break *0x401000      # 地址断点
(gdb) break file.c:42      # 源码行断点
(gdb) watch var            # 变量监控
(gdb) rwatch *0x401000     # 读断点
(gdb) awatch var           # 读写断点
(gdb) catch syscall        # 系统调用断点
(gdb) catch syscall write  # 特定syscall

# 运行控制
(gdb) run                  # 运行
(gdb) run < input.txt      # 带输入运行
(gdb) continue             # 继续
(gdb) nexti                # 单步指令
(gdb) stepi                # 步入指令
(gdb) next                 # 单步源码
(gdb) step                 # 步入源码
(gdb) finish               # 执行到函数返回
(gdb) until addr           # 执行到地址

# 寄存器与内存
(gdb) info registers       # 查看寄存器
(gdb) info registers rax rbx rcx  # 特定寄存器
(gdb) x/10x $rsp           # 查看栈内存
(gdb) x/10i $rip           # 查看指令
(gdb) x/s 0x402000         # 查看字符串
(gdb) x/gx $rbp-8          # 查看8字节值

# 动态修改
(gdb) set var = 1337       # 修改变量
(gdb) set $rax = 0         # 修改寄存器
(gdb) jump 0x401234        # 跳转执行

# 常用GDB脚本
cat > .gdbinit << 'EOF'
set pagination off
set confirm off
set disassembly-flavor intel
define hook-stop
    x/1i $rip
end
EOF

# GDB + Pwntools
python3 << 'EOF'
from pwn import *
context.arch = 'amd64'
p = gdb.debug('./target', '''
break *0x401123
continue
''')
p.interactive()
EOF
```

### 2. WinDbg调试

```cmd
# WinDbg (Windows调试器)
# 本地用户态调试
windbg target.exe
windbg -pn target.exe    # 按进程名附加
windbg -p PID            # 按PID附加

# 远程调试
# 服务端: windbg -server tcp:port=5000 target.exe
# 客户端: windbg -remote tcp:server=YOUR_IP,port=5000

# 内核调试
# 需要两台机器或虚拟机
windbg -k net:port=50000,key=1.2.3.4

# 常用命令
0:000> bp 0x401234          # 地址断点
0:000> bp kernel32!CreateFileW  # API断点
0:000> bl                   # 列出断点
0:000> bc *                 # 清除所有断点
0:000> g                    # 继续执行
0:000> t                    # 单步步入
0:000> p                    # 单步跳过
0:000> r                    # 查看寄存器
0:000> r eax = 0            # 修改寄存器
0:000> d esp L10            # 查看栈
0:000> dd poi(esp+4)        # 解析指针
0:000> k                    # 调用栈
0:000> lm                   # 加载模块

# PyKD - Python扩展
!py
import pykd
pykd.setBreakPoint(0x401000)
pykd.go()

# 调试脚本 (.wds)
$$ script.wds
bp kernel32!VirtualAlloc
g
.printf "VirtualAlloc: %p\n", @eax
bc *
g
```

### 3. x64dbg (Windows开源调试器)

```cmd
# 基础操作
# F9: 运行/继续
# F7: 单步步入
# F8: 单步跳过
# F2: 设置断点
# F4: 运行到光标处
# Ctrl+F9: 执行到返回
# Ctrl+F8: 自动步过
# Ctrl+G: 跳转到地址

# 常用功能
# 1. 搜索字符串 (右键 -> 查找 -> 所有模块/当前模块)
# 2. 查看SEH链 (视图 -> SEH链)
# 3. 查看调用栈 (视图 -> 调用栈)
# 4. 查看句柄 (视图 -> 句柄)
# 5. 修补二进制 (双击指令 -> 汇编 -> 应用)

# 插件
# ScyllaHide - 反反调试
# OllyDump - 内存转储
# xAnalyzer - 功能分析
# Graph - 流程图生成
```

### 4. API监控与钩子

```bash
# API Monitor (Windows)
# 监控指定进程的API调用

# Detours (Microsoft)
# 用于hook API
# 编译: cl /c hook.cpp
# link hook.obj detours.lib

# Frida - 跨平台动态插桩
# 附加进程
frida target.exe
frida -p PID
frida -n notepad.exe

# Frida脚本
cat > hook.js << 'EOF'
// Hook Windows API
var CreateFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
Interceptor.attach(CreateFileW, {
    onEnter: function(args) {
        console.log("[CreateFileW] " + Memory.readUtf16String(args[0]));
    },
    onLeave: function(retval) {
        console.log("[CreateFileW] Return: " + retval);
    }
});

// Hook函数
var targetFunc = Module.findExportByName("target.exe", "checkPassword");
Interceptor.attach(targetFunc, {
    onEnter: function(args) {
        console.log("checkPassword called with: " + args[0].readCString());
    },
    onLeave: function(retval) {
        console.log("checkPassword returned: " + retval);
        retval.replace(ptr(1));  // 始终返回成功
    }
});
EOF

frida -l hook.js target.exe

# 使用Frida Trace
frida-trace -i "CreateFileW" target.exe
frida-trace -i "*Password*" target.exe
frida-trace -i "recv" target.exe

# Pin Tool (Intel)
# 指令计数
pin -t inscount0.so -- target.exe
# 内存跟踪
pin -t memtrace.so -- target.exe

# DynamoRIO
drrun -c drmemory.dll -- target.exe
```

### 5. 内存分析与修补

```bash
# 内存转储
# Windows
procdump -ma PID dump.dmp
# 或任务管理器 -> 创建转储文件

# Linux
gcore PID
# 配置core dump: ulimit -c unlimited

# 进程内存读取
# Windows (PowerShell)
$process = Get-Process -Name target
$process | Format-List *

# 使用Process Hacker
# 右键进程 -> 内存 -> 查看

# 内存搜索
# x64dbg
ctrl+B 打开内存搜索
搜索字节序列: 90 90 90 90
搜索字符串: "password"

# 十六进制修补
# 使用xxd
xxd target.bin | sed 's/0a0b0c0d/90909090/g' | xxd -r > target_patched.bin

# 使用dd
echo -ne '\x90\x90\x90\x90' | dd of=target.bin bs=1 seek=0x1234 conv=notrunc

# IDA/Hex-Rays修补
# Edit -> Patch program -> Change byte
# 或使用Python API
idaapi.patch_byte(0x401000, 0x90)

# x64dbg修补
# 选中指令 -> 右键 -> 汇编 -> 修改 -> 应用
# 使用补丁管理器: 右键 -> 补丁 -> 保存补丁到文件
```

### 6. 反调试对抗

```bash
# 反反调试技术
# 检测常见的反调试技术
# 1. IsDebuggerPresent()
# 2. CheckRemoteDebuggerPresent()
# 3. NtQueryInformationProcess()
# 4. PEB.BeingDebugged标志
# 5. TLS回调检测

# Frida绕过反调试
cat > anti_debug_bypass.js << 'EOF'
// 绕过 IsDebuggerPresent
var IsDebuggerPresent = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
Interceptor.attach(IsDebuggerPresent, {
    onLeave: function(retval) {
        retval.replace(ptr(0));  // 返回 false
    }
});

// 绕过 NtQueryInformationProcess
var ntdll = Module.findExportByName("ntdll.dll", "NtQueryInformationProcess");
Interceptor.attach(ntdll, {
    onLeave: function(retval) {
        // 修改 ProcessDebugPort 返回
    }
});

// 时间检测绕过
var GetTickCount = Module.findExportByName("kernel32.dll", "GetTickCount");
var timeDiff = 0;
var lastTime = 0;
Interceptor.attach(GetTickCount, {
    onEnter: function(args) {
        if (lastTime == 0) {
            lastTime = this.context.eax;
        }
    },
    onLeave: function(retval) {
        // 确保时间增量很小
    }
});
EOF

# ScyllaHide (x64dbg插件)
# 自动绕过常见的反调试检查

# TitanHide (驱动级反调试)
# 加载驱动: net start TitanHide
```

### 7. 自动化调试脚本

```python
#!/usr/bin/env python3
# auto_debug.py - 自动化调试脚本

from pwn import *
import sys

def analyze_binary(target):
    print(f"[*] Analyzing: {target}")
    
    context.binary = target
    context.log_level = 'error'
    
    # 创建进程
    p = process(target)
    
    # 分析函数
    elf = ELF(target)
    print(f"[*] Architecture: {elf.arch}")
    print(f"[*] Entry point: {hex(elf.entry)}")
    
    # 查找关键函数
    for name, addr in elf.symbols.items():
        if 'password' in name.lower() or 'check' in name.lower() or 'login' in name.lower():
            print(f"[+] Found: {name} at {hex(addr)}")
    
    # 尝试反编译（如果有Ghidra）
    try:
        import subprocess
        subprocess.run(['ghidraHeadless', '/tmp/ghidra_proj', 'analysis',
                       '-import', target, '-postScript', 'Decompile.java'])
        print("[*] Decompilation requested")
    except:
        print("[!] Ghidra not available")
    
    p.close()

def fuzz_target(target, input_file=None):
    """Fuzz目标程序"""
    if input_file:
        with open(input_file) as f:
            payloads = [line.strip() for line in f]
    else:
        # 生成测试数据
        payloads = [
            b"A" * 100,
            b"%x.%x.%x.%x",
            b"' OR '1'='1",
            b"\x00" * 100,
            b"../../../../etc/passwd"
        ]
    
    for payload in payloads:
        try:
            p = process(target, timeout=3)
            p.send(payload)
            p.recvall(timeout=2)
            p.close()
        except:
            print(f"[!] Crash with payload: {payload[:50]}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        analyze_binary(sys.argv[1])
        fuzz_target(sys.argv[1])
    else:
        print(f"Usage: {sys.argv[0]} <binary>")
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| GDB | Linux调试器 | https://www.gnu.org/software/gdb/ |
| WinDbg | Windows调试器 | https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/ |
| x64dbg | Windows开源调试器 | https://x64dbg.com/ |
| Frida | 动态插桩框架 | https://frida.re/ |
| Process Hacker | 进程分析 | https://processhacker.sourceforge.io/ |
| API Monitor | API监控 | http://www.rohitab.com/apimonitor |
| IDA Pro + Debugger | 集成调试 | https://hex-rays.com/ |
| Ghidra | 调试器集成 | https://ghidra-sre.org/ |

## 参考资源
- [GDB User Manual](https://sourceware.org/gdb/current/onlinedocs/gdb/)
- [x64dbg Documentation](https://help.x64dbg.com/)
- [Frida Documentation](https://frida.re/docs/home/)
- [Reverse Engineering StackExchange](https://reverseengineering.stackexchange.com/)
- [OpenSecurityTraining - Dynamic Analysis](https://opensecuritytraining.info/DynamicAnalysis.html)
