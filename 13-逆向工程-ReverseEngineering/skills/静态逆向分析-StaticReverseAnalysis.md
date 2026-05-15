---
id: 13-003
title: "🔬 静态逆向分析 (Static Reverse Engineering)"
category: 逆向工程
category_en: "Reverse Engineering"
difficulty: ★★★★
tools: "IDA Pro, Ghidra, Radare2, Binary Ninja"
last_updated: 2025-07
tags: ["reverse-engineering", "malware-analysis", "debugging", "static-analysis"]
subdomain: reverse-engineering
nist_csf: ["DE.CM-04", "DE.AE-02"]
mitre_attack: ["T1204", "T1036"]
---
# 🔬 静态逆向分析 (Static Reverse Engineering)

## 概述
使用静态分析方法对二进制程序进行分析，不运行程序，通过反汇编、反编译等手段理解程序逻辑、发现漏洞和提取敏感信息。

## 核心技能

### 1. 文件格式分析

```bash
# 文件类型识别
file target_binary
file -i target_binary

# PE文件分析 (Windows)
# 使用pefile
python3 -c "
import pefile
pe = pefile.PE('target.exe')
print('Sections:', len(pe.sections))
print('Entry Point:', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
print('Image Base:', hex(pe.OPTIONAL_HEADER.ImageBase))
for section in pe.sections:
    print(f'{section.Name.decode().strip():10} {hex(section.VirtualAddress):10} {hex(section.SizeOfRawData):8}')
"

# PE解析工具
readpe target.exe
peinfo target.exe

# ELF文件分析 (Linux)
readelf -h target
readelf -S target      # 段表
readelf -l target      # 程序头
readelf -s target      # 符号表
readelf -d target      # 动态段
readelf -r target      # 重定位

objdump -x target      # 全部头信息
objdump -d target      # 反汇编
objdump -t target      # 符号表
objdump -R target      # 动态重定位
objdump -p target      # PE特定信息

# Mach-O文件分析 (macOS)
otool -h target         # 头信息
otool -l target         # Load commands
otool -L target         # 动态库依赖
```

### 2. 字符串与数据提取

```bash
# 提取ASCII字符串
strings target
strings -n 6 target      # 至少6字符
strings -e l target      # 宽字符 (Unicode)

# 提取并查找敏感信息
strings target | grep -iE "password|secret|key|token|flag|crypto|private|aes|rsa"
strings target | grep -E "http://|https://|ftp://|api\\."
strings target | grep -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"  # 邮箱

# 加密常量检测
strings target | grep -iE "SALT|IV|NONCE|SBOX|RC4|MD5|SHA|base64"
strings -n 32 target | sort | uniq -c | sort -rn | head -20  # 找出长字符串（可能为密钥）

# 导出hexdump
xxd target | head -50
hexdump -C target | head -50
```

### 3. 反汇编与反编译

```bash
# IDA Pro (商业) - 最强大的反汇编器
# 命令行: idat64 -A -B target  (生成IDB + ASM)
# 或使用: idat64 -L log.txt target

# Ghidra (开源) - NSA开发的逆向工具
# headless模式
ghidra -import /path/to/target -postScript AnalyzeHeadless.java
# 或使用: ghidraHeadless /project/dir ProjectName -import target -postScript script.py

# Radare2 / Rizin
# 基本分析
r2 target
[0x100000e60]> aaaa          # 自动分析
[0x100000e60]> afl           # 列出函数
[0x100000e60]> axt addr      # 交叉引用
[0x100000e60]> s addr        # 跳转到地址
[0x100000e60]> pdf @ function_name  # 反汇编函数
[0x100000e60]> VV            # 图形视图

# 自动分析脚本
r2 -q -c 'aaaa; afl > functions.txt; pd @@ sym.* > disasm.txt' target

# Binary Ninja (商业)
binaryninja -d target
# headless分析
binaryninja -language python -execute script.py target

# Objdump - 快速反汇编
objdump -d target          # 完整反汇编
objdump -d -M intel target # Intel语法
objdump -d -j .text target # 仅.text段
objdump -M x86-64 target   # 64位

# Hopper (macOS)
hopper -d target
```

### 4. 脱壳与修复

```bash
# 检测壳
# 使用Detect It Easy (DIE)
diec target

# 使用PEiD
# 适用于旧版PE文件

# 自定义壳检测
# 检查入口点偏移（正常PE通常在.text节）
# 检查节名称（UPX0, UPX1等是UPX壳的特征）
# 检查导入表（加壳后通常只有少数DLL）

# UPX脱壳
upx -d target.exe -o unpacked.exe

# ASPack脱壳
# 使用UnAspack

# Themida/VMP等强壳
# 手动脱壳或使用专用工具
# TheODBG + OllyDump
# Scylla (Import Reconstructor)

# 通用脱壳方法
# 1. 找到原始入口点 (OEP)
# 2. 在OEP处dump内存
# 3. 修复IAT (Import Address Table)
# 使用Scylla: 选择进程 -> IAT Autosearch -> Get Imports -> Fix Dump

# .NET脱壳
# de4dot - .NET反混淆/反编译
de4dot target.exe -o target_clean.exe
dnSpy target_clean.exe
```

### 5. 代码结构与算法分析

```bash
# 识别编译器
# GCC: __gmon_start__, __libc_csu_init
# MSVC: _stext, _text, _mainCRTStartup
# MinGW: mingw_initltsdrot_force
# Go: go.buildid, main.main, runtime.main

# 常见算法识别
# 使用FindCrypt2 (IDA插件)
# 或手动搜索签名

# AES常量检测
# S-Box: 63 7C 77 7B F2 6B 6F C5
# 轮常量: 01 02 04 08 10 20 40 80 1B 36

# Base64表
# "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
strings target | grep -E "^[A-Za-z0-9+/]{20,}={0,2}$"

# 自定义加密算法
# 查找异或操作 (XOR)
# 查找位移操作 (SHL/SHR)
# 查找自定义S-Box
```

### 6. 自动化反向分析

```python
#!/usr/bin/env python3
# static_analysis.py - 静态分析自动化

import subprocess
import re
import json
import os

class StaticAnalyzer:
    def __init__(self, target_file):
        self.target = target_file
        self.results = {
            'file_info': {},
            'strings': [],
            'functions': [],
            'suspicious': []
        }
    
    def analyze_file(self):
        """文件基本信息"""
        result = subprocess.run(['file', self.target], capture_output=True, text=True)
        self.results['file_info']['type'] = result.stdout.strip()
        
        result = subprocess.run(['strings', '-n', '6', self.target], 
                              capture_output=True, text=True)
        self.results['strings'] = result.stdout.split('\n')

    def find_suspicious(self):
        """查找可疑模式"""
        patterns = {
            'url': r'https?://[^\s]+',
            'ip': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'api_key': r'(?:api[_-]?key|apikey|secret)[=:]["\']?([^"\'&\s]+)',
        }
        
        for name, pattern in patterns.items():
            for line in self.results['strings']:
                if re.search(pattern, line, re.IGNORECASE):
                    self.results['suspicious'].append({
                        'type': name,
                        'value': line.strip()
                    })
    
    def analyze_with_r2(self):
        """使用Radare2分析"""
        commands = [
            'aaaa',                    # 自动分析
            'afl',                     # 函数列表
            'iI',                      # 二进制信息
            'iS',                      # 段信息
            'il',                      # 库
            'iE',                      # 入口点
        ]
        
        try:
            for cmd in commands:
                result = subprocess.run(
                    ['r2', '-q', '-c', f'{cmd}; quit', self.target],
                    capture_output=True, text=True, timeout=30
                )
                if cmd == 'afl':
                    self.results['functions'] = result.stdout.strip().split('\n')
        except Exception as e:
            print(f"Radare2 analysis failed: {e}")
    
    def generate_report(self, output_file):
        """生成分析报告"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        print(f"[+] Report saved to {output_file}")

# 使用示例
analyzer = StaticAnalyzer('sample_malware.exe')
analyzer.analyze_file()
analyzer.find_suspicious()
analyzer.analyze_with_r2()
analyzer.generate_report('analysis_report.json')
```

### 7. 工具链配置与脚本

```python
#!/usr/bin/env python3
# batch_analysis.py - 批量分析脚本

import os
import subprocess
import sys

def batch_analyze(directory):
    """批量分析目录中的所有二进制文件"""
    analyzable_extensions = ['.exe', '.dll', '.elf', '.bin', '.so', '.dylib']
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in analyzable_extensions:
                filepath = os.path.join(root, file)
                output_dir = os.path.join('analysis', file + '_report')
                os.makedirs(output_dir, exist_ok=True)
                
                print(f"\n[+] Analyzing: {filepath}")
                
                # 使用Ghidra headless分析
                if shutil.which('ghidraHeadless'):
                    subprocess.run([
                        'ghidraHeadless', output_dir, 'temp_proj',
                        '-import', filepath,
                        '-postScript', 'ExportReport.java',
                        '-overwrite'
                    ], timeout=300)
                
                # 使用strings提取信息
                with open(os.path.join(output_dir, 'strings.txt'), 'w') as f:
                    subprocess.run(['strings', '-n', '6', filepath], stdout=f)
                
                # 使用radare2
                subprocess.run([
                    'r2', '-q', '-c', 'aaaa; afl > functions.txt; quit', filepath
                ], cwd=output_dir)

if __name__ == "__main__":
    batch_analyze(sys.argv[1] if len(sys.argv) > 1 else '.')
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| IDA Pro | 专业反汇编器 | https://hex-rays.com/ |
| Ghidra | 开源逆向套件 | https://ghidra-sre.org/ |
| Radare2 | 开源逆向框架 | https://rada.re/n/ |
| Binary Ninja | 现代逆向平台 | https://binary.ninja/ |
| Detect It Easy | 壳检测 | https://github.com/horsicq/Detect-It-Easy |
| Cutter | Radare2 GUI | https://cutter.re/ |
| dnSpy | .NET反编译器 | https://github.com/dnSpy/dnSpy |

## 参考资源
- [Reverse Engineering for Beginners](https://beginners.re/)
- [OSDev Wiki - Executable Formats](https://wiki.osdev.org/ELF)
- [PE Format Specification (Microsoft)](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Ghidra Documentation](https://ghidra-sre.org/ghidra_docs/index.html)
- [Radare2 Book](https://book.rada.re/)
- [OpenSecurityTraining - Reverse Engineering](https://opensecuritytraining.info/ReverseEngineering.html)
