---
id: "30-005"
title: "浏览器与邮件取证 (Browser & Email Forensics)"
category: "数字取证"
category_en: "Digital Forensics"
difficulty: "★★★"
tools: "BrowserHistoryView, DB Browser for SQLite, MailStore, readpst, oletools"
last_updated: "2026-05"
tags: [forensics, browser, email, web-history, pst-analysis]
subdomain: digital-forensics
nist_csf: [DE.AE-02, DE.CM-07, RS.AN-01]
mitre_attack: [T1071, T1114, T1557, T1566]
---

# 浏览器与邮件取证 (Browser & Email Forensics)

## 概述

浏览器和电子邮件是日常网络活动的核心工具，也是数字取证中最丰富的证据源。浏览器历史记录包含用户的网页访问轨迹、搜索记录、下载文件信息；电子邮件则记录了通信往来和社交工程攻击的线索。本技能覆盖主流浏览器（Chrome/Firefox/Edge）和邮件客户端（Outlook/Thunderbird）的取证分析。

## 核心技能

### 1. 浏览器取证 — Chrome/Chromium

```bash
# Chrome 证据位置
# 历史记录: %LOCALAPPDATA%\Google\Chrome\User Data\Default\History
# 书签: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Bookmarks
# Cookies: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies
# 登录凭据: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
# 下载记录: %LOCALAPPDATA%\Google\Chrome\User Data\Default\History
# 缓存: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache\
# 扩展: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions\

# Chrome 数据库类型: SQLite
# 使用 SQLite 查询浏览器历史
sqlite3 "C:\Users\%USER%\AppData\Local\Google\Chrome\User Data\Default\History"

# 提取浏览历史
SELECT url, title, visit_count, last_visit_time
FROM urls
ORDER BY last_visit_time DESC
LIMIT 50;

# Chrome 时间戳转换（1601-01-01 微秒）
SELECT 
  url,
  title,
  datetime(last_visit_time/1000000-11644473600, 'unixepoch') AS visit_time
FROM urls
ORDER BY last_visit_time DESC;

# 搜索关键词
SELECT term, url FROM keyword_search_terms
JOIN urls ON keyword_search_terms.url_id = urls.id
ORDER BY keyword_search_terms.id;

# 下载记录
SELECT target_path, url, start_time, received_bytes, total_bytes
FROM downloads;

# Cookies
SELECT host_key, name, value, datetime(creation_utc/1000000-11644473600, 'unixepoch') AS created
FROM cookies
WHERE host_key LIKE '%target%';
```

```python
"""Chrome 浏览器取证分析"""

import sqlite3
import json
from datetime import datetime, timedelta

class ChromeForensics:
    """Chrome 浏览器取证"""
    
    def __init__(self, profile_path):
        self.profile = profile_path
        self.epoch_offset = 11644473600  # Windows 1601 to Unix epoch
    
    def convert_chrome_time(self, chrome_time):
        """Chrome 时间戳转人类可读"""
        if chrome_time == 0:
            return "unknown"
        return datetime.fromtimestamp(
            chrome_time / 1000000 - self.epoch_offset
        ).isoformat()
    
    def get_history(self, limit=100):
        """提取浏览历史"""
        db_path = f"{self.profile}/History"
        conn = sqlite3.connect(db_path)
        
        query = """
        SELECT url, title, visit_count, 
               last_visit_time, typed_count
        FROM urls
        ORDER BY last_visit_time DESC
        LIMIT ?
        """
        
        history = []
        for row in conn.execute(query, (limit,)):
            history.append({
                "url": row[0],
                "title": row[1],
                "visit_count": row[2],
                "last_visit": self.convert_chrome_time(row[3]),
                "typed_count": row[4]
            })
        conn.close()
        return history
    
    def get_downloads(self):
        """提取下载记录"""
        db_path = f"{self.profile}/History"
        conn = sqlite3.connect(db_path)
        
        query = """
        SELECT target_path, url, start_time, 
               received_bytes, total_bytes, state
        FROM downloads
        ORDER BY start_time DESC
        """
        
        downloads = []
        for row in conn.execute(query):
            downloads.append({
                "path": row[0],
                "url": row[1],
                "time": self.convert_chrome_time(row[2]),
                "size": f"{row[3]}/{row[4]} bytes",
                "completed": row[5] == 1
            })
        conn.close()
        return downloads
    
    def get_search_terms(self):
        """提取搜索关键词"""
        db_path = f"{self.profile}/History"
        conn = sqlite3.connect(db_path)
        
        query = """
        SELECT term, url FROM keyword_search_terms k
        JOIN urls u ON k.url_id = u.id
        """
        
        searches = []
        for row in conn.execute(query):
            searches.append({"term": row[0], "url": row[1]})
        conn.close()
        return searches
    
    def get_bookmarks(self):
        """提取书签"""
        bookmarks_path = f"{self.profile}/Bookmarks"
        import json
        with open(bookmarks_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        bookmarks = []
        def extract_bookmarks(node):
            if node.get('type') == 'url':
                bookmarks.append({
                    "name": node.get('name'),
                    "url": node.get('url'),
                    "date_added": self.convert_chrome_time(
                        int(node.get('date_added', '0')))
                })
            if 'children' in node:
                for child in node['children']:
                    extract_bookmarks(child)
        
        extract_bookmarks(data.get('roots', {}).get('bookmark_bar', {}))
        return bookmarks

# 使用示例
forensics = ChromeForensics(
    r"C:\Users\Target\AppData\Local\Google\Chrome\User Data\Default"
)
history = forensics.get_history(20)
for h in history:
    print(f"[{h['last_visit']}] {h['url']}")
```

### 2. 浏览器取证 — Firefox

```bash
# Firefox 证据位置
# 用户配置: %APPDATA%\Mozilla\Firefox\Profiles\*.default-release
# 历史记录: places.sqlite
# 书签: places.sqlite
# Cookies: cookies.sqlite
# 下载: downloads.sqlite
# 登录凭据: logins.json

# Firefox 使用 SQLite，与 Chrome 格式不同
sqlite3 "%APPDATA%\Mozilla\Firefox\Profiles\*.default-release\places.sqlite"

# 提取浏览历史
SELECT url, title, visit_count,
  datetime(last_visit_date/1000000, 'unixepoch') AS visit_time
FROM moz_places
ORDER BY last_visit_date DESC
LIMIT 50;

# Firefox 书签
SELECT b.title, p.url, 
  datetime(b.dateAdded/1000000, 'unixepoch') AS added
FROM moz_bookmarks b
JOIN moz_places p ON b.fk = p.id
WHERE b.type = 1;

# Firefox 下载记录
SELECT name, source, 
  datetime(startTime/1000000, 'unixepoch') AS start,
  state
FROM moz_downloads;

# 浏览器取证通用注意事项
# 1. 首先对数据库文件做哈希校验
# 2. 使用写保护复制证据
# 3. 避免打开浏览器导致时间戳更新
# 4. 记录文件系统时间戳
```

### 3. 邮件取证 — Outlook/PST

```bash
# Outlook PST/OST 文件位置
# PST (个人存储): %USERPROFILE%\Documents\Outlook Files\
# OST (脱机存储): %LOCALAPPDATA%\Microsoft\Outlook\
# 自动完成缓存: %APPDATA%\Microsoft\Outlook\NK2 (Outlook 2010-)
# 自动完成: %APPDATA%\Microsoft\Outlook\Stream_Autocomplete_* (Outlook 2013+)

# 使用 readpst (libpst) 转换 PST
readpst -o output_dir -r -j 4 "C:\Evidence\outlook.pst"

# readpst 输出 EML 或 MBOX 格式
# -o: 输出目录
# -r: 递归子文件夹
# -j: 并行线程数
# -e: 输出 EML 格式
# -m: 输出 MBOX 格式

# 将 PST 转换为 mbox 后导入取证工具
readpst -M -o output_mbox "C:\Evidence\outlook.pst"

# 提取邮件元数据
# 使用 pffexport (libpff)
pffexport -t all "C:\Evidence\outlook.pst"

# 查看邮件头
# 原始邮件头包含:
# Received: 邮件路由路径（检测伪造）
# Authentication-Results: SPF/DKIM/DMARC 验证结果
# Message-ID: 唯一标识
# Reply-To: 回复地址（可能不同）
# X-Originating-IP: 发件人 IP
```

```python
"""邮件取证分析"""

import mailbox
import email
import re
from email import policy
from datetime import datetime

class EmailForensics:
    """电子邮件取证分析"""
    
    def __init__(self):
        self.emails = []
    
    def analyze_eml(self, eml_path):
        """分析单个 EML 文件"""
        with open(eml_path, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
        
        return {
            "from": msg.get('From'),
            "to": msg.get('To'),
            "cc": msg.get('Cc'),
            "bcc": msg.get('Bcc'),
            "subject": msg.get('Subject'),
            "date": msg.get('Date'),
            "message_id": msg.get('Message-ID'),
            "received_chain": msg.get_all('Received'),
            "auth_results": msg.get('Authentication-Results'),
            "reply_to": msg.get('Reply-To'),
            "return_path": msg.get('Return-Path'),
            "content_type": msg.get('Content-Type'),
            "x_originating_ip": msg.get('X-Originating-IP'),
            "x_mailer": msg.get('X-Mailer')
        }
    
    def extract_original_ip(self, msg):
        """从邮件头提取发件人 IP"""
        received = msg.get_all('Received', [])
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        ips = []
        for header in received:
            found = re.findall(ip_pattern, header)
            ips.extend(found)
        return ips[0] if ips else None
    
    def analyze_mbox(self, mbox_path):
        """分析 MBOX 文件"""
        mbox = mailbox.mbox(mbox_path)
        
        analysis = {
            "total_messages": len(mbox),
            "date_range": {"earliest": None, "latest": None},
            "top_senders": {},
            "attachment_types": set(),
            "suspicious_emails": []
        }
        
        for message in mbox:
            # 统计发件人
            sender = message.get('From', 'unknown')
            analysis["top_senders"][sender] = \
                analysis["top_senders"].get(sender, 0) + 1
            
            # 统计附件
            if message.is_multipart():
                for part in message.walk():
                    if part.get_content_disposition() == 'attachment':
                        filename = part.get_filename()
                        if filename:
                            ext = filename.split('.')[-1].lower()
                            analysis["attachment_types"].add(ext)
            
            # 检测钓鱼邮件特征
            body = ""
            if message.is_multipart():
                for part in message.walk():
                    if part.get_content_type() == 'text/plain':
                        body = str(part.get_content())
                        break
            else:
                body = str(message.get_content())
            
            if self._is_suspicious(message, body):
                analysis["suspicious_emails"].append({
                    "subject": message['Subject'],
                    "from": message['From'],
                    "reason": self._check_reasons(message, body)
                })
        
        analysis["top_senders"] = dict(
            sorted(analysis["top_senders"].items(), 
                   key=lambda x: x[1], reverse=True)[:10]
        )
        return analysis
    
    def _is_suspicious(self, msg, body):
        """检测可疑邮件特征"""
        if not body:
            return False
        checks = [
            "urgent" in body.lower(),
            "click here" in body.lower(),
            "password" in body.lower(),
            "verify your account" in body.lower(),
            any(domain in str(msg.get('From', '')).lower() 
                for domain in ['@可疑域名.com']),
            msg.get('Reply-To') and msg.get('Reply-To') != msg.get('From')
        ]
        return sum(checks) >= 2
    
    def _check_reasons(self, msg, body):
        """列出可疑原因"""
        reasons = []
        if "urgent" in body.lower():
            reasons.append("紧急措辞")
        if "click here" in body.lower():
            reasons.append("诱导点击")
        if msg.get('Reply-To') and msg.get('Reply-To') != msg.get('From'):
            reasons.append("回复地址不一致")
        return "; ".join(reasons)

# 使用示例
analyzer = EmailForensics()
results = analyzer.analyze_mbox("evidence.mbox")
print(f"Total messages: {results['total_messages']}")
print(f"Suspicious: {len(results['suspicious_emails'])}")
```

### 4. 邮件头分析与社交工程检测

```bash
# 完整邮件头分析流程

# 1. 查看 Received 链
# 从下到上阅读,最后一跳是最接近收件人的
Received: from mail-smtp.example.com (192.168.1.1) by ...
Received: from mx.mail.com (203.0.113.5) by mail-smtp.example.com ...
Received: from unknown (10.0.0.1) by mx.mail.com ....

# 2. SPF/DKIM/DMARC 验证
# SPF 验证结果:
# Authentication-Results: spf=pass (sender IP 在 SPF 记录中)
# Authentication-Results: spf=fail (IP 不在 SPF 记录中)

# DKIM 签名验证:
# Authentication-Results: dkim=pass (签名有效)
# Authentication-Results: dkim=fail (签名无效)

# DMARC 策略:
# Authentication-Results: dmarc=pass (SPF+DKIM 一致)

# 3. 检测伪造邮件头
# X-Priority: High (社交工程常用)
# X-MSMail-Priority: High
# Importance: High

# 4. 社交工程检测特征
python3 -c "
import sys
import re

def analyze_email_headers(eml_file):
    with open(eml_file, 'r') as f:
        content = f.read()
    
    # 检测伪造的显示名称
    display_match = re.search(r'From:.*\"(.+?)\".*<(.+?)>', content)
    if display_match:
        display_name = display_match.group(1)
        actual_email = display_match.group(2)
        print(f'Display: {display_name}')
        print(f'Email: {actual_email}')
    
    # 检测回复地址差异
    reply_to = re.search(r'Reply-To:(.+?)(?:\n|$)', content)
    from_addr = re.search(r'From:.*?<(.+?)>', content)
    if reply_to and from_addr:
        if reply_to.group(1).strip() != from_addr.group(1).strip():
            print('[!] Reply-To 与 From 不一致')

analyze_email_headers('phishing_sample.eml')
"

# Thunderbird 取证
# 配置文件: %APPDATA%\Thunderbird\Profiles\*.default
# 邮件存储: ImapMail/ 和 Mail/
# 全局数据库: global-messages-db.sqlite
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| BrowserHistoryView | 浏览器历史查看 | https://www.nirsoft.net/utils/browser_history_view.html |
| ChromeHistoryView | Chrome 历史查看 | https://www.nirsoft.net/utils/chrome_history_view.html |
| DB Browser for SQLite | SQLite 数据库查看 | https://sqlitebrowser.org/ |
| readpst (libpst) | PST 转换工具 | https://www.five-ten-sg.com/libpst/ |
| oletools | OLE 文件分析 | https://github.com/decalage2/oletools |

## 参考资源

- [Browser Forensics — SANS](https://www.sans.org/blog/browser-forensics/)
- [Chrome Forensics — Forensic Focus](https://www.forensicfocus.com/articles/chrome-forensics/)
- [Email Forensics — NIST](https://csrc.nist.gov/publications/detail/sp/800-86/final)
- [Phishing Analysis — Cofense](https://cofense.com/phishing-analysis/)
- [OLE Tools Documentation](https://www.decalage.info/python/oletools)
