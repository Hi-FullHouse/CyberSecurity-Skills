---
id: 22-005
title: "🗄️ 数据库安全与加密 (Database Security & Encryption)"
category: 数据安全与隐私
category_en: "Data Security & Privacy"
difficulty: ★★★
tools: "Vault, CipherTrust, SQL Audit Tools, pgAudit, MySQL Audit Plugin"
last_updated: 2025-07
tags: ["data-security", "privacy", "dlp", "gdpr", "encryption", "data-classification"]
subdomain: data-security-privacy
nist_csf: ["PR.DS-01", "PR.DS-02", "PR.DS-05", "ID.GV-03"]
mitre_attack: ["T1530", "T1048", "T1567"]
---
# 🗄️ 数据库安全与加密 (Database Security & Encryption)

## 概述

数据库安全涵盖访问控制、审计日志、加密（TDE/列加密）、备份安全和配置加固。保障数据在存储层和应用层的机密性、完整性和可用性。支持关系型、NoSQL和云数据库。

## 核心技能

### 1. 数据库访问控制与身份认证

```sql
-- MySQL 安全配置
-- 创建专门的应用账户（最小权限）
CREATE USER 'app_user'@'10.0.0.%' IDENTIFIED BY 'strong_password_here';
GRANT SELECT, INSERT, UPDATE ON mydb.* TO 'app_user'@'10.0.0.%';
-- 拒绝DDL权限
REVOKE DROP, ALTER, CREATE ON mydb.* FROM 'app_user'@'10.0.0.%';

-- 强制SSL连接
ALTER USER 'app_user'@'10.0.0.%' REQUIRE SSL;

-- 账户锁定策略
ALTER USER 'app_user'@'10.0.0.%' 
  PASSWORD EXPIRE INTERVAL 90 DAY
  FAILED_LOGIN_ATTEMPTS 5
  PASSWORD_LOCK_TIME 1;

-- PostgreSQL 行级安全
CREATE POLICY user_policy ON users 
  USING (user_id = current_setting('app.current_user')::int);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- MongoDB 角色管理
db.createRole({
  role: "appReadWrite",
  privileges: [
    { resource: { db: "app", collection: "" }, actions: ["find", "insert", "update"] }
  ],
  roles: []
});
db.createUser({user: "app_user", pwd: "password", roles: ["appReadWrite"]});
```

### 2. 透明数据加密 (TDE)

```sql
-- SQL Server TDE
-- 创建主密钥
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'StrongPassword123!';

-- 创建证书
CREATE CERTIFICATE TDECert WITH SUBJECT = 'TDE Certificate';

-- 创建数据库加密密钥
USE MyDatabase;
CREATE DATABASE ENCRYPTION KEY
  WITH ALGORITHM = AES_256
  ENCRYPTION BY SERVER CERTIFICATE TDECert;

-- 启用TDE
ALTER DATABASE MyDatabase SET ENCRYPTION ON;

-- 检查TDE状态
SELECT DB_NAME(database_id) AS DBName, 
       encryption_state_desc = CASE encryption_state
         WHEN 0 THEN 'No encryption'
         WHEN 1 THEN 'Unencrypted'
         WHEN 2 THEN 'Encryption in progress'
         WHEN 3 THEN 'Encrypted'
         WHEN 4 THEN 'Key change in progress'
         WHEN 5 THEN 'Decryption in progress'
       END
FROM sys.dm_database_encryption_keys;

-- MySQL TDE (企业版)
-- 在my.cnf中配置
-- early-plugin-load=keyring_file.so
-- keyring_file_data=/var/lib/mysql-keyring/keyring
-- 创建加密表空间
CREATE TABLESPACE secure_ts ADD DATAFILE 'secure.ibd'
  ENCRYPTION='Y' DEFAULT STORAGE ENGINE=InnoDB;
CREATE TABLE secure_data (id INT, data VARCHAR(100)) TABLESPACE secure_ts;
```

### 3. 列级加密

```sql
-- PostgreSQL pgcrypto 列加密
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 对称加密 (列级)
-- 插入加密数据
INSERT INTO users (name, ssn, credit_card)
VALUES (
  '张三',
  pgp_sym_encrypt('123-45-6789', 'encryption_key'),
  pgp_sym_encrypt('4111-1111-1111-1111', 'encryption_key')
);

-- 查询解密
SELECT 
  name,
  pgp_sym_decrypt(ssn, 'encryption_key') AS ssn,
  pgp_sym_decrypt(credit_card, 'encryption_key') AS credit_card
FROM users WHERE name = '张三';

-- 非对称加密
-- 生成密钥对
SELECT gen_keypair('RSA', 2048) INTO keypair;

-- 使用公钥加密
UPDATE users SET ssn_encrypted = pgp_pub_encrypt('123-45-6789', dearmor(public_key));

-- MySQL AES加密
INSERT INTO users (name, ssn)
VALUES ('张三', AES_ENCRYPT('123-45-6789', 'encryption_key'));
SELECT name, AES_DECRYPT(ssn, 'encryption_key') AS ssn FROM users;
```

### 4. 数据库审计与监控

```bash
# PostgreSQL pgAudit 配置
# 在 postgresql.conf 中
shared_preload_libraries = 'pgaudit'
pgaudit.log = 'read,write,role,ddl'
pgaudit.log_catalog = off
pgaudit.log_level = 'notice'
pgaudit.log_relation = on

# 重启后设置审计规则
CREATE EXTENSION pgaudit;
# 会话级审计
SET pgaudit.session_level_read = on;
SET pgaudit.session_level_write = on;

# 对象级审计
SELECT audit.audit_table('users');
SELECT audit.audit_table('orders', 'insert,update,delete');

# 查看审计日志
SELECT * FROM pgaudit.log WHERE audit_type = 'DDL' ORDER BY event_time DESC;

# MySQL Audit Plugin (MariaDB)
# 安装插件
INSTALL SONAME 'server_audit';
# 配置审计
SET GLOBAL server_audit_logging = ON;
SET GLOBAL server_audit_events = 'CONNECT,QUERY,TABLE';
SET GLOBAL server_audit_incl_users = 'app_user,admin';
SET GLOBAL server_audit_file_rotate_size = 100000000;  # 100MB

# Oracle 审计
AUDIT SELECT, INSERT, UPDATE, DELETE ON app.users BY ACCESS;
AUDIT EXECUTE ON app.procedure_name;
AUDIT CREATE ANY TABLE BY admin;
```

### 5. 数据库安全基线加固

```ini
# MySQL 安全基线配置 (my.cnf)
[mysqld]
# 禁用local infile
local-infile=0
# 禁用符号链接
skip-symbolic-links=yes
# 禁用远程root登录
skip-networking=0
bind-address=127.0.0.1
# 最大连接数限制
max_connections=1000
max_user_connections=50
# 连接超时
connect_timeout=10
wait_timeout=600
# 密码策略
validate_password.policy=STRONG
validate_password.length=12
# 日志配置
log_error=/var/log/mysql/error.log
slow_query_log=ON
general_log=OFF
# SSL配置
ssl-ca=/etc/mysql/ssl/ca.pem
ssl-cert=/etc/mysql/ssl/server-cert.pem
ssl-key=/etc/mysql/ssl/server-key.pem

# PostgreSQL 安全基线 (postgresql.conf)
# 连接安全
listen_addresses = 'localhost'
password_encryption = 'scram-sha-256'
ssl = on
ssl_ciphers = 'HIGH:MEDIUM:+3DES:!aNULL'
# 审计日志
logging_collector = on
log_directory = 'pg_log'
log_filename = 'postgresql-%Y-%m-%d.log'
log_statement = 'ddl'
log_line_prefix = '%t %u %d %p %r '
log_checkpoints = on
log_connections = on
log_disconnections = on
log_lock_waits = on
log_temp_files = 0
# 查询控制
statement_timeout = 30000
idle_in_transaction_session_timeout = 60000
```

### 6. 数据库备份安全与恢复

```bash
# 加密数据库备份
# MySQL 加密备份
mysqldump --all-databases --single-transaction --routines --triggers | \
  gpg --encrypt --recipient backup-key@company.com > mysql_backup_$(date +%Y%m%d).sql.gpg

# PostgreSQL 加密备份
pg_dumpall | gzip | \
  openssl enc -aes-256-cbc -salt -pass pass:backup_password > pg_backup_$(date +%Y%m%d).sql.gz.enc

# MongoDB 加密备份
mongodump --archive | gzip | \
  openssl enc -aes-256-cbc -salt -pass pass:backup_password > mongo_backup.archive.gz.enc

# 备份完整性验证
# 校验PGP签名
gpg --verify backup.sql.gpg.sig backup.sql.gpg
# 校验SHA256
sha256sum -c backup.sha256

# 备份恢复演练
# 解密并恢复
openssl enc -d -aes-256-cbc -in backup.sql.gz.enc -pass pass:backup_password | \
  gunzip | mysql -u root -p
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| HashiCorp Vault | 密钥管理与数据库动态凭据 | https://www.vaultproject.io/ |
| Thales CipherTrust | 企业级数据库加密 | https://cpl.thalesgroup.com/ |
| pgAudit | PostgreSQL审计 | https://www.pgaudit.org/ |
| MySQL Audit Plugin | MariaDB/MySQL审计 | https://mariadb.com/kb/en/server_audit/ |
| DbProtect | 数据库安全扫描 | https://www.trustwave.com/ |
| SQLMap | 数据库注入检测 | https://sqlmap.org/ |

## 参考资源

- [OWASP Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
- [CIS Database Security Benchmarks](https://www.cisecurity.org/benchmark/database/)
- [NIST SP 800-53 — System and Communications Protection](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [MongoDB Security Checklist](https://www.mongodb.com/docs/manual/administration/security-checklist/)
- [PostgreSQL Security Best Practices](https://www.postgresql.org/docs/current/security.html)
