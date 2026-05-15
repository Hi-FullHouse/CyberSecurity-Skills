---
id: 14-007
title: "🔧 配置安全审计 (Configuration Security Audit)"
category: 安全审计
category_en: "Security Audit"
difficulty: ★★★
tools: "Lynis, OpenSCAP, CIS-CAT, Chef InSpec"
last_updated: 2025-07
tags: ["security-audit", "compliance", "cloud-audit", "container-audit", "network-audit"]
subdomain: security-audit
nist_csf: ["ID.GV-01", "ID.RM-01", "ID.SC-01"]
mitre_attack: []
---
# 🔧 配置安全审计 (Configuration Security Audit)

## 概述
对操作系统、数据库、中间件、网络设备进行安全配置核查，发现配置不当导致的潜在安全风险，依据CIS Benchmarks等基线标准进行评估。

## 核心技能

### 1. 操作系统安全配置审计

**Linux安全基线（CIS Benchmark）：**
```bash
# 用户与认证
grep "^PASS_MAX_DAYS" /etc/login.defs       # 密码最长有效期（≤90天）
grep "^PASS_MIN_LEN" /etc/login.defs        # 密码最小长度（≥8）
grep "^UMASK" /etc/login.defs                # 默认umask（027）

# 文件权限
find / -perm -4000 -type f 2>/dev/null      # 查找SUID文件
find / -perm -2000 -type f 2>/dev/null      # 查找SGID文件
ls -la /etc/shadow                           # shadow文件权限（600）

# 服务管理
systemctl list-unit-files --type=service | grep enabled  # 开机自启服务
ss -tlnp                                       # 监听端口
```

**Windows安全基线：**
```powershell
# 密码策略
net accounts /domain
Get-ADDefaultDomainPasswordPolicy

# 审计策略
auditpol /get /category:*

# 用户权限
Get-LocalGroupMember -Group "Administrators"
Get-LocalUser | Where-Object {$_.Enabled -eq $true}

# 服务检查
Get-Service | Where-Object {$_.StartType -eq "Auto" -and $_.Status -eq "Running"}
```

### 2. 数据库安全配置审计

**MySQL安全基线：**
```sql
-- 检查匿名用户
SELECT User, Host FROM mysql.user WHERE User='';

-- 检查空密码
SELECT User, Host FROM mysql.user WHERE LENGTH(Password)=0 OR Password='';

-- 检查远程root登录
SELECT User, Host FROM mysql.user WHERE User='root' AND Host='%';

-- 查看当前运行用户
SELECT CURRENT_USER();

-- 文件权限检查
SHOW VARIABLES LIKE 'secure_file_priv';
```

**PostgreSQL安全基线：**
```bash
# 检查pg_hba.conf配置
cat $PGDATA/pg_hba.conf | grep -v "^#" | grep -v "^$"

# 检查SSL配置
psql -c "SHOW ssl;"
psql -c "SELECT * FROM pg_settings WHERE name LIKE '%ssl%';"

# 审计日志配置
psql -c "SHOW logging_collector;"
psql -c "SHOW log_directory;"
```

### 3. 网络设备安全配置审计

**Cisco设备安全基线：**
```text
! 1. AAA认证
aaa new-model
aaa authentication login default local
aaa authorization exec default local

! 2. SSH替代Telnet
ip ssh version 2
transport input ssh

! 3. 日志配置
logging buffered 16384
logging host 10.0.0.10
service timestamps log datetime msec

! 4. 密码加密
service password-encryption
enable secret MyStr0ngPassw0rd!

! 5. 安全功能
ip cef
no ip source-route
no ip http server
```

### 4. 中间件安全配置审计

**Nginx安全配置检查：**
```nginx
# 安全头
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Strict-Transport-Security "max-age=31536000" always;

# 隐藏版本号
server_tokens off;

# 限制请求方法
if ($request_method !~ ^(GET|HEAD|POST)$ ) { return 405; }

# 限制请求速率
limit_req_zone $binary_remote_addr zone=one:10m rate=30r/m;
```

### 5. 自动化配置审计工具

```bash
# Lynis - Linux系统审计
lynis audit system
lynis audit system --quick

# OpenSCAP - 合规检查
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis \
  --results results.xml /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml

# CIS-CAT Pro - CIS官方工具
java -jar CIS-CAT.jar -a -b benchmark/CIS_Ubuntu_Linux_20.04_LTS_Benchmark_v1.1.0-xccdf.xml
```

## 常用工具
| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Lynis | Linux安全审计 | https://cisofy.com/lynis/ |
| OpenSCAP | 合规扫描框架 | https://www.open-scap.org/ |
| CIS-CAT | CIS官方配置评估工具 | https://learn.cisecurity.org/cis-cat |
| JTR (JtR) | 密码强度审计 | https://www.openwall.com/john/ |
| Nmap NSE | 配置扫描脚本 | https://nmap.org/nsedoc/ |

## 参考资源
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [Center for Internet Security](https://www.cisecurity.org/)
