---
id: 27-003
title: "Linux安全加固与基线检查 (Linux Hardening & Baseline)"
category: 操作系统安全
category_en: "OS Security"
difficulty: ★★★
tools: "CIS Benchmarks, 等保2.0, Lynis, OpenSCAP, auditd, SELinux, AppArmor"
last_updated: 2026-05
tags: ["os-security", "windows-hardening", "linux-hardening", "macos", "privilege-escalation"]
subdomain: os-security
nist_csf: ["PR.AC-01", "PR.DS-07", "PR.PT-01"]
mitre_attack: ["T1548", "T1552", "T1562"]
---
# Linux安全加固与基线检查 (Linux Hardening & Baseline)

## 概述

Linux 系统是企业基础设施的核心组成部分，安全加固是防范攻击的第一道防线。本技能以 CIS Linux Benchmarks、等保2.0 三级要求、NIST SP 800-53 为参考，系统化覆盖 Linux 内核参数调优、身份鉴别与访问控制、SELinux/AppArmor 强制访问控制、系统审计、网络层加固等关键领域，适用于 CentOS/RHEL、Ubuntu、Debian 等主流发行版。

## 核心技能

### 1. 系统基线检查与合规评估

```bash
# 使用 Lynis 进行全面安全审计
# 安装 Lynis
sudo apt-get install lynis        # Debian/Ubuntu
sudo yum install lynis             # RHEL/CentOS
# 运行系统审计
sudo lynis audit system
# 查看审计报告
sudo lynis show details

# 使用 OpenSCAP 进行合规扫描
# RHEL/CentOS 安装
sudo yum install openscap-scanner scap-security-guide
# 运行 CIS 基准扫描
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --results-arf results.xml \
  --report report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml

# Debian/Ubuntu 安装
sudo apt-get install libopenscap8
# 运行 DISA STIG 扫描
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_stig \
  --results-arf results.xml \
  --report report.html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml

# 等保2.0 三级自查脚本
# 身份鉴别（三级）
grep "^PASS_MAX_DAYS" /etc/login.defs        # 应 ≤ 90
grep "^PASS_MIN_LEN" /etc/login.defs         # 应 ≥ 8
grep "^FAIL_DELAY" /etc/login.defs            # 登录失败延迟

# 检查密码复杂度配置
cat /etc/pam.d/common-password | grep pam_pwquality.so
# 应包含: minlen=12, dcredit=-1, ucredit=-1, ocredit=-1, lcredit=-1

# 用户登录失败锁定
grep "pam_tally2" /etc/pam.d/common-auth
# 或使用 pam_faillock
grep "pam_faillock" /etc/pam.d/common-auth
```

### 2. 身份鉴别与访问控制

```bash
# 密码策略配置（/etc/login.defs）
cat >> /etc/login.defs << 'EOF'
PASS_MAX_DAYS   90
PASS_MIN_DAYS   1
PASS_MIN_LEN    12
PASS_WARN_AGE   7
EOF

# PAM 密码质量配置
# RHEL/CentOS 配置 /etc/security/pwquality.conf
cat >> /etc/security/pwquality.conf << 'EOF'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 3
gecoscheck = 1
EOF

# SSH 安全加固
cat >> /etc/ssh/sshd_config << 'EOF'
# 禁用 root 远程登录
PermitRootLogin no
# 使用密钥认证
PubkeyAuthentication yes
PasswordAuthentication no
# 限制协议版本
Protocol 2
# 禁用空密码
PermitEmptyPasswords no
# 设置闲置超时
ClientAliveInterval 300
ClientAliveCountMax 0
# 限制登录用户
AllowUsers adminuser opsuser
# 禁用转发
AllowTcpForwarding no
X11Forwarding no
EOF
systemctl restart sshd

# 配置 sudo 权限审计
cat >> /etc/sudoers.d/audit << 'EOF'
Defaults logfile=/var/log/sudo.log
Defaults log_input, log_output
Defaults passwd_tries=3
Defaults badpass_message="Unauthorized access attempt"
EOF
```

### 3. 强制访问控制（SELinux / AppArmor）

```bash
# ===== SELinux（RHEL/CentOS/Fedora） =====

# 检查 SELinux 状态
getenforce
sestatus

# 配置为强制模式
sudo setenforce 1                   # 立即生效
# 持久化配置（/etc/selinux/config）
sudo sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config

# SELinux 布尔值管理
getsebool -a
# 允许 httpd 网络连接
sudo setsebool -P httpd_can_network_connect on

# SELinux 上下文管理
# 查看文件上下文
ls -Z /var/www/html/
# 恢复默认上下文
sudo restorecon -Rv /var/www/html/
# 自定义上下文
sudo semanage fcontext -a -t httpd_sys_content_t "/web(/.*)?"
sudo restorecon -Rv /web/

# SELinux 审计日志分析
sudo ausearch -m avc -ts recent
sudo sealert -a /var/log/audit/audit.log

# ===== AppArmor（Ubuntu/Debian） =====

# 检查 AppArmor 状态
sudo aa-status
sudo apparmor_status

# 加载/卸载配置文件
sudo aa-enforce /path/to/profile
sudo aa-complain /path/to/profile  # 仅记录不阻止

# 创建自定义 AppArmor 配置文件
# 示例：限制 nginx
cat > /etc/apparmor.d/usr.sbin.nginx << 'EOF'
#include <tunables/global>

/usr/sbin/nginx {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  /usr/sbin/nginx mr,
  /var/log/nginx/*.log w,
  /var/www/html/ r,
  /var/www/html/** r,
  /etc/nginx/** r,
}
EOF
sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.nginx
```

### 4. 内核参数与系统层加固

```bash
# sysctl 内核参数安全配置
cat >> /etc/sysctl.d/99-security.conf << 'EOF'
# IP 转发（除非需要路由功能，否则禁用）
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# 禁用源路由验证
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# 启用反向路径过滤
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# 禁用 ICMP 重定向
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0

# 防止 SYN Flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_synack_retries = 2

# 日志伪造的包
net.ipv4.conf.all.log_martians = 1

# 禁用 magic SysRq
kernel.sysrq = 0

# 限制核心转储
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
EOF
sudo sysctl -p /etc/sysctl.d/99-security.conf

# 禁用不必要的内核模块
cat > /etc/modprobe.d/blacklist.conf << 'EOF'
# USB 存储
blacklist usb-storage
# 蓝牙
blacklist bluetooth
# FireWire
blacklist firewire-core
# 不常见的文件系统
blacklist cramfs
blacklist freevxfs
blacklist jffs2
blacklist hfs
blacklist hfsplus
blacklist squa
blacklist udf
EOF

# 设置 bootloader 密码
# GRUB2（CentOS/RHEL）
sudo grub2-setpassword
# GRUB（Ubuntu）
# 编辑 /etc/grub.d/40_custom 添加密码
# sudo update-grub
```

```bash
# seccomp 限制（使用 Docker/containerd 时自动生效）
# 查看 seccomp 模式
grep Seccomp /proc/1/status

# 使用 strace 检查系统调用
strace -c -p <PID>
```

### 5. 审计与日志监控

```bash
# auditd 审计系统配置
sudo apt-get install auditd audispd-plugins    # Debian/Ubuntu
sudo yum install audit                          # RHEL/CentOS

# 配置审计规则
cat > /etc/audit/rules.d/audit.rules << 'EOF'
# 删除所有现有规则
-D

# 缓冲区大小（改为 8192）
-b 8192

# 失败模式（0=silent, 1=print, 2=panic）
-f 1

# 系统管理员操作
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# 用户和组管理
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity

# 登录事件
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# 网络配置
-w /etc/hosts -p wa -k network
-w /etc/sysconfig/network -p wa -k network

# 系统关键文件
-w /etc/ssh/sshd_config -p wa -k sshd

# 进程监控
-a always,exit -S execve -k command_audit

# 时间修改
-a always,exit -S adjtimex -S settimeofday -S clock_settime -k time_change

# 内核模块加载
-w /sbin/insmod -p x -k module_insert
-w /sbin/modprobe -p x -k module_insert
-w /sbin/rmmod -p x -k module_remove
EOF

# 重启 auditd 服务
sudo systemctl restart auditd
sudo systemctl enable auditd

# 审计日志查询
sudo ausearch -k sudoers_changes -ts today
sudo ausearch -k identity -ts 24小时前
sudo augenrules --check

# 日志安全配置（rsyslog）
cat > /etc/rsyslog.d/security.conf << 'EOF'
# 认证日志分离
auth,authpriv.*                 /var/log/auth.log
# 内核日志
kern.*                          /var/log/kern.log
# 所有日志发送到远程日志服务器（防篡改）
*.*                             @logserver.domain.com:514
EOF
sudo systemctl restart rsyslog

# 日志完整性保护
sudo chattr +a /var/log/auth.log
sudo chattr +a /var/log/syslog
```

```bash
# 使用 osquery 进行实时系统监控
# 安装 osquery
sudo curl -L https://pkg.osquery.io/deb/osquery_5.9.1_1.linux_amd64.deb -o osquery.deb
sudo dpkg -i osquery.deb

# 运行查询
osqueryi "SELECT * FROM processes WHERE on_disk = 0;"                  # 无文件进程检测
osqueryi "SELECT * FROM listening_ports;"                              # 监听端口
osqueryi "SELECT * FROM socket_events WHERE time > $(date +%s) - 3600;" # 过去1小时连接
osqueryi "SELECT * FROM crontab;"                                      # 计划任务审计
osqueryi "SELECT * FROM kernel_modules;"                               # 内核模块
osqueryi "SELECT * FROM suid_bin WHERE username != 'root';"            # 非root SUID二进制
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Lynis | Linux 安全审计工具 | https://cisofy.com/lynis/ |
| OpenSCAP | SCAP 合规扫描 | https://www.open-scap.org/ |
| auditd | Linux 审计系统 | https://linux.die.net/man/8/auditd |
| osquery | 系统监控查询引擎 | https://osquery.io/ |
| Lynis | 系统堡垒测试 | https://cisofy.com/lynis/ |
| SELinux | 强制访问控制 | https://selinuxproject.org/ |
| AppArmor | 应用安全隔离 | https://apparmor.net/ |

## 参考资源

- [CIS Linux Benchmarks](https://www.cisecurity.org/benchmark/linux_os)
- [CIS Red Hat Enterprise Linux Benchmarks](https://www.cisecurity.org/benchmark/red_hat_linux)
- [CIS Ubuntu Linux Benchmarks](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [GB/T 22239-2019 信息安全技术 网络安全等级保护基本要求](https://openstd.samr.gov.cn/)
- [NIST SP 800-53 Rev 5 — AC Access Control](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [Linux Kernel Security — Kernel.org](https://www.kernel.org/doc/html/latest/admin-guide/security.html)
- [SELinux Documentation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/using_selinux/index)
- [MITRE ATT&CK — T1548 Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)
