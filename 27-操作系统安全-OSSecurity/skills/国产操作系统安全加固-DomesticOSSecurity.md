---
id: 27-006
title: "国产操作系统安全加固 (Domestic OS Security Hardening)"
category: 操作系统安全
category_en: "OS Security"
difficulty: ★★★
tools: "KylinOS, UOS, openEuler, 等保2.0, SM2/SM3/SM4, kylin-security-toolkit"
last_updated: 2026-05
tags: ["os-security", "windows-hardening", "linux-hardening", "macos", "privilege-escalation"]
subdomain: os-security
nist_csf: ["PR.AC-01", "PR.DS-07", "PR.PT-01"]
mitre_attack: ["T1548", "T1552", "T1562"]
---
# 国产操作系统安全加固 (Domestic OS Security Hardening)

## 概述

国产操作系统在政府、军工、金融、能源等关键基础设施领域的部署快速增长，其安全加固能力直接关系到国家安全。本技能覆盖银河麒麟（KylinOS）、统信 UOS、华为 openEuler 等主流国产操作系统的安全加固实践，以等保2.0 三级要求为核心基线，结合 GB/T 39786-2021《信息安全技术 操作系统安全技术要求》和 CIS 基准的适用部分，系统覆盖身份鉴别、访问控制、安全审计、密码合规（SM2/SM3/SM4国密算法）、可信计算等核心领域。

## 核心技能

### 1. 身份鉴别与用户安全管理

```bash
# ===== 银河麒麟 KylinOS V10 =====

# 密码策略配置（等保2.0 三级要求）
# 编辑 /etc/security/pwquality.conf
cat >> /etc/security/pwquality.conf << 'EOF'
minlen = 12                    # 密码最小长度 ≥ 8（三级要求）
dcredit = -1                   # 至少1个数字
ucredit = -1                   # 至少1个大写字母
lcredit = -1                   # 至少1个小写字母
ocredit = -1                   # 至少1个特殊字符
minclass = 4                   # 至少4种字符类型
maxrepeat = 3                  # 最多连续重复3个字符
difok = 5                      # 新密码至少5个字符不同
gecoscheck = 1                 # 检查是否包含用户信息
enforce_for_root               # 也应用于 root 用户
EOF

# 登录失败锁定策略（三级要求：≤5次）
cat > /etc/pam.d/common-auth << 'EOF'
auth     required       pam_env.so
auth     required       pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth     [success=1 default=ignore] pam_unix.so nullok
auth     [default=die]  pam_faillock.so authfail audit deny=5 unlock_time=900
auth     sufficient     pam_faillock.so authsucc audit deny=5 unlock_time=900
auth     required       pam_deny.so
EOF

# 登录超时退出
echo "TMOUT=600" >> /etc/profile
echo "export TMOUT" >> /etc/profile

# 麒麟安全策略工具
# kylin-security-toolkit 图形化工具
kylin-security-toolkit --set-password-policy

# 检查麒麟系统安全级别
cat /etc/sysconfig/kysec/security-level
# 设置安全级别（high/medium/low）
sudo kylin-security-config --set-level high

# ===== 统信 UOS V20 =====

# 密码复杂度（统信安全中心）
sudo uos-security-center --set-password-policy "minlen=12;minclass=4"

# UOS 安全中心命令行
sudo uos-security-center --status
sudo uos-security-center --enable-firewall
sudo uos-security-center --enable-login-security

# 用户登录限制
echo "DenyUsers=baduser" >> /etc/ssh/sshd_config
echo "AllowUsers=admin audit" >> /etc/ssh/sshd_config
systemctl restart sshd
```

### 2. 强制访问控制（MAC）与安全标记

```bash
# ===== 银河麒麟 KylinOS — 麒麟安全体系（KYSEC） =====

# KYSEC 状态检查
sudo kylin-security-config --status
# 预期输出类似：KYSEC level: high, Firewall: enabled, Audit: enabled

# KYSEC 强制访问控制策略
# 设置安全级别为高（启用强制访问控制）
sudo kylin-security-config --set-level high

# 查看进程安全标记
ps -Z
# 查看文件安全标记
ls -Z /etc/passwd

# KYSEC 策略管理
# 配置主体安全标记
sudo kysec-tools --set-subject-label /usr/sbin/sshd label:system_high

# 配置客体安全标记
sudo kysec-tools --set-object-label /etc/shadow label:secret

# 查看审计日志中的 KYSEC 事件
sudo ausearch -m KYMSG -ts today

# ===== 华为 openEuler — iSula 安全 =====

# iSula 安全容器配置
sudo isula info | grep -i security
# 启用 seccomp（系统调用过滤）
sudo isula run --security-opt seccomp=/path/to/seccomp-profile.json nginx

# openEuler 的 secGear 机密计算
# 使用 secGear 开发安全应用
sudo dnf install secgear-devel
secgear-env-setup
```

```bash
# ===== 统信 UOS — 安全策略统一管理 =====

# UOS 强制访问控制（DEEPIN MAC）
# 查看 MAC 策略
sudo dde-security-tools --mac-status
# 启用 MAC
sudo dde-security-tools --mac-enable

# UOS 应用沙箱
# 在沙箱中运行应用
sudo dde-sandbox run /path/to/application

# UOS 外设管控
# 禁用 USB 存储
sudo dde-security-tools --usb-storage disable
# 查看外设管控策略
sudo dde-security-tools --peripheral-policy
```

### 3. 国密算法（SM系列）合规配置

```bash
# ===== SM2/SM3/SM4 国密算法配置 =====

# 银河麒麟 — 使用国密 SSL
# 查看系统支持的加密算法
openssl list -cipher-algorithms | grep SM
openssl list -digest-algorithms | grep SM
openssl ecparam -list_curves | grep SM

# Nginx 启用国密 SSL（SM2证书）
cat > /etc/nginx/conf.d/ssl-sm.conf << 'EOF'
server {
    listen 443 ssl;
    
    # SM2 双证书（加密证书 + 签名证书）
    ssl_certificate     /etc/ssl/sm2/sm2_sign_cert.pem;
    ssl_certificate_key /etc/ssl/sm2/sm2_sign_key.pem;
    ssl_certificate     /etc/ssl/sm2/sm2_enc_cert.pem;
    ssl_certificate_key /etc/ssl/sm2/sm2_enc_key.pem;
    
    # 国密加密套件
    ssl_ciphers 'ECC-SM2-SM4-SM3:ECDHE-SM2-SM4-SM3';
    ssl_protocols TLSv1.1 TLSv1.2;
}
EOF

# SSH 使用 SM2 密钥
# 生成 SM2 密钥对
openssl ecparam -genkey -name SM2 -out ~/.ssh/sm2_key
openssl req -new -key ~/.ssh/sm2_key -out ~/.ssh/sm2_cert.csr -sm3

# SM4 文件加密
# 使用 SM4 加密文件
openssl enc -sm4-cbc -in secret.txt -out secret.txt.enc -K <hex_key> -iv <hex_iv>

# SM3 哈希校验
openssl dgst -sm3 /path/to/file
# 使用 gmssl 工具（国密 OpenSSL 分支）
gmssl sm3sum /path/to/file

# ===== openEuler — 国密支持 =====

# 安装国密算法包
sudo dnf install gmssl

# 使用 GMTLS（国密 TLS）
sudo dnf install gmtls
gmtls_server --cert sm2_cert.pem --key sm2_key.pem

# 检查系统 CA 证书中是否包含国密根证书
trust list | grep -i sm2
```

### 4. 日志审计与安全合规

```bash
# ===== 等保2.0 三级审计要求实施 =====

# 银河麒麟 — 安全审计配置
# KYSEC 审计配置
sudo kysec-tools --audit-config << 'EOF'
audit_rules:
  - identity_management: all
  - access_control: all
  - privilege_use: all
  - process_creation: all
  - network_connection: all
  - file_modification: /etc, /usr/bin, /usr/sbin
  - retention_days: 180     # 日志保存 ≥ 180天（三级要求）
EOF

# UOS — 审计日志管理
sudo uos-audit-tool --enable --level verbose
# 查看审计日志
sudo uos-audit-tool --query --since "2025-01-01" --until "2026-01-01"

# 通用 Linux 审计（适用于所有国产 OS）
# auditd 配置 — 等保2.0 三级审计规则
cat > /etc/audit/rules.d/djcp30.rules << 'EOF'
# 删除现有规则
-D
-b 16384

# 记录所有管理的用户、组、密码变更
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/ -p wa -k identity

# 记录所有特权执行
-a always,exit -S execve -F euid=0 -k privileged_command

# 记录系统管理行为
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# 记录网络配置变更
-w /etc/hosts -p wa -k network_config
-w /etc/sysconfig/ -p wa -k network_config

# 记录内核模块加载
-w /sbin/insmod -p x -k kernel_module
-w /sbin/modprobe -p x -k kernel_module
-w /sbin/rmmod -p x -k kernel_module

# 记录时间同步
-a always,exit -S adjtimex -S settimeofday -S clock_settime -k time
EOF

# 加载审计规则
sudo augenrules --load
sudo systemctl restart auditd

# 审计日志远程存储（满足三级保留要求）
cat > /etc/audisp/audisp-remote.conf << 'EOF'
remote_server = logcenter.domain.com
port = 60
transport = tcp
format = managed
EOF
sudo systemctl restart audispd

# 日志完整性保护
sudo chattr +a /var/log/audit/audit.log
sudo chattr +a /var/log/messages

# 等保自查脚本（适用于国产 OS）
cat > /usr/local/bin/djcp_check.sh << 'EOF'
#!/bin/bash
# 等保2.0 三级自查脚本

echo "=== 身份鉴别 ==="
echo "密码最大有效期: $(grep ^PASS_MAX_DAYS /etc/login.defs | awk '{print $2}')天（要求≤90）"
echo "密码最小长度: $(grep ^PASS_MIN_LEN /etc/login.defs | awk '{print $2}')位（要求≥8）"
echo "登录失败锁定: $(grep 'deny=' /etc/pam.d/common-auth | head -1)"

echo "=== 访问控制 ==="
echo "SELinux/KYSEC: $(getenforce 2>/dev/null || kylin-security-config --status 2>/dev/null)"

echo "=== 安全审计 ==="
echo "auditd 状态: $(systemctl is-active auditd)"
echo "审计日志大小: $(du -sh /var/log/audit/ 2>/dev/null)"

echo "=== 入侵防范 ==="
echo "最小权限原则检查:"
find / -perm -4000 -type f 2>/dev/null | wc -l
EOF
chmod +x /usr/local/bin/djcp_check.sh
```

### 5. 国产操作系统典型安全配置

```bash
# ===== 银河麒麟 KylinOS V10 — 安全加固常用配置 =====

# 关闭不必要的系统服务
systemctl disable bluetooth.service
systemctl disable cups.service
systemctl disable avahi-daemon.service
systemctl disable postfix.service

# 麒麟系统更新源配置
cat > /etc/apt/sources.list << 'EOF'
# 麒麟官方更新源
deb http://archive.kylinos.cn/kylin/KYLIN-ALL 10.1 main universe multiverse
EOF
sudo apt update && sudo apt upgrade -y

# 麒麟防火墙配置（基于 iptables/nftables）
sudo kylin-firewall --add-rule --service ssh --accept
sudo kylin-firewall --add-rule --port 443 --tcp --accept
sudo kylin-firewall --set-default-policy drop

# 禁用 kernel 转储
echo "kernel.core_pattern = |/bin/false" > /etc/sysctl.d/99-disable-core.conf
sudo sysctl -p /etc/sysctl.d/99-disable-core.conf

# 启用 ASLR
echo "kernel.randomize_va_space = 2" > /etc/sysctl.d/99-aslr.conf
sudo sysctl -p /etc/sysctl.d/99-aslr.conf

# ===== 统信 UOS V20 — 安全配置 =====

# UOS 安全中心一键扫描
sudo uos-security-center --full-scan

# UOS 应用商店安全配置
sudo uos-app-store --set-security-mode strict

# 配置 USB 设备白名单
sudo dde-security-tools --usb-whitelist add "VID:PID"

# 启用 UOS 远程安全认证
sudo uos-remote-security enable

# ===== 华为 openEuler — 安全配置 =====

# openEuler 安全加固工具
# A-Tune 自动性能/安全调优
sudo dnf install a-tune
sudo systemctl start a-tuned
sudo a-tune-profile set security

# openEuler secPaver 安全策略
sudo dnf install secpaver
sudo secpaver create-policy --type mac
sudo secpaver deploy-policy --policy default_mac

# openEuler 内核热补丁
sudo dnf install kernel-hotpatch
sudo kpatch list
```

```bash
# ===== 关键目录与文件权限加固 =====

# GRUB 启动加载器密码保护
# /etc/grub.d/40_custom
echo 'set superusers="admin"' >> /etc/grub.d/40_custom
echo 'password_pbkdf2 admin grub.pbkdf2.sha512.10000...' >> /etc/grub.d/40_custom
sudo update-grub

# 单用户模式认证保护
# 要求单用户模式输入 root 密码
echo "-:S:wait:/sbin/sulogin" >> /etc/inittab

# 关键系统文件加固
sudo chmod 600 /etc/shadow
sudo chmod 644 /etc/passwd
sudo chmod 644 /etc/group
sudo chattr +i /etc/shadow       # 防止意外删除

# 目录权限严格化
sudo chmod 750 /home           # 限制用户目录访问
sudo chmod 750 /root           # root 家目录
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| kylin-security-toolkit | 麒麟安全配置工具集 | https://www.kylinos.cn/ |
| uos-security-center | 统信安全中心 | https://www.uniontech.com/ |
| a-tune | openEuler 智能调优工具 | https://gitee.com/openeuler/A-Tune |
| secPaver | openEuler 安全策略管理 | https://gitee.com/openeuler/secpaver |
| gmssl | 国密算法 OpenSSL 分支 | https://github.com/guanzhi/GmSSL |
| secGear | openEuler 机密计算框架 | https://gitee.com/openeuler/secGear |
| Lycium | 国产 OS 安全测试工具 | https://gitee.com/ |

## 参考资源

- [GB/T 22239-2019 信息安全技术 网络安全等级保护基本要求](https://openstd.samr.gov.cn/)
- [GB/T 39786-2021 信息安全技术 操作系统安全技术要求](https://openstd.samr.gov.cn/)
- [银河麒麟 KylinOS 安全配置指南](https://www.kylinos.cn/support/technical.html)
- [统信 UOS 安全加固手册](https://www.uniontech.com/docs/)
- [华为 openEuler 安全指南](https://docs.openeuler.org/zh/docs/24.03_LTS/docs/security/security.html)
- [GM/T 0009-2012 SM2 密码算法使用规范](https://www.cryptorchina.com/)
- [GM/T 0010-2012 SM3 密码杂凑算法](https://www.cryptorchina.com/)
- [CIS Benchmarks for Linux (适用部分)](https://www.cisecurity.org/benchmark/linux_os)
- [MITRE ATT&CK — 中文版](https://attack.mitre.org/resources/versions/)
