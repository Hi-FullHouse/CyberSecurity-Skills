---
id: "30-004"
title: "Linux数字取证分析 (Linux Digital Forensics)"
category: "数字取证"
category_en: "Digital Forensics"
difficulty: "★★★★"
tools: "autopsy, sleuthkit, linux-ir, auditd, osquery, chkrootkit"
last_updated: "2026-05"
tags: [forensics, linux, system-analysis, artifact, incident-response]
subdomain: digital-forensics
nist_csf: [DE.AE-02, DE.CM-04, RS.AN-01]
mitre_attack: [T1059, T1505, T1543, T1546, T1554]
---

# Linux数字取证分析 (Linux Digital Forensics)

## 概述

Linux 系统在服务器和云环境中占据主导地位，也是攻击者常针对的目标。本技能覆盖 Linux 系统取证中的关键痕迹源，包括日志系统、文件系统时间轴、用户活动、持久化机制和 Rootkit 检测。

## 核心技能

### 1. Linux 日志取证

```bash
# 核心日志文件
/var/log/syslog      # 系统日志
/var/log/auth.log    # 认证日志（Ubuntu/Debian）
/var/log/secure      # 认证日志（RHEL/CentOS）
/var/log/messages    # 系统消息
/var/log/kern.log    # 内核日志
/var/log/cron        # Cron 任务日志
/var/log/audit/      # auditd 审计日志
/var/log/apache2/    # Apache 访问日志
/var/log/nginx/      # Nginx 访问日志
/var/log/btmp        # 登录失败记录
/var/log/wtmp        # 登录历史
/var/log/lastlog     # 最后登录时间

# 提取 SSH 暴力破解
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -20

# 提取所有成功的 SSH 登录
grep "Accepted password" /var/log/auth.log

# 提取 sudo 使用记录
grep "sudo" /var/log/auth.log

# 查看特权命令执行
ausearch -m COMMAND -ts recent

# auditd 审计规则 — 监控关键文件
/etc/audit/rules.d/audit.rules
# -w /etc/passwd -p wa -k passwd_changes
# -w /etc/shadow -p wa -k shadow_changes
# -w /etc/crontab -p wa -k cron_changes
# -w /etc/ssh/sshd_config -p wa -k sshd_config
# -w /bin/su -p x -k su_exec
# -w /usr/bin/sudo -p x -k sudo_exec
```

### 2. 用户与进程取证

```bash
# 当前登录用户
who
w

# 历史登录
last
lastb  # 失败的登录尝试
lastlog  # 所有用户最后登录

# 最近执行的命令
cat ~/.bash_history
cat ~/.zsh_history

# 提取所有用户的 bash_history
for user in $(ls /home/); do
    echo "=== $user ==="
    cat /home/$user/.bash_history 2>/dev/null
done

# 检查历史命令时间戳（如果启用 HISTTIMEFORMAT）
cat ~/.bash_history | awk '{print $1}' | sort | uniq -c

# 进程取证
# 查看所有进程（隐藏进程检测）
ps auxf
ps -ef

# 查看进程树
pstree -a

# 进程网络连接
netstat -tulpn
ss -tulpn

# /proc 文件系统分析（进程详细信息）
ls -la /proc/[pid]/
cat /proc/[pid]/cmdline    # 命令行参数
cat /proc/[pid]/environ    # 环境变量
ls -la /proc/[pid]/fd/     # 打开的文件描述符
cat /proc/[pid]/maps       # 内存映射

# 列出异常进程
# 1. 无关联二进制的进程
# 2. 隐藏进程（比较 ps 和 /proc 列表）
# 3. 从 /tmp /dev/shm 运行的进程
```

### 3. 文件系统时间轴

```bash
# 使用 Sleuth Kit 创建文件时间轴
# 获取文件系统元数据
fls -r -m / /dev/sda1 > body_file.txt

# 创建 MAC 时间轴
mactime -b body_file.txt -d > timeline.csv

# 使用 TSK 分析文件
# 查看 inode
istat /dev/sda1 123456

# 恢复已删除文件
icat /dev/sda1 123456 > recovered_file

# 文件系统时间戳分析
# stat 命令
stat /etc/passwd

# find 搜索
find / -xdev -mmin -60 -type f  # 过去60分钟修改的文件
find / -xdev -ctime -1 -type f  # 过去24小时元数据变化的文件
find / -xdev -atime -1 -type f  # 过去24小时访问的文件

# 检测时间戳修改（timestomping）
# 比较 ctime 和 atime 的巨大差距
```

```python
"""Linux 系统取证收集"""

import os
import subprocess
import json
from datetime import datetime

class LinuxForensicsCollector:
    """Linux 取证数据收集"""
    
    def __init__(self, output_dir):
        self.output = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def collect_system_info(self):
        """收集系统基本信息"""
        info = {}
        commands = {
            "hostname": "hostname",
            "kernel": "uname -a",
            "uptime": "uptime",
            "os_release": "cat /etc/os-release",
            "mount": "mount -l",
            "disk_usage": "df -h",
            "memory": "free -h"
        }
        
        for key, cmd in commands.items():
            try:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True
                )
                info[key] = result.stdout.strip()
            except Exception as e:
                info[key] = f"Error: {e}"
        
        with open(f"{self.output}/system_info.json", "w") as f:
            json.dump(info, f, indent=2)
    
    def collect_artifacts(self):
        """收集关键取证工件"""
        artifacts = {
            "passwd": "/etc/passwd",
            "shadow": "/etc/shadow",
            "group": "/etc/group",
            "sudoers": "/etc/sudoers",
            "crontab": "/etc/crontab",
            "hostname": "/etc/hostname",
            "hosts": "/etc/hosts",
            "ssh_config": "/etc/ssh/sshd_config"
        }
        
        for name, path in artifacts.items():
            try:
                result = subprocess.run(
                    f"cat {path}", shell=True, capture_output=True, text=True
                )
                with open(f"{self.output}/{name}", "w") as f:
                    f.write(result.stdout)
            except Exception:
                pass
    
    def collect_persistence(self):
        """检测持久化机制"""
        persistence_paths = [
            "/etc/cron.d/",
            "/etc/cron.daily/",
            "/etc/cron.hourly/",
            "/etc/cron.weekly/",
            "/etc/cron.monthly/",
            "/etc/init.d/",
            "/etc/systemd/system/",
            "/etc/systemd/system/multi-user.target.wants/",
            "~/.config/systemd/user/",
            "~/.bashrc",
            "~/.profile",
            "~/.ssh/authorized_keys"
        ]
        
        persistence_data = {}
        for path in persistence_paths:
            expanded = os.path.expanduser(path)
            if os.path.exists(expanded):
                result = subprocess.run(
                    f"ls -la {expanded} 2>/dev/null",
                    shell=True, capture_output=True, text=True
                )
                persistence_data[path] = result.stdout
        
        with open(f"{self.output}/persistence.txt", "w") as f:
            for path, content in persistence_data.items():
                f.write(f"\n=== {path} ===\n{content}")
    
    def collect_memory_forensics(self):
        """检查内存取证线索"""
        # 检查加载的内核模块
        result = subprocess.run(
            "lsmod", shell=True, capture_output=True, text=True
        )
        with open(f"{self.output}/modules.txt", "w") as f:
            f.write(result.stdout)
        
        # 检查可疑的内核模块
        suspicious = result.stdout
        if "hide" in suspicious.lower():
            print("[!] 可疑内核模块发现")

# 使用示例
collector = LinuxForensicsCollector("/evidence/linux-case")
collector.collect_system_info()
collector.collect_artifacts()
collector.collect_persistence()
```

### 4. Rootkit 与恶意软件检测

```bash
# Rootkit 检测
# chkrootkit
sudo chkrootkit

# rkhunter
sudo rkhunter --check

# 检测内核 Rootkit
# 检查内核模块
lsmod | head -50

# 检查 /sys/module/ 中的可疑模块
for mod in /sys/module/*; do
    if [ ! -f "$mod/version" ]; then
        echo "No version: $mod"
    fi
done

# LD_PRELOAD Rootkit 检测
cat /etc/ld.so.preload

# 检查 LD_PRELOAD 环境变量
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep LD_PRELOAD

# 文件完整性检查
# 使用 rpm -V（RHEL）或 debsums（Debian）
rpm -Va | grep -E "(S|5)"  # RHEL 验证所有包
debsums -c  # Debian 验证所有包

# 检测系统二进制替换
dpkg --verify  # Debian 系统文件校验

# /proc 文件系统异常
# hidden process detection
comm -13 <(ls /proc | grep '^[0-9]' | sort) \
        <(ps -eo pid | grep '^ *[0-9]' | sort)
```

### 5. 容器取证（Docker）

```bash
# Docker 容器取证
# 查看所有容器（包括已停止）
docker ps -a

# 查看容器日志
docker logs <container_id>

# 导出容器文件系统
docker export <container_id> -o container.tar
tar xvf container.tar

# 查看容器元数据
docker inspect <container_id>

# 挂载容器文件系统
docker container diff <container_id>

# 提交容器快照
docker commit <container_id> forensic_snapshot

# Container 文件取证
# 查看容器内进程（从宿主机）
ps aux | grep container-shim

# 查看容器卷挂载
docker inspect --format='{{json .Mounts}}' <container_id>

# 事件日志
docker events --since 24h
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| The Sleuth Kit | 文件系统取证 | https://www.sleuthkit.org/ |
| Autopsy | 图形化取证平台 | https://www.autopsy.com/ |
| chkrootkit | Rootkit 检测 | https://www.chkrootkit.org/ |
| osquery | 系统状态查询 | https://osquery.io/ |
| Auditd | 审计框架 | https://people.redhat.com/sgrubb/audit/ |

## 参考资源

- [SANS Linux Forensics Cheat Sheet](https://www.sans.org/blog/linux-forensics/)
- [Linux Incident Response — Jason Blanchard](https://github.com/jipegit/linux-ir-training)
- [Digital Forensics and Incident Response — Linux](https://www.dfir.training/linux-forensics)
- [NIST SP 800-86 — Forensic Techniques](https://csrc.nist.gov/publications/detail/sp/800-86/final)
- [Docker Forensics — Binalyze](https://blog.binalyze.com/docker-forensics/)
