---
id: 15-005
title: "🛑 事件遏制与清除 (Containment & Eradication)"
category: 应急响应
category_en: "Incident Response"
difficulty: ★★★★
tools: "Firewall ACL, EDR隔离, GPO, 网络分段"
last_updated: 2025-07
tags: ["incident-response", "forensics", "memory-forensics", "threat-hunting", "ransomware"]
subdomain: incident-response
nist_csf: ["RS.RP-01", "RS.CO-02", "RS.AN-01", "RS.MI-01"]
mitre_attack: ["T1486", "T1490", "T1485", "T1562"]
---
# 🛑 事件遏制与清除 (Containment & Eradication)

## 概述
事件遏制（Containment）与清除（Eradication）是应急响应中最关键的阶段。目标是在最小化业务影响的前提下，阻止攻击者进一步活动，并从受影响的系统中彻底清除威胁。

## 核心技能

### 1. 遏制策略选择

根据事件类型选择适当的遏制策略：

| 策略 | 适用场景 | 优点 | 缺点 |
|:---|:---|:---|:---|
| 🔌 网络隔离 | 勒索软件、横向移动 | 快速阻断 | 可能中断业务 |
| 🛡️ 端口阻断 | C2通信、数据外传 | 精准阻断 | 需要识别C2流量 |
| 👤 账户禁用 | 账号失陷 | 不影响系统 | 可能被检测到 |
| 🔒 进程终止 | 恶意进程 | 即时见效 | 可能触发反制 |
| 📦 快照回滚 | 虚拟机场景 | 恢复快速 | 可能丢失数据 |
| ⚡ 断网断电 | 极端紧急情况 | 完全隔离 | 影响最大 |

### 2. 网络层面遏制

```bash
# 防火墙规则 — 阻断C2通信
# iptables/Linux
iptables -A OUTPUT -d 185.xxx.xxx.xxx -j DROP
iptables -A OUTPUT -p tcp --dport 4444 -j LOG --log-prefix "C2_BLOCKED:"
iptables -A FORWARD -s 10.0.1.100 -j DROP  # 隔离失陷主机

# Windows防火墙
netsh advfirewall firewall add rule name="Block_C2" dir=out remoteip=185.xxx.xxx.xxx action=block
netsh advfirewall firewall add rule name="Isolate_Host" dir=in remoteip=any action=block

# 交换机ACL — 在接入层阻断
conf t
access-list 100 deny ip host 10.0.1.100 any
access-list 100 permit ip any any
interface GigabitEthernet0/1
ip access-group 100 in

# VLAN隔离 — 将失陷主机移入隔离VLAN
conf t
interface GigabitEthernet0/1
switchport access vlan 999  # 隔离VLAN

# DNS Sinkhole — 将恶意域名解析到黑洞
# 在DNS服务器上添加Sinkhole记录
# 添加恶意域名解析到127.0.0.1或专用sinkhole IP
```

### 3. 端点层面遏制

#### EDR隔离
```bash
# CrowdStrike — 网络隔离
csfalcon -f --host-id <HOST_ID> --action contain

# Microsoft Defender for Endpoint
# 在安全门户操作: 设备 → 隔离设备

# SentinelOne — 完全隔离
sentinelctl network isolate <AGENT_ID>

# Carbon Black — 隔离端点
cbcli.exe isolate <SENSOR_ID>
```

#### 手动隔离（无EDR场景）
```powershell
# Windows — 禁用网卡
Disable-NetAdapter -Name "Ethernet" -Confirm:$false

# 停止特定服务（如远程控制服务）
Stop-Service -Name "RemoteRegistry" -Force
Set-Service -Name "RemoteRegistry" -StartupType Disabled

# 禁用WMI（阻止横向移动）
reg add HKLM\SYSTEM\CurrentControlSet\Services\Winmgmt /v Start /t REG_DWORD /d 4 /f

# 清理计划任务（清除持久化）
schtasks /DELETE /TN "MaliciousTask" /F

# Linux — 禁用网卡
ifconfig eth0 down
# 或
ip link set eth0 down

# 终止恶意进程
kill -9 <PID>
pkill -f "malicious_process_name"
```

### 4. 账户安全处置

```powershell
# 立即禁用失陷账户
Disable-ADAccount -Identity "compromised_user"

# 强制所有用户登出
Get-ADUser -Filter * | ForEach-Object {
    Get-ADComputer -Filter * | ForEach-Object {
        Invoke-Command -ComputerName $_.Name -ScriptBlock {
            quser | ForEach-Object {
                $session = ($_ -split '\s+')[2]
                logoff $session
            }
        }
    }
}

# 重置所有活跃会话令牌
# Azure AD
Revoke-AzureADUserAllRefreshToken -ObjectId "user@domain.com"

# 撤销Kerberos TGT（域控执行）
klist -li 0x3e4 purge

# 重置密码并强制下次修改
Set-ADAccountPassword -Identity "compromised_user" -Reset -NewPassword (ConvertTo-SecureString "TempP@ss123!" -AsPlainText -Force)
Set-ADUser -Identity "compromised_user" -ChangePasswordAtLogon $true
```

### 5. 恶意软件清除

```bash
# 终止进程树（包含子进程）
taskkill /F /T /IM malicious.exe

# 删除恶意文件（先确认路径）
del /F /S /Q C:\Windows\Temp\malware.exe
del /F /S /Q C:\Users\*\AppData\Local\Temp\*.tmp

# Linux
rm -rf /var/tmp/.systemd-service
rm -f /usr/lib/systemd/system/malicious.service
systemctl daemon-reload

# 清除注册表持久化
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Malware" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Malware" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" /v "Malware" /f

# 清除启动文件夹
del "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\malware.lnk"

# 清除WMI持久化
wmic /namespace:\\root\subscription PATH __EventFilter DELETE
wmic /namespace:\\root\subscription PATH CommandLineEventConsumer DELETE
wmic /namespace:\\root\subscription PATH __FilterToConsumerBinding DELETE
```

### 6. 系统恢复与加固

```powershell
# 修复系统文件完整性
sfc /scannow
dism /online /cleanup-image /restorehealth

# 重置安全策略（组策略强制刷新）
gpupdate /force

# 恢复hosts文件
copy C:\Windows\System32\drivers\etc\hosts.bak C:\Windows\System32\drivers\etc\hosts

# 刷新DNS缓存
ipconfig /flushdns

# 重置网络堆栈
netsh int ip reset
netsh winsock reset
```

```bash
# Linux系统恢复
# 恢复被修改的系统文件
rpm -Va  # 验证RPM包完整性
apt-get --reinstall install <package>  # Debian系重装

# 检查并修复文件权限
find /etc -type f -perm /o+w -ls
chmod -R go-w /etc

# 清除SSH后门
grep -v "ssh-rsa AAAA" ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.clean
mv ~/.ssh/authorized_keys.clean ~/.ssh/authorized_keys
```

### 7. 遏制效果验证

```powershell
# 确认C2通信已阻断
Test-NetConnection 185.xxx.xxx.xxx -Port 4444 | Select-Object TcpTestSucceeded

# 确认恶意服务已停止
Get-Service | Where-Object {$_.Status -eq "Running"} | Where-Object {$_.DisplayName -match "malware"}

# 确认恶意进程已终止
Get-Process | Where-Object {$_.ProcessName -match "malware"}

# 确认网络流量已切断
Get-NetTCPConnection | Where-Object {$_.RemoteAddress -eq "185.xxx.xxx.xxx"}

# 确认域账户已禁用
Get-ADUser compromised_user -Properties Enabled | Select-Object Name, Enabled
```

### 8. 遏制决策树

```text
事件确认
   │
   ├─ 是否涉及关键业务系统？
   │    ├─ 是 → 评估业务影响，制定分阶段遏制策略
   │    └─ 否 → 立即执行完全隔离
   │
   ├─ 是否为勒索软件？
   │    ├─ 是 → 立即断开所有网络连接，保留加密文件
   │    └─ 否 → 按标准遏制流程处理
   │
   ├─ 攻击者是否处于活跃状态？
   │    ├─ 是 → 优先阻断C2，再执行端点遏制
   │    └─ 否 → 优先取证分析，再执行清除
   │
   └─ 是否需要保留证据？
        ├─ 是 → 先做内存/磁盘快照，再执行遏制
        └─ 否 → 立即执行遏制
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| EDR (CrowdStrike/Defender/S1) | 端点检测与隔离 | 商业产品 |
| netsh / iptables | 网络层阻断 | 系统内置 |
| Sysinternals Suite | 进程/服务管理 | https://learn.microsoft.com/sysinternals/ |
| Autoruns | 持久化分析清理 | https://learn.microsoft.com/sysinternals/downloads/autoruns |
| Process Explorer | 进程树分析 | https://learn.microsoft.com/sysinternals/downloads/process-explorer |
| PowerSCC | AD应急清理 | https://github.com/cyberark/ACLight |

## 参考资源

- [SANS — Containment and Eradication](https://www.sans.org/white-papers/incident-handlers-handbook/)
- [NIST SP 800-61 — Incident Response Lifecycle](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [MITRE ENGAGE — 对抗性交互策略](https://engage.mitre.org/)
- [CrowdStrike — Incident Response Playbooks](https://www.crowdstrike.com/cybersecurity-101/incident-response/)
