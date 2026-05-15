---
id: 27-005
title: "macOS安全评估与加固 (macOS Security Assessment & Hardening)"
category: 操作系统安全
category_en: "OS Security"
difficulty: ★★★★
tools: "SIP, TCC, MDM, osquery, Santa, BlockBlock, KnockKnock, objective-see tools"
last_updated: 2026-05
tags: ["os-security", "windows-hardening", "linux-hardening", "macos", "privilege-escalation"]
subdomain: os-security
nist_csf: ["PR.AC-01", "PR.DS-07", "PR.PT-01"]
mitre_attack: ["T1548", "T1552", "T1562"]
---
# macOS安全评估与加固 (macOS Security Assessment & Hardening)

## 概述

macOS 在企业环境中日益普及，其基于 XNU 内核的安全机制（SIP、TCC、AMFI、XProtect）与其他操作系统有显著差异。本技能覆盖 macOS 安全架构解析、本地安全评估、隐私保护与 TCC 策略管理、端点检测与响应配置、企业 MDM 安全策略实施，同时涵盖 macOS 攻击面分析（恶意软件持续化、TCC 绕过、Gatekeeper 逃逸等），帮助安全人员全面评估和加固 macOS 环境。参考 NIST SP 800-179（macOS 安全指南）和 CIS Apple macOS Benchmarks。

## 核心技能

### 1. macOS 安全架构与基线检查

```bash
# 检查 SIP（系统完整性保护）状态
csrutil status
# System Integrity Protection status: enabled.

# 检查 FileVault 加密状态
fdesetup status
# FileVault is On.

# 检查 XProtect（内置防恶意软件）版本
system_profiler SPInstallDataType | grep XProtect
# XProtectPlistConfigData: 2159

# 检查 Gatekeeper 状态
spctl --status
# assessments enabled

# 检查防火墙状态
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
# Firewall is enabled.

# 检查 FileVault 配置详情
fdesetup list
sudo fdesetup status -extended

# 检查全盘访问权限和隐私策略
# 查看 TCC 数据库
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access;"

# 检查已批准的 kernel extensions
kextstat | grep -v com.apple
# 检查已批准的 system extensions
systemextensionsctl list

# CIS 基线检查脚本
# 使用 CIS Benchmark 评估工具
sudo python3 /path/to/CIS_Benchmark/assessment.py --level 1 --level 2
```

```bash
# 使用 osquery 进行 macOS 安全审计
osqueryi "SELECT * FROM startup_items;"                               # 启动项审计
osqueryi "SELECT * FROM launchd;"                                     # 所有 Launchd plists
osqueryi "SELECT * FROM kernel_extensions WHERE started != 1;"        # 未启动的内核扩展
osqueryi "SELECT * FROM authorizations WHERE rule = 'authenticate';"  # 授权策略
osqueryi "SELECT * FROM applications WHERE bundle_name LIKE '%VPN%' OR bundle_name LIKE '%remote%';"
osqueryi "SELECT * FROM alf WHERE state = 0;"                         # 防火墙关闭的机器
osqueryi "SELECT * FROM managed_policies;"                            # MDM 策略状态
```

### 2. macOS 端点检测与安全防护

```bash
# 使用 Objective-See 工具进行安全检测
# 安装 BlockBlock（持久化监控）
# 下载: https://objective-see.com/products/blockblock.html

# 安装 KnockKnock（启动项检测）
open /Applications/KnockKnock.app

# 安装 ReiKey（键盘记录器检测）
open /Applications/ReiKey.app

# 后台安全监控配置
# 使用 Santa（Google 的 macOS 应用白名单系统）
# 客户端安装
sudo santactl sync              # 同步策略
sudo santactl status            # 查看状态

# 查看 Santa 日志
log show --predicate 'subsystem == "com.google.santa"' --last 1h

# 使用 osquery 进行威胁狩猎
osqueryi "SELECT * FROM processes WHERE path NOT LIKE '/System/%' AND path NOT LIKE '/usr/%' AND path NOT LIKE '/Applications/%';"
osqueryi "SELECT * FROM processes WHERE path LIKE '%/%.app/Contents/MacOS/%' AND path NOT LIKE '/Applications/%';"
osqueryi "SELECT * FROM disk_encryption;"                             # 加密状态

# 日志分析
# macOS 统一日志查询
log show --predicate 'eventMessage contains "ssh"' --last 1h
log show --predicate '(subsystem contains "com.apple.security") && (eventType == "error")' --last 24h

# 检查系统中已安装的配置文件
sudo profiles -P -o stdout-xml | xmllint --format -
sudo profiles -C -v                # 查看配置文件的证书
```

```powershell
# macOS 移动设备管理 (MDM) 安全策略配置
# 通过 MDM 配置安全策略（即用配置文件描述）

# 主要 MDM 安全策略（payload 格式）
# 1. Passcode Policy
# 2. Restrictions Payload — 禁用特定功能
# 3. Security & Privacy Payload — FileVault 强制
# 4. Kernel Extension Policy — 仅允许白名单 kext

# 通过配置文件强制加密
# /etc/configuration/security.mobileconfig
# com.apple.MCX.FileVault2 -> RequireFileVault = true
# com.apple.security.firewall -> EnableFirewall = true

# 查看当前生效的配置策略
sudo profiles -L -v
```

### 3. TCC 权限与隐私控制

```bash
# TCC（透明度、同意与数据控制）管理

# 查看 TCC 数据库位置
# 系统级：/Library/Application Support/com.apple.TCC/TCC.db
# 用户级：~/Library/Application Support/com.apple.TCC/TCC.db

# 查询授权记录
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "
SELECT 
  client, 
  service, 
  auth_value, 
  auth_reason 
FROM access 
WHERE auth_value = 2;"  # 2=Allowed, 1=Denied, 0=Unspecified

# TCC 绕过技术识别
# 检查是否有应用利用 CVE-2021-30657（Gatekeeper 绕过）
# 检查是否有应用利用 CVE-2023-26818（TCC 绕过）

# 重置特定应用的 TCC 权限
tccutil reset Camera com.example.app
tccutil reset All                              # 重置所有 TCC 权限（谨慎）

# 全盘访问权限审计
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "
SELECT client, auth_value 
FROM access 
WHERE service = 'kTCCServiceSystemPolicyAllFiles';"

# 屏幕录制权限审计
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "
SELECT client FROM access 
WHERE service = 'kTCCServiceScreenCapture' AND auth_value = 2;"

# 输入监控权限审计
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "
SELECT client FROM access 
WHERE service = 'kTCCServiceListenEvent' AND auth_value = 2;"
```

### 4. macOS 恶意软件与防御分析

```bash
# 常见 macOS 恶意软件持久化位置

# LaunchAgents / LaunchDaemons
ls -la ~/Library/LaunchAgents/                # 用户级启动代理
ls -la /Library/LaunchAgents/                 # 系统级启动代理
ls -la /Library/LaunchDaemons/                # 系统级守护进程
ls -la /System/Library/LaunchAgents/          # 操作系统级（受 SIP 保护）

# 检测非 Apple 签名的 Launch 项目
for plist in /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist; do
  signing=$(codesign -dvv "$plist" 2>&1 | grep "Authority=" | head -1)
  if [[ ! "$signing" =~ "Apple" ]]; then
    echo "Unsigned/third-party: $plist"
  fi
done

# 检测可疑的 cron job
crontab -l
ls -la /usr/lib/cron/tabs/
ls -la /etc/periodic/

# 启动项和后门检测
# Login Items
osascript -e 'tell application "System Events" to get the name of every login item'

# Kernel Extensions
kextstat | grep -v com.apple

# System Extensions（macOS 11+ 替代 kext）
systemextensionsctl list

# 可疑文件检测
# 检查通常应空的目录
ls -la /var/tmp/
ls -la /tmp/
# 检查具有隐藏文件名的可疑应用
mdfind "kMDItemKind == 'Application'" | while read app; do
  if [[ "$(basename "$app")" =~ ^\. ]]; then
    echo "Suspicious hidden app: $app"
  fi
done
```

```bash
# macOS 恶意代码分析基础
# 检查 Mach-O 二进制文件
file /path/to/suspicious_binary
otool -L /path/to/suspicious_binary    # 列出链接的库
codesign -dvv /path/to/suspicious_binary  # 证书信息

# 检查应用是否经过公证
spctl -a -t exec -vv /path/to/Application.app

# 检查是否包含 XProtect 已知恶意代码
xprotect check /path/to/suspicious_binary

# 检查 Notarization 票据
stapler validate /path/to/Application.app
stapler validate -q /path/to/Application.pkg

# DNS 查询监控（常见 C2 通信检测）
log show --predicate '(process == "mDNSResponder") && (eventMessage contains ".com")' --last 1h

# 网络连接监控
sudo lsof -i -n -P | grep ESTABLISHED | grep -v "Apple"
nettop -m tcp -J state -n -l 1 | grep -v "Apple"
```

### 5. macOS 安全加固实施

```bash
# macOS 安全加固 Checklist（参考 CIS Benchmarks）

# 1. 系统更新自动安装
sudo softwareupdate --schedule on
sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool TRUE

# 2. 启用 FileVault 全盘加密
sudo fdesetup enable -defer /var/db/FileVaultRecovery.plist

# 3. 配置系统防火墙
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

# 4. 禁用不必要的服务
# 禁用远程登录（SSH）
sudo systemsetup -setremotelogin off
# 禁用蓝牙共享
sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.Bluetooth PrefKeyServicesEnabled -bool false
# 禁用 AirDrop
sudo defaults write /Library/Preferences/com.apple.sharingd AirDropRequiresPassword -bool true

# 5. 安全设置
# 禁用自动登录
sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null
# 屏幕锁定时效（5分钟）
sudo defaults write /Library/Preferences/com.apple.screensaver askForPassword -int 1
sudo defaults write /Library/Preferences/com.apple.screensaver askForPasswordDelay -int 0

# 6. 来宾账户禁用
sudo sysadminctl -guestAccount off

# 7. 禁用诊断共享
sudo defaults write /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory AutoSubmit -bool false

# 8. 配置安全时钟（Find My Mac 和 iCloud 安全）
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Objective-See Tools | macOS 安全检测工具集 | https://objective-see.com/products.html |
| Santa | macOS 应用白名单系统 | https://github.com/google/santa |
| osquery | 系统监控查询引擎 | https://osquery.io/ |
| BlockBlock | 持久化监控 | https://objective-see.com/products/blockblock.html |
| KnockKnock | 启动项检测 | https://objective-see.com/products/knockknock.html |
| ReiKey | 键盘记录器检测 | https://objective-see.com/products/reikey.html |
| swiftDialog | MDM 策略提示工具 | https://github.com/swiftDialog/swiftDialog |

## 参考资源

- [CIS Apple macOS Benchmarks](https://www.cisecurity.org/benchmark/apple_macos)
- [NIST SP 800-179 — Guide to Securing Apple macOS](https://csrc.nist.gov/publications/detail/sp/800-179/rev-1/final)
- [Apple Platform Security Guide](https://support.apple.com/en-us/guide/security/welcome/web)
- [Objective-See Blog — macOS Security Research](https://objective-see.com/blog.html)
- [macOS Security & Privacy — The Eclectic Light Company](https://eclecticlight.co/category/security/)
- [MITRE ATT&CK — macOS Techniques](https://attack.mitre.org/techniques/enterprise/platforms/macOS/)
- [Apple TCC Research — Wojciech Regula](https://wojciechregula.blog/)
- [macOS Red Teaming — HackTricks](https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation)
