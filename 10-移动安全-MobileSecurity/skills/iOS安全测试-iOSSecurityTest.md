---
id: 10-002
title: "🍎 iOS安全测试 (iOS Security Testing)"
category: 移动安全
category_en: "Mobile Security"
difficulty: ★★★★★
tools: "Frida, Objection, class-dump, Ghidra, checkra1n"
last_updated: 2025-07
tags: ["mobile-security", "android", "ios", "mobile-audit"]
subdomain: mobile-security
nist_csf: ["PR.AC-01", "PR.DS-03", "PR.PT-01"]
mitre_attack: ["T1475", "T1514", "T1529", "T1204"]
---
# 🍎 iOS安全测试 (iOS Security Testing)

## 概述
对iOS应用程序进行安全评估，包括IPA分析、运行时调试、越狱检测绕过和API安全测试。

## 核心技能

### 1. IPA分析与反编译

```bash
# 提取IPA
# 从越狱设备
scp -P 2222 root@localhost:/var/containers/Bundle/Application/UUID/App.app/ App.ipa

# 解压IPA
unzip App.ipa -d App_Payload/

# 查看Info.plist
plutil -p Info.plist
cat Info.plist

# 查看二进制保护
otool -l App | grep -E "cryptid|crypt"  # 检查加密
# cryptid 0 = 未加密, cryptid 1 = 已加密

# 使用class-dump导出头文件
class-dump -H App -o headers/

# 使用Hopper/IDA反汇编
# Hopper: 打开二进制文件进行反编译
# IDA Pro: 高级反汇编器

# 使用Ghidra逆向
ghidra App

# 查看字符串
strings App | grep -i "password\|secret\|key\|token\|api"
```

### 2. 运行时调试

```bash
# 使用lldb调试
# 附加到进程
lldb -p PID
lldb -n AppName

# 常用lldb命令
(lldb) po [UIApplication sharedApplication]
(lldb) po [[[UIApplication sharedApplication] keyWindow] recursiveDescription]
(lldb) po [[NSUserDefaults standardUserDefaults] dictionaryRepresentation]
(lldb) br set -n "-[ViewController viewDidLoad]"
(lldb) memory read --format hex --count 32 0x100000000

# 使用Cycript
cycript -p AppName
cy# UIApp
cy# [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var/mobile/Containers/Data/Application" error:nil]
cy# [NSClassFromString(@"SecretClass") sharedInstance]

# 使用Frida
frida -U -l ios_hook.js AppName
# iOS Frida脚本示例:
# ObjC.classes.SecretManager.alloc().init()
# var className = ObjC.classes["TargetClass"];
# className["- secretMethod"].implementation = function() { ... }
```

### 3. 网络流量分析

```bash
# 配置Burp Suite代理
# 1. 设置WiFi代理到Burp
# 2. 安装Burp证书
# 使用AirDrop或scp上传证书
scp burp_ca.der root@ios_device:/tmp/
# 安装证书
# 设置 -> 通用 -> VPN与设备管理 -> 安装

# SSL Pinning绕过
# 使用Frida
objection -g com.example.app explore
ios sslpinning disable

# 使用SSL Kill Switch 2
# 从Cydia安装

# 使用Burp + Proxy切换
# ProxySwitchy插件自动切换

# 抓取HTTP/HTTPS
# 通过代理即可

# 抓取非HTTP流量
# 使用tcpdump（越狱设备）
tcpdump -i en0 -w capture.pcap
```

### 4. 本地存储分析

```bash
# 访问应用沙盒（越狱设备）
# 数据目录
/var/mobile/Containers/Data/Application/UUID/

# 提取数据
scp -r root@ios_device:/var/mobile/Containers/Data/Application/UUID/Documents/ ./

# 查看UserDefaults
plutil -p ~/Library/Preferences/com.example.app.plist

# 查看Keychain数据
# 使用Keychain-Dumper
./keychain_dumper > keychain.txt

# 查看CoreData/SQLite
sqlite3 ~/Library/Application Support/App.sqlite ".tables"

# 查看NSUserDefaults
defaults read com.example.app

# 查看密钥链访问权限
otool -l App | grep -A 4 "keychain-access-groups"

# 查看钥匙串
security dump-keychain -d /path/to/keychain
```

### 5. 二进制保护绕过

```bash
# 越狱检测绕过
# 常见检测方法
# 1. 检查Cydia路径: /Applications/Cydia.app
# 2. 检查越狱文件: /bin/bash, /usr/sbin/sshd
# 3. check dyld: MobileSubstrate, SubstrateLoader
# 4. fork()测试

# Frida绕过
frida -U -l jailbreak_bypass.js AppName

# 常见的绕过工具
# Liberty Lite (Cydia)
# Shadow (Cydia)
# A-Bypass (Cydia)

# 反调试绕过
# ptrace检测
# sysctl检测
# syscall检测

# 完整性检查绕过
# 使用Frida hook
# NSBundle.bundleIdentifier
# NSBundle.mainBundle.infoDictionary

# 使用objection
objection -g com.example.app explore
ios jailbreak disable
```

### 6. iBruteForce测试

```bash
# IDOR测试 - 修改User ID
curl -s "https://api.example.com/users/1001/profile" \
  -H "Authorization: Bearer iOS_TOKEN"

# 本地认证绕过
# 使用Cycript
cycript -p AppName
cy# [BiometricAuth authenticateWithReason:@"test"]

# Keychain数据泄露
# 检查是否在NSLog或Crashlytics中输出keychain数据

# 剪贴板泄露
# 监控UIPasteboard使用
cy# [UIPasteboard generalPasteboard].string

# URL Scheme劫持
# 检查自定义URL Scheme
grep -r "CFBundleURLSchemes" headers/
# 测试canOpenURL
cy# [[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"appscheme://test"]]

# Universal Links验证
# 检查apple-app-site-association文件
curl -s "https://example.com/apple-app-site-association"
```

### 7. OWASP MASVS iOS检查

```bash
# OWASP MASVS iOS特定检查

ios_checks = {
    "MSTG-PLATFORM-4": "TouchID/FaceID是否正确实现?",
    "MSTG-PLATFORM-5": "是否有屏幕截图泄露?",
    "MSTG-STORAGE-6": "Keychain数据是否设置了正确的访问控制?",
    "MSTG-STORAGE-7": "剪贴板在使用后是否被清除?",
    "MSTG-NETWORK-4": "是否使用了ATS (App Transport Security)?",
    "MSTG-NETWORK-5": "是否使用了Certificate Pinning?",
    "MSTG-IOS-1": "UIWebView还是WKWebView?",
    "MSTG-IOS-2": "iCloud备份是否包含敏感数据?",
    "MSTG-IOS-3": "是否启用了文件保护?",
    "MSTG-IOS-4": "键盘输入是否安全?",
    "MSTG-IOS-5": "是否正确处理远程通知?",
    "MSTG-IOS-6": "是否使用了User Enrollment?",
}

# 检查ATS配置
plutil -p Info.plist | grep -A 10 "NSAppTransportSecurity"
# 检查 NSAllowsArbitraryLoads 是否设为 true

# 检查iCloud备份
# 在Info.plist中检查 UIFileSharingEnabled, LSSupportsOpeningDocumentsInPlace
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Frida | 动态插桩 | https://frida.re/ |
| Objection | 运行时探索 | https://github.com/sensepost/objection |
| Hopper Disassembler | 反汇编器 | https://www.hopperapp.com/ |
| class-dump | 头文件导出 | http://stevenygard.com/projects/class-dump/ |
| Cycript | Objective-C脚本 | http://www.cycript.org/ |
| Keychain-Dumper | Keychain导出 | https://github.com/ptoomey3/Keychain-Dumper |
| MobSF | 移动安全框架 | https://github.com/MobSF/Mobile-Security-Framework-MobSF |
| idb | iOS调试桥 | https://github.com/dmayer/idb |

## 参考资源
- [OWASP iOS Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [iOS Security Guide (Apple)](https://www.apple.com/business/docs/site/iOS_Security_Guide.pdf)
- [The iPhone Wiki](https://www.theiphonewiki.com/)
- [HackTricks - iOS](https://book.hacktricks.xyz/mobile-apps-pentesting/ios-pentesting)
- [iOS Application Security](https://github.com/nsobject/ios-application-security)
