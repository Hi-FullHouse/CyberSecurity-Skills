---
id: 10-001
title: "📱 Android安全测试 (Android Security Testing)"
category: 移动安全
category_en: "Mobile Security"
difficulty: ★★★
tools: "drozer, Frida, APKTool, MobSF, Jadx"
last_updated: 2025-07
tags: ["mobile-security", "android", "ios", "mobile-audit"]
subdomain: mobile-security
nist_csf: ["PR.AC-01", "PR.DS-03", "PR.PT-01"]
mitre_attack: ["T1475", "T1514", "T1529", "T1204"]
---
# 📱 Android安全测试 (Android Security Testing)

## 概述
对Android应用程序进行安全评估，包括静态分析、动态调试、逆向工程和API安全测试。

## 核心技能

### 1. APK信息收集

```bash
# 使用aapt获取基本信息
aapt dump badging app.apk
aapt dump permissions app.apk
aapt dump configurations app.apk

# 使用apktool反编译
apktool d app.apk -o app_decompiled/
apktool d -f app.apk -o app_source/ --no-res  # 不反编译资源

# 查看AndroidManifest.xml
# 反编译后查看
cat app_decompiled/AndroidManifest.xml

# 使用jadx反编译Java源码
jadx -d jadx_output/ app.apk
jadx-gui app.apk  # GUI方式查看

# 在线分析
# https://www.virustotal.com/
# https://app.any.run/
```

### 2. 静态安全分析

```bash
# 权限分析
# 检查高危权限
grep -E "INTERNET|READ_EXTERNAL|WRITE_EXTERNAL|CAMERA|RECORD_AUDIO|READ_SMS|ACCESS_FINE_LOCATION" AndroidManifest.xml

# 检查导出组件
# activity, service, receiver 设置 android:exported="true"

# 检查WebView配置
grep -r "setJavaScriptEnabled\|addJavascriptInterface\|loadUrl\|setAllowFileAccess" jadx_output/
grep -r "WebView" jadx_output/

# 检查数据存储
grep -r "SharedPreferences\|getSharedPreferences\|SQLite\|openOrCreateDatabase\|getExternalStorageDir\|getCacheDir" jadx_output/

# 检查HTTPS/SSL
grep -r "HttpURLConnection\|OkHttp\|Retrofit\|HttpsURLConnection\|SSLSocketFactory" jadx_output/

# 检查硬编码密钥/令牌
grep -r "api_key\|secret\|token\|password\|aws\|azure\|firebase" jadx_output/
```

### 3. 动态安全分析

```bash
# 使用adb调试
# 安装APK
adb install app.apk
adb install -r app.apk  # 覆盖安装
adb install -t app.apk  # 测试APK

# 查看日志
adb logcat | grep -E "WebView|Javascript|JNI|Error|Exception"

# 查看Activity
adb shell dumpsys package com.example.app | grep -A 10 "Activity Resolver Table"
adb shell am start -n com.example.app/.MainActivity

# 截取屏幕
adb shell screencap -p /sdcard/screen.png
adb pull /sdcard/screen.png

# 录制屏幕
adb shell screenrecord /sdcard/demo.mp4

# 获取应用数据
adb shell run-as com.example.app cat /data/data/com.example.app/databases/app.db
adb backup -f backup.ab com.example.app

# 使用Frida挂钩
# Hook方法
frida -U -l hook.js com.example.app
# Frida脚本hook.js:
# Java.perform(function() {
#     var cls = Java.use("com.example.target.Class");
#     cls.targetMethod.implementation = function() {
#         console.log("Method called");
#         return this.targetMethod();
#     };
# });
```

### 4. 网络流量分析

```bash
# 配置Burp Suite代理
# 1. 设置代理: adb shell settings put global http_proxy 192.168.1.100:8080
# 2. 安装Burp证书
adb push burp_ca.der /sdcard/
adb shell
# 在设备上安装证书（Android 7+需要root或Magisk模块）

# 使用mitmproxy
mitmproxy -p 8080
adb shell settings put global http_proxy 192.168.1.100:8080

# 抓取所有流量
# 使用tcpdump
adb shell tcpdump -i any -p -s 0 -w /sdcard/capture.pcap
adb pull /sdcard/capture.pcap

# SSL Pinning绕过
# 使用Frida
frida -U -l ssl_pinning_bypass.js com.example.app

# Objection自动绕过
objection -g com.example.app explore
android sslpinning disable

# 使用Magisk模块: TrustMeAlready
```

### 5. 本地数据存储分析

```bash
# 提取应用数据
adb backup -f backup.ab com.example.app
# 提取backup.ab
dd if=backup.ab bs=1 skip=24 | openssl zlib -d > backup.tar
tar xvf backup.tar

# 检查SQLite数据库
sqlite3 /data/data/com.example.app/databases/database.db ".tables"
sqlite3 /data/data/com.example.app/databases/database.db "SELECT * FROM users;"

# 检查SharedPreferences
cat /data/data/com.example.app/shared_prefs/*.xml

# 检查内部文件
adb shell ls -la /data/data/com.example.app/files/
adb shell cat /data/data/com.example.app/files/sensitive_data.txt

# 检查外部存储
adb shell ls -la /sdcard/Android/data/com.example.app/
```

### 6. 漏洞检测

```bash
# Drozer - Android安全审计框架
drozer console connect
dz> run app.package.list -f example
dz> run app.activity.info -a com.example.app
dz> run app.provider.info -a com.example.app
dz> run app.service.info -a com.example.app
dz> run app.broadcast.info -a com.example.app

# Content Provider探测
dz> run scanner.provider.finduris -a com.example.app
dz> run app.provider.query content://com.example.app/users
dz> run app.provider.query content://com.example.app/database --selection "' OR '1'='1"

# Activity暴露检测
dz> run app.activity.start --component com.example.app com.example.app.SettingsActivity

# Intent攻击
dz> run app.broadcast.send --action com.example.action.SECRET --extra string secret xyz

# 使用MobSF (Mobile Security Framework)
docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf
# 上传APK到 http://localhost:8000

# 使用QARK
qark --apk app.apk
```

### 7. OWASP MASVS检查

```bash
# OWASP Mobile Security Testing Guide (MSTG) 检查项

# MASVS-L1 (基础安全)
# 1. 安全数据存储
# 2. 网络通信安全
# 3. 认证与授权
# 4. 代码质量
# 5. 隐私保护

# MASVS-L2 (深度防御)
# 6. 防篡改
# 7. 反逆向工程
# 8. 完整性验证

# 常见问题清单
checks = {
    "MSTG-STORAGE-1": "SharedPreferences是否加密?",
    "MSTG-STORAGE-2": "数据库是否加密?",
    "MSTG-STORAGE-3": "敏感信息是否存储在外部存储?",
    "MSTG-STORAGE-4": "键盘输入是否泄露?",
    "MSTG-NETWORK-1": "是否使用HTTPS?",
    "MSTG-NETWORK-2": "SSL Pinning是否实现?",
    "MSTG-NETWORK-3": "是否使用证书透明度?",
    "MSTG-PLATFORM-1": "是否使用WebView?",
    "MSTG-PLATFORM-2": "Intent是否安全?",
    "MSTG-AUTH-1": "是否存在本地认证绕过?",
    "MSTG-CODE-1": "是否使用混淆?",
    "MSTG-CODE-2": "调试是否已禁用?"
}
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| APKTool | APK反编译 | https://ibotpeaches.github.io/Apktool/ |
| jadx | Java反编译器 | https://github.com/skylot/jadx |
| Frida | 动态插桩 | https://frida.re/ |
| Drozer | Android安全审计 | https://github.com/FSecureLABS/drozer |
| MobSF | 移动安全框架 | https://github.com/MobSF/Mobile-Security-Framework-MobSF |
| Objection | 运行时探索 | https://github.com/sensepost/objection |
| QARK | 快速Android审查 | https://github.com/linkedin/qark |
| APKLeaks | APK信息泄露扫描 | https://github.com/dwisiswant0/apkleaks |

## 参考资源
- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [OWASP MASVS](https://mas.owasp.org/MASVS/)
- [Android Security Checklist](https://developer.android.com/topic/security/best-practices)
- [HackTricks - Android](https://book.hacktricks.xyz/mobile-apps-pentesting/android-app-pentesting)
