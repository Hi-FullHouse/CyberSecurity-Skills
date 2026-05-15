---
id: 22-002
title: "🛡️ DLP数据防泄漏策略 (Data Loss Prevention)"
category: 数据安全与隐私
category_en: "Data Security & Privacy"
difficulty: ★★★★
tools: "Microsoft DLP, Symantec DLP, Digital Guardian, Forcepoint DLP, OpenDLP"
last_updated: 2025-07
tags: ["data-security", "privacy", "dlp", "gdpr", "encryption", "data-classification"]
subdomain: data-security-privacy
nist_csf: ["PR.DS-01", "PR.DS-02", "PR.DS-05", "ID.GV-03"]
mitre_attack: ["T1530", "T1048", "T1567"]
---
# 🛡️ DLP数据防泄漏策略 (Data Loss Prevention)

## 概述

数据防泄漏（DLP）通过内容识别、策略控制和行为监控，防止敏感数据通过网络、终端和存储渠道被未授权外泄。覆盖数据**静态**（存储）、**传输中**（网络）和**使用中**（终端）三种状态。

## 核心技能

### 1. 网络DLP (Network DLP)

```bash
# 使用Zeek/Bro进行网络流量数据检测
# 检测敏感数据在HTTP/HTTPS传输
zeek -C -r capture.pcap

# 自定义Zeek脚本检测信用卡号
cat << 'EOF' > /usr/share/zeek/site/dlp.zeek
module DLP;
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (to_lower(name) == "content-type" && /json|xml|csv/ in value) {
        print fmt("HTTP API传输: %s -> %s", c$http$uri, c$id$orig_h);
    }
}
EOF

# 使用nDPI协议识别
ndpiReader -i eth0 -s 60 -w ndpi-output.txt

# 检测DNS隧道数据泄露
tshark -r capture.pcap -Y "dns.txt_len > 60" -T fields -e dns.qry.name
```

### 2. 终端DLP (Endpoint DLP)

```powershell
# Windows 终端DLP检测 (PowerShell)
# 监控USB设备接入
Register-WmiEvent -Query "SELECT * FROM Win32_VolumeChangeEvent WHERE EventType=2" -Action {
    Write-EventLog -LogName Security -Source DLP -EntryType Warning -EventId 4100 -Message "USB设备接入告警"
}

# 监控剪贴板操作（敏感数据复制）
Add-Type -AssemblyName System.Windows.Forms
$clipboardText = [System.Windows.Forms.Clipboard]::GetText()
if ($clipboardText -match '\b\d{4}-\d{4}-\d{4}-\d{4}\b') {
    Write-Warning "检测到信用卡号被复制到剪贴板!"
    [System.Windows.Forms.Clipboard]::Clear()
}

# 监控打印操作
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PrintService/Admin'; ID=307} | 
    Select-Object TimeCreated, Message

# 检测截屏行为
# 使用进程监控
Get-Process | Where-Object { $_.ProcessName -match 'SnippingTool|Snip|ScreenCapture' }
```

### 3. 存储DLP与数据发现

```bash
# 扫描共享文件夹中的敏感数据
# 使用ClamAV + DLP规则
clamscan -r --heuristic-alerts --gen-json /shared/folder

# 使用PowerShell扫描文件服务器
powershell << 'PS'
$patterns = @(
    '\d{4}-\d{4}-\d{4}-\d{4}',  # 信用卡
    '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # 邮箱
    '1[3-9]\d{9}'  # 手机号
)
Get-ChildItem -Path "\\fileserver\share" -Recurse -File | 
    Select-String -Pattern $patterns | 
    Export-Csv -Path "dlp_findings.csv" -NoTypeInformation
PS
```

### 4. DLP策略配置与响应

```yaml
# Microsoft DLP策略示例 (PowerShell)
$dlpPolicy = @{
    Name = "PII保护策略"
    Mode = "Enable"
    Rules = @(
        @{
            Name = "阻止信用卡外传"
            Condition = "ContentContainsSensitiveInformation 'Credit Card'"
            Action = "BlockAccess | NotifyUser | GenerateIncident"
            Priority = 1
        },
        @{
            Name = "告警身份证外传"
            Condition = "ContentContainsSensitiveInformation 'China ID Card'"
            Action = "NotifyUser | GenerateAlert"
            Priority = 2
        },
        @{
            Name = "审计手机号外传"
            Condition = "ContentContainsSensitiveInformation 'Phone Number'"
            Action = "AuditOnly"
            Priority = 3
        }
    )
}

# Symantec DLP策略诊断
# 检查策略是否命中
dlpcmd policy -list
dlpcmd policy -test -name "PII Policy" -file sample_data.txt
```

### 5. DLP绕过检测与防护

```bash
# 检测DLP绕过尝试
# 检测数据压缩后外传
tcpdump -i eth0 -A 'tcp port 443' | grep -E '(zip|rar|7z|tar|gz)' 

# 检测图片隐写传输
# 使用StegExpose检测
java -jar StegExpose.jar stego_images/

# 检测编码混淆
# base64编码的数据通常有较高熵值
python3 << 'EOF'
import base64
import re

def detect_encoded_data(text):
    # 检测base64编码块
    b64_pattern = r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    matches = re.findall(b64_pattern, text)
    for m in matches:
        try:
            decoded = base64.b64decode(m)
            if any(c.isascii() and not c.isprintable() for c in decoded):
                print(f"检测到编码数据外传: {m[:50]}...")
        except:
            pass
EOF
```

### 6. 云DLP策略

```bash
# AWS Macie - 敏感数据发现
aws macie2 create-classification-job \
  --job-type SCHEDULED \
  --s3-job-definition bucketDefinitions=[{bucketId=my-data-bucket}] \
  --sampling-percentage 50

# GCP DLP API扫描
curl -X POST -H "Authorization: Bearer $(gcloud auth application-default print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{"item": {"value": "用户手机号: 13800138000"}, "inspectConfig": {"infoTypes": [{"name": "CHINA_PHONE_NUMBER"}]}}' \
  "https://dlp.googleapis.com/v2/projects/my-project/content:inspect"

# Azure Purview DLP策略
az purview classification-rule create \
  --account-name my-purview \
  --name "ChinaIDRule" \
  --classification-name "China ID Number"
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Microsoft Purview DLP | 企业级DLP策略管理 | https://learn.microsoft.com/en-us/purview/dlp |
| Symantec DLP | 网络、终端、存储全覆盖 | https://www.broadcom.com/cyber-resilience |
| Digital Guardian | 终端DLP与数据保护 | https://www.digitalguardian.com/ |
| OpenDLP | 开源DLP扫描工具 | https://code.google.com/archive/p/opendlp/ |
| zeek-dlp | 开源网络DLP框架 | https://github.com/zeek/zeek |
| MyDLP | 开源DLP解决方案 | https://github.com/eminaygun/mydlp |

## 参考资源

- [NIST SP 800-53 — Data Protection Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [CISA Data Loss Prevention Best Practices](https://www.cisa.gov/data-loss-prevention)
- [OWASP Data Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Data_Protection_Cheat_Sheet.html)
- [ISO 27001 Annex A.8 — Asset Management](https://www.iso.org/standard/27001)
