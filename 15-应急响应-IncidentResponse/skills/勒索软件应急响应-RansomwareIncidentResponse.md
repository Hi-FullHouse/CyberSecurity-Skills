---
id: "15-008"
title: "💰 勒索软件应急响应 (Ransomware Incident Response)"
category: "应急响应"
category_en: "Incident Response"
difficulty: "★★★★★"
tools: "EDR工具, 解密工具, 备份恢复, FLARE VM"
last_updated: "2025-07"
---
# 💰 勒索软件应急响应 (Ransomware Incident Response)

## 概述
勒索软件（Ransomware）是当前最具破坏力的网络威胁之一。应急响应的核心目标包括：遏制加密扩散、评估影响范围、尝试数据恢复、防止二次勒索。参照 **No More Ransom** 项目、**FS-ISAC** 和 **CISA Ransomware Guide** 最佳实践。

## 核心技能

### 1. 勒索软件事件紧急处置流程

```text
┌─────────────────────────────────────────────────────────┐
│                   发现勒索软件事件                         │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│  第一步：立即上报 — 通知IR团队和管理层                     │
│   ⏱ T+0 分钟                                            │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│  第二步：网络隔离 — 断开受影响主机的所有网络连接             │
│   ⏱ T+10 分钟                                           │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│  第三步：保护备份 — 确认备份系统未被加密                   │
│   ⏱ T+20 分钟                                           │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│  第四步：IoC提取 — 获取勒索信、文件扩展名、钱包地址         │
│   ⏱ T+30 分钟                                           │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│  第五步：威胁识别 — 识别勒索软件家族，检查是否有解密工具      │
│   ⏱ T+60 分钟                                           │
└─────────────────────────────────────────────────────────┘
```

### 2. 快速勒索软件样本分析

```bash
# 第一步：获取勒索信息和痕迹

# 提取勒索信内容
cat README_TO_DECRYPT.txt
cat HOW_TO_DECRYPT.html

# 查看被加密文件的扩展名
ls *.encrypted | head
ls *.locked | head
ls *.[a-zA-Z0-9]{5,8} | head  # 随机扩展名

# 识别勒索软件家族
# 1. 使用ID Ransomware
#    https://id-ransomware.malwarehunterteam.com/
#    上传勒索信或加密文件样本

# 2. 使用YARA规则匹配
yara64.exe -s C:\tools\yara\ransomware_rules.yar ransom_note.txt

# 3. 查看钱包地址
grep -oE "bc1[0-9a-zA-Z]{25,39}|1[0-9a-zA-Z]{24,33}|3[0-9a-zA-Z]{24,33}" ransom_note.txt
grep -oE "0x[0-9a-fA-F]{40}" ransom_note.txt  # ETH地址
```

### 3. 勒索软件家族识别速查表

| 家族名称 | 扩展名 | 勒索信名称 | 解密工具 | 传播方式 |
|:---|:---|:---|:---:|:---|
| LockBit | `.lockbit` | `README.txt` | 有（部分） | RDP爆破/钓鱼 |
| BlackCat/ALPHV | `.alphv` | `README.hta` | 无 | RDP/SMB弱口令 |
| BlackBasta | `.basta` | `readme.txt` | 无 | QakBot投递 |
| REvil/Sodinokibi | `.sodinokibi` | `readme.txt` | 有（已公开） | 漏洞利用/钓鱼 |
| Dharma/Crysis | `.id-<ID>.<email>` | `INFO.hta` | 有（部分） | RDP爆破 |
| Maze/Cartel | `.maze` | `DECRYPT-FILES.txt` | 有（已公开） | 漏洞利用 |
| Ryuk | `.ryk` | `RyukReadMe.txt` | 无 | TrickBot投递 |
| Conti | `.conti` | `CONTACT.txt` | 有（部分泄露） | BazarLoader |
| Clop | `.clop` | `ClopReadMe.txt` | 无 | 数据盗窃+加密 |
| WannaCry | `.WNCRY` | `@Please_Read_Me@.txt` | 有 ✅ | SMB永恒之蓝 |

### 4. 备份恢复策略

```bash
# 关键操作：在确认备份安全之前，不要尝试恢复！

# 检查VSS卷影副本（勒索软件通常会删除VSS）
vssadmin list shadows /for=C:
vssadmin list providers

# 如果VSS未被删除，可以尝试恢复
vssadmin list shadows /for=C:
# 获取Shadow Copy ID，然后运行:
wbadmin get versions
wbadmin start recovery -version:MM/DD/YYYY-HH:MM -itemType:Volume -items:C:

# 从VSS恢复单个文件
# 使用ShadowExplorer浏览卷影副本

# 网络备份恢复（确认备份文件未被加密）
# 检查备份挂载点
dir \\backup-server\share\backups\

# 最后的恢复手段 — 从脱机备份恢复
# ● 磁带备份
# ● 异地冷备份
# ● 云备份（带时间点恢复）
```

### 5. 解密工具查找

```bash
# No More Ransom 项目 — 最权威的免费解密工具来源
# 网站: https://www.nomoreransom.org/
# 上传加密文件样本或勒索信，搜索解密工具

# 欧盟刑警组织解密工具合集
git clone https://github.com/EU-EC3/Ransomware-Decrypt-Tools.git

# AV/安全厂商免费解密工具
# ● Kaspersky RakhniDecryptor
# ● Avast Decryption Tools
# ● Emsisoft Decryptor
# ● Trend Micro Ransomware Decryptor

# 已知解密工具速查
# WannaCry:     wannakiwi.exe
# GandCrab:     gandcrab_decryptor
# TeslaCrypt:   teslacrypt_decryptor
# CryptoLocker: cryptolocker_decryptor

# 注意：不要直接运行未验证的"解密工具" — 可能是二次勒索
```

### 6. 防止二次攻击核心措施

```powershell
# 1. 修复RDP弱口令
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | 
    Where-Object {$_.TimeCreated -gt (Get-Date).AddDays(-7)} | 
    Group-Object -Property @{$_.Properties[5].Value} | 
    Where-Object Count -gt 100 | Select Name, Count

# 2. 禁用不必要的RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1

# 3. 启用MFA（所有管理员账户）
# Azure AD: 条件访问策略 → 要求MFA

# 4. 配置Windows防火墙 — 仅允许必要端口
New-NetFirewallRule -DisplayName "Block RDP (Admin)" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block

# 5. 禁用SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# 6. 配置AppLocker（限制执行权限）
# 策略: 仅允许签名程序和C:\Program Files下的程序执行

# 7. 启用PowerShell日志记录
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
```

### 7. 决策树 — 是否支付赎金

```text
                发现勒索软件
                    │
                    ▼
          ┌─────────────────────┐
          │   有可用备份？       │
          ├─────┬───────┬───────┤
          │ 是  │  部分  │  无   │
          └──┬──┴───┬───┴───┬───┘
             │      │       │
             ▼      ▼       ▼
         ┌────┐ ┌─────┐ ┌──────┐
         │恢  │ │部 分 │ │评 估 │
         │复  │ │恢 复 │ │支 付 │
         │备  │ │+解 密│ │风 险 │
         │份  │ │工 具 │ │      │
         └────┘ └─────┘ └──┬───┘
                            │
              ┌─────────────┴─────────────┐
              │ 支付决策关键考量因素        │
              ├───────────────────────────┤
              │ ● 解密成功率（历史记录）    │
              │ ● 数据敏感度与泄露风险      │
              │ ● 业务中断成本             │
              │ ● 法律/合规风险（OFAC）    │
              │ ● 声誉影响                │
              │ ● 二次勒索概率             │
              └───────────────────────────┘
```

**关于赎金的官方立场：**

> ⚠️ **不推荐支付赎金。** 支付赎金不能保证数据恢复，且会进一步助长勒索软件产业。根据US Treasury OFAC指引，向某些勒索软件组织支付赎金可能违反制裁法规。

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| ID Ransomware | 勒索软件家族识别 | https://id-ransomware.malwarehunterteam.com/ |
| No More Ransom | 解密工具合集 | https://www.nomoreransom.org/ |
| Emsisoft Decryptor | 多家族解密工具 | https://www.emsisoft.com/ransomware-decryption-tools/ |
| Kasperski RakhniDecryptor | 多家族解密 | https://noransom.kaspersky.com/ |
| ShadowExplorer | VSS卷影浏览 | https://www.shadowexplorer.com/ |
| FTK Imager | 加密文件取证镜像 | https://www.exterro.com/ftk-imager |
| CISA Ransomware Guide | 官方应急指南 | https://www.cisa.gov/ransomware |

## 参考资源

- [CISA — Ransomware Guide](https://www.cisa.gov/sites/default/files/publications/CISA_MS-ISAC_Ransomware%20Guide_S508C.pdf)
- [No More Ransom Project](https://www.nomoreransom.org/)
- [FS-ISAC Ransomware](https://www.fsisac.com/)
- [US Treasury OFAC — Ransomware Advisory](https://home.treasury.gov/policy-issues/financial-sanctions/recent-actions/20210921)
- [MITRE D3FEND — Ransomware Mitigations](https://d3fend.mitre.org/)
- [The DFIR Report — 真实勒索软件案例分析](https://thedfirreport.com/)
