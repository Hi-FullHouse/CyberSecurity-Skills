---
id: 22-001
title: "📋 数据分类与分级保护 (Data Classification & Grading)"
category: 数据安全与隐私
category_en: "Data Security & Privacy"
difficulty: ★★★
tools: "Data Classification Toolkit, Varonis, Microsoft Purview, BigID, Spirion"
last_updated: 2025-07
tags: ["data-security", "privacy", "dlp", "gdpr", "encryption", "data-classification"]
subdomain: data-security-privacy
nist_csf: ["PR.DS-01", "PR.DS-02", "PR.DS-05", "ID.GV-03"]
mitre_attack: ["T1530", "T1048", "T1567"]
---
# 📋 数据分类与分级保护 (Data Classification & Grading)

## 概述

数据分类分级是数据安全治理的基石。根据数据的敏感程度、业务影响和法规要求，对数据进行分级标识，并实施差异化的访问控制和保护策略。本标准参考 **ISO 27001**、**等级保护2.0**、**GDPR** 和 **NIST SP 800-60** 等规范。

## 核心技能

### 1. 数据分类框架设计

```plaintext
# 典型数据分类四级体系
Level 1 - 公开 (Public): 对外宣传资料、公开文档
Level 2 - 内部 (Internal): 内部邮件、制度文档、非敏感运营数据
Level 3 - 敏感 (Confidential): 客户信息、财务数据、业务策略
Level 4 - 绝密 (Restricted): 商业秘密、核心算法、用户隐私数据

# 等级保护2.0 数据分级
一级 - 一般数据：泄露不损害公共利益
二级 - 重要数据：泄露损害公共利益
三级 - 核心数据：泄露严重损害国家安全
```

### 2. 自动化数据发现与分类

```bash
# 使用Microsoft Purview (PowerShell)
# 创建敏感信息类型
New-DlpSensitiveInformationType -Name "CreditCard" -Description "Credit Card Number"
# 创建数据分类规则
New-DlpComplianceRule -Name "CCN Detection" -ContentContainsSensitiveInformation @{Name="CreditCard"; minCount="1"; maxCount="5"}

# 使用Varonis Data Classification Scanner
# 扫描网络共享中的数据
Get-Content "\\server\share" | Select-String -Pattern "\d{4}-\d{4}-\d{4}-\d{4}" -SimpleMatch

# 使用Python进行正则匹配分类
python3 << 'EOF'
import re
import os

patterns = {
    'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'phone_cn': r'1[3-9]\d{9}',
    'id_card_cn': r'\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b'
}

for root, dirs, files in os.walk('/data'):
    for file in files:
        path = os.path.join(root, file)
        try:
            with open(path, 'r', errors='ignore') as f:
                content = f.read()
                for name, pattern in patterns.items():
                    if re.search(pattern, content):
                        print(f"[{name}] {path}")
        except:
            pass
EOF
```

### 3. 数据分级标记与标签管理

```bash
# AWS 数据标签
aws s3api put-object-tagging --bucket my-bucket --key data.csv \
  --tagging 'TagSet=[{Key=Classification,Value=Confidential},{Key=Retention,Value=7Y}]'

# Azure 数据标签
# 使用PowerShell设置Azure Information Protection标签
Set-AIPFileLabel -Path "C:\data\report.docx" -LabelID "confidential-label-id" -JustificationMessage "Data classification audit"

# 数据库列级标记 (PostgreSQL)
COMMENT ON COLUMN users.phone IS 'ENCRYPTED:LEVEL3:PII';
COMMENT ON COLUMN users.email IS 'MASKED:LEVEL2:PII';

# 元数据管理工具
# Apache Atlas - 数据血缘与分类
curl -u admin:admin -X POST -H "Content-Type: application/json" \
  -d '{"classification":"PII","entityGuid":"guid-xxxx"}' \
  http://atlas:21000/api/atlas/v2/entity/guid-xxxx/classifications
```

### 4. 数据生命周期安全管理

```bash
# 数据保留策略设置 (Windows File Server)
fsutil behavior set disablelastaccess 1

# Linux文件系统数据保留
# 设置文件不可变属性（防止删除）
chattr +a sensitive_data.csv

# 数据安全删除
# Windows: 使用cipher覆盖
cipher /w:C:\data\

# Linux: 使用shred安全删除
shred -vfz -n 7 sensitive_data.csv

# 数据库数据脱敏导出
# MySQL
SELECT 
  CONCAT(LEFT(name, 1), '***') as name,
  CONCAT(LEFT(phone, 3), '****', RIGHT(phone, 4)) as phone,
  email
INTO OUTFILE '/tmp/export_masked.csv'
FROM users;
```

### 5. 数据分类分级检查清单

| 检查项 | 方法 | 合规标准 |
|:---|:---|:---:|
| 敏感数据发现 | 正则扫描/ML分类器 | ISO 27001 A.8.2.1 |
| 数据分级标签 | 自动化标记策略 | 等级保护 2.0 |
| 访问控制策略 | 基于分级的最小权限 | NIST SP 800-53 |
| 加密存储 | 静态加密(AES-256) | GDPR Art.32 |
| 传输加密 | TLS 1.2+ | PCI DSS 4.0 |
| 数据保留 | 自动过期策略 | 个保法 Art.19 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Microsoft Purview | 企业级数据治理与分类 | https://learn.microsoft.com/en-us/purview/ |
| Varonis DSP | 数据安全平台 | https://www.varonis.com/ |
| BigID | 数据智能与隐私平台 | https://bigid.com/ |
| Apache Atlas | 开源数据血缘与分类 | https://atlas.apache.org/ |
| Spirion | 敏感数据发现 | https://www.spirion.com/ |
| SleuthKit | 文件系统分析 | https://www.sleuthkit.org/ |

## 参考资源

- [ISO 27001:2022 — Annex A 8.2 Data classification](https://www.iso.org/standard/27001)
- [NIST SP 800-60 — Guide for Mapping Types of Information](https://csrc.nist.gov/publications/detail/sp/800-60/vol-1-rev-1/final)
- [等级保护2.0 — 数据安全分级指南](https://www.gov.cn/zhengce/zhengceku/2022-12/16/content_5732384.htm)
- [OWASP Data Classification](https://owasp.org/www-project-data-security-taxonomy/)
- [GDPR — Data Protection Principles](https://gdpr-info.eu/art-5-gdpr/)
