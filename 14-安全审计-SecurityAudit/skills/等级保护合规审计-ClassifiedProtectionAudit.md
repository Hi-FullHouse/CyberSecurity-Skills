---
id: 14-005
title: "🏛️ 等级保护合规审计 (Classified Protection Compliance Audit)"
category: 安全审计
category_en: "Security Audit"
difficulty: ★★★★
tools: "等保自查工具, 合规扫描平台"
last_updated: 2025-07
tags: ["security-audit", "compliance", "cloud-audit", "container-audit", "network-audit"]
subdomain: security-audit
nist_csf: ["ID.GV-01", "ID.RM-01", "ID.SC-01"]
mitre_attack: []
---
# 🏛️ 等级保护合规审计 (Classified Protection Compliance Audit)

## 概述
依据《网络安全法》及《信息安全技术 网络安全等级保护基本要求》（GB/T 22239-2019），对信息系统进行等级保护合规评估，检查安全控制措施是否符合对应等级要求。

## 核心技能

### 1. 等级保护基本概念

**等级划分：**
| 等级 | 名称 | 适用对象 |
|:---:|:---|:---|
| 一级 | 自主保护 | 一般系统 |
| 二级 | 指导保护 | 重要系统 |
| 三级 | 监督保护 | 关键基础设施 |
| 四级 | 强制保护 | 极端重要系统 |
| 五级 | 专控保护 | 国家核心系统 |

### 2. 等保2.0测评流程

```text
测评准备 → 方案编制 → 现场测评 → 分析报告 → 整改跟踪
   ↓          ↓          ↓          ↓          ↓
 调研表   编制方案   技术+管理   生成报告   复测确认
```

### 3. 技术安全检查要点

**安全物理环境：**
- 机房位置选择、物理访问控制、温湿度控制
- 电力供应（UPS、冗余）、防雷接地、消防系统

**安全通信网络：**
- 网络架构（区域划分、访问控制）
- 通信加密（TLS/SSH）、边界防护

**安全计算环境：**
- 身份鉴别（双因素、口令策略）
- 访问控制（最小权限原则）
- 安全审计（日志完整、留存>6个月）
- 入侵防范、恶意代码防范

### 4. 安全管理检查要点

**安全管理制度：**
- 安全策略文档、管理制度、操作规程
- 审批流程、变更管理流程

**安全管理机构：**
- 安全岗位设置、人员配备
- 授权审批机制

**安全管理人员：**
- 人员录用、离岗安全
- 安全意识培训、外部人员管理

### 5. 自动合规检查脚本

```bash
# Linux安全检查
cat /etc/passwd | awk -F: '{print $1, $3, $7}'  # 检查用户权限
cat /etc/shadow | awk -F: '{print $1, $2}'       # 检查密码策略
systemctl list-units --type=service --state=running  # 检查运行服务

# Windows安全检查
net user                                     # 列出用户
net localgroup administrators                # 检查管理员组成员
secpol.msc                                   # 检查安全策略
auditpol /get /category:*                    # 检查审计策略
```

### 6. 等保测评工具

```bash
# 使用python自动化检查
pip install security-audit-tool
security-audit --level 3 --output report.html

# 检查Web应用安全
nikto -h https://target.com
nmap --script http-security-headers target.com
```

## 常用工具
| 工具 | 用途 | 链接 |
|:---|:---|:---|
| 等保工具箱 | 等保测评专用工具集 | 公安部推荐 |
| OpenSCAP | 合规扫描框架 | https://www.open-scap.org/ |
| Lynis | 系统安全审计 | https://cisofy.com/lynis/ |
| SecurityHeaders | HTTP安全头检查 | https://securityheaders.com/ |

## 参考资源
- [GB/T 22239-2019 等保2.0基本要求](https://openstd.samr.gov.cn/)
- [等保2.0定级指南](https://www.mps.gov.cn/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
