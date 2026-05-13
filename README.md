# 🔒 CyberSecurity-Skills · 网络安全技能库

> **渗透测试全流程技能体系** — 从信息收集到报告撰写的完整知识框架

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

## 📋 概述

本仓库以 **渗透测试执行标准（PTES）** 为核心框架，结合 **OWASP测试指南**、**NIST SP 800-115** 等国际标准，系统化整理了网络安全渗透测试全流程所需的 **技能清单（Skills Checklist）**。

每个技能条目包含：
- ✅ 技术原理说明
- ✅ 常用工具/命令
- ✅ 实战操作示例
- ✅ 参考资源链接

---

## 🗺️ 目录结构

```
CyberSecurity-Skills/
│
├── 01-信息搜集-Reconnaissance/         # 信息收集与侦察
├── 02-漏洞扫描-VulnerabilityScanning/  # 漏洞发现与扫描
├── 03-漏洞利用-Exploitation/           # 漏洞利用与攻击
├── 04-权限提升-PrivilegeEscalation/    # 权限提升
├── 05-后渗透-PostExploitation/         # 后渗透利用
├── 06-横向移动-LateralMovement/        # 横向移动
├── 07-持久化-Persistence/              # 持久化控制
├── 08-痕迹清除-CoveringTracks/         # 痕迹清除
├── 09-报告撰写-Reporting/              # 渗透测试报告
├── 10-移动安全-MobileSecurity/         # 移动安全
├── 11-无线安全-WirelessSecurity/       # 无线网络安全
├── 12-代码审计-CodeAudit/              # 代码安全审计
├── 13-逆向工程-ReverseEngineering/     # 逆向工程
└── 14-安全审计-SecurityAudit/          # 安全合规审计
```

---

## 🗂️ 渗透测试全流程（14大阶段，共56个技能）

| 阶段 | 中文名称 | 英文名称 | 技能数 |
|:---:|:---|:---|:---:|
| 01 | 🔍 信息搜集 | Reconnaissance | 7 |
| 02 | 📡 漏洞扫描 | Vulnerability Scanning | 6 |
| 03 | 💥 漏洞利用 | Exploitation | 8 |
| 04 | ⬆️ 权限提升 | Privilege Escalation | 4 |
| 05 | 🕵️ 后渗透 | Post-Exploitation | 1 |
| 06 | 🔄 横向移动 | Lateral Movement | 3 |
| 07 | 🔗 持久化 | Persistence | 1 |
| 08 | 🧹 痕迹清除 | Covering Tracks | 1 |
| 09 | 📝 报告撰写 | Reporting | 5 |
| 10 | 📱 移动安全 | Mobile Security | 2 |
| 11 | 📶 无线安全 | Wireless Security | 1 |
| 12 | 🔬 代码审计 | Code Audit | 8 |
| 13 | ⚙️ 逆向工程 | Reverse Engineering | 3 |
| 14 | 🛡️ 安全审计 | Security Audit | 6 |
| | | **总计** | | **56** |

---

## 📌 完整技能清单

### 阶段 01 · 🔍 信息搜集 (Reconnaissance)

| # | 技能名称 | 文件名 |
|:---:|:---|:---|
| 1 | 🕵️ 被动信息搜集 / OSINT | `被动信息搜集-PassiveRecon.md` |
| 2 | 🎯 主动信息搜集 | `主动信息搜集-ActiveRecon.md` |
| 3 | 🌐 DNS枚举 | `DNS枚举-DNSEnumeration.md` |
| 4 | 🔗 子域名探测 | `子域名探测-SubdomainDiscovery.md` |
| 5 | 🔍 网络空间搜索引擎 | `网络空间搜索引擎-OSINT-SearchEngine.md` |
| 6 | 👥 社会工程学信息 | `社会工程学信息-SocialEngineeringInfo.md` |
| 7 | 🖥️ 目标技术栈识别 | `目标技术栈识别-TechStackFingerprint.md` |

### 阶段 02 · 📡 漏洞扫描 (Vulnerability Scanning)

| # | 技能名称 | 文件名 |
|:---:|:---|:---|
| 1 | 📡 Web漏洞扫描 | `Web漏洞扫描-WebVulnScan.md` |
| 2 | 🌐 网络漏洞扫描 | `网络漏洞扫描-NetworkVulnScan.md` |
| 3 | 🗄️ 数据库安全评估 | `数据库安全评估-DatabaseAssessment.md` |
| 4 | 🔌 API安全测试 | `API安全测试-APISecurityTest.md` |
| 5 | 🔧 配置审计扫描 | `配置审计扫描-ConfigAuditScan.md` |
| 6 | 🤖 漏洞扫描器自动化 | `漏洞扫描器自动化-VulnScannerAutomation.md` |

### 阶段 03 · 💥 漏洞利用 (Exploitation)

| # | 技能名称 | 文件名 |
|:---:|:---|:---|
| 1 | 🌐 Web漏洞利用 | `Web漏洞利用-WebExploitation.md` |
| 2 | 💉 SQL注入利用 | `SQL注入利用-SQLInjection.md` |
| 3 | ⚡ XSS跨站脚本 | `XSS跨站脚本-XSSExploitation.md` |
| 4 | 📂 文件包含与上传 | `文件包含利用-FileInclusion.md` |
| 5 | ⌨️ 命令注入 | `命令注入-CommandInjection.md` |
| 6 | 🔗 SSRF服务端请求伪造 | `SSRF服务端请求伪造-SSRF.md` |
| 7 | 🔐 认证绕过 | `认证绕过-AuthBypass.md` |
| 8 | 💀 Metasploit框架利用 | `Metasploit框架利用-Metasploit.md` |

### 阶段 04 · ⬆️ 权限提升 (Privilege Escalation)

| # | 技能名称 | 文件名 |
|:---:|:---|:---|
| 1 | 🐧 Linux提权 | `Linux提权-LinuxPrivEsc.md` |
| 2 | 🪟 Windows提权 | `Windows提权-WindowsPrivEsc.md` |
| 3 | ⬆️ 内核与服务配置错误提权 | `内核漏洞与服务配置错误提权-KernelServicePrivEsc.md` |
| 4 | 🔑 凭证窃取与利用 | `凭证窃取与利用-CredentialTheft.md` |

### 阶段 05 · 🕵️ 后渗透 (Post-Exploitation)

| # | 技能名称 | 文件名 |
|:---:|:---|:---|
| 1 | 🕵️ 信息收集与数据窃取 | `信息收集与数据窃取-InfoGatheringDataExfil.md` |

### 阶段 06 · 🔄 横向移动 (Lateral Movement)

| # | 技能名称 | 文件名 |
|:---:|:---|:---|
| 1 | 🔄 横向移动 | `横向移动-LateralMovement.md` |
| 2 | 🔗 内网代理与隧道 | `内网代理与隧道-InternalProxyTunnel.md` |
| 3 | 🔁 PsExec与WMI远程执行 | `PsExec与WMI远程执行-PsExecWMI.md` |

### 阶段 07 · 🔗 持久化 (Persistence)

| # | 技能名称 | 文件名 |
|:---:|:---|:---|
| 1 | 🔐 持久化 - 长期控制 | `持久化-Persistence.md` |

### 阶段 08 · 🧹 痕迹清除 (Covering Tracks)

| # | 技能名称 | 文件名 |
|:---:|:---|:---|
| 1 | 🧹 痕迹清除与反取证 | `痕迹清除-CoveringTracks.md` |

### 阶段 09 · 📝 报告撰写 (Reporting)

| # | 技能名称 | 文件名 |
|:---:|:---|:---|
| 1 | 📝 渗透测试报告编写 | `报告编写-PentestReport.md` |
| 2 | 📊 漏洞评级与CVSS评分 | `漏洞评级与CVSS-VulnRatingCVSS.md` |
| 3 | 📄 Markdown安全报告模板 | `安全报告模板-Markdown.md` |
| 4 | 🌐 HTML安全报告模板 | `安全报告模板-HTML.md` |
| 5 | 📑 Word/PDF安全报告模板 | `安全报告模板-Word.md` |

### 阶段 10 · 📱 移动安全 (Mobile Security)

| # | 技能名称 | 文件名 |
|:---:|:---|:---|
| 1 | 📱 Android安全测试 | `Android安全测试-AndroidSecurityTest.md` |
| 2 | 🍎 iOS安全测试 | `iOS安全测试-iOSSecurityTest.md` |

### 阶段 11 · 📶 无线安全 (Wireless Security)

| # | 技能名称 | 文件名 |
|:---:|:---|:---|
| 1 | 📶 Wi-Fi安全审计 | `WiFi安全审计-WiFiSecurityAudit.md` |

### 阶段 12 · 🔬 代码审计 (Code Audit)

| # | 技能名称 | 文件名 |
|:---:|:---|:---|
| 1 | 🔍 PHP代码审计 | `PHP代码审计-PHPCodeAudit.md` |
| 2 | ☕ Java代码审计 | `Java代码审计-JavaCodeAudit.md` |
| 3 | 🌐 JavaScript/Node.js代码审计 | `JavaScript代码审计-JSCodeAudit.md` |
| 4 | 🐍 Python代码审计 | `Python代码审计-PythonCodeAudit.md` |
| 5 | ⚙️ C代码审计 | `C代码审计-CCodeAudit.md` |
| 6 | 🔧 C++代码审计 | `C++代码审计-CPPCodeAudit.md` |
| 7 | 🦀 Rust代码审计 | `Rust代码审计-RustCodeAudit.md` |
| 8 | 🐹 Go代码审计 | `Go代码审计-GoCodeAudit.md` |

### 阶段 13 · ⚙️ 逆向工程 (Reverse Engineering)

| # | 技能名称 | 文件名 |
|:---:|:---|:---|
| 1 | 🔬 静态逆向分析 | `静态逆向分析-StaticReverseAnalysis.md` |
| 2 | ⚙️ 动态调试分析 | `动态调试分析-DynamicDebugAnalysis.md` |
| 3 | 🦠 恶意软件分析 | `恶意软件分析-MalwareAnalysis.md` |

### 阶段 14 · 🛡️ 安全审计 (Security Audit)

| # | 技能名称 | 文件名 |
|:---:|:---|:---|
| 1 | 🏛️ 等级保护合规审计 | `等级保护合规审计-ClassifiedProtectionAudit.md` |
| 2 | 🔧 配置安全审计 | `配置安全审计-ConfigSecurityAudit.md` |
| 3 | 🏗️ 安全架构审计 | `安全架构审计-SecurityArchitectureAudit.md` |
| 4 | ☁️ 云安全审计 | `云安全审计-CloudSecurityAudit.md` |
| 5 | 🐳 容器安全审计 | `容器安全审计-ContainerSecurityAudit.md` |
| 6 | 🌐 网络安全合规评估 | `网络安全合规评估-NetworkComplianceAssessment.md` |

---

## 🎯 使用方式

### 作为学习路线
按编号顺序 01 → 14 依次学习，每个阶段内的技能文件独立阅读。

### 作为实战Checklist
在进行渗透测试时，逐项对照各阶段 Skills 清单，确保全面覆盖。

### 作为教学材料
讲师可按阶段组织课程，每个 Skill 文件可作为一节课的教学大纲。

---

## 🔗 参考项目与致谢

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — 渗透测试Payload大全
- [Awesome-Hacking](https://github.com/Hack-with-Github/Awesome-Hacking) — 黑客资源集合
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — OWASP测试指南
- [PTES](http://www.pentest-standard.org/) — 渗透测试执行标准
- [HackTricks](https://book.hacktricks.xyz/) — 渗透测试技巧百科
- [GTFOBins](https://gtfobins.github.io/) — Unix二进制提权清单
- [LOLBAS](https://lolbas-project.github.io/) — Windows二进制利用清单

---

## 📄 许可证

本项目基于 MIT 许可证开源，仅供合法的安全研究与授权测试使用。

> ⚠️ **免责声明**：所有技能与工具请仅在获得授权的前提下使用，滥用造成的后果由使用者自行承担。
