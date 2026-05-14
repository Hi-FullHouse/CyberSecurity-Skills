# 🚨 阶段十五：应急响应 (Incident Response)

## 目标
建立系统化的网络安全应急响应能力，覆盖事件发现、分析、遏制、清除、恢复与复盘的完整生命周期。参照 **NIST SP 800-61 Rev 2**、**SANS PICERL** 和 **ISO 27035** 等国际标准，培养从事件分类到深度取证的全流程实战技能。

## 核心技能清单

| # | 技能名称 | 难度 | 推荐工具 |
|:---:|:---|:---:|:---|
| 1 | 事件分类与优先级评估 | ★★★ | 事件管理平台, SIRP工具 |
| 2 | 日志收集与分析 | ★★★ | ELK Stack, Splunk, Wazuh |
| 3 | 内存取证分析 | ★★★★★ | Volatility, Rekall, LiME |
| 4 | 磁盘取证与数据恢复 | ★★★★ | FTK Imager, Autopsy, dd |
| 5 | 网络流量分析 | ★★★★ | Wireshark, Zeek, Suricata |
| 6 | 恶意样本分析 | ★★★★★ | Cuckoo Sandbox, Ghidra, YARA |
| 7 | 事件遏制与清除 | ★★★★ | Firewall ACL, EDR隔离, GPO |
| 8 | 勒索软件应急响应 | ★★★★★ | EDR工具, 解密工具, 备份恢复 |
| 9 | 云环境应急响应 | ★★★★ | AWS GuardDuty, Azure Sentinel |
| 10 | 威胁狩猎 | ★★★★★ | KQL, YARA, Sigma, MITRE ATT&CK |
| 11 | SOAR自动化响应 | ★★★★ | Splunk SOAR, Shuffle, Tines |
| 12 | 事件复盘与报告 | ★★★ | 复盘模板, Root Cause分析 |
| 13 | 🤖 AI安全应急响应 | ★★★★ | AI IR Framework, MITRE ATLAS, TheHive |

## Skills 目录

- [`skills/事件分类与优先级评估-IncidentTriage.md`](skills/事件分类与优先级评估-IncidentTriage.md)
- [`skills/日志收集与分析-LogCollectionAnalysis.md`](skills/日志收集与分析-LogCollectionAnalysis.md)
- [`skills/内存取证分析-MemoryForensics.md`](skills/内存取证分析-MemoryForensics.md)
- [`skills/磁盘取证与数据恢复-DiskForensicsDataRecovery.md`](skills/磁盘取证与数据恢复-DiskForensicsDataRecovery.md)
- [`skills/网络流量分析-NetworkTrafficAnalysis.md`](skills/网络流量分析-NetworkTrafficAnalysis.md)
- [`skills/恶意样本分析-MalwareSampleAnalysis.md`](skills/恶意样本分析-MalwareSampleAnalysis.md)
- [`skills/事件遏制与清除-ContainmentEradication.md`](skills/事件遏制与清除-ContainmentEradication.md)
- [`skills/勒索软件应急响应-RansomwareIncidentResponse.md`](skills/勒索软件应急响应-RansomwareIncidentResponse.md)
- [`skills/云环境应急响应-CloudIncidentResponse.md`](skills/云环境应急响应-CloudIncidentResponse.md)
- [`skills/威胁狩猎-ThreatHunting.md`](skills/威胁狩猎-ThreatHunting.md)
- [`skills/SOAR自动化响应-SOARAutomation.md`](skills/SOAR自动化响应-SOARAutomation.md)
- [`skills/事件复盘与报告-LessonsLearnedReporting.md`](skills/事件复盘与报告-LessonsLearnedReporting.md)
- [`skills/AI安全应急响应-AISecurityIncidentResponse.md`](skills/AI安全应急响应-AISecurityIncidentResponse.md)

## 参考资源

- [NIST SP 800-61 Rev 2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS Incident Handling Steps (PICERL)](https://www.sans.org/white-papers/33901/)
- [ISO/IEC 27035 — Information Security Incident Management](https://www.iso.org/standard/78973.html)
- [FIRST — Forum of Incident Response and Security Teams](https://www.first.org/)
- [MITRE ATT&CK — Detection & Response](https://attack.mitre.org/)
- [DFIR Review — 数字取证与事件响应社区](https://dfirreview.com/)
- [The DFIR Report — 真实事件分析报告](https://thedfirreport.com/)
