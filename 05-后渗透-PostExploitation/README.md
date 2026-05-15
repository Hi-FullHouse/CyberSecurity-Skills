# 🕵️ 阶段五：后渗透 (Post-Exploitation)

## 目标
在获得目标控制权后，进行持续信息收集、敏感数据提取和远程控制。

## 核心技能清单
| # | 技能名称 | 难度 | 推荐工具 |
|:---:|:---|:---:|:---|
| 1 | 信息收集与数据窃取 | ★★★★ | 系统命令, Powerview, BloodHound |
| 2 | 凭证转储与哈希传递 | ★★★★ | Mimikatz, Impacket, Secretsdump |
| 3 | 远程控制与交互式Shell | ★★★★ | Cobalt Strike, Metasploit, Empire |
| 4 | 键盘记录与屏幕捕获 | ★★★★ | 键盘记录器, 截屏工具 |

## Skills 目录
- [`skills/信息收集与数据窃取-InfoGatheringDataExfil.md`](skills/信息收集与数据窃取-InfoGatheringDataExfil.md)
- [`skills/凭证转储与哈希传递-CredentialDumpingPtH.md`](skills/凭证转储与哈希传递-CredentialDumpingPtH.md)
- [`skills/远程控制与交互式Shell-RemoteControlShell.md`](skills/远程控制与交互式Shell-RemoteControlShell.md)
- [`skills/键盘记录与屏幕捕获-KeyloggingScreenCapture.md`](skills/键盘记录与屏幕捕获-KeyloggingScreenCapture.md)

## 参考资源
- [MITRE ATT&CK — Collection](https://attack.mitre.org/tactics/TA0009/)
- [MITRE ATT&CK — Exfiltration](https://attack.mitre.org/tactics/TA0010/)
- [HackTricks — Post Exploitation](https://book.hacktricks.xyz/)
- [BloodHound — Active Directory Attack Path Mapping](https://github.com/BloodHoundAD/BloodHound)
