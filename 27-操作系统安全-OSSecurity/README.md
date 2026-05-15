# 🖥️ 阶段二十七：操作系统安全 (OS Security)

## 目标
系统化覆盖操作系统层安全加固基线、攻击技术、权限维持与防御策略，涵盖 Windows、Linux、macOS 及国产操作系统，结合国内外优秀实践（CIS Benchmarks、等保2.0）建立完整的 OS 安全知识体系。

## 核心技能清单
| # | 技能名称 | 难度 | 攻击/防御 | 推荐工具 |
|:---:|:---|:---:|:--------:|:---|
| 1 | Windows安全加固与基线检查 | ★★★ | 防御 | CIS Benchmarks, GPO, LGPO, Microsoft Security Compliance Toolkit |
| 2 | Windows攻击与横向移动技术 | ★★★★ | 攻击 | Impacket, Mimikatz, Rubeus, BloodHound, CrackMapExec |
| 3 | Linux安全加固与基线检查 | ★★★ | 防御 | Lynis, OpenSCAP, auditd, SELinux, AppArmor |
| 4 | Linux攻击与权限维持技术 | ★★★★ | 攻击 | LinPEAS, GTFO Bins, systemctl, Chisel, Diamorphine |
| 5 | macOS安全评估与加固 | ★★★★ | 两者 | SIP, TCC, MDM, osquery, Santa, Goal, BlockBlock |
| 6 | 国产操作系统安全加固 | ★★★ | 防御 | KylinOS, UOS, openEuler, 等保2.0, SM2/SM3/SM4 |

## Skills 目录
- [`skills/Windows安全加固与基线检查-WindowsHardeningBaseline.md`](skills/Windows安全加固与基线检查-WindowsHardeningBaseline.md)
- [`skills/Windows攻击与横向移动技术-WindowsAttackLateralMovement.md`](skills/Windows攻击与横向移动技术-WindowsAttackLateralMovement.md)
- [`skills/Linux安全加固与基线检查-LinuxHardeningBaseline.md`](skills/Linux安全加固与基线检查-LinuxHardeningBaseline.md)
- [`skills/Linux攻击与权限维持技术-LinuxAttackPersistence.md`](skills/Linux攻击与权限维持技术-LinuxAttackPersistence.md)
- [`skills/macOS安全评估与加固-macOSSecurityHardening.md`](skills/macOS安全评估与加固-macOSSecurityHardening.md)
- [`skills/国产操作系统安全加固-DomesticOSSecurity.md`](skills/国产操作系统安全加固-DomesticOSSecurity.md)

## 参考资源
- [CIS Benchmarks](https://www.cisecurity.org/benchmark/)
- [GB/T 22239-2019 信息安全技术 网络安全等级保护基本要求](https://openstd.samr.gov.cn/)
- [MITRE ATT&CK — Enterprise Tactics](https://attack.mitre.org/tactics/enterprise/)
- [NIST SP 800-53 Rev 5 — Security and Privacy Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [Microsoft Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)
- [Apple Platform Security Guide](https://support.apple.com/en-us/guide/security/welcome/web)
- [银河麒麟安全配置指南](https://www.kylinos.cn/support/technical.html)
- [华为 openEuler 安全指南](https://docs.openeuler.org/zh/docs/24.03_LTS/docs/security/security.html)
