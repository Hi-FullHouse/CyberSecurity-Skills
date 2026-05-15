# 🔗 阶段七：持久化 (Persistence)

## 目标
在目标系统中建立持久化后门，确保系统重启或密码变更后仍能保持访问。

## 核心技能清单
| # | 技能名称 | 难度 | 推荐工具 |
|:---:|:---|:---:|:---|
| 1 | 持久化控制 | ★★★ | MSF Venom, Cobalt Strike, 计划任务, 自启动项 |
| 2 | 启动项与登录自动执行 | ★★★ | Autoruns, schtasks, systemd, launchd |
| 3 | 账户创建与凭证持久化 | ★★★ | net user, Mimikatz, AWS CLI, Azure AD |
| 4 | Office应用程序持久化 | ★★★★ | EvilClippy, macro_pack, VBA |
| 5 | Bootkit与固件持久化 | ★★★★★ | Chipsec, Flashrom, UEFITool |

## Skills 目录
- [`skills/持久化-Persistence.md`](skills/持久化-Persistence.md)
- [`skills/启动项与登录自动执行-BootLogonAutostart.md`](skills/启动项与登录自动执行-BootLogonAutostart.md)
- [`skills/账户持久化-AccountPersistence.md`](skills/账户持久化-AccountPersistence.md)
- [`skills/Office应用程序持久化-OfficePersistence.md`](skills/Office应用程序持久化-OfficePersistence.md)
- [`skills/Bootkit与固件持久化-BootkitFirmwarePersistence.md`](skills/Bootkit与固件持久化-BootkitFirmwarePersistence.md)

## 参考资源
- [MITRE ATT&CK — Persistence](https://attack.mitre.org/tactics/TA0003/)
- [HackTricks — Persistence](https://book.hacktricks.xyz/windows-hardening/stealth-persistence)
- [SharPersist — Windows Persistence Toolkit](https://github.com/fireeye/SharPersist)
- [PayloadsAllTheThings — Persistence](https://github.com/swisskyrepo/PayloadsAllTheThings)
