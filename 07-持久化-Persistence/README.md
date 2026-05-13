# 🔗 阶段七：持久化 (Persistence)

## 目标
在目标系统中建立持久化后门，确保系统重启或密码变更后仍能保持访问。

## 核心技能清单
| # | 技能名称 | 难度 | 推荐工具 |
|:---:|:---|:---:|:---|
| 1 | 后门植入 | ★★★ | MSF Venom, Cobalt Strike, 自定义木马 |
| 2 | 计划任务 | ★★☆ | at/schtasks (Windows), cron (Linux) |
| 3 | 自启动项 | ★★☆ | 注册表Run键, 启动文件夹 |
| 4 | 服务持久化 | ★★★ | Windows服务, Systemd服务 |
| 5 | WebShell维持 | ★★★ | 小马/大马, 一句话木马 |

## Skills 目录
- [`skills/后门植入-BackdoorInstall.md`](skills/后门植入-BackdoorInstall.md)
- [`skills/计划任务-ScheduledTasks.md`](skills/计划任务-ScheduledTasks.md)
- [`skills/自启动项-AutoStartRegistry.md`](skills/自启动项-AutoStartRegistry.md)
- [`skills/服务持久化-ServicePersistence.md`](skills/服务持久化-ServicePersistence.md)
- [`skills/WebShell维持-WebShellPersistence.md`](skills/WebShell维持-WebShellPersistence.md)
