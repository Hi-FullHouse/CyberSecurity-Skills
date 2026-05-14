# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2025-07

### Added
- 新增 `index.schema.json` — JSON Schema 验证文件，确保 index.json 结构合法
- 新增 `agent-manifest.json` — AI Agent 入口清单，标准化智能体集成接口
- 新增 `skill_query.py` — AI Agent 可编程 CLI API（支持 list-modules / list-skills / get-skill / search / resolve / validate 命令）
- 新增 `AGENT_USAGE.md` — AI Agent 集成指南，含查询方式和工作流示例
- 新增 `.github/workflows/validate.yml` — GitHub Actions CI 自动验证工作流
- 新增 Badge 标识（Agent-Ready / Skills / CLI）

### Fixed
- 修复 index.json 中阶段5（后渗透）的 `skill_count` 由 1 修正为 4，补充缺失的3个技能条目
- 修复 README 中阶段5技能数（1→4）
- 修复 README 和 index.json 中总技能数（83→86），与实际文件数一致 (Red & Blue Team) — 3个技能
- 后渗透阶段(05)：
  - 键盘记录与屏幕捕获 (Keylogging & Screen Capture)
  - 凭证转储与哈希传递 (Credential Dumping & PtH)
  - 远程控制与交互式Shell (Remote Control & Shell)
  - 会话劫持与令牌窃取 (Session Hijacking & Token Theft)
- 持久化阶段(07)：新增DLL劫持与侧加载、BIOS/UEFI持久化
- 痕迹清除阶段(08)：新增日志清理、时间戳篡改、取证对抗
- 新增 SECURITY.md、CODE_OF_CONDUCT.md
- 新增 `.github/workflows/link-check.yml` CI配置

### Changed
- 修复AI Agent文件名空格导致URL编码问题
- 补齐所有阶段README的"参考资源"章节
- 优化README主目录"参考项目与致谢"链接
- 更新 index.json 技能总数与版本号

### Fixed
- 修复Markdown链接中%20编码问题
- 修复部分文件中的错别字和格式问题

## [2.0.0] - 2025-07

### Added
- 初始完整版本，覆盖16个阶段，83个技能
