# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.0] - 2026-05-15

### Added
- **新增12个模块（28-39）**：覆盖威胁狩猎、威胁情报、数字取证、SOC运营、IAM、容器安全、API安全、密码学与PKI、零信任架构、端点安全、勒索软件防御、安全治理与合规，共44个技能
  - 模块28（威胁狩猎）：威胁狩猎方法论、Sigma规则工程、ATT&CK狩猎、流量异常检测
  - 模块29（威胁情报）：TAXII/STIX管理、MISP平台、APT归因、情报驱动运营
  - 模块30（数字取证）：磁盘镜像、Volatility内存分析、Windows/Linux取证、浏览器邮件取证
  - 模块31（SOC运营）：SIEM关联分析、事件分级、SOAR自动化、SOC效能度量
  - 模块32（IAM）：企业IAM策略、PAM、云IAM联邦、AD攻击路径分析
  - 模块33（容器安全）：镜像扫描、K8s RBAC、Falco运行时、容器逃逸检测
  - 模块34（API安全）：OWASP API测试、API认证授权、GraphQL微服务安全
  - 模块35（密码学与PKI）：TLS/SSL配置、PKI证书管理、加密算法与密钥管理
  - 模块36（零信任架构）：ZTA设计、微隔离SDP、ZTNA与IAM集成
  - 模块37（端点安全）：EDR规则、文件less恶意软件、端点加固、移动安全MDM
  - 模块38（勒索软件防御）：攻击链分析、应急响应、加固与备份策略
  - 模块39（安全治理与合规）：框架审计、风险管理、策略与安全意识
- **Frontmatter全面增强**：为全部195个技能文件添加 tags / subdomain / nist_csf / mitre_attack 字段
- 新增 `scripts/enrich_frontmatter.py` — 批量frontmatter增强脚本
- 新增模块28-39的 `README.md` 入口文件

### Changed
- 技能总数从159扩展至195，模块数从27扩展至39
- 更新 `index.json`：版本 v2.4.0，`total_skills` 195，`total_modules` 39
- 更新 `agent-manifest.json`：技能数更新至195，frontmatter字段新增4个
- 更新根 `README.md`：目录树新增模块28-39，模块表格新增12行，全技能表新增阶段28-39

### Added
- **新增模块27（操作系统安全）**：覆盖 Windows/Linux/macOS/国产操作系统安全，6个技能
  - Windows安全加固与基线检查（★★★）— CIS基准、GPO、Defender、Credential Guard、等保2.0
  - Windows攻击与横向移动技术（★★★★）— Kerberos攻击、ACL滥用、DCSync、NTLM中继
  - Linux安全加固与基线检查（★★★）— CIS基准、SELinux/AppArmor、auditd、内核参数
  - Linux攻击与权限维持技术（★★★★）— Capabilities滥用、容器逃逸、systemd持久化、rootkit
  - macOS安全评估与加固（★★★★）— SIP、TCC、XProtect、MDM策略
  - 国产操作系统安全加固（★★★）— KylinOS、UOS、openEuler、SM2/SM3/SM4国密
- 技能总数从153扩展至159，模块数从26扩展至27

### Changed
- 更新 `index.json`：版本 v2.3.0，`total_skills` 159，`total_modules` 27
- 更新 `agent-manifest.json`：技能数更新至159
- 更新根 `README.md`：目录树新增模块27，全技能表新增阶段27

## [2.2.1] - 2026-05-15

### Added
- 模块07（持久化）新增4个技能：启动项与登录自动执行、账户创建与凭证持久化、Office应用程序持久化、Bootkit与固件持久化
- 模块08（痕迹清除）新增3个技能：进程注入与代码注入、代码混淆与反分析、AMSI绕过与EDR规避
- 技能总数从146扩展至153，覆盖 MITRE ATT&CK 更多技术点
- 新增 `.gitattributes` 标准化跨平台换行符
- 新增 `scripts/` 目录，集中管理辅助开发脚本

### Changed
- **难度体系全面标准化**：将模块01/02/03/09中残留的旧3星制（含☆）统一转换为5星制（仅★），消除语义冲突
- 更新 `agent-manifest.json`：新增 `total_skills` 结构化字段，版本提升至 v1.1.0
- 更新 `index.json`：版本 v2.2.1，`last_updated` 更新至 2026-05-15

### Fixed
- 修复根 `README.md` 模块22技能名称与实际文件不一致问题
- 修复根 `README.md` 目录树遗漏模块15（应急响应）问题
- 补齐模块04/05/06/07/08/10/11的参考资源章节
- 更新 `CONTRIBUTING.md` 技能模板为YAML frontmatter + 标准化段落格式
- 优化 `.gitignore` 覆盖更多临时文件模式
- 清理根目录临时文件 `_ls22.ps1`、`_tmp_list.ps1`

## [2.2.0] - 2026-05-13

### Added
- 新增模块17-26，覆盖云安全、DevSecOps、工控安全、区块链/Web3、物联网、数据安全与隐私、社会工程学、红蓝对抗、供应链安全、漏洞管理
- 模块15（应急响应）扩展至13个技能，覆盖威胁狩猎、SOAR自动化、AI安全应急响应等
- 模块16（大模型安全/LLM Security）新增10个技能，覆盖提示注入、红队测试、联邦学习等
- 模块14（安全审计）扩展至7个技能，新增AI Agent安全审计
- 技能总数从86扩展至146

### Changed
- 调整模块02/03为混合难度格式，部分技能采用5星制

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
