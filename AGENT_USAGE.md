# 🤖 AI Agent 使用指南 — CyberSecurity-Skills

> 本文件指导 **AI Agent**（如 Claude Code、Cursor、CodeGPT 等）如何自动识别、查询和调用本技能库。

---

## 一、自动发现机制

AI Agent 通过以下入口文件自动发现本仓库的结构和能力：

| 文件 | 用途 |
|:---|:---|
| [`agent-manifest.json`](agent-manifest.json) | **AI Agent 入口清单** — 描述项目能力、调用方式和示例 |
| [`index.json`](index.json) | **结构化索引** — 按模块组织的完整技能列表，含 ID、难度、文件名 |
| [`index.schema.json`](index.schema.json) | **JSON Schema** — 验证 index.json 结构合法性 |
| [`skill_query.py`](skill_query.py) | **可编程 API** — CLI 工具，支持 `search` / `list` / `resolve` / `validate` |

---

## 二、技能文件格式规范

每个技能文件（`.md`）均包含标准化的 YAML frontmatter，便于机器解析：

```yaml
---
id: "15-001"                           # 模块ID-技能序号
title: "🤖 AI安全应急响应"             # 技能标题
category: "应急响应"                    # 中文分类
category_en: "Incident Response"       # 英文分类
difficulty: "★★★★"                     # 难度（★~★★★★★）
tools: "AI IR Framework, MITRE ATLAS" # 推荐工具
last_updated: "2025-07"               # 最后更新
---
```

### 文件内标准段落结构

| 段落标题 | 用途 | 是否必须 |
|:---|:---|:---:|
| `## 概述` | 技能背景、适用场景 | ✅ |
| `## 核心技能` | 技术原理、命令示例、代码片段 | ✅ |
| `## 漏洞评级与评估矩阵` | 风险等级、CVSS 评分 | ⭕ |
| `## 常用工具` | 工具清单表 | ✅ |
| `## 参考资源` | 外部链接和标准引用 | ✅ |

---

## 三、AI Agent 调用方式

### 方式 1：通过 `skill_query.py` 查询

```bash
# 列出所有模块
python skill_query.py list-modules

# 列出模块 15（应急响应）的所有技能
python skill_query.py list-skills --module 15

# 获取特定技能的完整内容
python skill_query.py get-skill --id 15-001

# 搜索与 "SQL注入" 相关的技能
python skill_query.py search --keyword SQL注入

# 解析技能文件的绝对路径
python skill_query.py resolve --module 3 --skill SQL注入

# 验证索引与实际文件的一致性
python skill_query.py validate
```

### 方式 2：直接解析 `index.json`

AI Agent 可以直接读取 `index.json` 获取结构化数据：

```python
import json

with open("index.json", "r", encoding="utf-8") as f:
    index = json.load(f)

# 遍历所有模块和技能
for mod in index["modules"]:
    print(f"[{mod['id']}] {mod['name_cn']} ({mod['skill_count']} skills)")
    for skill in mod["skills"]:
        print(f"  - {skill['name']} [{skill['difficulty']}]")
        print(f"    文件: {mod['path']}/skills/{skill['file']}")
```

### 方式 3：读取 `agent-manifest.json` 获取集成信息

```python
import json

with open("agent-manifest.json", "r", encoding="utf-8") as f:
    manifest = json.load(f)

# 获取入口点和能力定义
for cap_name, cap_info in manifest["capabilities"].items():
    print(f"能力: {cap_name}")
    print(f"  {cap_info['description']}")
    print(f"  调用方式: {cap_info['invocation_hint']}")
```

---

## 四、AI Agent 工作流示例

### 场景：根据用户需求搜索并加载技能

```
用户: "如何检测提示注入攻击？"

Agent 工作流:
1. python skill_query.py search --keyword 提示注入
   → 发现 16-大模型安全-LLMSecurity 模块中的技能匹配

2. python skill_query.py list-skills --module 16
   → 列出所有 LLM 安全技能，找到 "LLM提示注入与安全防护"

3. python skill_query.py resolve --module 16 --skill 提示注入
   → 获取文件路径: /skills/LLM提示注入与安全防护-PromptInjectionDefense.md

4. 读取该文件，提取核心技能和命令示例回复用户
```

### 场景：渗透测试全流程检查

```
用户: "帮我做一个完整的渗透测试技能检查清单"

Agent 工作流:
1. python skill_query.py list-modules
   → 获取所有 16 个阶段

2. for each module: python skill_query.py list-skills --module <id>
   → 获取每个阶段的技能列表

3. 组合成完整的渗透测试检查清单返回用户
```

---

## 五、AI Agent 自有技能集成

本项目可作为 AI Agent（如 Claude Code）的 **community skill** 使用：

1. 将本仓库克隆到 Agent 可访问的路径
2. 在 Agent 的系统提示中添加技能路径引用
3. Agent 通过 `skill_query.py` 或直接读取 `index.json` 获取技能内容

```json
// 在 agent 配置中引用
{
  "skills": [
    {
      "name": "cybersecurity-skills",
      "path": "/path/to/CyberSecurity-Skills",
      "manifest": "agent-manifest.json"
    }
  ]
}
```

---

## 六、贡献指南

- 新增技能文件后，务必更新 `index.json` 和运行 `python skill_query.py validate`
- 保持 YAML frontmatter 字段完整
- 确保所有命令示例都包含在 ` ``` ` 代码块中
- 文件编码必须为 UTF-8

---

> 💡 有任何集成问题，请通过 Atomgit Issues 提出。
