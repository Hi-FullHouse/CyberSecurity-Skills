# 📝 阶段九：报告撰写 (Reporting) — v2.0

> **更新**: 2025-Q1 | **特性**: 三格式统一模板体系 · AI Agent 原生接口 · 业界最佳实践

## 目标

将渗透测试发现的问题、利用过程和修复建议整理成专业的安全评估报告，覆盖 **Markdown / HTML / Word** 三种主流输出格式。所有模板遵循统一的 JSON Schema 数据模型，便于 AI Agent 跨格式调用和批量生成。

## 核心技能清单

| # | 技能名称 | 难度 | 推荐工具 | 对应文件 |
|:---:|:---|:---:|:---|---:|
| 1 | 渗透测试报告编写方法论 | ★★★ | 结构化模板 + 质量标准 | [`skills/报告编写-PentestReport.md`](skills/报告编写-PentestReport.md) |
| 2 | 漏洞评级与 CVSS 评分 | ★★★ | CVSS 3.1/4.0, DREAD | [`skills/漏洞评级与CVSS-VulnRatingCVSS.md`](skills/漏洞评级与CVSS-VulnRatingCVSS.md) |
| 3 | **Markdown 安全报告** | ★★ | Typora / VS Code / Mermaid | [`skills/安全报告模板-Markdown.md`](skills/安全报告模板-Markdown.md) |
| 4 | **HTML 安全报告（交互式）** | ★★★ | Chart.js / 暗色模式 / PDF导出 | [`skills/安全报告模板-HTML.md`](skills/安全报告模板-HTML.md) |
| 5 | **Word/PDF 安全报告** | ★★★ | python-docx / LibreOffice | [`skills/安全报告模板-Word.md`](skills/安全报告模板-Word.md) |

## 模板体系总览

三个模板共享统一的数据模型（JSON Schema），AI Agent 只需一份数据即可生成任意格式的报告：

```
┌─────────────────────────────────────────────────────────────┐
│                    统一数据模型 (JSON)                       │
│  report_meta · executive_summary · scope · methodology      │
│  findings · systems · compliance_mapping · appendix         │
└──────────────────┬──────────────────┬───────────────────────┘
                   │                  │
        ┌──────────▼──────────┐  ┌────▼─────────────┐
        │  Markdown           │  │  HTML             │
        │  (skills/模板-MD)   │  │  (skills/模板-HTML)│
        │  - 完整模板结构      │  │  - Chart.js 图表   │
        │  - Mermaid 图表      │  │  - 暗色/亮色切换   │
        │  - 5种模板变体       │  │  - 侧边栏导航      │
        │  - Python 生成器     │  │  - 打印/PDF        │
        └─────────────────────┘  └────────────────────┘
                    ┌──────────────────────┐
                    │  Word (.docx)        │
                    │  (skills/模板-Word)  │
                    │  - 完整封面+目录     │
                    │  - 风险等级颜色标注   │
                    │  - 页眉页脚+页码     │
                    │  - python-docx 生成器│
                    └──────────────────────┘
```

## 各模板核心特性对比

| 特性 | Markdown | HTML | Word |
|:---|:---:|:---:|:---:|
| **输出格式** | .md | .html | .docx → PDF |
| **阅读方式** | Typora / VS Code / GitHub | 浏览器直接打开 | Microsoft Word / LibreOffice |
| **交互式图表** | Mermaid (文本) | Chart.js (动态) | 静态表格+进度条 |
| **暗色模式** | — | ✅ CSS Variables | — |
| **侧边栏导航** | — | ✅ 固定侧边栏 | ✅ 文档导航窗格 |
| **打印/PDF导出** | 浏览器打印 | Ctrl+P 直接打印 | Word "导出为PDF" |
| **自动生成代码** | ✅ Python 脚本 | ✅ Python 脚本 | ✅ Python 脚本 |
| **AI Agent 调用** | ✅ `MarkdownReportAgent` | ✅ `HTMLReportGenerator` | ✅ `WordReportGenerator` |
| **批量生成** | ✅ `batch_generate()` | ✅ `batch_generate()` | ✅ `batch_generate()` |
| **CVSS 3.1/4.0** | ✅ | ✅ | ✅ |
| **OWASP Top 10 映射** | ✅ | ✅ | ✅ |

## 统一 JSON Schema（AI Agent 数据模型）

三个模板共享同一数据接口，Agent 只需准备一次数据：

```python
# AI Agent 调用示例 - 只需修改目标格式
data = {"report_meta": {...}, "executive_summary": {...}, "findings": [...]}

# 生成 Markdown
from markdown_report_generator import MarkdownReportAgent
MarkdownReportAgent().build_report(data, template="full")

# 生成 HTML
from html_report_generator_agent import HTMLReportGenerator
HTMLReportGenerator(data).generate("report.html")

# 生成 Word
from security_report_word_generator import WordReportGenerator
WordReportGenerator().generate(data, "report.docx")
```

## Skills 目录

- [`skills/报告编写-PentestReport.md`](skills/报告编写-PentestReport.md) — 渗透测试报告编写方法论
- [`skills/漏洞评级与CVSS-VulnRatingCVSS.md`](skills/漏洞评级与CVSS-VulnRatingCVSS.md) — 漏洞评级与CVSS评分
- [`skills/安全报告模板-Markdown.md`](skills/安全报告模板-Markdown.md) — **标准 Markdown 安全报告模板**，覆盖完整报告结构，含 Python 生成器
- [`skills/安全报告模板-HTML.md`](skills/安全报告模板-HTML.md) — **响应式 HTML 安全报告模板**，含 Chart.js 图表、暗色模式、侧边栏导航
- [`skills/安全报告模板-Word.md`](skills/安全报告模板-Word.md) — **Word/PDF 安全报告自动生成器**（python-docx），含完整封面/目录/页眉页脚

## 参考资源

- [PTES Reporting Guidelines](http://www.pentest-standard.org/index.php/Reporting)
- [SANS Report Writing](https://www.sans.org/white-papers/36057/)
- [OWASP Testing Guide - Reporting](https://owasp.org/www-project-web-security-testing-guide/latest/4-Reporting)
- [CVSS 4.0 Specification](https://www.first.org/cvss/v4-0/)
- [NIST SP 800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/document_library/)
