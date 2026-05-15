---
id: 02-005
title: "🤖 漏洞扫描器自动化 (Vulnerability Scanner Automation)"
category: 漏洞扫描
category_en: "Vulnerability Scanning"
difficulty: ★★★
tools: "Nuclei, Nikto, 自定义脚本, Jenkins"
last_updated: 2025-07
tags: ["vulnerability-scanning", "web-security", "network-security", "database-security"]
subdomain: vulnerability-scanning
nist_csf: ["ID.RA-01", "DE.CM-08", "PR.IP-12"]
mitre_attack: ["T1595", "T1589", "T1592"]
---
# 🤖 漏洞扫描器自动化 (Vulnerability Scanner Automation)

## 概述
使用脚本和自动化工具实现大规模、高效率的漏洞扫描流程，包括批量扫描、结果分析和报告生成。

## 核心技能

### 1. Nuclei - 模板化漏洞扫描

```bash
# 基础扫描
nuclei -u https://example.com

# 批量扫描多个目标
nuclei -l targets.txt

# 指定模板目录
nuclei -u https://example.com -t ~/nuclei-templates/

# 按严重级别过滤
nuclei -u https://example.com -severity critical,high

# 使用特定类别模板
nuclei -u https://example.com -t cves/ -t exposures/
nuclei -u https://example.com -t vulnerabilities/

# 输出多种格式
nuclei -u https://example.com -o results.txt -json -jsonl -markdown

# 自动更新模板
nuclei -update-templates

# 限速扫描（避免封IP）
nuclei -u https://example.com -rate-limit 30 -bulk-size 25
```

### 2. 自定义Nuclei模板编写

```yaml
# CVE自定义模板示例: cve-2024-xxx.yaml
id: cve-2024-xxx

info:
  name: Example Vulnerability
  author: security-researcher
  severity: high
  description: Description of the vulnerability
  reference:
    - https://example.com/advisory
  tags: cve,cve2024,rce

requests:
  - method: GET
    path:
      - "{{BaseURL}}/vulnerable-endpoint"
    matchers:
      - type: word
        words:
          - "specific_error_string"
        condition: or

---
# SSRF检测模板示例
id: ssrf-detection

info:
  name: SSRF Detection
  severity: medium

requests:
  - method: GET
    path:
      - "{{BaseURL}}/fetch?url=http://{{interactsh-url}}"
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
```

### 3. 自动化扫描脚本

```bash
#!/bin/bash
# auto_vuln_scan.sh - 自动化漏洞扫描脚本

TARGET=$1
OUTPUT_DIR="scan_$(date +%Y%m%d_%H%M%S)"

mkdir -p $OUTPUT_DIR

echo "[*] Starting scan for $TARGET"

# Phase 1: Subdomain enumeration
echo "[1/4] Subdomain enumeration..."
subfinder -d $TARGET -o $OUTPUT_DIR/subdomains.txt
httpx -l $OUTPUT_DIR/subdomains.txt -o $OUTPUT_DIR/alive.txt

# Phase 2: Port scanning
echo "[2/4] Port scanning..."
naabu -list $OUTPUT_DIR/alive.txt -o $OUTPUT_DIR/ports.txt

# Phase 3: URL crawling
echo "[3/4] URL crawling..."
katana -list $OUTPUT_DIR/alive.txt -o $OUTPUT_DIR/urls.txt

# Phase 4: Vulnerability scanning
echo "[4/4] Vulnerability scanning..."
nuclei -l $OUTPUT_DIR/alive.txt -o $OUTPUT_DIR/nuclei_results.txt \
  -severity critical,high,medium -json -j $OUTPUT_DIR/nuclei_results.json

echo "[+] Scan complete! Results in $OUTPUT_DIR"
```

### 4. Python自动化扫描框架

```python
#!/usr/bin/env python3
# vuln_pipeline.py - 漏洞扫描流水线

import subprocess
import json
import datetime
import os

class VulnPipeline:
    def __init__(self, target, output_dir=None):
        self.target = target
        self.output_dir = output_dir or f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.output_dir, exist_ok=True)
        self.results = {}

    def run_command(self, cmd, name):
        """执行命令并记录结果"""
        print(f"[*] Running {name}...")
        outfile = os.path.join(self.output_dir, f"{name}.txt")
        with open(outfile, 'w') as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
        print(f"[+] {name} complete -> {outfile}")
        return outfile

    def recon(self):
        """信息收集阶段"""
        self.run_command(
            ["subfinder", "-d", self.target, "-silent"],
            "subdomains"
        )
        self.run_command(
            ["httpx", "-l", os.path.join(self.output_dir, "subdomains.txt"), "-silent", "-o"],
            "alive"  # 这里使用httpx时在-c后传递文件名
        )

    def scan(self):
        """漏洞扫描阶段"""
        alive_file = os.path.join(self.output_dir, "alive.txt")
        if os.path.exists(alive_file):
            self.run_command(
                ["nuclei", "-l", alive_file, "-severity", "critical,high,medium",
                 "-json", "-o", os.path.join(self.output_dir, "vulns.json")],
                "vulnerabilities"
            )

    def report(self):
        """生成报告"""
        vulns_file = os.path.join(self.output_dir, "vulns.json")
        if os.path.exists(vulns_file):
            vulns = []
            with open(vulns_file) as f:
                for line in f:
                    if line.strip():
                        vulns.append(json.loads(line))

            # 按严重级别统计
            severity_count = {}
            for v in vulns:
                sev = v.get("info", {}).get("severity", "unknown")
                severity_count[sev] = severity_count.get(sev, 0) + 1

            print(f"\n=== Scan Summary ===")
            print(f"Target: {self.target}")
            print(f"Total vulnerabilities found: {len(vulns)}")
            for sev, count in sorted(severity_count.items()):
                print(f"  {sev}: {count}")

    def run(self):
        """执行完整流水线"""
        print(f"=== Starting scan pipeline for {self.target} ===")
        self.recon()
        self.scan()
        self.report()
        print(f"=== Scan complete! Output: {self.output_dir} ===")

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else input("Enter target: ")
    pipeline = VulnPipeline(target)
    pipeline.run()
```

### 5. 结果分析与去重

```bash
# Nuclei结果分析
cat nuclei_results.json | jq -r 'select(.info.severity == "critical") | .info.name' | sort -u

# 按IP统计漏洞数量
cat nuclei_results.json | jq -r '.host' | sort | uniq -c | sort -rn

# 按模板统计
cat nuclei_results.json | jq -r '.["template-id"]' | sort | uniq -c | sort -rn

# 生成HTML报告
cat nuclei_results.json | jq -r '
  "<tr><td>\(.host)</td><td>\(.info.name)</td><td>\(.info.severity)</td></tr>"
' | sed '1i\<table><tr><th>Host</th><th>Vulnerability</th><th>Severity</th></tr>' | sed '$a\</table>' > report.html
```

### 6. 分布式扫描

```bash
# 使用Interlace进行多目标并行扫描
interlace -tL targets.txt -c "nuclei -u _target_ -o _output_/_target_-results.txt" -o results

# 分片扫描
# 将IP段分成多个子网分别扫描
split -l 10 targets.txt target_chunk_
for chunk in target_chunk_*; do
  nuclei -l $chunk -o "${chunk}_results.txt" &
done
wait
echo "All scans complete"

# 使用 массовое (mass) 扫描
masscan -p1-65535 --rate=100000 192.168.0.0/16 -oL masscan_results.txt
awk '{print $4":"$3}' masscan_results.txt | sort -u > open_ports.txt
```

## 自动化工具链

| 阶段 | 工具 | 功能 |
|:---|:---|:---|
| 信息收集 | Subfinder + Amass | 子域名发现 |
| 存活检测 | httpx | HTTP服务存活 |
| 端口扫描 | Naabu + Masscan | 端口发现 |
| URL收集 | Katana + Gau | 端点发现 |
| 漏洞扫描 | Nuclei | 模板化扫描 |
| 报告生成 | json-to-markdown | 格式化输出 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Nuclei | 模板扫描器 | https://github.com/projectdiscovery/nuclei |
| Interlace | 并行任务执行 | https://github.com/codingo/Interlace |
| Sif | 扫描流水线编排 | https://github.com/projectdiscovery/sif |
| Uncover | API聚合查询 | https://github.com/projectdiscovery/uncover |
| Notify | 结果通知 | https://github.com/projectdiscovery/notify |

## 参考资源
- [Nuclei Templates文档](https://nuclei.projectdiscovery.io/)
- [ProjectDiscovery工具链](https://github.com/projectdiscovery)
- [Awesome-Nuclei](https://github.com/nicolOmart/Awesome-Nuclei)
