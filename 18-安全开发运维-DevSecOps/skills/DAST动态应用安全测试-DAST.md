---
id: 18-004
title: "🌐 DAST动态应用安全测试 (Dynamic Application Security Testing)"
category: 安全开发运维
category_en: DevSecOps
difficulty: ★★★★
tools: "OWASP ZAP, Burp Suite, Acunetix, Arachni, Nikto"
last_updated: 2025-07
tags: ["devsecops", "ci-cd", "sast", "dast", "iac-security", "supply-chain"]
subdomain: devsecops
nist_csf: ["PR.IP-12", "ID.RA-01", "DE.CM-08"]
mitre_attack: []
---
# 🌐 DAST动态应用安全测试 (Dynamic Application Security Testing)

## 概述
在运行时对Web应用进行自动化安全测试，识别OWASP Top 10漏洞，包括爬虫、认证扫描、主动扫描和API测试。

## 核心技能

### 1. OWASP ZAP自动化扫描

```bash
# Docker快速部署ZAP
docker run -d --name zap \
  -p 8080:8080 \
  -v $(pwd):/zap/wrk/:rw \
  -u zap \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.disablekey=true

# 被动扫描
curl "http://localhost:8080/JSON/pscan/action/recordsCount/"

# 主动扫描
# 1. 爬取网站
curl "http://localhost:8080/JSON/spider/action/scan/?url=http://target.com"

# 2. 主动扫描
curl "http://localhost:8080/JSON/ascan/action/scan/?url=http://target.com&recurse=true"

# ZAP CLI快速扫描
docker run --rm -v $(pwd):/zap/wrk/:rw \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py \
  -t https://target.com \
  -r report.html

# or
# API扫描
docker run --rm -v $(pwd):/zap/wrk/:rw \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py \
  -t https://target.com/api/openapi.json \
  -f openapi \
  -r api-report.html
```

### 2. 高级ZAP配置

```python
# Python ZAP客户端
from zapv2 import ZAPv2

target = 'https://target.com'
api_key = 'change-me'
zap = ZAPv2(apikey=api_key, proxies={'http': 'http://localhost:8080', 'https': 'http://localhost:8080'})

# 爬取
print(f'Spidering target {target}')
scan_id = zap.spider.scan(target)
while int(zap.spider.status(scan_id)) < 100:
    print(f'Spider progress: {zap.spider.status(scan_id)}%')
print('Spider completed')

# 主动扫描
print(f'Scanning target {target}')
scan_id = zap.ascan.scan(target)
while int(zap.ascan.status(scan_id)) < 100:
    print(f'Scan progress: {zap.ascan.status(scan_id)}%')
print('Scan completed')

# 获取告警
alerts = zap.core.alerts(baseurl=target, start=0, count=100)
for alert in alerts:
    print(f"[{alert['risk']}] {alert['alert']}: {alert['url']}")

# 生成报告
with open('zap-report.html', 'w') as f:
    f.write(zap.core.htmlreport())
```

### 3. CI/CD集成DAST

```yaml
# GitHub Actions DAST
name: DAST Security Scan
on:
  deployment_status:
jobs:
  dast:
    if: github.event.deployment_status.state == 'success'
    runs-on: ubuntu-latest
    steps:
      - name: ZAP Scan
        uses: zaproxy/action-full-scan@v0.11.0
        with:
          target: ${{ github.event.deployment_status.target_url }}
          token: ${{ secrets.GITHUB_TOKEN }}
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'
          
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: zap-report
          path: report.html

# GitLab CI DAST
stages:
  - dast

dast_scan:
  stage: dast
  image: ghcr.io/zaproxy/zaproxy:stable
  script:
    - zap-full-scan.py -t $CI_ENVIRONMENT_URL -r report.html
  artifacts:
    paths:
      - report.html
    reports:
      dast: report.html
```

### 4. 定制扫描策略

```bash
# 上下文配置（认证扫描）
cat << 'JSON' > context.json
{
  "name": "MyApp",
  "includePaths": ["https://target.com/.*"],
  "excludePaths": ["https://target.com/logout.*"],
  "authentication": {
    "method": "form",
    "loginUrl": "https://target.com/login",
    "loginRequestData": "username={%username%}&password={%password%}&csrf={%csrf_token%}",
    "credentials": {
      "username": "testuser",
      "password": "testpass"
    }
  }
}
JSON

# 导入上下文
curl -X POST "http://localhost:8080/JSON/context/action/importContext/" \
  -d "contextFile=context.json"

# 设置用户
curl "http://localhost:8080/JSON/authentication/action/setAuthenticationMethod/" \
  -d "contextId=1&authMethodName=form&authMethodConfigParams=loginUrl=https://target.com/login&loginRequestData=username={%username%}&password={%password%}"
```

### 5. DAST扫描检查清单

| # | 检查项 | OWASP Top 10 2021 | 严重程度 |
|:---:|:---|:---:|:---:|
| 1 | SQL注入检测 | A03:2021 | 🔴 严重 |
| 2 | XSS跨站脚本 | A03:2021 | 🔴 严重 |
| 3 | 命令注入 | A03:2021 | 🔴 严重 |
| 4 | SSRF服务端请求伪造 | A10:2021 | 🟠 高危 |
| 5 | CSRF跨站请求伪造 | A01:2021 | 🟠 高危 |
| 6 | 敏感信息泄露 | A04:2021 | 🟠 高危 |
| 7 | 认证绕过 | A07:2021 | 🔴 严重 |
| 8 | 越权访问(BAC/IDOR) | A01:2021 | 🔴 严重 |
| 9 | CORS配置不当 | A05:2021 | 🟡 中危 |
| 10 | 开放重定向 | A03:2021 | 🟡 中危 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| OWASP ZAP | 开源DAST工具 | https://www.zaproxy.org/ |
| Burp Suite Professional | Web安全测试 | https://portswigger.net/burp |
| Acunetix | 商业DAST | https://www.acunetix.com/ |
| Arachni | 开源Web扫描 | https://github.com/Arachni/arachni |
| Nikto | Web服务器扫描 | https://github.com/sullo/nikto |
| Nuclei | 模板化扫描 | https://github.com/projectdiscovery/nuclei |

## 参考资源
- [OWASP Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [NIST SP 800-115 — Dynamic Testing](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- [ZAP CI/CD Integration Guide](https://www.zaproxy.org/docs/docker/)
