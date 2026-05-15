---
id: 18-003
title: "🔍 SAST静态应用安全测试 (Static Application Security Testing)"
category: 安全开发运维
category_en: DevSecOps
difficulty: ★★★★
tools: "SonarQube, Semgrep, CodeQL, Fortify, Checkmarx"
last_updated: 2025-07
tags: ["devsecops", "ci-cd", "sast", "dast", "iac-security", "supply-chain"]
subdomain: devsecops
nist_csf: ["PR.IP-12", "ID.RA-01", "DE.CM-08"]
mitre_attack: []
---
# 🔍 SAST静态应用安全测试 (Static Application Security Testing)

## 概述
在开发阶段对源码进行自动安全扫描，识别SQL注入、XSS、命令注入、安全配置错误等漏洞，实现左移安全。

## 核心技能

### 1. Semgrep规则编写与使用

```bash
# 安装Semgrep
pip install semgrep

# 运行预定义规则
semgrep --config=auto .
semgrep --config=p/python .
semgrep --config=p/javascript .
semgrep --config=p/java .

# 使用自定义规则
semgrep --config=rules/ .

# 输出格式
semgrep --config=auto . --output=semgrep-report.json --json
semgrep --config=auto . --output=semgrep-report.sarif --sarif

# CI模式只在diff上扫描
semgrep --config=auto . --baseline-commit=main

# 自定义规则示例 - rules/sql-injection.yaml
rules:
  - id: python-sql-injection
    pattern-either:
      - pattern: |
          cursor.execute("..." + $USER_INPUT + "...")
      - pattern: |
          db.execute(f"...{$USER_INPUT}...")
    message: "检测到SQL注入风险 - 用户输入直接拼接到SQL查询"
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-89"
      owasp: "A1:2021-Injection"
```

### 2. CodeQL深度分析

```bash
# 安装CodeQL CLI
# 下载codeql-cli
wget https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql.zip
unzip codeql.zip
export PATH=$PATH:./codeql

# 创建CodeQL数据库
# 对于Python
codeql database create python-db --language=python --source-root=./

# 对于JavaScript
codeql database create js-db --language=javascript --source-root=./

# 运行查询
codeql database analyze python-db --format=sarif-latest --output=codeql-results.sarif

# CodeQL安全查询
# ql/path-injection.ql
# import python
# from DataFlow::Node source, DataFlow::Node sink
# where source instanceof RemoteFlowSource
#   and sink instanceof FileSystemWriteAccess
# select source, sink
```

### 3. SonarQube集成

```bash
# Docker部署SonarQube
docker run -d --name sonarqube \
  -p 9000:9000 \
  -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true \
  sonarqube:community

# 运行扫描 (Python)
sonar-scanner \
  -Dsonar.projectKey=my-project \
  -Dsonar.sources=. \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.login=<token>

# quality gate配置
# sonar-project.properties
sonar.projectKey=my-project
sonar.sources=src
sonar.tests=tests
sonar.python.version=3.11
sonar.python.coverage.reportPaths=coverage.xml
sonar.python.xunit.reportPath=test-report.xml
```

### 4. 语言特定安全检查

```python
# Python SAST检查示例
# ❌ 不良实践: eval/exec执行用户输入
user_input = request.GET.get('code')
result = eval(user_input)  # ❌ 危险

# ❌ 不良实践: 不安全的反序列化
import pickle
data = pickle.loads(request.body)  # ❌ 危险

# ❌ 不良实践: 命令注入
os.system(f"ping {user_input}")  # ❌ 危险

# ❌ 不良实践: 不安全的redirect
redirect(request.GET.get('next'))  # ❌ 开放重定向

# ✅ 良好实践: 安全的替代方案
import subprocess
subprocess.run(["ping", "-c", "1", user_input], shell=False, check=True)
```

```javascript
// JavaScript/Node.js SAST检查示例
// ❌ 不良实践: eval
const result = eval(userInput);  // ❌ 危险

// ❌ 不良实践: 不安全的正则
const re = new RegExp(userInput);  // ❌ ReDoS风险

// ❌ 不良实践: SQL注入
const sql = `SELECT * FROM users WHERE id = ${userInput}`;  // ❌ 危险

// ❌ 不良实践: noSQL注入
db.collection('users').find({ username: userInput });  // ❌ 需要输入验证

// ✅ 良好实践
const sql = 'SELECT * FROM users WHERE id = ?';
db.query(sql, [userInput], (err, result) => { ... });
```

### 5. SAST工具比较

| 工具 | 语言覆盖 | 性能 | 误报率 | 许可证 | CI集成 |
|:---|:---:|:---:|:---:|:---:|:---:|
| Semgrep | 25+ | ⚡高 | 低 | 开源 | ✅ |
| CodeQL | 12 | ⚡中 | 中 | 免费 | ✅ |
| SonarQube | 30+ | ⚡中 | 中 | 社区版/企业 | ✅ |
| Fortify | 28+ | 🐢低 | 低 | 商业 | ✅ |
| Checkmarx | 25+ | 🐢低 | 低 | 商业 | ✅ |
| Bandit | Python | ⚡高 | 中 | 开源 | ✅ |
| ESLint Security | JS/TS | ⚡高 | 低 | 开源 | ✅ |

### 6. 左移安全实践

```bash
# 开发前：安全编码规范
# pre-commit hook - 本地检查
pip install pre-commit
cat << 'YAML' > .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.58.0
    hooks:
      - id: semgrep
        args: ["--config=auto", "--error"]
YAML
pre-commit install

# CI阶段：自动阻断高危漏洞
# GitHub Actions
name: SAST Scan
on: pull_request
jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Semgrep Scan
        uses: semgrep/semgrep-action@v1
        with:
          config: p/default
          publishToken: ${{ secrets.SEMGREP_APP_TOKEN }}
          auditOn: push
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Semgrep | 轻量级SAST | https://semgrep.dev/ |
| CodeQL | 深度代码分析 | https://github.com/github/codeql |
| SonarQube | 代码质量与安全 | https://www.sonarsource.com/ |
| Bandit | Python安全扫描 | https://github.com/PyCQA/bandit |
| ESLint Plugin Security | JS/TS安全 | https://github.com/nodesecurity/eslint-plugin-security |
| Brakeman | Ruby on Rails安全 | https://github.com/presidentbeef/brakeman |

## 参考资源
- [OWASP SAST Best Practices](https://owasp.org/www-community/Source_Code_Analysis_Tools)
- [NIST SP 800-115 — Static Code Analysis](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- [GitHub CodeQL Documentation](https://docs.github.com/code-security/codeql-cli)
- [Semgrep Rule Writing Guide](https://semgrep.dev/docs/writing-rules/overview/)
