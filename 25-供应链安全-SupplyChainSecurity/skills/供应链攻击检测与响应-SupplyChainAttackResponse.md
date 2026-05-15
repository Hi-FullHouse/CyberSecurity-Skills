---
id: 25-006
title: "🎯 供应链攻击检测与响应 (Supply Chain Attack Detection & Response)"
category: 供应链安全
category_en: "Supply Chain Security"
difficulty: ★★★★
tools: "GuardDog, GraphQL API Security, Falco, Network Policy, OPA"
last_updated: 2025-07
tags: ["supply-chain-security", "sbom", "dependency-check", "container-image", "third-party-risk"]
subdomain: supply-chain-security
nist_csf: ["ID.SC-01", "ID.SC-02", "PR.DS-10"]
mitre_attack: ["T1195", "T1525"]
---
# 🎯 供应链攻击检测与响应 (Supply Chain Attack Detection & Response)

## 概述

供应链攻击（如 SolarWinds、Codecov、Log4Shell）利用软件供应链的信任关系，通过污染上游组件来攻陷下游用户。检测和响应供应链攻击需要多层可见性和快速响应能力。

## 核心技能

### 1. 供应链攻击检测策略

```python
#!/usr/bin/env python3
# 供应链攻击检测引擎

import hashlib
import json
from datetime import datetime

class SupplyChainDetector:
    def __init__(self):
        self.known_artifacts = {}
        self.alerts = []
    
    def check_package_integrity(self, package_name, version, 
                                  expected_hash, actual_hash):
        """验证包完整性"""
        if expected_hash != actual_hash:
            self.alerts.append({
                'type': 'hash_mismatch',
                'package': f"{package_name}@{version}",
                'severity': 'critical',
                'detail': f"哈希不匹配: 期望{expected_hash[:16]}..., 实际{actual_hash[:16]}...",
                'timestamp': datetime.now().isoformat()
            })
            return False
        return True
    
    def detect_dependency_confusion(self, package_name, 
                                     public_version, internal_usage):
        """检测依赖混淆攻击"""
        # 检查内部包是否被公开包覆盖
        if internal_usage and public_version:
            self.alerts.append({
                'type': 'dependency_confusion',
                'package': package_name,
                'severity': 'critical',
                'detail': f"内部包{package_name}有同名的公开版本@{public_version}",
                'recommendation': '使用作用域包名(@scope/package)'
            })
            return True
        return False
    
    def check_malicious_code_patterns(self, source_code):
        """检测恶意代码模式"""
        import re
        
        malicious_patterns = {
            'encoded_payload': r'(base64|decode|unescape).*(exec|eval|system|shell)',
            'phone_home': r'(request|fetch|http.get|curl).*(?:[0-9]{1,3}\.){3}[0-9]{1,3}',
            'obfuscated_code': r'eval\(function\(p,a,c,k,e,d\)',
            'npm_grab': r'https?://(?!registry\.npmjs\.org).*\.(tgz|tar\.gz)',
            'suspicious_install': r'(preinstall|postinstall|install).*(curl|wget|bash)'
        }
        
        findings = []
        for pattern_name, pattern in malicious_patterns.items():
            matches = re.findall(pattern, source_code, re.IGNORECASE)
            if matches:
                findings.append({
                    'type': pattern_name,
                    'matches': len(matches),
                    'severity': 'high'
                })
        
        return findings

# 使用示例
detector = SupplyChainDetector()
detector.check_package_integrity("lodash", "4.17.21", 
                                  "abc123...", "def456...")
detector.detect_dependency_confusion("internal-auth", "1.0.0", True)
print(json.dumps(detector.alerts, indent=2))
```

### 2. 依赖混淆攻击防护

```bash
# 依赖混淆（Dependency Confusion）攻击防护
# 1. 使用作用域包
# npm配置
npm config set @company:registry https://private-registry.company.com

# Yarn v2 配置
cat << 'EOF' > .yarnrc.yml
npmScopes:
  company:
    npmRegistryServer: "https://private-registry.company.com"
    npmAlwaysAuth: true
EOF

# 2. 验证包来源
# Python pip 配置
cat << 'EOF' > pip.conf
[global]
index-url = https://private-pypi.company.com/simple
extra-index-url = https://pypi.org/simple
trusted-host = private-pypi.company.com
EOF

# 3. 使用工具检测依赖混淆风险
# GuardDog 检测
pip install guarddog
guarddog pypi scan requirements.txt
guarddog npm scan package-lock.json

# 检测npm包的恶意行为
guarddog npm verify react  # 检查知名包的完整性
guarddog pypi scan mypackage  # 检查PyPI包

# 4. 内部包命名最佳实践
# 使用公司前缀/作用域
# ❌ 容易冲突: auth-lib
# ✅ 安全: @company/auth-lib
# ✅ 安全: company-auth-lib

# 5. 安装前验证
# npm预安装检查
cat << 'EOF' > .npmrc
# 强制使用公司注册表
registry=https://private-registry.company.com
EOF

# Python环境锁定
pip freeze > requirements-locked.txt
# 使用hash检查
pip hash requirements-locked.txt > requirements-hashes.txt
```

### 3. 运行时供应链攻击检测

```bash
# 运行时安全监控
# 使用Falco检测容器异常
# 检测容器内执行敏感命令
- rule: Detect Package Installation at Runtime
  desc: 检测运行时安装软件包
  condition: container.id != host and
    (proc.name = "apt" or proc.name = "yum" or proc.name = "apk" or
     proc.name = "pip" or proc.name = "npm")
  output: "容器运行时安装软件包 (user=%user.name command=%proc.cmdline container=%container.name)"
  priority: WARNING
  tags: [supply_chain, runtime]

# 检测容器内反向shell
- rule: Reverse Shell Detected
  desc: 检测容器内反向shell
  condition: spawned_process and
    (proc.name = "bash" or proc.name = "sh") and
    (proc.args contains "/dev/tcp/" or proc.args contains "/dev/udp/")
  output: "检测到反向shell (user=%user.name container=%container.name shell=%proc.name)"
  priority: CRITICAL
  tags: [supply_chain, compromise]

# 检测未知的DNS请求
- rule: Suspicious DNS Query
  desc: 检测可疑DNS查询
  condition: fd.type="dns" and not
    dns.question.domain in (allowed_domains)
  output: "可疑DNS查询 (domain=%dns.question.domain container=%container.name)"
  priority: WARNING
  tags: [supply_chain, c2]
```

### 4. 供应链事件响应清单

```markdown
# 供应链安全事件响应清单

## 阶段1: 确认与评估 (0-2小时)
- [ ] 确认受影响的产品/版本
- [ ] 评估攻击范围（内部+客户）
- [ ] 确定CVE/攻击类型
- [ ] 判断是否为供应链攻击
- [ ] 启动应急响应团队

## 阶段2: 遏制 (2-4小时)
- [ ] 标记受影响版本的组件
- [ ] 阻断恶意版本的下载/使用
- [ ] 从制品库移除恶意版本
- [ ] 通知下游用户
- [ ] 部署WAF/IDS规则阻断攻击流量

## 阶段3: 根除 (4-24小时)
- [ ] 确认安全版本/补丁
- [ ] 扫描所有受影响系统
- [ ] 替换恶意组件
- [ ] 轮换所有受影响凭证
- [ ] 审计所有访问日志

## 阶段4: 恢复 (24-72小时)
- [ ] 部署已验证的安全版本
- [ ] 增强后续版本的监控
- [ ] 验证所有安全控制有效
- [ ] 通知客户修复完成

## 阶段5: 改进 (1-4周)
- [ ] 根本原因分析
- [ ] 更新供应商评估标准
- [ ] 增强自动检测能力
- [ ] SBOM要求推广至所有供应商
- [ ] 安全架构评审和改进
```

### 5. 供应链安全度量指标

```python
# 供应链安全KPI
supply_chain_kpis = {
    "sbom_coverage": {
        "metric": "SBOM覆盖率",
        "target": "95%",
        "description": "所有生产组件生成SBOM的比例"
    },
    "dependency_vulnerability_fix_time": {
        "metric": "依赖漏洞修复时间",
        "target": "高危<48h, 严重<24h",
        "description": "从发现到修复的时间"
    },
    "vendor_assessment_completion": {
        "metric": "供应商评估完成率",
        "target": "100%",
        "description": "关键供应商年度评估完成比例"
    },
    "unsigned_artifact_ratio": {
        "metric": "未签名制品比例",
        "target": "<5%",
        "description": "未代码签名的可部署制品比例"
    },
    "supply_chain_incident_count": {
        "metric": "供应链安全事件数",
        "target": "0",
        "description": "季度供应链安全事件数量"
    }
}
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| GuardDog | 恶意包检测 | https://github.com/DataDog/guarddog |
| Falco | 运行时安全监控 | https://falco.org/ |
| OPA Gatekeeper | K8s策略引擎 | https://www.openpolicyagent.org/ |
| Dependency-Check | 依赖漏洞扫描 | https://owasp.org/www-project-dependency-check/ |
| Sigstore | 签名验证 | https://www.sigstore.dev/ |

## 参考资源

- [CISA Understanding Supply Chain Attacks](https://www.cisa.gov/supply-chain-attacks)
- [OpenSSF Securing Software Repositories](https://openssf.org/repos/)
- [NIST SP 800-204D — Secure Software Development](https://csrc.nist.gov/publications/detail/sp/800-204d/draft)
- [CNCF Supply Chain Compromise Paper](https://www.cncf.io/wp-content/uploads/)
- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)
