---
id: "39-001"
title: "安全框架与合规审计 (Security Framework & Compliance Audit)"
category: "安全治理与合规"
category_en: "Governance & Compliance"
difficulty: "★★★"
tools: "NIST CSF, ISO 27001, SOC 2, CIS Controls, AuditBoard"
last_updated: "2026-05"
tags: [compliance, audit, framework, iso27001, nist-csf, soc2, governance]
subdomain: governance-compliance
nist_csf: [ID.GV-01, ID.RM-01, ID.SC-01, ID.GV-03]
mitre_attack: []
---

# 安全框架与合规审计 (Security Framework & Compliance Audit)

## 概述

安全框架为企业提供了系统化的安全管理方法论，合规审计确保安全措施符合法规和行业标准。本技能覆盖主流安全框架（NIST CSF、ISO 27001、SOC 2、CIS、PCI DSS、HIPAA）的核心要求、控制映射方法、审计准备和合规自动化。

## 核心技能

### 1. 安全框架概览与对比

```python
"""主流安全框架对比与选择"""

class SecurityFrameworkComparator:
    """安全框架对比"""
    
    FRAMEWORKS = {
        "NIST CSF 2.0": {
            "type": "通用框架",
            "region": "全球（美国主导）",
            "focus": "网络安全风险管理",
            "structure": "6个功能: 治理-识别-保护-检测-响应-恢复",
            "certification": "自评/第三方评估",
            "best_for": ["所有行业", "关键基础设施", "政府机构"],
            "implementation_time": "3-12个月"
        },
        "ISO 27001": {
            "type": "管理体系标准",
            "region": "国际 (ISO)",
            "focus": "信息安全管理体系 (ISMS)",
            "structure": "Annex A 14个域, 93个控制项",
            "certification": "第三方认证（强制）",
            "best_for": ["需要正式认证的企业", "跨国企业", "IT服务商"],
            "implementation_time": "6-18个月"
        },
        "SOC 2": {
            "type": "审计标准",
            "region": "美国 (AICPA)",
            "focus": "服务组织的安全控制",
            "structure": "5个信任准则: 安全-可用-机密-隐私-处理完整性",
            "certification": "CPA审计报告 (Type I/II)",
            "best_for": ["SaaS/云服务商", "外包数据处理", "托管服务商"],
            "implementation_time": "6-12个月"
        },
        "CIS Controls v8": {
            "type": "技术控制指南",
            "region": "全球",
            "focus": "技术安全控制实施",
            "structure": "18个域, 153个 safeguard",
            "certification": "自评/第三方评估",
            "best_for": ["需要具体技术实施指南", "中小型企业"],
            "implementation_time": "1-6个月"
        },
        "PCI DSS v4.0": {
            "type": "行业合规",
            "region": "全球 (支付卡行业)",
            "focus": "支付卡数据安全",
            "structure": "6个目标, 12个要求",
            "certification": "QSA审计/SAQ自评",
            "best_for": ["处理信用卡支付的企业", "支付服务商"],
            "implementation_time": "6-18个月"
        },
        "HIPAA": {
            "type": "法规合规",
            "region": "美国",
            "focus": "健康信息保护",
            "structure": "隐私规则 + 安全规则 + 违规通知",
            "certification": "OCR审计（政府）",
            "best_for": ["医疗机构", "健康应用开发商", "健康数据处理者"],
            "implementation_time": "3-12个月"
        }
    }
    
    @staticmethod
    def select_framework(industry, region, needs_certification, org_size):
        """推荐最佳框架"""
        recommendations = []
        
        for name, info in SecurityFrameworkComparator.FRAMEWORKS.items():
            score = 0
            
            # 行业匹配
            for kw in [industry, org_size]:
                if any(kw.lower() in str(b).lower() for b in info["best_for"]):
                    score += 3
            
            # 认证需求
            if needs_certification and ("认证" in info.get("certification", "") 
                                         or "审计" in info.get("certification", "")):
                score += 2
            
            # 区域匹配
            if region.lower() in info.get("region", "").lower():
                score += 1
            
            if score > 0:
                recommendations.append({
                    "framework": name,
                    "score": score,
                    "type": info["type"],
                    "certification": info["certification"],
                    "time": info["implementation_time"]
                })
        
        return sorted(recommendations, key=lambda x: x["score"], reverse=True)
    
    @staticmethod
    def control_mapping(source_framework, target_framework):
        """框架控制映射"""
        # NIST CSF → ISO 27001 映射示例
        mappings = {
            "ID.AM-01 (资产清单)": ["A.5.9 (信息资产清单)", "A.8.1.1 (资产清单)"],
            "ID.GV-01 (安全策略)": ["A.5.1 (信息安全策略)", "A.5.2 (信息安全角色)"],
            "PR.AC-01 (身份管理)": ["A.9.2 (用户访问管理)", "A.9.4 (系统访问控制)"],
            "PR.DS-01 (数据加密)": ["A.8.24 (加密)", "A.10.1 (加密控制)"],
            "DE.CM-01 (持续监控)": ["A.8.16 (监控)", "A.12.4 (日志记录)"],
            "RS.MI-01 (事件遏制)": ["A.16.1 (事件响应)", "A.16.1.5 (事件响应)"],
            "RC.RP-01 (恢复计划)": ["A.17.1 (业务连续性)", "A.12.3 (备份)"],
        }
        
        return mappings


# 使用示例
selector = SecurityFrameworkComparator()
recs = selector.select_framework(
    industry="SaaS", region="global", 
    needs_certification=True, org_size="中型"
)
for r in recs:
    print(f"{r['framework']}: {r['score']}pts — {r['type']}")
```

### 2. 审计准备与执行

```python
"""合规审计引擎"""

class ComplianceAuditor:
    """合规审计引擎"""
    
    def __init__(self, framework="iso27001"):
        self.framework = framework
        self.findings = []
        self.evidence_collected = []
    
    def audit_control(self, control_id, requirement, evidence):
        """审计单个控制项"""
        finding = {
            "control_id": control_id,
            "requirement": requirement,
            "evidence": evidence,
            "status": "not_tested",
            "gaps": [],
            "recommendations": []
        }
        
        # 评估证据充分性
        if not evidence:
            finding["status"] = "non_compliant"
            finding["gaps"].append("无证据提供")
            finding["recommendations"].append("建立证据收集流程")
        elif evidence.get("type") == "documentation":
            # 文档类证据
            if evidence.get("approved") and evidence.get("reviewed_within_days", 999) < 365:
                finding["status"] = "compliant"
            else:
                finding["status"] = "needs_improvement"
                finding["gaps"].append("文档未及时审阅")
        elif evidence.get("type") == "technical":
            # 技术类证据（日志、配置等）
            if evidence.get("coverage_percent", 0) >= 95:
                finding["status"] = "compliant"
            else:
                finding["status"] = "partially_compliant"
                finding["gaps"].append(f"覆盖率不足: {evidence.get('coverage_percent', 0)}%")
        
        self.findings.append(finding)
        return finding
    
    def audit_summary(self):
        """审计总结"""
        total = len(self.findings)
        if total == 0:
            return {"status": "no_findings"}
        
        counts = {"compliant": 0, "partially_compliant": 0, "non_compliant": 0, "needs_improvement": 0}
        for f in self.findings:
            if f["status"] in counts:
                counts[f["status"]] += 1
        
        score = round(counts["compliant"] / total * 100, 1)
        
        return {
            "framework": self.framework,
            "total": total,
            "compliant": counts["compliant"],
            "partially_compliant": counts["partially_compliant"],
            "non_compliant": counts["non_compliant"],
            "needs_improvement": counts["needs_improvement"],
            "compliance_score": score,
            "verdict": "PASS" if score >= 90 else "CONDITIONAL" if score >= 70 else "FAIL",
            "critical_gaps": [
                f for f in self.findings 
                if f["status"] == "non_compliant"
            ]
        }
    
    def generate_remediation_plan(self):
        """生成整改计划"""
        plan = []
        
        for finding in self.findings:
            if finding["status"] != "compliant":
                plan.append({
                    "control": finding["control_id"],
                    "gaps": finding["gaps"],
                    "recommendations": finding["recommendations"],
                    "priority": "HIGH" if finding["status"] == "non_compliant" else "MEDIUM"
                })
        
        return plan


# 使用示例
auditor = ComplianceAuditor("iso27001")
auditor.audit_control("A.9.1.2", "访问控制策略", {
    "type": "documentation", "approved": True, "reviewed_within_days": 180
})
auditor.audit_control("A.12.6.1", "漏洞管理", {
    "type": "technical", "coverage_percent": 72
})
summary = auditor.audit_summary()
print(f"Compliance: {summary['compliance_score']}% — {summary['verdict']}")
```

```bash
# 审计自动化与证据收集

# 1. 自动收集合规证据
# Windows 安全基线证据收集脚本
$evidence_dir = "C:\AuditEvidence\$(Get-Date -Format 'yyyy-MM-dd')"
New-Item -ItemType Directory -Path $evidence_dir -Force

# 安全策略证据
secedit /export /cfg "$evidence_dir\security_policy.inf"

# 用户权限分配
Get-WmiObject -Class Win32_UserAccount | Export-Csv "$evidence_dir\user_accounts.csv"

# 审计策略配置
auditpol /get /category:* > "$evidence_dir\audit_policy.txt"

# 防火墙规则
netsh advfirewall firewall show rule name=all > "$evidence_dir\firewall_rules.txt"

# 服务列表
Get-Service | Export-Csv "$evidence_dir\services.csv"

# 已安装补丁
Get-HotFix | Export-Csv "$evidence_dir\patches.csv"

# 2. Linux 证据收集
EVIDENCE_DIR="/audit_evidence/$(date +%Y-%m-%d)"
mkdir -p $EVIDENCE_DIR

# 用户和权限
cat /etc/passwd > $EVIDENCE_DIR/passwd.txt
cat /etc/shadow > $EVIDENCE_DIR/shadow.txt
cat /etc/sudoers > $EVIDENCE_DIR/sudoers.txt

# 网络配置
iptables -L -n -v > $EVIDENCE_DIR/iptables.txt
ss -tuln > $EVIDENCE_DIR/listening_ports.txt

# 安全配置
ls -la /etc/ssh/sshd_config > $EVIDENCE_DIR/ssh_permissions.txt
cat /etc/ssh/sshd_config > $EVIDENCE_DIR/sshd_config.txt

# 审计日志
ausearch -m USER_LOGIN -ts today > $EVIDENCE_DIR/audit_logins.txt

# 3. 合规仪表盘查询 (Splunk)
# 用于持续合规监控
index=windows_security EventID=4688
| stats count by AccountName, ProcessName
| where count > 100
| eval alert = "异常进程创建频率 — 需审计"
```

### 3. 合规自动化

```python
"""持续合规监控引擎"""

class ContinuousComplianceMonitor:
    """持续合规监控"""
    
    def __init__(self):
        self.controls = {}
        self.check_results = []
    
    def add_control_check(self, control_id, name, check_type, command):
        """添加合规检查项"""
        self.controls[control_id] = {
            "name": name,
            "type": check_type,
            "command": command,
            "schedule": "daily"
        }
    
    def run_checks(self):
        """执行合规检查"""
        for ctrl_id, ctrl in self.controls.items():
            result = {
                "control_id": ctrl_id,
                "name": ctrl["name"],
                "type": ctrl["type"],
                "timestamp": __import__('datetime').datetime.now().isoformat(),
                "passed": False,
                "detail": ""
            }
            
            if ctrl["type"] == "registry":
                # Windows 注册表检查
                result["passed"] = ctrl["command"].get("expected") == ctrl["command"].get("actual")
                result["detail"] = f"Expected: {ctrl['command'].get('expected')}, Got: {ctrl['command'].get('actual')}"
            
            elif ctrl["type"] == "config":
                # 配置文件检查
                result["passed"] = ctrl["command"].get("value") == ctrl["command"].get("expected")
                result["detail"] = f"Config check: {ctrl['command'].get('path', 'N/A')}"
            
            elif ctrl["type"] == "scan":
                # 扫描结果检查
                result["passed"] = ctrl["command"].get("vulnerabilities", 0) == 0
                result["detail"] = f"Found {ctrl['command'].get('vulnerabilities', 0)} vulnerabilities"
            
            self.check_results.append(result)
        
        return self.summary()
    
    def summary(self):
        """生成监控摘要"""
        total = len(self.check_results)
        passed = sum(1 for r in self.check_results if r["passed"])
        
        return {
            "total_checks": total,
            "passed": passed,
            "failed": total - passed,
            "compliance": round(passed / total * 100, 1) if total else 0,
            "timestamp": __import__('datetime').datetime.now().isoformat(),
            "details": self.check_results
        }


# 使用示例
cmon = ContinuousComplianceMonitor()
cmon.add_control_check("CIS-1.1.1", "密码历史", "registry", {
    "expected": 24, "actual": 24
})
cmon.add_control_check("CIS-2.2.3", "防火墙启用", "registry", {
    "expected": 1, "actual": 1
})
result = cmon.run_checks()
print(f"Daily compliance: {result['compliance']}% ({result['passed']}/{result['total']})")
```

```bash
# 合规自动化工具链

# 1. OpenSCAP 合规扫描
# SCAP 自动化合规
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --results scan-results.xml \
  --report report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml

# 2. InSpec 基础设施测试 (持续合规)
# 自动化合规测试
cat > profile/controls/ssh_spec.rb << 'EOF'
title 'SSH Compliance Checks'

control 'ssh-1' do
  impact 1.0
  title 'SSH: Disable root login'
  desc 'Prevent direct root login over SSH'
  describe sshd_config do
    its('PermitRootLogin') { should eq 'no' }
  end
end

control 'ssh-2' do
  impact 1.0
  title 'SSH: Use only Protocol 2'
  desc 'SSH Protocol 1 is insecure'
  describe sshd_config do
    its('Protocol') { should eq '2' }
  end
end
EOF

# 执行 InSpec 测试
inspec exec profile/ --reporter cli html:report.html

# 3. 合规报告自动发送 (每周)
cat > /etc/cron.weekly/compliance_report.sh << 'SCRIPT'
#!/bin/bash
REPORT_DIR="/var/compliance_reports"
DATE=$(date +%Y-%m-%d)
mkdir -p $REPORT_DIR

# 运行 OpenSCAP 扫描并生成报告
oscap xccdf eval \
  --profile cis \
  --results $REPORT_DIR/scan-$DATE.xml \
  --report $REPORT_DIR/report-$DATE.html \
  /usr/share/scap/ssg-content.ssg-rhel8-ds.xml

# 发送报告到 SIEM
curl -X POST $SIEM_ENDPOINT \
  -H "Content-Type: application/json" \
  -d "{\"report\": \"$REPORT_DIR/report-$DATE.html\", \"date\": \"$DATE\"}"

# 记录合规趋势
python3 << PYEOF
import json, datetime
with open("$REPORT_DIR/scan-$DATE.xml") as f:
    content = f.read()
# 解析结果并记录到时间序列数据库
PYEOF
SCRIPT
chmod +x /etc/cron.weekly/compliance_report.sh
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| NIST CSF | 网络安全框架 | https://www.nist.gov/cyberframework |
| ISO 27001 | ISMS 标准 | https://www.iso.org/isoiec-27001-information-security.html |
| CIS Controls | 安全控制指南 | https://www.cisecurity.org/controls/v8 |
| OpenSCAP | 合规自动化扫描 | https://www.open-scap.org/ |
| InSpec | 基础设施合规测试 | https://www.chef.io/products/inspec |

## 参考资源

- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [ISO 27001:2022 — Annex A](https://www.iso.org/standard/27001)
- [SOC 2 Trust Services Criteria](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-guidance/soc-2)
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/document_library/)
- [CIS Controls v8 Implementation Guide](https://www.cisecurity.org/controls/v8)
