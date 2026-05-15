---
id: 26-006
title: "🏆 漏洞奖励计划与安全众测 (Bug Bounty & Crowdsourced Testing)"
category: 漏洞管理
category_en: "Vulnerability Management"
difficulty: ★★★
tools: "HackerOne, Bugcrowd, Synack, 补天平台, 漏洞盒子, Intigriti, YesWeHack"
last_updated: 2025-07
tags: ["vulnerability-management", "cve", "patch-management", "bug-bounty", "prioritization"]
subdomain: vulnerability-management
nist_csf: ["ID.RA-01", "PR.IP-12", "DE.CM-08"]
mitre_attack: []
---
# 🏆 漏洞奖励计划与安全众测 (Bug Bounty & Crowdsourced Testing)

## 概述

漏洞奖励计划和众测利用全球白帽社区的力量，发现传统安全测试难以覆盖的安全盲区。相比传统渗透测试，众测具有**持续覆盖、成本弹性、人才多样性**等优势。核心能力包括**计划设计、平台运营、漏洞分级、社区管理和ROI度量**。

## 核心技能

### 1. 漏洞奖励计划设计

```markdown
# 漏洞奖励计划设计模板

## 1. 范围定义
### 在范围内 (In Scope)
- 主域名: *.example.com
- API: api.example.com/v2/*
- 移动应用: iOS v3.0+, Android v4.0+
- 源代码: 公开GitHub仓库 (仅安全相关)

### 不在范围内 (Out of Scope)
- 第三方服务: 由供应商托管
- 内部管理系统: *.internal.example.com
- 已弃用服务: legacy.example.com
- 社会工程学攻击
- 物理安全测试

## 2. 漏洞分类与奖励
| 严重级别 | 漏洞类型 | 最低奖励 | 最高奖励 |
|:---:|:---|:---:|:---:|
| 🔴 严重 | RCE, SQL注入(任意), SSRF出网, 认证绕过 | $5,000 | $20,000 |
| 🟠 高危 | XSS存储型, CSRF敏感操作, IDOR水平越权 | $1,000 | $4,999 |
| 🟡 中危 | XSS反射型, 开放重定向, CSRF普通操作 | $250 | $999 |
| 🔵 低危 | 信息泄露, 安全配置问题 | $50 | $249 |

## 3. 评分规则
- **可利用性权重**: RCE(10), SQLi(9), SSRF(8), LFI(7), XSS存储(6), CSRF(5)
- **影响权重**: 数据泄露(10), 服务中断(8), 权限提升(7), 信息泄露(4)
- **奖励 = 基础金额 × 可利用性权重/10 × 影响权重/10

## 4. 规则
- 严格遵守测试范围
- 禁止破坏数据 (使用测试账号test/test)
- 禁止DoS/DDoS攻击
- 发现后立即报告，不公开披露
- 初犯违规: 警告; 再犯: 取消资格
```

```python
#!/usr/bin/env python3
# 漏洞奖励计算引擎

class BountyCalculator:
    """漏洞奖励计算引擎"""
    
    def __init__(self):
        # 基础奖励表 (USD)
        self.base_rewards = {
            'critical': 5000,
            'high': 1000,
            'medium': 250,
            'low': 50
        }
        
        # 可利用性乘数
        self.exploitability_multiplier = {
            'remote_code_execution': 2.0,
            'sql_injection_arbitrary': 1.8,
            'ssrf_outbound': 1.6,
            'authentication_bypass': 1.5,
            'lfi_rfi': 1.4,
            'stored_xss': 1.2,
            'idor': 1.3,
            'privilege_escalation': 1.5,
            'csrf_on_sensitive': 0.9,
            'reflected_xss': 0.6,
            'open_redirect': 0.4,
            'information_disclosure': 0.3,
            'misconfiguration': 0.2
        }
        
        # 影响范围乘数
        self.impact_multiplier = {
            'all_users': 1.5,
            'admin_users': 1.3,
            'specific_users': 1.0,
            'internal_only': 0.6,
            'self_only': 0.3
        }
        
        # 质量乘数
        self.quality_multiplier = {
            'excellent': 1.3,  # 含PoC+修复建议
            'good': 1.0,       # 含清晰复现步骤
            'fair': 0.7,       # 仅描述
            'poor': 0.3        # 信息不足
        }
    
    def calculate(self, vuln_type, severity, impact_scope, quality, asset_criticality=1.0):
        """计算奖励金额"""
        base = self.base_rewards.get(severity, 100)
        exploit_mult = self.exploitability_multiplier.get(vuln_type, 0.5)
        impact_mult = self.impact_multiplier.get(impact_scope, 0.5)
        quality_mult = self.quality_multiplier.get(quality, 0.5)
        
        reward = base * exploit_mult * impact_mult * quality_mult * asset_criticality
        return round(reward)
    
    def suggest_bounty(self, report):
        """根据报告内容自动建议奖励"""
        base = self.calculate(
            vuln_type=report.get('vuln_type'),
            severity=report.get('severity'),
            impact_scope=report.get('impact_scope'),
            quality=report.get('quality'),
            asset_criticality=report.get('asset_criticality', 1.0)
        )
        
        # 额外加成
        bonus = 0
        if report.get('has_poc_code'): bonus += base * 0.2
        if report.get('has_fix_suggestion'): bonus += base * 0.1
        if report.get('first_report_from_researcher'): bonus += base * 0.15
        
        total = base + bonus
        return {
            'base_reward': base,
            'bonus': round(bonus),
            'total_reward': round(total),
            'notes': '包含PoC代码' if report.get('has_poc_code') else ''
        }

# 使用示例
calc = BountyCalculator()
report = {
    'vuln_type': 'remote_code_execution',
    'severity': 'critical',
    'impact_scope': 'all_users',
    'quality': 'excellent',
    'has_poc_code': True,
    'has_fix_suggestion': True,
    'asset_criticality': 1.2
}
result = calc.suggest_bounty(report)
print(f"建议奖励: ${result['total_reward']} (基础: ${result['base_reward']} + 加成: ${result['bonus']})")
```

### 2. HackerOne API 集成

```python
#!/usr/bin/env python3
# HackerOne API 集成

import requests
import base64
from datetime import datetime

class HackerOneClient:
    """HackerOne API客户端"""
    
    def __init__(self, username, api_key, program_handle):
        credentials = f"{username}:{api_key}"
        encoded = base64.b64encode(credentials.encode()).decode()
        self.headers = {
            "Authorization": f"Basic {encoded}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        self.base = "https://api.hackerone.com/v1"
        self.program = program_handle
    
    def get_reports(self, state="open", page_size=25):
        """获取漏洞报告"""
        params = {
            "filter[program][]": self.program,
            "filter[state][]": state,
            "page[size]": page_size
        }
        resp = requests.get(f"{self.base}/reports",
                          params=params, headers=self.headers)
        return resp.json().get('data', [])
    
    def get_report_detail(self, report_id):
        """获取单个报告详情"""
        resp = requests.get(f"{self.base}/reports/{report_id}",
                          headers=self.headers)
        return resp.json()
    
    def create_report(self, title, description, severity_rating, 
                      vulnerability_type, asset_identifier):
        """创建漏洞报告（走HackerOne披露流程）"""
        report_data = {
            "data": {
                "type": "report",
                "attributes": {
                    "title": title,
                    "vulnerability_information": description,
                    "severity_rating": severity_rating,  # critical/high/medium/low/none
                },
                "relationships": {
                    "program": {
                        "data": {
                            "id": self.program,
                            "type": "program"
                        }
                    },
                    "vulnerability_types": {
                        "data": [{
                            "id": vulnerability_type,
                            "type": "vulnerability-type"
                        }]
                    },
                    "asset_identifiers": {
                        "data": [{
                            "data": {
                                "identifier": asset_identifier,
                                "asset_type": "url"
                            }
                        }]
                    }
                }
            }
        }
        
        resp = requests.post(f"{self.base}/reports",
                           json=report_data, headers=self.headers)
        return resp.json()
    
    def get_reward_rules(self):
        """获取奖励规则"""
        resp = requests.get(f"{self.base}/programs/{self.program}/reward_rules",
                          headers=self.headers)
        return resp.json().get('data', [])
    
    def get_staff_analytics(self):
        """获取安全团队分析指标"""
        params = {"filter[program][]": self.program}
        resp = requests.get(f"{self.base}/analytics/staff",
                          params=params, headers=self.headers)
        return resp.json()
    
    def generate_program_report(self):
        """生成计划运营报告"""
        open_reports = self.get_reports(state="new")
        triaged = self.get_reports(state="triaged")
        resolved = self.get_reports(state="resolved")
        
        # 统计严重级别
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for report in open_reports:
            sev = report.get('attributes', {}).get('severity_rating', 'low')
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        # 计算平均响应时间
        response_times = []
        for report in open_reports + triaged:
            created = report.get('attributes', {}).get('created_at')
            first_response = report.get('attributes', {}).get('first_program_activity_at')
            if created and first_response:
                diff = (datetime.fromisoformat(first_response.replace('Z', '+00:00')) -
                       datetime.fromisoformat(created.replace('Z', '+00:00')))
                response_times.append(diff.total_seconds() / 3600)
        
        avg_response = sum(response_times) / len(response_times) if response_times else 0
        
        return {
            "program": self.program,
            "report_date": datetime.now().isoformat(),
            "open_reports": len(open_reports),
            "triaged": len(triaged),
            "resolved_this_month": len(resolved),
            "severity_breakdown": severity_counts,
            "avg_response_time_hours": round(avg_response, 1),
            "total_bounties_paid": self.get_total_bounties()
        }
    
    def get_total_bounties(self):
        """获取已支付奖励总额"""
        resp = requests.get(f"{self.base}/programs/{self.program}/bounties",
                          headers=self.headers)
        bounties = resp.json().get('data', [])
        total = sum(float(b.get('attributes', {}).get('amount', 0)) 
                   for b in bounties)
        return total

# 使用示例
client = HackerOneClient("your-username", "your-api-key", "your-program")
report = client.generate_program_report()
print(f"开放报告: {report['open_reports']}, 平均响应: {report['avg_response_time_hours']}h")
```

### 3. 众测平台运营管理

```python
#!/usr/bin/env python3
# 众测运营管理

import json
from datetime import datetime, timedelta

class CrowdTestManager:
    """众测运营管理"""
    
    def __init__(self, program_name, scope=[]):
        self.program = program_name
        self.scope = scope
        self.reports = []
        self.researchers = {}
        self.sessions = []
    
    def launch_session(self, name, start_date, end_date, 
                      max_reports=None, max_reward_budget=None):
        """发起众测会话"""
        session = {
            'id': len(self.sessions) + 1,
            'name': name,
            'start': start_date,
            'end': end_date,
            'max_reports': max_reports,
            'max_reward_budget': max_reward_budget,
            'total_reports': 0,
            'total_paid': 0,
            'status': 'pending',
            'researchers': []
        }
        self.sessions.append(session)
        return session
    
    def invite_researcher(self, researcher_id, skill_level, 
                          speciality, session_id=None):
        """邀请白帽研究员"""
        if researcher_id not in self.researchers:
            self.researchers[researcher_id] = {
                'id': researcher_id,
                'total_reports': 0,
                'accepted_rate': 0,
                'total_earnings': 0,
                'average_quality': 0,
                'joined_date': datetime.now().isoformat(),
                'speciality': speciality
            }
        
        researcher = self.researchers[researcher_id]
        researcher['skill_level'] = skill_level
        
        if session_id:
            session = self.sessions[session_id - 1]
            session['researchers'].append(researcher_id)
        
        return researcher
    
    def submit_report(self, researcher_id, report_data, session_id=None):
        """白帽提交漏洞报告"""
        report = {
            'id': len(self.reports) + 1,
            'researcher_id': researcher_id,
            'title': report_data.get('title'),
            'cve_id': report_data.get('cve_id'),
            'severity': report_data.get('severity', 'medium'),
            'vuln_type': report_data.get('vuln_type'),
            'asset': report_data.get('asset'),
            'reproducible': report_data.get('reproducible', True),
            'has_poc': report_data.get('has_poc', False),
            'submitted_at': datetime.now().isoformat(),
            'status': 'pending_review',
            'session_id': session_id
        }
        
        self.reports.append(report)
        
        if researcher_id in self.researchers:
            self.researchers[researcher_id]['total_reports'] += 1
        
        return report
    
    def triage_report(self, report_id, triage_result):
        """审核报告"""
        report = next((r for r in self.reports if r['id'] == report_id), None)
        if not report:
            return None
        
        report['status'] = triage_result.get('status', 'accepted')  # accepted/duplicate/invalid/out_of_scope
        report['severity'] = triage_result.get('severity', report['severity'])
        report['triaged_by'] = triage_result.get('triager')
        report['triaged_at'] = datetime.now().isoformat()
        
        return report
    
    def award_bounty(self, report_id, amount):
        """发放奖励"""
        report = next((r for r in self.reports if r['id'] == report_id), None)
        if report:
            report['bounty'] = amount
            report['status'] = 'resolved'
            report['resolved_at'] = datetime.now().isoformat()
            
            researcher_id = report['researcher_id']
            if researcher_id in self.researchers:
                self.researchers[researcher_id]['total_earnings'] += amount
            
            # 更新会话统计
            if report['session_id']:
                session = self.sessions[report['session_id'] - 1]
                session['total_reports'] += 1
                session['total_paid'] += amount
        
        return report
    
    def program_statistics(self):
        """计划运营统计数据"""
        total_reports = len(self.reports)
        accepted = len([r for r in self.reports if r['status'] == 'resolved'])
        total_bounties = sum(r.get('bounty', 0) for r in self.reports if r.get('bounty'))
        
        by_severity = {}
        for r in self.reports:
            sev = r['severity']
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        # 研究员排名
        top_researcherrs = sorted(
            self.researchers.values(),
            key=lambda x: x['total_earnings'],
            reverse=True
        )[:5]
        
        return {
            "program": self.program,
            "total_reports": total_reports,
            "accepted_reports": accepted,
            "acceptance_rate": f"{accepted/total_reports*100:.1f}%" if total_reports > 0 else "0%",
            "total_bounties_paid": total_bounties,
            "severity_distribution": by_severity,
            "active_researchers": len(self.researchers),
            "top_researchers": [
                {'id': r['id'], 'earnings': r['total_earnings'], 'reports': r['total_reports']}
                for r in top_researcherrs
            ],
            "roi_estimate": self._calculate_roi()
        }
    
    def _calculate_roi(self):
        """估算ROI"""
        # 假设自动化扫描遗漏的严重漏洞可能造成$100K+损失
        # 众测发现X个严重漏洞 = 避免X * $100K损失
        critical_found = len([r for r in self.reports if r['severity'] == 'critical' and r['status'] == 'resolved'])
        total_cost = sum(r.get('bounty', 0) for r in self.reports)
        avoided_loss = critical_found * 100000  # 假设每个严重漏洞$100K
        roi = ((avoided_loss - total_cost) / total_cost * 100) if total_cost > 0 else 0
        return {"avoided_loss": avoided_loss, "total_cost": total_cost, "roi_percent": f"{roi:.0f}%"}

# 使用示例
manager = CrowdTestManager("Example-Scope")
session = manager.launch_session("夏季众测2025", "2025-07-01", "2025-08-01", max_reward_budget=50000)
manager.invite_researcher("白帽Alice", "expert", "web-security", session['id'])
report = manager.submit_report("白帽Alice", {
    "title": "SQL注入漏洞", "severity": "critical", "vuln_type": "sql_injection",
    "asset": "api.example.com/user", "has_poc": True
}, session['id'])
manager.triage_report(report['id'], {"status": "accepted", "severity": "critical"})
manager.award_bounty(report['id'], 5000)
stats = manager.program_statistics()
print(json.dumps(stats, indent=2, ensure_ascii=False))
```

### 4. 漏洞分级与奖励矩阵

```yaml
# 漏洞分级标准与对应奖励（参考）
vulnerability_classification:
  critical:
    payout_range: "$2,000 - $20,000"
    examples:
      - "远程代码执行 (RCE)"
      - "任意SQL注入 (可获取全部数据)"
      - "任意文件读取/写入"
      - "身份认证绕过（无需用户交互）"
      - "服务器端请求伪造 (SSRF) — 出网"
    criteria: "直接导致服务器被完全控制或核心数据泄露"
    
  high:
    payout_range: "$500 - $4,999"
    examples:
      - "存储型XSS（影响所有用户）"
      - "IDOR越权操作（可访问其他用户数据）"
      - "权限提升（普通用户→管理员）"
      - "CSRF导致敏感操作（改密码/转账）"
      - "不安全的直接对象引用"
    criteria: "可导致有限数据泄露或部分权限提升"
    
  medium:
    payout_range: "$100 - $999"
    examples:
      - "反射型/存储型XSS（有限影响）"
      - "CSRF导致非敏感操作"
      - "开放重定向"
      - "服务器端请求伪造 (SSRF) — 不出网"
      - "子域名劫持"
      - "不安全的HTTP方法"
    criteria: "有安全影响但有限制条件"
    
  low:
    payout_range: "$25 - $249"
    examples:
      - "信息泄露（敏感但不直接可用）"
      - "缺少安全头（HSTS/X-Frame-Options）"
      - "HTTPS证书配置问题"
      - "目录列表"
      - "调试页面泄露"
      - "TLS配置弱项"
    criteria: "提供有价值信息但难以直接利用"
    
  informative:
    payout_range: "$0 (感恩信/小礼物)"
    examples:
      - "最佳实践建议"
      - "非安全问题的配置建议"
      - "重复报告（先到先得）"
    criteria: "有价值但不属于安全漏洞"

# 奖励加成规则
reward_bonus_rules:
  - criterion: "含完整可利用PoC代码"
    bonus: "+20%"
  - criterion: "含修复建议代码"
    bonus: "+10%"
  - criterion: "首次向该计划报告"
    bonus: "+15%"
  - criterion: "同一研究员连续高质量报告"
    bonus: "+5% (逐次累积至+20%)"
  - criterion: "发现0-day（无已知CVE）"
    bonus: "+50%"
```

### 5. 众测ROI与度量

| 指标 | 描述 | 行业基准 | 优秀标准 |
|:---|:---|:---:|:---:|
| 漏洞接收率 | 有效报告/总数 | 25-35% | > 40% |
| 严重+高危占比 | Critical+High/有效报告 | 15-25% | > 20% |
| 平均响应时间 | 从提交到初筛回复 | 4-8小时 | < 2小时 |
| 平均修复时间 | 从确认到修复完成 | 30-60天 | < 14天 (严重) |
| 研究员留存率 | 6个月内再提交比例 | 30-40% | > 50% |
| 每年漏洞数 | 每年收到的有效报告数 | 50-200 | > 200 |
| ROI倍数 | 避免损失/总投入 | 3-5x | > 10x |
| 误报率 | 无效/重复报告比例 | 30-40% | < 25% |

### 6. 国内众测平台（补天/漏洞盒子）集成

```bash
# 补天平台（Qihoo 360）
# 发布漏洞信息通告
curl -X POST https://butian.360.cn/api/v1/vuln/ \
  -H "Authorization: Token your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "SQL注入漏洞",
    "severity": "高危",
    "type": "SQL注入",
    "url": "https://example.com/search",
    "description": "搜索参数未过滤导致SQL注入",
    "reproduce_steps": "1. 访问 /search?q=test 2. 测试单引号注入",
    "impact": "可能导致数据泄露",
    "fix_suggestion": "使用参数化查询"
  }'

# 漏洞盒子（FIT）
# 提交漏洞
curl -X POST https://api.loudonghezi.com/v1/submit/ \
  -H "Authorization: Token your-token" \
  -d "vuln_type=sql_injection&target=https://example.com"

# 查询奖励
curl -X GET https://api.loudonghezi.com/v1/rewards/ \
  -H "Authorization: Token your-token"
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| HackerOne | 全球漏洞奖励平台 | https://www.hackerone.com/ |
| Bugcrowd | 众测与漏洞管理 | https://www.bugcrowd.com/ |
| Synack | 邀请制安全测试平台 | https://www.synack.com/ |
| 补天平台 | 国内最大漏洞响应平台 | https://butian.360.cn/ |
| 漏洞盒子 | 企业漏洞响应平台 | https://www.loudonghezi.com/ |
| Intigriti | 欧洲众测平台 | https://www.intigriti.com/ |
| YesWeHack | 全球漏洞奖励计划 | https://www.yeswehack.com/ |

## 参考资源

- [ISO 29147 — Vulnerability Disclosure](https://www.iso.org/standard/72311.html)
- [ISO 30111 — Vulnerability Handling](https://www.iso.org/standard/72312.html)
- [CISA Vulnerability Disclosure Policy (VDP) Guidance](https://www.cisa.gov/vulnerability-disclosure-policy)
- [OWASP Bug Bounty Guide](https://owasp.org/www-project-bug-bounty-guide/)
- [FIRST CVD Framework — Coordinated Vulnerability Disclosure](https://www.first.org/global/sigs/vulnerability-coordination/)
- [HackerOne Hacker-Powered Security Report](https://www.hackerone.com/trends)
- [Google Project Zero Vulnerability Disclosure](https://googleprojectzero.blogspot.com/)
