---
id: 25-005
title: "🏢 第三方供应商风险评估 (Third-Party Vendor Risk Assessment)"
category: 供应链安全
category_en: "Supply Chain Security"
difficulty: ★★★★
tools: "BitSight, SecurityScorecard, OneTrust Vendor Risk, Prevalent, Panorays"
last_updated: 2025-07
tags: ["supply-chain-security", "sbom", "dependency-check", "container-image", "third-party-risk"]
subdomain: supply-chain-security
nist_csf: ["ID.SC-01", "ID.SC-02", "PR.DS-10"]
mitre_attack: ["T1195", "T1525"]
---
# 🏢 第三方供应商风险评估 (Third-Party Vendor Risk Assessment)

## 概述

第三方供应商是供应链安全中最薄弱的环节之一。通过系统化的供应商安全评估、持续监控和合同约束，有效管理由外部合作伙伴带来的安全风险。

## 核心技能

### 1. 供应商安全问卷

```python
#!/usr/bin/env python3
# 供应商安全评估问卷自动化

import json
from datetime import datetime

class VendorSecurityQuestionnaire:
    def __init__(self, vendor_name, tier):
        self.vendor_name = vendor_name
        self.tier = tier  # 1=关键, 2=重要, 3=一般
        self.responses = {}
        self.risk_score = 0
    
    def ask_security_domains(self):
        """核心安全域问题"""
        domains = {
            "identity_access": {
                "questions": [
                    {"q": "是否启用MFA?", "weight": 10},
                    {"q": "是否实施最小权限原则?", "weight": 8},
                    {"q": "密码策略是否满足NIST标准?", "weight": 7}
                ]
            },
            "data_protection": {
                "questions": [
                    {"q": "数据传输是否加密(TLS 1.2+)?", "weight": 10},
                    {"q": "数据存储是否加密(AES-256)?", "weight": 10},
                    {"q": "是否有数据分类策略?", "weight": 8},
                    {"q": "数据备份是否为离线/加密?", "weight": 7}
                ]
            },
            "incident_response": {
                "questions": [
                    {"q": "是否有IR计划?", "weight": 9},
                    {"q": "安全事件报告时间?", "weight": 8},
                    {"q": "是否有应急演练?", "weight": 7}
                ]
            },
            "compliance": {
                "questions": [
                    {"q": "是否通过SOC2认证?", "weight": 10},
                    {"q": "是否通过ISO 27001认证?", "weight": 9},
                    {"q": "是否符合GDPR?", "weight": 9}
                ]
            },
            "supply_chain": {
                "questions": [
                    {"q": "是否有自己的供应商评估流程?", "weight": 7},
                    {"q": "是否披露关键的次级供应商?", "weight": 6},
                    {"q": "是否有SBOM要求?", "weight": 8}
                ]
            }
        }
        return domains
    
    def calculate_risk_level(self):
        """计算风险等级"""
        if self.tier == 1:  # 关键供应商
            thresholds = {"low": 80, "medium": 60, "high": 0}
        elif self.tier == 2:
            thresholds = {"low": 70, "medium": 50, "high": 0}
        else:
            thresholds = {"low": 60, "medium": 40, "high": 0}
        
        if self.risk_score >= thresholds["low"]:
            return "低风险"
        elif self.risk_score >= thresholds["medium"]:
            return "中风险"
        return "高风险"
    
    def generate_report(self):
        """生成评估报告"""
        risk = self.calculate_risk_level()
        report = {
            "vendor": self.vendor_name,
            "tier": f"Tier {self.tier}",
            "assessment_date": datetime.now().isoformat(),
            "risk_score": self.risk_score,
            "risk_level": risk,
            "recommendations": self._get_recommendations()
        }
        return report
    
    def _get_recommendations(self):
        if self.risk_score >= 80:
            return ["继续保持", "建议季度重新评估"]
        elif self.risk_score >= 60:
            return [
                "要求整改中低风险项",
                "提供整改时间表",
                "合同中增加安全条款"
            ]
        return [
            "立即要求安全整改",
            "限制数据访问范围",
            "考虑替代供应商",
            "月度和法律审查"
        ]

# 使用示例
vendor = VendorSecurityQuestionnaire("XX云服务商", 1)
# 评估过程...
vendor.risk_score = 72
report = vendor.generate_report()
print(json.dumps(report, indent=2, ensure_ascii=False))
```

### 2. 供应商安全监控

```bash
# 使用安全评级平台监控供应商
# BitSight API
curl -X GET "https://api.bitsighttech.com/ratings/v1/companies/portfolio" \
  -H "Authorization: Bearer $BITSIGHT_API_KEY"

# SecurityScorecard API
curl -X GET "https://api.securityscorecard.io/v2/companies/portfolio" \
  -H "Authorization: Bearer $SC_API_KEY"

# 自动化获取供应商安全评分
python3 << 'EOF'
import requests
import json

def monitor_vendor_security(vendor_name, api_key):
    """监控供应商安全态势"""
    # 查询供应商安全事件
    headers = {"Authorization": f"Bearer {api_key}"}
    
    # 获取最近安全评级趋势
    url = f"https://api.securityscorecard.io/v2/companies/{vendor_name}/history"
    resp = requests.get(url, headers=headers)
    
    if resp.status_code == 200:
        data = resp.json()
        scores = [entry['score'] for entry in data.get('entries', [])]
        
        if len(scores) >= 3:
            trend = scores[-1] - scores[-3]
            status = "🟢 改善" if trend > 0 else ("🔴 下降" if trend < 0 else "⚪ 持平")
            
            print(f"供应商: {vendor_name}")
            print(f"当前评分: {scores[-1]}/100")
            print(f"趋势: {status} ({trend:+.1f})")
            print(f"90天最低分: {min(scores)}")
            
            if scores[-1] < 60:
                print("⚠️ 供应商安全评级低于警戒线")
        return data

# 监控多个供应商
vendors = ["vendor-a", "vendor-b", "vendor-c"]
for vendor in vendors:
    monitor_vendor_security(vendor, "your-api-key")
EOF
```

### 3. 供应商安全合同条款

```markdown
# 供应商安全合同关键条款

## 数据保护条款
1. **数据安全**
   - 供应商须实施符合行业标准的技术和组织措施
   - 数据加密标准: TLS 1.2+ (传输), AES-256 (存储)
   - 数据隔离: 多租户环境下须实施逻辑隔离

2. **违规通知**
   - 安全事件通知: 发现后24小时内
   - 数据泄露通知: 发现后48小时内
   - 按需提供事件分析报告

3. **审计权利**
   - 年度安全审计权
   - 第三方渗透测试报告共享
   - 安全控制证明（SOC2/ISO 27001）

4. **次级供应商**
   - 须披露所有数据子处理者
   - 次级供应商变更须提前通知
   - 次级供应商须符合等同安全要求

5. **退出条款**
   - 服务终止后的安全数据删除
   - 数据导出的格式和时限保证
   - 过渡期的安全支持
```

### 4. 供应商风险矩阵

| 风险维度 | 权重 | 低风险(1分) | 中风险(2分) | 高风险(3分) |
|:---|:---:|:---|:---|:---|
| 安全认证 | 15% | SOC2/ISO双认证 | SOC2或ISO | 无认证 |
| 数据敏感度 | 20% | 非敏感数据 | 内部数据 | 个人/敏感数据 |
| 网络访问 | 20% | 无网络连接 | 受限网络接入 | 直接网络访问 |
| 数据存储位置 | 15% | 本地/合规区 | 境内 | 跨境无协议 |
| 安全事件历史 | 15% | 3年无事件 | 1起低危事件 | 多起/高危事件 |
| 灾备能力 | 15% | 多地多活 | 主备切换 | 无灾备 |

### 5. 供应链攻击响应

```yaml
# 供应链安全事件响应流程
supply_chain_incident_response:
  phase_1_detect:
    - "确认受影响的供应商/组件"
    - "评估影响范围"
    - "通知安全团队"
    actions: ["技术分析", "影响评估"]
    
  phase_2_contain:
    - "隔离受影响系统"
    - "断开供应商连接"
    - "阻断恶意通信"
    actions: ["网络隔离", "访问阻断"]
    
  phase_3_eradicate:
    - "移除恶意组件"
    - "回滚到安全版本"
    - "替换受影响的供应商"
    actions: ["清除", "替换"]
    
  phase_4_recover:
    - "恢复服务（使用验证版本）"
    - "加强监控"
    - "全面扫描"
    actions: ["恢复", "强化监控"]
    
  phase_5_improve:
    - "评估供应商评估流程"
    - "更新供应商安全要求"
    - "加强供应链监控能力"
    actions: ["流程改进", "技术增强"]
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| BitSight | 安全评级平台 | https://www.bitsight.com/ |
| SecurityScorecard | 供应商安全评分 | https://securityscorecard.com/ |
| OneTrust VRM | 供应商风险管理 | https://www.onetrust.com/ |
| Prevalent | 第三方风险管理 | https://www.prevalent.net/ |
| Panorays | 自动化供应商评估 | https://panorays.com/ |

## 参考资源

- [NIST SP 800-161 — Supply Chain Risk Management](https://csrc.nist.gov/publications/detail/sp/800-161/final)
- [CISA Supply Chain Risk Management](https://www.cisa.gov/supply-chain-risk-management)
- [ISO 28001 — Supply Chain Security](https://www.iso.org/standard/45654.html)
- [Shared Assessments SIG Questionnaire](https://sharedassessments.org/)
- [ENISA Supply Chain Security Recommendations](https://www.enisa.europa.eu/publications)
