---
id: 18-006
title: "🧠 安全需求与威胁建模 (Security Requirements & Threat Modeling)"
category: 安全开发运维
category_en: DevSecOps
difficulty: ★★★★
tools: "STRIDE, PASTA, Threat Dragon, OWASP Cornucopia, Microsoft TMT"
last_updated: 2025-07
tags: ["devsecops", "ci-cd", "sast", "dast", "iac-security", "supply-chain"]
subdomain: devsecops
nist_csf: ["PR.IP-12", "ID.RA-01", "DE.CM-08"]
mitre_attack: []
---
# 🧠 安全需求与威胁建模 (Security Requirements & Threat Modeling)

## 概述
在系统设计阶段系统化识别安全威胁和风险，建立安全需求基线。涵盖STRIDE、PASTA、LINDDUN等主流威胁建模方法论。

## 核心技能

### 1. STRIDE威胁建模

```text
STRIDE威胁分类框架
┌─────────────────────────────────────────────────────┐
│ 威胁类型    │ 定义              │ 示例              │
├─────────────┼───────────────────┼───────────────────┤
│ S - Spoofing│ 身份伪造          │ 假冒身份登录      │
│ T - Tampering│ 数据篡改         │ SQL注入篡改数据库  │
│ R - Repudiation│ 否认操作       │ 无审计日志否认操作 │
│ I - Info Disclosure│ 信息泄露   │ 返回敏感数据      │
│ D - Denial of Service│ 拒绝服务 │ 请求洪泛          │
│ E - Elevation of Privil│ 提权  │ 垂直/水平越权     │
└─────────────────────────────────────────────────────┘

STRIDE应用示例 - Web应用
┌──────────────────────────────────────────────────────┐
│ 组件: 用户登录模块                                    │
│                                                       │
│ Spoofing:      暴力破解/凭证填充攻击                   │
│ Tampering:     Cookie篡改/请求参数篡改                 │
│ Repudiation:   无审计日志的异常登录                     │
│ Info Disclosure: 返回密码哈希/用户名枚举               │
│ Denial of Svc: 登录接口高频请求                        │
│ Elevation:     普通用户提权为管理员                    │
│                                                       │
│ 安全需求:                                            │
│ 1. 强制MFA (反Spoofing)                              │
│ 2. 请求签名验证 (反Tampering)                         │
│ 3. 登录审计日志 (反Repudiation)                       │
│ 4. 统一错误消息 (反Info Disclosure)                   │
│ 5. 速率限制 (反DoS)                                  │
│ 6. 最小权限RBAC (反Elevation)                         │
└──────────────────────────────────────────────────────┘
```

### 2. PASTA威胁建模流程

```bash
# PASTA方法论 - 7步流程
# Step 1: 定义业务目标
# Step 2: 定义技术范围
# Step 3: 分解应用架构
# Step 4: 威胁分析
# Step 5: 漏洞分析
# Step 6: 枚举攻击
# Step 7: 风险评估和缓解

# 使用Threat Dragon创建威胁模型
# 安装Threat Dragon
docker run -d -p 3000:3000 --name threat-dragon \
  owasp/threat-dragon:stable

# 使用结构化的威胁模型文件
cat << 'JSON' > threat-model.json
{
  "version": "1.1",
  "name": "Web App Threat Model",
  "description": "Web应用威胁模型",
  "architecture": {
    "diagramType": "Threat Dragon",
    "boundaries": [
      {"name": "用户浏览器", "boundaryType": "trust"},
      {"name": "互联网", "boundaryType": "untrust"},
      {"name": "Web服务器", "boundaryType": "trust"},
      {"name": "API服务器", "boundaryType": "trust"},
      {"name": "数据库", "boundaryType": "trust"}
    ]
  },
  "threats": [
    {
      "type": "Spoofing",
      "risk": "Critical",
      "control": "MFA Implementation"
    }
  ]
}
JSON
```

### 3. 安全需求清单

| 安全域 | 需求 | 优先级 | 验证方式 |
|:---|:---|:---:|:---|
| 认证 | 密码复杂度≥8位+大小写+数字+特殊字符 | P0 | SAST+功能测试 |
| 认证 | MFA支持 | P0 | 功能测试 |
| 授权 | RBAC最小权限模型 | P0 | 渗透测试 |
| 授权 | 服务端权限校验（非仅前端） | P0 | DAST |
| 输入验证 | 所有输入做白名单/参数化查询 | P0 | SAST+DAST |
| 加密传输 | TLS 1.3强制 | P0 | 配置审计 |
| 加密存储 | 敏感数据AES-256加密 | P1 | 代码审计 |
| 日志审计 | 登录/权限变更/敏感操作审计 | P1 | 配置检查 |
| 会话管理 | JWT生命周期不超过15min/自动过期 | P1 | 渗透测试 |
| 速率限制 | API速率限制 | P2 | 负载测试 |
| CSP | Content-Security-Policy头 | P2 | DAST |
| CORS | 白名单源限制 | P2 | 配置审计 |

### 4. OWASP ASVS (Application Security Verification Standard)

```text
ASVS等级概览
┌───────────────────────────────────────────────────────────┐
│ 等级 │ 适用场景          │ 检查项数 │ 目标                    │
├──────┼───────────────────┼─────────┼────────────────────────┤
│ L1   │ 所有应用          │ 40+     │ 基本安全控制            │
│ L2   │ 处理敏感数据      │ 120+    │ 多数OWASP Top 10防护    │
│ L3   │ 高安全要求        │ 180+    │ 深度防御、全栈保护      │
└───────────────────────────────────────────────────────────┘

ASVS L1快速检查示例
1. 验证类别: V2 认证验证
   - 2.1.1: 密码至少8位字符
   - 2.1.2: 密码允许包含Unicode/空格
   - 2.5.1: 验证凭证使用参数化API
   
2. 验证类别: V3 会话管理
   - 3.1.1: Cookie设置secure, httponly, samesite
   - 3.2.1: 会话ID使用加密随机数
   
3. 验证类别: V4 访问控制
   - 4.1.1: 禁止越权访问
   - 4.1.3: 最小权限原则
```

### 5. 威胁建模工具使用

```bash
# OWASP Threat Dragon
# 安装和启动
docker run -d -p 3000:3000 \
  -v threat-dragon-data:/app/data \
  -e NODE_ENV=production \
  owasp/threat-dragon:stable

# Microsoft Threat Modeling Tool (TMT)
# Windows安装
# https://learn.microsoft.com/security/engineering/threat-modeling-tool
# 创建威胁模型
# 使用STRIDE模板
# 导出报告

# 使用开源工具OWASP Cornucopia
# 以卡片形式进行安全需求分类
# 下载PDF: https://owasp.org/www-project-cornucopia/
```

### 6. 数据流图(DFD)示例

```mermaid
graph TD
    User((用户)) -->|HTTPS请求| WebApp[Web应用服务器]
    WebApp -->|API调用| API[API网关]
    API -->|查询| DB[(数据库)]
    API -->|缓存| Redis[(Redis缓存)]
    API -->|消息| Queue[消息队列]
    Worker[后台Worker] --> Queue
    Worker -->|写| DB
    
    style User fill:#f9f,stroke:#333
    style WebApp fill:#bbf,stroke:#333
    style API fill:#bbf,stroke:#333
    style DB fill:#bfb,stroke:#333
    style Queue fill:#fbb,stroke:#333

威胁边界:
- 用户 ↔ 互联网: 未信任边界
- 互联网 ↔ WebApp: 需要WAF/TLS
- API ↔ 数据库: 需要SQL参数化
- Worker ↔ 队列: 需要消息签名
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| OWASP Threat Dragon | 开源威胁建模 | https://github.com/OWASP/threat-dragon |
| Microsoft TMT | 威胁建模工具 | https://learn.microsoft.com/security/engineering/threat-modeling-tool |
| OWASP ASVS | 应用安全验证标准 | https://asvs.owasp.org/ |
| OWASP Cornucopia | 安全需求卡片 | https://owasp.org/www-project-cornucopia/ |
| Threatspec | 代码嵌入威胁建模 | https://github.com/threatspec/threatspec |

## 参考资源
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [Microsoft Threat Modeling](https://learn.microsoft.com/security/engineering/threat-modeling)
- [NIST SP 800-154 — Threat Modeling](https://csrc.nist.gov/publications/detail/sp/800-154/draft)
- [STRIDE vs PASTA vs LINDDUN comparison](https://insights.sei.cmu.edu/blog/threat-modeling-12-available-methods/)
