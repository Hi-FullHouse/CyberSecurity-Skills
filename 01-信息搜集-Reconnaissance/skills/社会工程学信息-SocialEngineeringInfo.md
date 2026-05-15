---
id: 01-005
title: "👥 社会工程学信息收集 (Social Engineering Information Gathering)"
category: 信息搜集
category_en: Reconnaissance
difficulty: ★★★★
tools: "theHarvester, Sherlock, Maltego"
last_updated: 2025-07
tags: ["reconnaissance", "osint", "information-gathering", "dns-enumeration", "passive-recon"]
subdomain: reconnaissance
nist_csf: ["ID.AM-01", "ID.AM-04", "DE.CM-01"]
mitre_attack: ["T1595", "T1592", "T1590", "T1596"]
---
# 👥 社会工程学信息收集 (Social Engineering Information Gathering)

## 概述
收集目标组织的人员信息、组织结构、联系方式，为社会工程学攻击或暴力破解提供素材。

## 核心技能

### 1. 人员信息收集

```bash
# theHarvester - 收集邮件、员工信息
theHarvester -d example.com -b google,linkedin,bing,baidu

# 在LinkedIn搜索目标公司员工
# 搜索: "Company Name" "employee"
# 查看公司页面 → 人员列表

# 在招聘网站寻找技术栈信息
# 拉勾、Boss直聘、猎聘搜索目标公司
```

### 2. 邮箱验证与猜测

```bash
# 邮箱格式猜测
# 常见格式: firstname.lastname@example.com
#            firstinitial.lastname@example.com
#            firstname@example.com

# Hunter.io API验证邮箱
curl "https://api.hunter.io/v2/email-verifier?email=test@example.com&api_key=KEY"

# 邮箱验证工具
hunter verify --email test@example.com

# 验证邮箱是否存在
smtp-user-enum -M VRFY -U users.txt -t mail.example.com
```

### 3. 用户名收集

```bash
# Sherlock - 跨平台用户名搜索
sherlock username

# 从公司邮箱提取用户名模式
# admin@example.com → admin
# john.doe@example.com → john.doe

# 生成用户名列表
python3 -c "
first_names = ['john', 'jane', 'bob']
last_names = ['smith', 'doe']
for f in first_names:
    for l in last_names:
        print(f'{f}.{l}')
        print(f'{f}{l}')
        print(f'{f[0]}{l}')
        print(f'{l}{f}')
"
```

### 4. GitHub信息泄露

```bash
# GitDorker
gitdorker -d example.com -o output -nb -tf ./tf/ -q

# truffleHog
trufflehog git https://github.com/example/example-repo

# 手动GitHub搜索
# "example.com" password
# "example.com" api_key
# "example.com" secret
# "example.com" token

# GitLeaks
gitleaks detect --source /path/to/repo -v
```

### 5. 密码泄露数据库

```bash
# Have I Been Pwned API
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com" -H "hibp-api-key: KEY"

# 检查已泄露的密码
# https://haveibeenpwned.com/Passwords

# DeHashed - 付费密码搜索
# https://dehashed.com/

# IntelX - 数据泄露搜索
# https://intelx.io/
```

### 6. 社交媒体分析

```bash
# Twitter/X搜索
# 搜索: from:@username (某用户发的推)
# 搜索: geocode:lat,lon,radius (地理位置)

# 微信/微博搜索
# 公众平台搜公司名
# 搜狗微信搜索

# 知乎/脉脉
# 搜索目标公司技术和员工信息
```

### 7. 钓鱼信息收集

```markdown
# 需要收集的信息
1. **内部系统名称**：OA、ERP、CRM等系统名称
2. **技术栈信息**：使用的语言、框架、云服务
3. **内部术语**：项目代号、团队名称
4. **组织架构**：部门关系、汇报层级
5. **合作伙伴**：供应商、客户信息
6. **活动信息**：团建、会议、培训（可伪造邀请）
```

### 8. 物理信息收集

```bash
# Google Maps/Street View - 查看办公大楼
# 搜索: "Company Name" 地址

# Google Earth - 查看办公楼结构

# 办公楼平面图搜索
# site:floorplans.com "Company Name"
```

## 信息收集Checklist

- [ ] 公司域名和子域名
- [ ] 各业务系统名称
- [ ] 员工姓名和邮箱
- [ ] 技术栈和技术负责人
- [ ] 组织架构图
- [ ] 电话/传真号码
- [ ] 办公地址和分部位置
- [ ] 合作伙伴和供应商
- [ ] 社交媒体账号
- [ ] 公开的代码仓库
- [ ] 招聘信息中的技术细节
- [ ] 新闻稿和公告信息

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| theHarvester | 邮箱/用户名收集 | https://github.com/laramies/theHarvester |
| Sherlock | 用户名搜索 | https://github.com/sherlock-project/sherlock |
| GitDorker | GitHub泄露搜索 | https://github.com/obheda12/GitDorker |
| Hunter.io | 邮箱查找/验证 | https://hunter.io/ |
| Phonebook | 综合信息搜索 | https://phonebook.cz/ |

## 参考资源
- [Social Engineering Toolkit (SET)](https://github.com/trustedsec/social-engineer-toolkit)
- [Gophish - 钓鱼框架](https://github.com/gophish/gophish)
- [Recon-ng Social Engineering模块](https://github.com/lanmaster53/recon-ng)
