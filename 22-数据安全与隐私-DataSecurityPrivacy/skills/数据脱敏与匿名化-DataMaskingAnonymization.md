---
id: 22-003
title: "🔏 数据脱敏与匿名化 (Data Masking & Anonymization)"
category: 数据安全与隐私
category_en: "Data Security & Privacy"
difficulty: ★★★★
tools: "ARX Data Anonymizer, Privacy Analytics, Oracle DPM, PostgreSQL Anonymizer, Delphix"
last_updated: 2025-07
tags: ["data-security", "privacy", "dlp", "gdpr", "encryption", "data-classification"]
subdomain: data-security-privacy
nist_csf: ["PR.DS-01", "PR.DS-02", "PR.DS-05", "ID.GV-03"]
mitre_attack: ["T1530", "T1048", "T1567"]
---
# 🔏 数据脱敏与匿名化 (Data Masking & Anonymization)

## 概述

数据脱敏和匿名化是通过变形、替换、泛化等技术，在保留数据可用性的前提下消除敏感信息的技术手段。用于测试环境、数据共享、分析和合规场景。关键技术包括：**k-匿名**、**l-多样性**、**t-紧密性**和**差分隐私**。

## 核心技能

### 1. 静态数据脱敏 (Static Data Masking - SDM)

```sql
-- PostgreSQL 静态脱敏
-- 姓名脱敏：保留姓氏，名字替换为*
UPDATE users SET name = CONCAT(LEFT(name, 1), '***');

-- 手机号脱敏：138****8000
UPDATE users SET phone = CONCAT(LEFT(phone, 3), '****', RIGHT(phone, 4));

-- 身份证脱敏
UPDATE users SET id_card = CONCAT(LEFT(id_card, 6), '**********', RIGHT(id_card, 4));

-- 邮箱脱敏
UPDATE users SET email = CONCAT(LEFT(email, 2), '***@', SPLIT_PART(email, '@', 2));

-- 地址泛化（保留省市，隐藏街道）
UPDATE users SET address = CONCAT(
  SPLIT_PART(address, '省', 1), '省',
  SPLIT_PART(SPLIT_PART(address, '省', 2), '市', 1), '市***'
);

-- MySQL 脱敏函数
INSERT INTO test_users (name, phone, email)
SELECT 
  INSERT(name, 2, CHAR_LENGTH(name)-1, REPEAT('*', CHAR_LENGTH(name)-1)),
  INSERT(phone, 4, 4, '****'),
  INSERT(email, 2, INSTR(email, '@')-2, REPEAT('*', INSTR(email, '@')-2))
FROM production_users;
```

### 2. 动态数据脱敏 (Dynamic Data Masking - DDM)

```sql
-- SQL Server 动态数据脱敏
ALTER TABLE users
ALTER COLUMN email ADD MASKED WITH (FUNCTION = 'email()');
ALTER TABLE users
ALTER COLUMN phone ADD MASKED WITH (FUNCTION = 'partial(1,"****",3)');
ALTER TABLE users
ALTER COLUMN name ADD MASKED WITH (FUNCTION = 'partial(1,"***",0)');

-- 创建不屏蔽的用户（管理员）
CREATE USER admin_user WITHOUT LOGIN;
GRANT UNMASK TO admin_user;

-- PostgreSQL 动态脱敏 (使用pg_ddm扩展)
-- 需要先安装 pg_ddm
CREATE MASKING POLICY mask_name ON users
  USING (substr(name, 1, 1) || '***')
  FOR COLUMN name;

-- Oracle 数据脱敏 (Enterprise Manager)
BEGIN
  DBMS_REDACT.ADD_POLICY(
    object_schema => 'APP',
    object_name   => 'USERS',
    policy_name   => 'phone_mask',
    column_name   => 'PHONE',
    function_type => DBMS_REDACT.PARTIAL,
    function_parameters => '1,4,****,3'
  );
END;
```

### 3. k-匿名化与数据发布隐私保护

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ARX-style k-匿名化实现示例

import pandas as pd
from itertools import combinations

def apply_k_anonymity(df, quasi_identifiers, k=5):
    """简化版k-匿名实现"""
    # 对每个准标识符进行泛化
    for col in quasi_identifiers:
        if df[col].dtype == 'object':
            # 字符串类型：截断到首字符
            df[col] = df[col].str[:1] + '**'
        elif df[col].dtype in ['int64', 'float64']:
            # 数值类型：按范围分桶
            min_val, max_val = df[col].min(), df[col].max()
            bin_width = (max_val - min_val) / 10
            df[col] = pd.cut(df[col], bins=10, precision=0)
    
    # 检查k-匿名性
    counts = df.groupby(quasi_identifiers).size()
    violating = counts[counts < k]
    
    print(f"k={k}匿名检验:")
    print(f"  违反k-匿名的组数: {len(violating)}")
    print(f"  最小等价类大小: {counts.min()}")
    
    return df

# 使用示例
data = {
    'name': ['张三', '李四', '王五', '赵六', '陈七'] * 20,
    'age': [25, 35, 45, 28, 52] * 20,
    'zipcode': ['100001', '200001', '300001', '100002', '400001'] * 20,
    'disease': ['A', 'B', 'C', 'A', 'B'] * 20
}
df = pd.DataFrame(data)
anonymized = apply_k_anonymity(df, ['age', 'zipcode'], k=10)
print(anonymized.head(10))
```

### 4. 差分隐私实现

```python
# 差分隐私 - Laplace机制实现
import numpy as np

def laplace_mechanism(data, epsilon, sensitivity=1.0):
    """Laplace机制差分隐私"""
    scale = sensitivity / epsilon
    noise = np.random.laplace(0, scale, len(data))
    return data + noise

def count_with_dp(data, epsilon):
    """带差分隐私的计数查询"""
    true_count = len(data)
    noise = np.random.laplace(0, 1/epsilon)
    return max(0, true_count + noise)

# 示例：统计年龄平均值
ages = np.array([25, 32, 28, 45, 35, 29, 41, 33, 27, 38])
epsilon = 0.1  # 隐私预算（越小隐私越好）

mean_age = np.mean(ages)
dp_mean = np.mean(laplace_mechanism(ages, epsilon))

print(f"真实均值: {mean_age:.2f}")
print(f"差分隐私均值(ε={epsilon}): {dp_mean:.2f}")

# 组合隐私预算
def compose_epsilon(epsilons):
    """计算组合查询的隐私预算（串行组合定理）"""
    return sum(epsilons)

# 高级组合定理
def advanced_composition(k, epsilon, delta=1e-5):
    """k次查询的高级组合隐私预算"""
    return epsilon * np.sqrt(2 * k * np.log(1/delta)) + k * epsilon * (np.exp(epsilon) - 1)
```

### 5. 数据库动态脱敏配置

```bash
# PostgreSQL Anonymizer 扩展
# 安装扩展
CREATE EXTENSION IF NOT EXISTS anon CASCADE;
SELECT anon.init();

# 定义脱敏规则
SECURITY LABEL FOR anon ON COLUMN users.name 
  IS 'MASKED WITH FUNCTION anon.fake_first_name()';

SECURITY LABEL FOR anon ON COLUMN users.phone 
  IS 'MASKED WITH FUNCTION anon.partial(anon.random_phone(),3,******,3)';

SECURITY LABEL FOR anon ON COLUMN users.email 
  IS 'MASKED WITH FUNCTION anon.fake_email()';

SECURITY LABEL FOR anon ON COLUMN users.id_card 
  IS 'MASKED WITH FUNCTION anon.random_string(18)';

# 执行匿名化
SELECT anon.anonymize_database();

# 匿名化导出
SELECT anon.anonymize('users') TO '/tmp/anonymized_users.csv';

# 使用pg_dump匿名化导出
pg_dump --column-inserts --data-only \
  -t users | sed -e 's/[0-9]\{11\}/138****8000/g' > anonymized_dump.sql
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| ARX Data Anonymizer | 综合性数据匿名化工具 | https://arx.deidentifier.org/ |
| PostgreSQL Anonymizer | PG内置脱敏扩展 | https://postgresql-anonymizer.readthedocs.io/ |
| Delphix | 动态数据平台 | https://www.delphix.com/ |
| Oracle Data Masking | Oracle企业脱敏 | https://www.oracle.com/security/data-masking/ |
| Google DP | Google差分隐私库 | https://github.com/google/differential-privacy |
| OpenDP | 开源差分隐私库 | https://opendp.org/ |

## 参考资源

- [NIST SP 800-188 — De-identification](https://csrc.nist.gov/publications/detail/sp/800-188/draft)
- [ISO 29100 — Privacy Framework](https://www.iso.org/standard/62306.html)
- [k-anonymity: A Model For Protecting Privacy](https://epic.org/wp-content/uploads/privacy/reidentification/sweeney_article.pdf)
- [差分隐私入门指南](https://www.cis.upenn.edu/~aaroth/Papers/privacybook.pdf)
- [OWASP Data Protection](https://cheatsheetseries.owasp.org/cheatsheets/Data_Protection_Cheat_Sheet.html)
