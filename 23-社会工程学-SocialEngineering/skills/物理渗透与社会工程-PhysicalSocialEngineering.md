---
id: 23-003
title: "🏢 物理渗透与社会工程 (Physical Social Engineering)"
category: 社会工程学
category_en: "Social Engineering"
difficulty: ★★★★
tools: "Pretexting Framework, Badge Clone, Lockpick Set, RFID Cloner"
last_updated: 2025-07
tags: ["social-engineering", "phishing", "vishing", "physical-security", "awareness"]
subdomain: social-engineering
nist_csf: ["PR.AT-01", "PR.AT-02"]
mitre_attack: ["T1566", "T1598", "T1204"]
---
# 🏢 物理渗透与社会工程 (Physical Social Engineering)

## 概述

物理渗透测试通过伪装身份、尾随进入、物理设备植入等方式评估组织的物理安全控制。结合社会工程技术，突破人员、流程和技术的防线。

## 核心技能

### 1. 身份伪装与情景构建

```markdown
# 伪装角色卡片

## 场景A: 网络检修工程师
- **身份**: 第三方网络服务商工程师
- **伪装物**: 工装（带logo）、工具箱、工作单、工作证
- **话术**: "我们是XX网络的服务商，来检修3楼弱电间的交换机"
- **应对质疑**: 
  - 询问工单号 → "工单号是SR-2025-07842，可以查IT值班经理确认"
  - 需要陪同 → "好的，我们按规矩来，麻烦您了"
- **目标**: 进入弱电间/机房，获取网络拓扑、接入恶意设备

## 场景B: 新员工入职
- **身份**: 第一天入职的新员工
- **伪装物**: 工牌（仿制）、入职邮件截图
- **话术**: "我是今天入职的新同事，行政说IT在5楼"
- **目标**: 跟随员工进入办公区、观察内部布局、获取WiFi密码

## 场景C: 清洁/维护人员
- **身份**: 大楼清洁公司人员
- **伪装物**: 清洁工装、打扫工具、通行证
- **时机**: 下班后或早晨保洁时段
- **目标**: 进入办公区拍照、收集废纸中的敏感文件
```

### 2. 门禁系统绕过

```bash
# RFID卡克隆
# 使用Proxmark3
# 读取低频卡(125kHz)
lf search
lf em 410x read

# 读取高频卡(13.56MHz)
hf search
hf mf read

# 克隆低频卡
lf em 410x write --id 0x12345678

# 克隆Mifare Classic卡
# 1. 获取密钥
hf mf chk --t 1
# 2. 读取数据
hf mf rdbl --blk 0 --key A --key FFFFFFFFFFFF
# 3. 写入空白卡
hf mf wrbl --blk 0 --key A --key FFFFFFFFFFFF -d <data>
hf mf wrbl --blk 1 --key A --key FFFFFFFFFFFF -d <data>

# 使用Flipper Zero
# 读取并模拟RFID卡
# Read RFID -> Save -> Emulate
# 低频读取
125kHz RFID -> Read
# 高频读取
13.56MHz -> Mifare Classic -> Read

# 使用NFCGate复制手机NFC
# Android端
adb shell am start -n com.nfcgate.nfcgate/.ui.MainActivity
# 启动中继模式
```

### 3. 尾随进入（Tailgating）

```python
#!/usr/bin/env python3
# 尾随成功率分析工具

import random

class TailgatingSimulation:
    def __init__(self, environment):
        self.env = environment
        self.success_rate = 0.7  # 基线成功率
    
    def calculate_success_probability(self, time_of_day, entry_type, props):
        """计算尾随成功概率"""
        base = self.success_rate
        
        # 时间因素
        time_factors = {
            "morning_rush": 0.95,  # 早高峰
            "lunch": 0.85,         # 午餐时间
            "afternoon": 0.60,     # 下午
            "evening": 0.75,       # 下班后
            "night": 0.30          # 深夜
        }
        
        # 入口类型
        entry_factors = {
            "main_gate": 0.4,      # 大门（门卫检查）
            "side_door": 0.7,      # 侧门
            "parking": 0.8,        # 停车场入口
            "loading_dock": 0.9,   # 货运入口
            "smoking_area": 0.85   # 吸烟区
        }
        
        # 伪装道具
        prop_bonus = 0.1 if props else 0
        
        probability = base * time_factors.get(time_of_day, 0.5) * entry_factors.get(entry_type, 0.5) + prop_bonus
        return min(probability, 1.0)

# 物理渗透检查清单
physical_assessment_checklist = {
    "外围": [
        "围墙/栅栏高度与完整性",
        "监控摄像头覆盖范围",
        "停车场进出管控"
    ],
    "入口": [
        "门禁系统类型（RFID/生物识别）",
        "前台人员警惕性",
        "快递/外卖接收流程"
    ],
    "内部": [
        "敏感区域（机房/财务）",
        "工位电脑锁屏策略",
        "敏感文件处置（碎纸机使用）"
    ],
    "技术": [
        "WiFi信号覆盖（是否有外部可连接的SSID）",
        "网口（是否开放，是否需要认证）",
        "会议室设备安全"
    ]
}
```

### 4. 物理渗透报告模板

```markdown
# 物理渗透测试报告

## 测试概要
- **测试日期**: 
- **目标地点**: 
- **测试方法**: □ 尾随 □ 身份伪装 □ 设备植入 □ 社交工程
- **总体成功率**: 

## 测试详情

### 尝试1: 尾随进入
- **时间**: 
- **方法**: 
- **结果**: □ 成功 □ 失败
- **详情**: 

### 尝试2: 身份伪装
- **伪装身份**: 
- **进入区域**: 
- **获取信息**: 
- **详情**: 

## 发现的风险项
| 编号 | 风险描述 | 严重程度 | 建议措施 |
|:---:|:---|:---:|:---|
| 1 | | | |
| 2 | | | |

## 附图
（附图应包括：入口照片、门禁型号、路线图等）
```

### 5. 物理安全防御评估

```python
# 物理安全成熟度评估
physical_security_maturity = {
    "level_1_initial": {
        "description": "基础门禁，无额外控制",
        "score": 1,
        "characteristics": [
            "单一门禁方式（仅RFID卡）",
            "无访客登记制度",
            "监控摄像头覆盖不足50%",
            "无门禁告警联动"
        ]
    },
    "level_2_defined": {
        "description": "有明确安全制度和多层控制",
        "score": 2,
        "characteristics": [
            "多因素门禁（卡+生物识别）",
            "访客登记+陪同制度",
            "监控覆盖关键区域",
            "门禁异常告警"
        ]
    },
    "level_3_managed": {
        "description": "主动安全管理和定期评估",
        "score": 3,
        "characteristics": [
            "AI行为分析摄像头",
            "人员识别与白名单",
            "定期物理渗透测试",
            "员工安全培训计划"
        ]
    },
    "level_4_optimized": {
        "description": "持续优化和智能安全运营",
        "score": 4,
        "characteristics": [
            "零信任物理安全架构",
            "实时身份验证与定位",
            "自动响应与事件联动",
            "全面安全文化建设"
        ]
    }
}
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Proxmark3 | RFID卡读写/克隆工具 | https://proxmark.com/ |
| Flipper Zero | 多功能安全测试工具 | https://flipperzero.one/ |
| Lockpick Set | 物理开锁工具 | https://www.lockpicktools.com/ |
| NFCGate | NFC中继攻击工具 | https://github.com/nfcgate/nfcgate |
| HackRF | SDR射频分析 | https://greatscottgadgets.com/hackrf/ |

## 参考资源

- [Physical Security Assessment Methodology](https://www.cisa.gov/physical-security)
- [NIST SP 800-53 — Physical and Environmental Protection](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [SANS Physical Security Assessment](https://www.sans.org/white-papers/)
- [ISO 27001 Annex A.11 — Physical Security](https://www.iso.org/standard/27001)
