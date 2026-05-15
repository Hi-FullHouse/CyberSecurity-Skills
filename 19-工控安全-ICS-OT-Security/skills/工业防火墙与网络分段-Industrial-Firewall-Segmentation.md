---
id: 19-006
title: "🔒 工业防火墙与网络分段 (Industrial Firewall & Segmentation)"
category: 工控安全
category_en: "ICS/OT Security"
difficulty: ★★★★
tools: "Tofino Security, Claroty, Nozomi, pfSense, iptables"
last_updated: 2025-07
tags: ["ics-security", "ot-security", "scada", "plc", "iec-62443", "industrial-security"]
subdomain: ics-ot-security
nist_csf: ["PR.AC-01", "PR.DS-07", "PR.PT-01"]
mitre_attack: ["T0843", "T0839", "T0881", "T0855"]
---
# 🔒 工业防火墙与网络分段 (Industrial Firewall & Segmentation)

## 概述
基于Purdue企业参考架构的OT网络分段方法论，涵盖工业防火墙部署策略、安全区(Security Zone)与管道(Conduit)的IEC 62443合规设计。

## 核心技能

### 1. Purdue模型网络分段

```text
Purdue企业参考架构 (PERA)
┌───────────────────────────────────────────────┐
│ 等级 5 │ 企业网络 (Enterprise Zone)          │
│        │ Email, Web, ERP                      │
│────────┼──────────────────────────────────────│
│ 等级 4 │ 数据中心 (DMZ)                       │
│        │ 补丁服务器, 远程访问网关, 历史数据库   │
│────────┼──────────────────────────────────────│
│ 等级 3 │ 制造运营管理 (MOM)                    │
│        │ MES, 生产调度, 质量系统               │
│────────┼──────────────────────────────────────│
│ 等级 2 │ 过程控制 (Purdue 2)                   │
│        │ SCADA, HMI, 工程师站                  │
│────────┼──────────────────────────────────────│
│ 等级 1 │ 基本控制 (Purdue 1)                   │
│        │ PLC, RTU, DCS, 远程I/O               │
│────────┼──────────────────────────────────────│
│ 等级 0 │ 物理过程 (Purdue 0)                   │
│        │ 传感器, 执行器, 电机, 阀门            │
└───────────────────────────────────────────────┘

安全要求:
- 等级3-5: IT安全策略为主
- 等级0-2: OT安全策略 (可用性优先 > 完整性 > 机密性)
- 跨等级通信必须通过工业防火墙
- DMZ实施双向访问控制
```

### 2. 工业防火墙部署

```bash
# 使用pfSense作为工业防火墙
# 安装pfSense (物理机或VM)
# 配置OT网段隔离

# 基础规则配置
# WAN -> OT: 全部阻止，仅允许特定VPN
# OT -> WAN: 仅允许特定补丁服务器访问
# DMZ -> OT: 仅允许必要端口白名单

# iptables OT规则示例
# 允许特定IP的工程站访问PLC
iptables -A FORWARD -i eth0 -o eth1 \
  -s 192.168.10.0/24 -d 192.168.100.0/24 \
  -p tcp --dport 102 -j ACCEPT  # Siemens S7

iptables -A FORWARD -i eth0 -o eth1 \
  -s 192.168.10.0/24 -d 192.168.100.0/24 \
  -p tcp --dport 502 -j ACCEPT  # Modbus

# 默认拒绝所有
iptables -A FORWARD -i eth0 -o eth1 -j DROP

# 使用Tofino (Hirschmann) 工业防火墙
# Tofino规则示例
# 规则1: 允许工程站->PLC (S7协议)
# 源: 10.10.1.0/24
# 目标: 10.10.2.100
# 协议: S7 (TCP 102)
# 操作: 允许
# 动作: 告警
# 
# 规则2: 允许HMI->PLC (读操作)
# 源: 10.10.2.0/24
# 协议: Modbus 功能码01,02,03,04
# 操作: 允许
# 
# 规则3: 禁止HMI->PLC (写操作)
# 源: 10.10.2.0/24
# 协议: Modbus 功能码05,06,15,16
# 操作: 拒绝
```

### 3. IEC 62443安全区与管道

```yaml
# 安全区 (Security Zone) 定义
安全区 1: "S1-控制区"
  描述: 关键生产线PLC和HMI
  安全等级: SL 3
  元素:
    - PLC_PRODUCT_LINE_1
    - PLC_PRODUCT_LINE_2
    - HMI_LINE_1
    - HMI_LINE_2

安全区 2: "S2-工程区"
  描述: 工程师站和配置工具
  安全等级: SL 2
  元素:
    - ENG_WORKSTATION_1
    - ENG_WORKSTATION_2
    - GIT_SERVER (PLC程序版本)

安全区 3: "DMZ区"
  描述: 补丁服务器和历史数据库
  安全等级: SL 1
  元素:
    - PATCH_SERVER
    - HISTORIAN_SERVER

# 管道 (Conduit) 定义
Conduit 1: "C1-工程访问"
  源区: S2-工程区
  目标区: S1-控制区
  协议白名单:
    - S7 (TCP 102)
    - Modbus (TCP 502)
  安全要求:
    - 源IP白名单
    - 深度包检测(DPI)
    - 会话日志

Conduit 2: "C2-数据采集"
  源区: S1-控制区
  目标区: S3-DMZ
  协议白名单:
    - OPC UA (TCP 4840)
    - MQTT (TCP 8883)
  安全要求:
    - 单向数据流 (Read Only)
    - TLS加密
```

### 4. 工业协议深度包检测

```bash
# 基于iptables的Modbus深度包检测
# 仅允许Modbus功能码01-04 (读操作)
iptables -A FORWARD -p tcp --dport 502 \
  -m u32 --u32 "0>>22&0x3C@8=0x1" -j ACCEPT  # 功能码01
iptables -A FORWARD -p tcp --dport 502 \
  -m u32 --u32 "0>>22&0x3C@8=0x2" -j ACCEPT  # 功能码02
iptables -A FORWARD -p tcp --dport 502 \
  -m u32 --u32 "0>>22&0x3C@8=0x3" -j ACCEPT  # 功能码03
iptables -A FORWARD -p tcp --dport 502 \
  -m u32 --u32 "0>>22&0x3C@8=0x4" -j ACCEPT  # 功能码04
iptables -A FORWARD -p tcp --dport 502 -j DROP  # 拒绝写操作

# 使用Snort/Suricata规则检测Modbus攻击
alert tcp any any -> $OT_NET 502 (
  msg:"Modbus尝试写入操作";
  content:"|00 00 00 00 00 05 01 05|";
  classtype:attempted-recon;
  sid:1000001;
)
```

### 5. OT网络分段成熟度评估

| 等级 | 描述 | 特征 | 安全级别 |
|:---:|:---|:---|:---:|
| 0 | 无分段 | PLC直接连公司网 | ❌ 极其危险 |
| 1 | 基本防火墙 | IT/OT间有防火墙，控制层无分段 | ⚠️ 基本 |
| 2 | 基于Purdue的分段 | 每层之间有防火墙 | ✅ 推荐 |
| 3 | 应用层控制 | 工业协议DPI + 功能码过滤 | ✅ 增强 |
| 4 | 零信任分段 | 所有PLC间通信也受控 | 🏆 最佳 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Tofino Xenon Security | 工业防火墙 | https://www.hirschmann.com/ |
| Claroty | OT网络分段 | https://claroty.com/ |
| Nozomi Guardian | OT网络可视化 | https://www.nozominetworks.com/ |
| pfSense | 开源防火墙 | https://www.pfsense.org/ |
| Snort/Suricata | 工控IDS | https://suricata.io/ |
| nProbe | OT网络流量分析 | https://www.ntop.org/ |

## 参考资源
- [IEC 62443-3-2 — Security Levels for Zones and Conduits](https://www.iec.ch/)
- [NIST SP 800-82 Rev.3 — Guide to ICS Security](https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final)
- [SANS — ICS Network Segmentation](https://www.sans.org/white-papers/ics-network-segmentation/)
- [CISA — OT Network Segmentation Guide](https://www.cisa.gov/ot-security)
