---
id: 19-005
title: "🚨 工控安全应急预案 (ICS Incident Response)"
category: 工控安全
category_en: "ICS/OT Security"
difficulty: ★★★★★
tools: "Dragos Platform, Claroty, Nozomi, Wireshark, YARA"
last_updated: 2025-07
tags: ["ics-security", "ot-security", "scada", "plc", "iec-62443", "industrial-security"]
subdomain: ics-ot-security
nist_csf: ["PR.AC-01", "PR.DS-07", "PR.PT-01"]
mitre_attack: ["T0843", "T0839", "T0881", "T0855"]
---
# 🚨 工控安全应急预案 (ICS Incident Response)

## 概述
针对工业控制系统和OT环境的应急响应方法论，涵盖工控特有的安全事件检测、响应策略、系统恢复和工控取证分析。

## 核心技能

### 1. OT事件检测与识别

```text
OT安全事件检测指标 (IoCs)
┌──────────────────────────────────────────────────────────┐
│ 检测层     │ 具体指标                    │ 工具          │
├────────────┼─────────────────────────────┼──────────────┤
│ 网络层     │ 异常Modbus/DNP3功能码       │ Wireshark    │
│            │ 向PLC的未授权写入操作        │ Zeek         │
│            │ 异常协议流量模式              │ Nozomi       │
│ 主机层     │ 工程站上的恶意软件            │ AV + EDR    │
│            │ 异常进程/计划任务             │ Sysmon       │
│ 物理层     │ PLC LED异常闪烁              │ 人工巡检     │
│            │ HMI显示异常                 │ 人工巡检     │
│ PLC内部    │ Ladder Logic被篡改           │ 固件校验     │
│            │ 程序校验和不匹配              │ PLC诊断      │
│ 应用层     │ HMI/SCADA告警被静音          │ 日志审计     │
│            │ 历史数据缺失                  │ 数据库检查   │
└──────────────────────────────────────────────────────────┘
```

### 2. OT事件响应流程

```text
OT特定事件响应流程
┌──────────────────────────────────────────────────────┐
│ 1. 识别与分类 (5分钟)                                 │
│    ├─ 判断: OT事件 vs IT事件                          │
│    ├─ 影响范围: 单台PLC vs 整条产线                   │
│    └─ 安全影响: 生产安全 vs 数据安全                  │
├──────────────────────────────────────────────────────┤
│ 2. 遏制 (15分钟)                                     │
│    ├─ ⚠️ 先确认: 断开网络 vs 确保生产安全            │
│    ├─ 网络隔离: 切断受影响的OT网段                    │
│    ├─ ⚠️ 不要直接关闭PLC!!! (可能导致物理损坏)        │
│    └─ 切换到手动/旁路模式                             │
├──────────────────────────────────────────────────────┤
│ 3. 取证 (1-4小时)                                    │
│    ├─ 镜像PLC固件和配置                               │
│    ├─ 捕获网络流量(PCAP)                              │
│    ├─ 收集HMI/历史数据库日志                          │
│    └─ 记录PLC LED状态和物理指示                        │
├──────────────────────────────────────────────────────┤
│ 4. 根因分析 (4-24小时)                                │
│    ├─ 分析攻击入口点                                  │
│    ├─ 复现攻击路径                                    │
│    └─ 确定影响的资产                                  │
├──────────────────────────────────────────────────────┤
│ 5. 恢复 (按业务需求)                                  │
│    ├─ 从已验证备份恢复PLC程序                          │
│    ├─ 更新固件和补丁                                  │
│    ├─ 修改默认密码                                    │
│    └─ 逐步恢复生产                                    │
├──────────────────────────────────────────────────────┤
│ 6. 复盘与改进 (1周内)                                 │
│    ├─ 事件复盘报告                                    │
│    ├─ 改进安全控制                                    │
│    └─ 更新应急预案                                    │
└──────────────────────────────────────────────────────┘
```

### 3. OT事件取证分析

```bash
# PLC流量取证
# 捕获Modbus通信记录
tshark -r ics_incident.pcap -Y "modbus.func_code == 5 || modbus.func_code == 6 || modbus.func_code == 15 || modbus.func_code == 16" \
  -T fields -e ip.src -e ip.dst -e modbus.func_code -e modbus.reference_num -e modbus.data

# 分析S7通信
tshark -r ics_incident.pcap -Y "s7comm" \
  -T fields -e s7comm.param.func -e s7comm.param.item_count

# 检测异常连接尝试
tshark -r ics_incident.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport | grep -v "102\|502\|20000"

# PLC程序校验
# Siemens S7 - 比较PLC程序与备份
# Allen-Bradley - 使用RSLogix校验CRC

# YARA规则 - OT恶意软件检测
cat << 'YARA' > ot_malware.yar
rule OT_Malicious_Modbus {
    meta:
        description = "检测已知OT恶意软件签名"
    strings:
        $modbus_cmds = { 05 00 FF 00 06 00 01 00 0F 00 10 }
        $stuxnet_str = "Stuxnet" nocase
        $trisis_str = "TRISIS" nocase
        $industroyer = "Industroyer" nocase
    condition:
        any of them
}
YARA

yara -r ot_malware.yar /evidence/
```

### 4. OT-Specific攻击分析

```text
知名OT攻击事件响应参考
┌───────────────────────────────────────────────────────────────┐
│ 攻击名称      │ 目标          │ 响应要点                    │
├───────────────┼───────────────┼─────────────────────────────┤
│ Stuxnet (2010)│ 伊朗核离心机  │ 检查PLC逻辑+固件完整性     │
│ TRISIS (2017) │ Schneider    │ 隔离SIS系统，物理检查       │
│              │ Triconex SIS  │ 验证安全仪表系统未被篡改    │
│ Industroyer   │ 乌克兰电力网 │ 切断所有外部连接            │
│ (2016)       │              │ 手动切换变电站操作           │
│ Colonial Pipe │ 美国燃油管道 │ 关闭关键管道系统              │
│ (2021)       │              │ 启用离线备份系统              │
│ Pipedream     │ 多供应商PLC  │ 识别受影响设备型号            │
│ (2022)       │              │ 应用厂商安全公告              │
└───────────────────────────────────────────────────────────────┘
```

### 5. 应急预案核心检查清单

| # | 应急准备项 | 责任人 | 频次 |
|:---:|:---|:---:|:---:|
| 1 | OT资产清单(含网络拓扑)是否最新 | OT运维 | 每月 |
| 2 | PLC/HMI程序备份是否有效 | OT工程师 | 每周 |
| 3 | OT应急联系人名单是否更新 | 安全经理 | 每季 |
| 4 | OT安全演练是否执行 | 联合团队 | 每半年 |
| 5 | 物理旁路/手动操作是否可用 | 操作员 | 每次启动前 |
| 6 | OT监控系统是否覆盖所有网段 | 安全团队 | 部署时 |
| 7 | 是否有防爆区域的取证预案 | 安全+HSE | 年度 |
| 8 | 供应商应急联系方式是否有效 | 采购 | 年度 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Dragos Platform | OT威胁检测与响应 | https://www.dragos.com/ |
| Claroty | OT安全与资产可见性 | https://claroty.com/ |
| Nozomi Guardian | OT网络监控 | https://www.nozominetworks.com/ |
| Wireshark | OT协议取证 | https://www.wireshark.org/ |
| YARA | OT恶意软件检测 | https://virustotal.github.io/yara/ |
| CSET (CISA) | OT安全评估 | https://github.com/cisagov/cset |

## 参考资源
- [CISA — ICS Incident Response](https://www.cisa.gov/ics-incident-response)
- [NIST SP 800-61 Rev.2 — Incident Response](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS — ICS Incident Response Plan](https://www.sans.org/white-papers/ics-incident-response/)
- [Dragos — OT IR Playbook](https://www.dragos.com/incident-response/)
