---
id: 24-002
title: "🔵 蓝队防御与检测 (Blue Team Defense & Detection)"
category: 红蓝对抗
category_en: "Red/Blue Team"
difficulty: ★★★★
tools: "Splunk, Wazuh, Elastic Security, Sentinel, Sigma Rules"
last_updated: 2025-07
tags: ["red-team", "blue-team", "purple-team", "bas", "adversary-simulation"]
subdomain: red-blue-team
nist_csf: ["DE.AE-02", "RS.AN-01", "ID.RM-01"]
mitre_attack: ["T1595", "T1562"]
---
# 🔵 蓝队防御与检测 (Blue Team Defense & Detection)

## 概述

蓝队负责检测、分析和响应安全威胁。基于 **NIST SP 800-61** 和 **MITRE ATT&CK** 框架，构建从日志收集到告警响应的完整检测防御体系，覆盖SIEM规则编写、威胁狩猎、EDR配置和SOC运营。

## 核心技能

### 1. SIEM检测规则编写

```python
# Sigma 规则格式 - 通用检测规则标准
# Sigma规则文件: sysmon_susp_powershell_download.yml
title: Suspicious PowerShell Download
id: 5f4b8c9d-1a2b-3c4d-5e6f-7a8b9c0d1e2f
status: experimental
description: 检测PowerShell远程下载行为
author: Blue Team
date: 2025/07/01
tags:
    - attack.t1059.001
    - attack.command_and_control
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: 
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - 'Net.WebClient'
            - 'DownloadString'
            - 'DownloadFile'
            - 'Invoke-WebRequest'
            - 'wget'
            - 'curl'
            - 'Start-BitsTransfer'
    filter_known:
        CommandLine|contains:
            - 'Update-Help'
            - 'Register-PackageSource'
    condition: selection and not filter_known
falsepositives:
    - 合法的PowerShell脚本下载更新
level: high

# 将Sigma规则转换为Splunk搜索
# sigmac -t splunk sigma_rules/sysmon_susp_powershell_download.yml
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe") 
(CommandLine="*Net.WebClient*" OR CommandLine="*DownloadString*" 
 OR CommandLine="*DownloadFile*" OR CommandLine="*Invoke-WebRequest*"
 OR CommandLine="*wget*" OR CommandLine="*curl*" OR CommandLine="*Start-BitsTransfer*")
NOT (CommandLine="*Update-Help*" OR CommandLine="*Register-PackageSource*")
```

### 2. EDR配置与告警规则

```yaml
# Wazuh EDR 自定义告警规则
<group name="windows,sysmon,attack">
  # 检测Mimikatz使用
  <rule id="100001" level="12">
    <if_sid>92001</if_sid>
    <field name="win.eventdata.originalFileName">mimikatz.exe</field>
    <description>Mimikatz Detected - Credential Theft Indicator</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
    <options>no_full_log</options>
    <group>credential_access,t1003,</group>
  </rule>

  # 检测Pass-the-Hash
  <rule id="100002" level="10">
    <if_sid>92001</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)sekurlsa::logonpasswords</field>
    <description>Pass-the-Hash Attempt via Mimikatz</description>
    <mitre>
      <id>T1550.002</id>
    </mitre>
    <group>lateral_movement,t1550,</group>
  </rule>

  # 检测0元注册表持久化
  <rule id="100003" level="8">
    <if_sid>92001</if_sid>
    <field name="win.system.eventID">^13$</field>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)CurrentVersion\\Run</field>
    <description>Registry Run Key Persistence</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
    <group>persistence,t1547,</group>
  </rule>
</group>

# Elastic Security 检测规则 (KQL)
PUT _detection_engine/rules
{
  "description": "检测通过WMI远程执行命令",
  "enabled": true,
  "false_positives": ["IT管理员合法WMI操作"],
  "filters": [
    { "query": { "match_phrase": { "event.code": "4688" } } },
    { "query": { "wildcard": { "process.parent.name": "wmiprvse.exe" } } }
  ],
  "index": ["windows-logs-*"],
  "interval": "5m",
  "name": "WMI Lateral Movement Detection",
  "risk_score": 73,
  "rule_id": "WMI-001",
  "severity": "high",
  "tags": ["T1047", "Lateral Movement"],
  "type": "query",
  "query": "event.code:4688 AND process.parent.name:wmiprvse.exe AND process.name:(cmd.exe OR powershell.exe)"
}
```

### 3. 威胁狩猎流程

```python
#!/usr/bin/env python3
# 威胁狩猎 - 主动搜索潜在威胁

class ThreatHunter:
    def __init__(self, siem_connector):
        self.siem = siem_connector
    
    def hunt_unusual_rdp_traffic(self):
        """搜索异常的RDP连接"""
        query = """
        index=network sourcetype=netflow
        app=ms-rdp AND bytes_in > 10000000
        | stats count by src_ip, dst_ip, avg(bytes_in) as avg_bytes
        | where avg_bytes > 50000000
        | lookup geoip src_ip as src_ip
        | table src_ip, dst_ip, count, avg_bytes, City, Country
        | sort - avg_bytes
        """
        return self.siem.search(query)
    
    def hunt_late_night_access(self):
        """搜索深夜异常访问"""
        from datetime import datetime, timedelta
        yesterday = datetime.now() - timedelta(days=1)
        
        query = f"""
        index=auth sourcetype=windows_security EventCode=4624
        date_hour > 22 OR date_hour < 5
        NOT AccountName IN (known_service_accounts)
        | stats count by AccountName, WorkstationName, src_ip
        | where count > 10
        """
        return self.siem.search(query)
    
    def hunt_data_exfiltration(self):
        """搜索数据外泄迹象"""
        query = """
        index=proxy sourcetype=webproxy
        bytes_out > 50000000
        NOT url_domain IN (trusted_domains)
        | stats sum(bytes_out) by src_ip, url_domain, user
        | where sum(bytes_out) > 100000000
        | eval size_mb = round(sum(bytes_out)/1048576, 2)
        | table src_ip, user, url_domain, size_mb
        | sort - size_mb
        """
        return self.siem.search(query)
    
    def hunt_ioc_based(self, iocs):
        """基于IOC的威胁搜索"""
        results = {}
        for ioc in iocs:
            # 文件哈希搜索
            query = f'index=edr (file_hash:"{ioc["hash"]}")'
            results[ioc["name"]] = self.siem.search(query)
        return results

# 使用示例 (假设有SIEM连接器)
# hunter = ThreatHunter(splunk_connector)
# rdp_anomalies = hunter.hunt_unusual_rdp_traffic()
```

### 4. SOC运营指标

```python
# SOC KPI度量模型
soc_kpis = {
    "detection_metrics": {
        "mttd": "Mean Time to Detect (平均检测时间)",
        "mttr": "Mean Time to Respond (平均响应时间)",
        "alert_coverage": "告警规则覆盖率 (已覆盖/总ATT&CK技术)",
        "false_positive_rate": "误报率 (误报/总告警)",
        "detection_rate": "检出率 (已检测/总真实攻击)"
    },
    "triage_metrics": {
        "tier1_time": "初级分析师处理时间 (<15min)",
        "tier2_escalation_time": "升级时间 (<30min)",
        "tier3_investigation_time": "深度调查时间 (<4h)"
    },
    "improvement_metrics": {
        "rule_tuning": "规则优化频率 (周)",
        "use_case_backlog": "待办用例数量",
        "incident_to_rule": "事件转为检测规则的时间"
    }
}

class SOCDashboard:
    def __init__(self):
        self.metrics = {}
    
    def calculate_soc_maturity_score(self):
        """计算SOC成熟度分数"""
        scores = {
            "level_1": {"score": 1, "name": "初始级 - 基本日志收集"},
            "level_2": {"score": 2, "name": "已定义级 - 标准化流程"},
            "level_3": {"score": 3, "name": "管理级 - KPI驱动运营"},
            "level_4": {"score": 4, "name": "量化级 - 数据驱动决策"},
            "level_5": {"score": 5, "name": "优化级 - 持续自动化改进"}
        }
        # 计算当前成熟度
        return {
            "current_level": "level_3",
            "score": 3,
            "next_steps": ["引入SOAR自动化", "建立ML异常检测", "扩展威胁情报集成"]
        }
```

### 5. 告警分级与响应流程

```markdown
# 告警分级响应标准

## 严重等级
| 等级 | 颜色 | 定义 | 响应时间 | 响应级别 |
|:---:|:---:|:---|:---:|:---:|
| P0 | 🔴 严重 | 核心业务系统被攻陷 | 15分钟 | 全员响应 |
| P1 | 🟠 高危 | 敏感数据泄露风险 | 30分钟 | 高级分析师 |
| P2 | 🟡 中危 | 可疑行为待确认 | 4小时 | 标准分析师 |
| P3 | 🔵 低危 | 信息性告警 | 24小时 | 批量处理 |

## 标准响应流程
```mermaid
1. 告警触发 → 2. Triage验证(5min) → 3. 分级评估 → 
4. 调查取证 → 5. 遏制清除 → 6. 复盘改进
```

## 红蓝对抗后改进闭环
1. **发现优化**: 红队发现的盲区 → 新增检测规则
2. **规则调优**: 误报率 > 30% → 规则优化
3. **工具增强**: 检测覆盖缺口 → 引入新工具/数据源
4. **人员提升**: 知识盲区 → 专项培训
5. **流程改进**: 响应瓶颈 → SOP更新
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Splunk ES | SIEM与安全分析 | https://www.splunk.com/ |
| Wazuh | 开源EDR/XDR | https://wazuh.com/ |
| Elastic Security | SIEM/威胁检测 | https://www.elastic.co/security |
| Sigma HQ | 通用检测规则格式 | https://github.com/SigmaHQ/sigma |
| TheHive | SOC协作平台 | https://thehive-project.org/ |

## 参考资源

- [NIST SP 800-61 Rev2 — Incident Response](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [MITRE ATT&CK Detection Engineering](https://attack.mitre.org/resources/detection-engineering/)
- [SOC-CMM — SOC Capability Maturity Model](https://www.soc-cmm.com/)
- [SANS Blue Team Training](https://www.sans.org/cyber-security-courses/blue-team-operations/)
- [CISA Cyber Defense Framework](https://www.cisa.gov/cyber-defense)
