# 🤖 SOAR自动化响应 (SOAR Automation)

## 概述
SOAR（Security Orchestration, Automation and Response）通过编排安全工具、标准化响应流程和自动化重复性任务，显著缩短事件响应时间。参照 **Splunk SOAR**、**Palo Alto Cortex XSOAR** 和 **开源Shuffle** 最佳实践。

## 核心技能

### 1. SOAR架构

```text
┌──────────────────────────────────────────────────┐
│                  SOAR平台                          │
│  ┌─────────┐  ┌─────────┐  ┌──────────────────┐ │
│  │ 编排     │  │ 自动化   │  │ 响应执行          │ │
│  │ (Orch)   │  │ (Auto)  │  │ (Response)       │ │
│  ├─────────┤  ├─────────┤  ├──────────────────┤ │
│  │ · Play- │  │ · 自动  │  │ · 隔离端点        │ │
│  │ book编排 │  │  封堵   │  │ · 禁用账户        │ │
│  │ · 跨    │  │ · 自动  │  │ · 阻止IP          │ │
│  │  工具链  │  │  分析   │  │ · 通知上报        │ │
│  │ · 状态  │  │ · 自动  │  │ · 工单更新        │ │
│  │  管理   │  │  分类   │  │                  │ │
│  └─────────┘  └─────────┘  └──────────────────┘ │
│                                                   │
│  ┌──────────────────────────────────────────────┐ │
│  │      案例管理 (Case Management)              │ │
│  │  · Triage · 调查 · 协作 · 报告              │ │
│  └──────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────┘
                       │
     ┌─────────────────┼─────────────────┐
     ▼                 ▼                 ▼
┌─────────┐     ┌─────────┐       ┌─────────┐
│ SIEM     │     │ EDR/AV  │       │ 工单    │
│ Splunk   │     │ CS/Def  │       │ Jira/SN  │
│ ELK      │     │ Sentinel│       │ ServiceNow│
└─────────┘     └─────────┘       └─────────┘
```

### 2. 通用响应剧本 (Playbook) 模板

```yaml
# 通用Playbook: 失陷主机自动化响应
name: "Compromised Host Response"
trigger:
  - source: "EDR"
    rule: "Malware Detection"
  - source: "SIEM"
    rule: "Ransomware Alert"
    
steps:
  # Step 1: 自动分类和定级
  triage:
    - action: enrich_entity
      target: "endpoint"
      sources: ["CMDB", "AD", "Vulnerability DB"]
    
  # Step 2: 遏制 — 网络隔离
  containment_network:
    - action: edr_isolate
      target: "endpoint"
      platform: "crowdstrike|defender|sentinelone"
  
  # Step 3: 遏制 — 禁用账户
  containment_account:
    - action: disable_account
      target: "user"
      platform: "active_directory|azure_ad"
  
  # Step 4: 取证
  forensics:
    - action: collect_artifacts
      files: ["memory.dmp", "prefetch/*.pf", "evtx/*.evtx", "usnjournal"]
    - action: upload_to_s3
  
  # Step 5: 通知
  notification:
    - action: send_slack
      channel: "#incident-response"
    - action: create_ticket
      system: "service-now"
      priority: "P1"
```

### 3. Splunk SOAR (Phantom) Playbook

```python
# Splunk SOAR Playbook 示例 — 自动化恶意IP封堵
import phantom.rules as phantom

def on_start(container):
    # 1. 获取事件中的IP
    ip_address = phantom.get_severity(container)
    artifact = phantom.get_artifacts(container=container)
    malicious_ip = artifact[0]['cef']['sourceAddress']
    
    # 2. 威胁情报查询
    vt_result = phantom.act('lookup ip', parameters=[{'ip': malicious_ip}])
    
    # 3. 如果确认恶意，自动封堵
    if vt_result[0]['summary']['malicious'] > 0:
        # 在防火墙封堵
        phantom.act('block ip', parameters=[{
            'ip': malicious_ip,
            'device_group': 'Production Firewalls'
        }])
        
        # 创建告警
        phantom.act('send alert', parameters=[{
            'message': f'Blocked malicious IP: {malicious_ip}'
        }])
    
    return

def on_finish(container, summary):
    phantom.update_container(container, status='closed')
    return
```

### 4. Shuffle (开源SOAR) Workflow

```yaml
# Shuffle Workflow (OpenAPI格式)
name: Phishing Response
start:
  - Webhook Trigger: true
    trigger:
      type: webhook
      method: POST
      path: /phishing-email

actions:
  - Extract_IoCs:
    - type: python
      script: |
        import re
        body = get_input("body")
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', body)
        urls = re.findall(r'https?://[^\s]+', body)
        return {"ips": ips, "urls": urls}
  
  - VirusTotal_Check:
    - type: http
      method: GET
      url: "https://www.virustotal.com/api/v3/urls/{{base64(actions.Extract_IoCs.urls[0])}}"
      headers:
        x-apikey: "${VT_API_KEY}"
  
  - Block_Network:
    - type: http
      method: POST
      url: "https://api.crowdstrike.com/indicators/entities/iocs/v1"
      body:
        action: "prevent"
        value: "{{actions.Extract_IoCs.ips[0]}}"
  
  - Notify:
    - type: slack
      message: |
        🚨 钓鱼邮件告警
        IP: {{actions.Extract_IoCs.ips}}
        URL: {{actions.Extract_IoCs.urls}}
        状态: 已自动封堵
```

### 5. 常用自动化场景

#### 自动IoC封堵
```python
def auto_block_threat_indicator(ioc_type, ioc_value, platform):
    """统一IoC封堵接口"""
    
    block_actions = {
        "crowdstrike": {
            "method": "POST",
            "url": "https://api.crowdstrike.com/indicators/entities/iocs/v1",
            "payload": {
                "action": "prevent",
                "type": ioc_type,  # ipv4, domain, sha256
                "value": ioc_value,
                "applied_globally": True
            }
        },
        "palo_alto": {
            "method": "POST",
            "url": f"https://{firewall}/api/?type=config&action=set",
            "payload": {
                "xpath": f"/config/devices/entry/vsys/entry/rulebase/security/rules/entry[@name='Auto-Block']/destination",
                "element": f"<member>{ioc_value}</member>"
            }
        },
        "waf": {
            "method": "PATCH",
            "url": f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules",
            "payload": {
                "action": "block",
                "expression": f"(ip.src eq {ioc_value})"
            }
        }
    }
    
    action = block_actions.get(platform)
    if action:
        return requests.request(**action)
```

#### 自动取证采集
```python
import boto3
import subprocess

def auto_collect_forensics(endpoint_ip):
    """自动采集失陷主机取证数据"""
    
    artifacts = {
        "memory": {
            "windows": "winpmem.exe dump.raw",
            "linux": "dd if=/dev/mem of=mem.raw"
        },
        "logs": {
            "windows": "wevtutil epl Security sec.evtx",
            "windows_system": "wevtutil epl System sys.evtx"
        },
        "prefetch": "copy C:\\Windows\\Prefetch\\*.pf prefetch/"
    }
    
    # 通过预先部署的agent或SSH执行采集
    for artifact_type, command in artifacts.items():
        result = remote_execute(endpoint_ip, command)
        upload_to_s3(result, f"forensics/{endpoint_ip}/{artifact_type}/")
    
    return {"status": "collected", "artifacts": list(artifacts.keys())}
```

### 6. 事件自动分类引擎

```python
class AutoTriageEngine:
    """自动事件分类引擎"""
    
    def __init__(self):
        self.severity_rules = {
            "ransomware": 1,
            "data_breach": 1,
            "c2_communication": 2,
            "malware_detection": 2,
            "brute_force": 3,
            "scanning": 4
        }
    
    def classify(self, alert):
        score = 0
        
        # 1. 基于事件类型
        event_type = alert.get('type', 'unknown')
        score += self.severity_rules.get(event_type, 5)
        
        # 2. 基于影响范围
        affected_hosts = alert.get('hosts', [])
        score += min(len(affected_hosts), 10)
        
        # 3. 基于数据敏感性
        data_level = alert.get('data_sensitivity', 'low')
        sensitivity_map = {'high': 10, 'medium': 5, 'low': 1}
        score += sensitivity_map.get(data_level, 1)
        
        # 4. 基于攻击者活跃状态
        if alert.get('active', False):
            score += 10
        
        # 定级
        if score >= 20:
            return "P1 - Critical"
        elif score >= 15:
            return "P2 - High"
        elif score >= 10:
            return "P3 - Medium"
        else:
            return "P4 - Low"
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Splunk SOAR (Phantom) | 商业SOAR平台 | https://www.splunk.com/soar |
| Palo Alto Cortex XSOAR | SOAR+案例管理 | https://www.paloaltonetworks.com/cortex/xsoar |
| Shuffle | 开源SOAR | https://shuffler.io/ |
| Wazuh | 开源HIDS+SIEM | https://wazuh.com/ |
| TheHive+Cortex | 开源IR平台+分析引擎 | https://thehive-project.org/ |
| Tines | 低代码SOAR | https://www.tines.com/ |
| Swimlane | 低代码SOAR | https://swimlane.com/ |
| N8N | 通用自动化（可做SOAR） | https://n8n.io/ |

## 参考资源

- [SANS — Automating Incident Response](https://www.sans.org/white-papers/automating-incident-response/)
- [ISACA — SOAR: 安全自动化最佳实践](https://www.isaca.org/)
- [CISA — 自动化响应指南](https://www.cisa.gov/)
- [Shuffle Workflow Examples](https://github.com/Shuffle/shuffle-workflows)
- [Awesome SOAR](https://github.com/cyberhive/awesome-soar)
