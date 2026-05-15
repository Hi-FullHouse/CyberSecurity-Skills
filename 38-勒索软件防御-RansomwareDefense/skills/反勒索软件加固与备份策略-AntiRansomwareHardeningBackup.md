---
id: "38-003"
title: "反勒索软件加固与备份策略 (Anti-Ransomware Hardening & Backup Strategy)"
category: "勒索软件防御"
category_en: "Ransomware Defense"
difficulty: "★★★★"
tools: "Veeam, Azure Backup, AWS Backup, Rubrik, Cohesity"
last_updated: "2026-05"
tags: [ransomware, hardening, backup, disaster-recovery, immutable-backup]
subdomain: ransomware-defense
nist_csf: [PR.DS-04, PR.DS-10, PR.IP-04, DE.CM-01]
mitre_attack: [T1486, T1490]
---

# 反勒索软件加固与备份策略 (Anti-Ransomware Hardening & Backup Strategy)

## 概述

勒索软件防御的核心在于"防得住、备得稳、恢复得快"。主动加固减少攻击面，智能备份确保可恢复。本技能覆盖反勒索软件系统加固、3-2-1备份策略、不可变备份架构、以及备份恢复演练自动化。

## 核心技能

### 1. 反勒索软件加固

```python
"""反勒索软件加固引擎"""

class AntiRansomwareHardening:
    """反勒索软件加固配置"""
    
    HARDENING_CHECKS = {
        "windows": [
            {
                "category": "攻击面减少",
                "checks": [
                    ("禁用 PowerShell v2", "DWORD", r"HKLM\...\PowerShellV2", 0),
                    ("启用 ASR 规则", "GUID", "ASR Rules", "全部启用"),
                    ("启用 Controlled Folder Access", "DWORD", "EnableControlledFolderAccess", 1),
                    ("禁用 LLMNR/mDNS", "DWORD", r"HKLM\...\EnableMulticast", 0),
                    ("禁用 WPAD", "DWORD", r"HKLM\...\Wpad", 0),
                ]
            },
            {
                "category": "权限控制",
                "checks": [
                    ("限制本地管理员权限", "策略", "仅限需要的人员", ""),
                    ("启用 LAPS 本地管理员密码管理", "策略", "LAPS 部署", ""),
                    ("禁用 SeDebugPrivilege 给普通用户", "策略", "用户权限分配", ""),
                    ("启用 UAC 级别 5", "DWORD", "EnableLUA", 1),
                ]
            },
            {
                "category": "网络防护",
                "checks": [
                    ("禁用 SMBv1", "DWORD", r"HKLM\...\SMB1", 0),
                    ("启用 SMB 签名", "DWORD", r"HKLM\...\SMBSigning", 1),
                    ("限制 RDP 源 IP", "防火墙", "仅允许 VPN 网段", ""),
                    ("启用 Windows 防火墙日志", "策略", "审核日志记录", ""),
                    ("禁用 NTLMv1", "DWORD", "LMCompatibilityLevel", 5),
                ]
            },
            {
                "category": "检测与防护",
                "checks": [
                    ("部署 EDR 到所有端点", "工具", "CrowdStrike/Defender", ""),
                    ("启用 Sysmon 日志", "工具", "Sysmon 配置", ""),
                    ("启用 PowerShell 脚本块日志", "DWORD", "EnableScriptBlockLogging", 1),
                    ("启用 Windows 事件日志转发", "策略", "WEF 订阅", ""),
                ]
            }
        ],
        "linux": [
            {
                "category": "SSH 安全",
                "checks": [
                    ("禁用密码认证", "sshd_config", "PasswordAuthentication no", ""),
                    ("禁用 Root 登录", "sshd_config", "PermitRootLogin no", ""),
                    ("限制 SSH 源 IP", "hosts.allow", "sshd: 10.0.0.0/8", ""),
                ]
            },
            {
                "category": "文件系统防护",
                "checks": [
                    ("配置不可变属性", "chattr", "关键文件 +i 属性", ""),
                    ("启用 SELinux/AppArmor", "强制模式", " enforcing", ""),
                    ("启用审计守护进程", "auditd", "关键文件监控", ""),
                ]
            }
        ]
    }
    
    @staticmethod
    def generate_hardening_report(platform, config_status):
        """生成加固报告"""
        results = []
        passed = 0
        total = 0
        
        for category in AntiRansomwareHardening.HARDENING_CHECKS.get(platform, []):
            for check in category["checks"]:
                total += 1
                name, _, config, expected = check
                actual = config_status.get(name, "missing")
                
                if actual == expected:
                    passed += 1
                    status = "passed"
                else:
                    status = "failed"
                
                results.append({
                    "name": name,
                    "category": category["category"],
                    "status": status,
                    "actual": actual,
                    "expected": expected
                })
        
        return {
            "platform": platform,
            "passed": passed,
            "total": total,
            "compliance": round(passed / total * 100, 2) if total else 0,
            "details": results
        }


# 使用示例
harden = AntiRansomwareHardening()
report = harden.generate_hardening_report("windows", {
    "禁用 PowerShell v2": 0,
    "启用 ASR 规则": "全部启用",
    "启用 Controlled Folder Access": 1,
})
print(f"Hardening compliance: {report['compliance']}% ({report['passed']}/{report['total']})")
```

```bash
# Windows 反勒索软件加固命令

# 1. 启用 Controlled Folder Access (CFA)
# 保护关键目录不被勒索软件加密
Set-MpPreference -EnableControlledFolderAccess Enabled
Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\Data"
Add-MpPreference -ControlledFolderAccessProtectedFolders "D:\SharedDocs"

# 2. 配置 ASR 规则 — 关键反勒索规则
$asr_rules = @{
    "c1db55ab-c21a-4637-b3ea-a6c10f4f6e3b" = "Block ransomware behavior"
    "e6db77e5-3df2-4bcf-b52a-9b4d3b6b5c6a" = "Block untrusted executable from USB"
    "b2b3f03d-6a4c-4b7e-8c9d-0a1b2c3d4e5f" = "Block credential stealing from LSASS"
}

foreach ($guid in $asr_rules.Keys) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $guid `
                     -AttackSurfaceReductionRules_Actions Enabled
}

# 3. 禁用 SMBv1 (主要攻击入口)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
sc.exe config mrxsmb10 start= disabled

# 4. LAPS 部署 (防止本地管理员横向扩散)
# 扩展 AD Schema
Import-Module AdmPwd.ps
Update-AdmPwdADSchema
Set-AdmPwdComputerSelfPermission -OrgUnit "OU=Workstations,DC=domain,DC=com"

# 5. 关键文件防篡改 (Linux)
# 使用 chattr +i 保护备份脚本和配置
sudo chattr +i /etc/rsyslog.conf
sudo chattr +i /etc/cron.d/backup
sudo chattr +i /root/.ssh/authorized_keys
```

### 2. 3-2-1 备份策略

```python
"""3-2-1 备份策略引擎"""

class BackupStrategy:
    """3-2-1 备份策略管理"""
    
    # 3-2-1 原则: 3份副本, 2种介质, 1份异地
    
    BACKUP_TIERS = {
        "tier1_local": {
            "name": "本地快速恢复",
            "storage": "本地磁盘 / NAS / SAN",
            "retention_days": 7,
            "rpo_hours": 4,      # 恢复点目标
            "rto_hours": 2,      # 恢复时间目标
            "frequency": "每4小时"
        },
        "tier2_offsite": {
            "name": "异地备份",
            "storage": "云端 / 异地数据中心",
            "retention_days": 30,
            "rpo_hours": 24,
            "rto_hours": 8,
            "frequency": "每天"
        },
        "tier3_archive": {
            "name": "长期归档",
            "storage": "不可变存储 / 磁带 / 冷存储",
            "retention_days": 365,
            "rpo_hours": 168,    # 1周
            "rto_hours": 48,
            "frequency": "每周"
        }
    }
    
    def __init__(self):
        self.policies = {}
    
    def add_policy(self, name, data_type, criticality, **params):
        """添加备份策略"""
        policy = {
            "name": name,
            "data_type": data_type,
            "criticality": criticality,
            "schedule": params.get("schedule", "0 */4 * * *"),
            "retention": {
                "daily": params.get("daily_retention", 7),
                "weekly": params.get("weekly_retention", 4),
                "monthly": params.get("monthly_retention", 12),
                "yearly": params.get("yearly_retention", 3)
            },
            "immutable": params.get("immutable", True),
            "encryption": params.get("encryption", "AES-256"),
            "targets": params.get("targets", ["local", "cloud"])
        }
        
        # 按关键性推荐策略
        if criticality == "critical":
            policy["rpo_minutes"] = 15  # 15分钟 RPO
            policy["targets"] = ["local", "cloud", "tape"]
        elif criticality == "high":
            policy["rpo_minutes"] = 60
            policy["targets"] = ["local", "cloud"]
        else:
            policy["rpo_minutes"] = 1440  # 24小时
            
        self.policies[name] = policy
        return policy
    
    def validate_321_compliance(self):
        """验证 3-2-1 合规性"""
        results = []
        
        for name, policy in self.policies.items():
            copies = len(policy["targets"]) + 1  # +1 生产数据
            media_types = len(set(policy["targets"]))
            has_offsite = "cloud" in policy["targets"] or "tape" in policy["targets"]
            
            compliant = (
                copies >= 3 and
                media_types >= 2 and
                has_offsite and
                policy["immutable"]
            )
            
            results.append({
                "policy": name,
                "copies": copies,
                "media_types": media_types,
                "offsite": has_offsite,
                "immutable": policy["immutable"],
                "compliant": compliant,
                "gaps": [] if compliant else [
                    "需增加副本数" if copies < 3 else "",
                    "需增加存储介质类型" if media_types < 2 else "",
                    "需配置异地存储" if not has_offsite else "",
                    "需启用不可变存储" if not policy["immutable"] else ""
                ]
            })
        
        return results


# 使用示例
bkp = BackupStrategy()
bkp.add_policy("SQL 数据库", "database", "critical",
               immutable=True, targets=["local", "cloud", "tape"])
bkp.add_policy("文件服务器", "file", "high",
               immutable=True, targets=["local", "cloud"])
compliance = bkp.validate_321_compliance()
for r in compliance:
    print(f"{r['policy']}: {'✓ Compliant' if r['compliant'] else '✗ Non-compliant'}")
```

### 3. 不可变备份架构

```bash
# 不可变备份 — 防止勒索软件加密/删除备份

# 1. AWS S3 Object Lock (不可变存储)
aws s3api put-object-lock-configuration \
  --bucket ransomware-backup \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Days": 14
      }
    }
  }'

# 备份上传时启用锁定
aws s3 cp /backup/sql-full.bak s3://ransomware-backup/daily/ \
  --object-lock-mode COMPLIANCE \
  --object-lock-retain-until-date 2026-06-01

# 2. Azure Blob Immutable Storage
az storage container immutability-policy create \
  --account-name ransombackup \
  --container-name backups \
  --period 30 \
  --locked

# 3. Linux 不可变文件系统 (chattr + NFS)
# 在备份服务器上创建不可变挂载
mkdir -p /backup/immutable
chmod 700 /backup/immutable

# 使用 rsnapshot 创建只读快照
cat > /etc/rsnapshot.conf << 'EOF'
config_version  1.2
snapshot_root   /backup/immutable/
cmd_cp          /bin/cp
cmd_rm          /bin/rm
cmd_rsync       /usr/bin/rsync
retain          daily   7
retain          weekly  4
retain          monthly 6

backup          /data/           localhost/
backup          /etc/            localhost/
backup_script   /usr/bin/mysqldump -u root --all-databases > /backup/sqldump.sql  localhost/
EOF

# 对备份目录设置不可变属性
chattr -R +i /backup/immutable/daily.0/
# 注意: 每次备份完成后重新添加到新目录

# 4. Veeam Hardened Repository (Linux 不可变存储)
# Veeam Linux 加固仓库使用 XFS + immutability
# 在 Linux 备份代理上:
mkfs.xfs /dev/sdb1
mount -o noatime,nodiratime /dev/sdb1 /backup/repo

# Veeam 配置不可变备份
Set-VBRBackupRepository -Repository $repo -MakeImmutable $true
Set-VBRJob -Job $job -EnableImmutability $true -ImmutabilityPeriod 14

# 5. 离线/气隙备份 (Air-Gap)
# 定期同步到离线磁盘
# 备份完成后物理断开连接
# 使用可移动介质定期轮换
```

```python
"""备份恢复演练"""

class BackupDrillPlanner:
    """备份恢复演练计划"""
    
    DRILL_TYPES = {
        "tabletop": {
            "name": "桌面演练",
            "frequency": "每月",
            "duration_hours": 2,
            "description": "讨论恢复流程，不实际操作"
        },
        "partial": {
            "name": "部分恢复演练",
            "frequency": "每季度",
            "duration_hours": 4,
            "description": "恢复单个关键系统"
        },
        "full_dr": {
            "name": "全面灾难恢复",
            "frequency": "每年",
            "duration_hours": 24,
            "description": "完整恢复所有关键系统"
        }
    }
    
    @staticmethod
    def plan_drill(drill_type, systems):
        """规划演练"""
        config = BackupDrillPlanner.DRILL_TYPES.get(drill_type)
        if not config:
            return None
        
        steps = []
        
        if drill_type == "tabletop":
            steps = [
                "确认参与人员 (IT/安全/管理层)",
                "选择一个勒索软件场景",
                "逐步骤回顾恢复流程",
                "识别流程缺陷和改进点",
                "记录发现项"
            ]
        elif drill_type == "partial":
            steps = [
                "选择恢复目标系统",
                "通知利益相关方",
                "启动恢复流程",
                "从备份还原系统",
                "验证数据完整性 (校验和对比)",
                "测试系统功能",
                "记录恢复时间 (RTO 验证)",
                "回顾并改进"
            ]
        elif drill_type == "full_dr":
            steps = [
                "模拟勒索软件场景 (C2 通信 + 加密)",
                "触发检测和告警",
                "执行隔离和遏制",
                "从不可变备份还原",
                "验证 AD/DNS/DHCP 核心服务",
                "恢复关键业务应用",
                "验证数据一致性",
                "测试安全控制有效性",
                "生成恢复报告",
                "高层汇报"
            ]
        
        return {
            "type": config["name"],
            "duration": config["duration_hours"],
            "systems": systems,
            "steps": steps,
            "success_criteria": {
                "rto_met": f"RTO < {config['duration_hours']}h",
                "data_integrity": "100% 数据校验通过",
                "security": "所有安全措施生效"
            }
        }
    
    @staticmethod
    def evaluate_drill(logs):
        """评估演练结果"""
        total_steps = len(logs)
        completed = sum(1 for l in logs if l["status"] == "success")
        failed = sum(1 for l in logs if l["status"] == "failed")
        
        # 计算实际 RTO
        start_time = min(l["timestamp"] for l in logs)
        end_time = max(l["timestamp"] for l in logs)
        actual_rto = (end_time - start_time).total_seconds() / 3600
        
        return {
            "success_rate": round(completed / total_steps * 100, 1),
            "completed": completed,
            "failed": failed,
            "total": total_steps,
            "actual_rto_hours": round(actual_rto, 2),
            "verdict": "PASS" if completed == total_steps else "PARTIAL" if completed > 0 else "FAIL"
        }


# 使用示例
planner = BackupDrillPlanner()
drill = planner.plan_drill("partial", ["AD域控", "SQL数据库", "文件服务器"])
print(f"Drill: {drill['type']} — {len(drill['steps'])} steps")
```

### 4. 备份监控与告警

```bash
# 备份健康监控

# 1. Veeam 备份监控
# 检查最近24小时备份状态
Get-VBRBackupSession | Where-Object { 
    $_.CreationTime -gt (Get-Date).AddHours(-24) 
} | Select-Object Name, JobType, State, Result

# 发送备份失败告警到 SIEM
Get-VBRBackupSession | Where-Object { 
    $_.Result -eq "Failed" -and 
    $_.CreationTime -gt (Get-Date).AddHours(-24)
} | ForEach-Object {
    # 发送到 Splunk
    $event = @{
        sourcetype = "veeam_backup"
        event = @{
            job_name = $_.Name
            status = $_.Result
            time = $_.CreationTime.ToString("o")
        }
    }
    # Invoke-RestMethod -Uri $splunk_hec_url -Method Post -Body ($event | ConvertTo-Json)
}

# 2. 备份完整性检查 (每月)
# Veeam SureBackup — 自动验证备份可恢复
Start-VBRSureBackup -Job "SQL-DB-Backup" -ApplicationGroup "SQL-Servers"

# 3. Linux 备份验证
# 校验备份文件完整性
echo "Verify backup integrity..."
for f in /backup/*.tar.gz; do
    sha256sum -c "${f}.sha256"
    if [ $? -ne 0 ]; then
        echo "ALERT: Backup integrity check FAILED for $f" | \
          mail -s "BACKUP INTEGRITY FAILURE" security@company.com
    fi
done

# 4. 勒索软件扫描备份文件
# 挂载备份并扫描
mount -o loop /backup/full_backup.img /mnt/verify
clamscan -r /mnt/verify --log=/var/log/clamav/backup-scan.log

# 5. 备份容量监控
df -h /backup | awk 'NR==2 {print "Used: "$3" / "$2" ("$5")"}'
if [ $(df /backup | awk 'NR==2 {print $5}' | tr -d '%') -gt 85 ]; then
    echo "WARNING: Backup storage >85% full"
fi
```

```python
"""备份 SLA 监控仪表盘"""

class BackupSLAMonitor:
    """备份 SLA 监控"""
    
    def __init__(self):
        self.backup_jobs = []
    
    def add_job(self, name, rpo_minutes, rto_minutes):
        """添加备份作业"""
        from math import inf
        self.backup_jobs.append({
            "name": name,
            "rpo_minutes": rpo_minutes,
            "rto_minutes": rto_minutes,
            "history": []
        })
    
    def record_backup(self, job_name, success, duration_minutes, data_size_gb):
        """记录备份结果"""
        for job in self.backup_jobs:
            if job["name"] == job_name:
                from datetime import datetime
                job["history"].append({
                    "timestamp": datetime.now(),
                    "success": success,
                    "duration": duration_minutes,
                    "data_size_gb": data_size_gb
                })
    
    def sla_compliance(self):
        """计算 SLA 合规率"""
        results = []
        
        for job in self.backup_jobs:
            if not job["history"]:
                continue
            
            # RPO 合规检测
            last_backup = max(job["history"], key=lambda x: x["timestamp"])
            from datetime import timedelta
            hours_since = (
                last_backup["timestamp"] - 
                min(job["history"], key=lambda x: x["timestamp"])["timestamp"]
            ).total_seconds() / 60
            
            rpo_compliant = hours_since <= job["rpo_minutes"]
            rto_compliant = last_backup["duration"] <= job["rto_minutes"]
            success_rate = sum(1 for h in job["history"] if h["success"]) / len(job["history"]) * 100
            
            results.append({
                "job": job["name"],
                "success_rate": round(success_rate, 1),
                "rpo_compliant": rpo_compliant,
                "rto_compliant": rto_compliant,
                "last_backup": last_backup["timestamp"].isoformat(),
                "overall_compliant": rpo_compliant and rto_compliant and success_rate >= 99.0
            })
        
        return results


# 使用示例
sla = BackupSLAMonitor()
sla.add_job("SQL DB", rpo_minutes=60, rto_minutes=30)
sla.add_job("File Server", rpo_minutes=240, rto_minutes=120)
print("SLA compliance configured")
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Veeam Backup | 企业备份与恢复 | https://www.veeam.com/ |
| Rubrik | 云数据管理 | https://www.rubrik.com/ |
| AWS Backup | AWS 备份服务 | https://aws.amazon.com/backup/ |
| Azure Backup | Azure 备份服务 | https://azure.microsoft.com/en-us/products/backup/ |
| rsnapshot | Linux 快照备份 | https://rsnapshot.org/ |

## 参考资源

- [CISA Ransomware Protection Best Practices](https://www.cisa.gov/ransomware)
- [NIST SP 800-209 — Ransomware Prevention](https://csrc.nist.gov/publications/detail/sp/800-209/final)
- [3-2-1 Backup Strategy — Veeam](https://www.veeam.com/blog/backup-strategy.html)
- [Immutable Backup Best Practices](https://www.rubrik.com/resources/immutable-backup)
- [Microsoft Ransomware Protection](https://learn.microsoft.com/en-us/security/ransomware/)
