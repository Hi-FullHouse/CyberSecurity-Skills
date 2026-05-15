---
id: "37-003"
title: "端点加固与合规基线 (Endpoint Hardening & Compliance Baseline)"
category: "端点安全"
category_en: "Endpoint Security"
difficulty: "★★★★"
tools: "CIS Benchmarks, Microsoft Baselines, OpenSCAP, InSpec, Ansible"
last_updated: "2026-05"
tags: [endpoint-hardening, compliance, cis-benchmarks, security-baseline, automation]
subdomain: endpoint-security
nist_csf: [PR.AC-01, PR.DS-07, PR.IP-01, PR.PT-01]
mitre_attack: [T1562, T1564]
---

# 端点加固与合规基线 (Endpoint Hardening & Compliance Baseline)

## 概述

端点加固是减少攻击面的基础安全措施。通过配置安全基线、关闭不必要的服务、强化系统配置，可以抵御大量常见攻击。本技能覆盖 CIS 基准检查、安全基线部署和合规自动化。

## 核心技能

### 1. CIS 基准与安全基线

```python
"""安全基线检查引擎"""

class SecurityBaselineChecker:
    """安全基线检查"""
    
    # Windows 安全基线检查项
    WINDOWS_BASELINE = {
        "账户策略": [
            ("密码最短长度: 14字符", "检查", "reg", r"HKLM\...\MinimumPasswordLength", 14),
            ("密码历史: 24个", "检查", "reg", r"HKLM\...\PasswordHistorySize", 24),
            ("账户锁定阈值: 5次", "检查", "reg", r"HKLM\...\LockoutBadCount", 5),
            ("账户锁定时长: 15分钟", "检查", "reg", r"HKLM\...\LockoutDuration", 15)
        ],
        "安全选项": [
            ("管理员账户重命名", "检查", "reg", r"HKLM\...\NewAdministratorName", ""),
            ("来宾账户禁用", "检查", "reg", r"HKLM\...\EnableGuestAccount", 0),
            ("UAC 启用: 级别5", "检查", "reg", r"HKLM\...\EnableLUA", 1),
            ("远程桌面 NLA 认证", "检查", "reg", r"HKLM\...\UserAuthentication", 1)
        ],
        "审计策略": [
            ("审计登录事件: 成功+失败", "检查", "auditpol", "Logon", "Success and Failure"),
            ("审计进程创建: 成功+失败", "检查", "auditpol", "Process Creation", "Success and Failure"),
            ("审计账号管理: 成功+失败", "检查", "auditpol", "Account Management", "Success and Failure")
        ],
        "Windows Defender": [
            ("实时保护启用", "检查", "reg", r"HKLM\...\Real-Time Protection", 1),
            ("云保护级别", "检查", "reg", r"HKLM\...\Cloud Protection Level", 2),
            ("定期扫描启用", "检查", "reg", r"HKLM\...\Periodic Scanning", 1)
        ]
    }
    
    def __init__(self):
        self.results = []
    
    def check_windows_baseline(self, system_config):
        """执行 Windows 基线检查"""
        for category, checks in self.WINDOWS_BASELINE.items():
            for check_name, _, check_type, key, expected in checks:
                actual = system_config.get(key, "not_found")
                
                passed = actual == expected
                self.results.append({
                    "category": category,
                    "check": check_name,
                    "expected": expected,
                    "actual": actual,
                    "passed": passed,
                    "severity": "HIGH" if not passed else "INFO"
                })
        
        return self.compliance_score()
    
    def compliance_score(self):
        """计算合规率"""
        total = len(self.results)
        if total == 0:
            return 0
        passed = sum(1 for r in self.results if r["passed"])
        return {
            "score": round(passed / total * 100, 1),
            "passed": passed,
            "total": total,
            "failed": total - passed
        }

# 使用示例
checker = SecurityBaselineChecker()
system_config = {
    r"HKLM\...\MinimumPasswordLength": 14,
    r"HKLM\...\LockoutBadCount": 5,
}
score = checker.check_windows_baseline(system_config)
print(f"Compliance: {score['score']}% ({score['passed']}/{score['total']})")
```

### 2. 自动加固部署

```bash
# Windows 安全加固 — PowerShell DSC

# 1. 应用 CIS 基准 (PowerShell)
$cis_settings = @{
    # 账户策略
    "MinimumPasswordLength" = 14
    "PasswordHistorySize" = 24
    "LockoutBadCount" = 5
    
    # 安全选项
    "EnableLUA" = 1
    "EnableGuestAccount" = 0
    "UserAuthentication" = 1
    
    # 网络保护
    "DisableLLMNR" = 1
    "DisableNetBIOS" = 1
    "EnableFirewall" = 1
    
    # 攻击面减少
    "DisablePowerShellV2" = 1
    "DisableWDigest" = 1
    "DisableRC4" = 1
}

# 加固脚本示例
Write-Host "Applying Windows security hardening..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableDomainCreds" -Value 1

# 2. 攻击面减少规则 (ASR)
# Microsoft Defender ASR 规则
$asr_rules = @{
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office from creating executable content"
    "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office from creating child processes"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block executable files from email"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block Office communication applications"
}

foreach ($guid in $asr_rules.Keys) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $guid -AttackSurfaceReductionRules_Actions Enabled
    Write-Host "Enabled ASR: $($asr_rules[$guid])"
}

# 3. 防火墙规则
New-NetFirewallRule -DisplayName "Block SMB outbound" -Direction Outbound -Protocol TCP -LocalPort 445 -Action Block
New-NetFirewallRule -DisplayName "Block RDP from non-admin" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block

# 4. Windows Defender 配置
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -CloudBlockLevel High
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -LowfiThreatLevel Default_Action Quarantine
Set-MpPreference -SubmitSamplesConsent Always
```

```yaml
# Linux 安全加固 — Ansible Playbook
---
- name: Linux Security Hardening
  hosts: all
  become: yes
  tasks:
    - name: 1. 更新系统包
      apt:
        update_cache: yes
        upgrade: security
    
    - name: 2. SSH 加固
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
      loop:
        - {regexp: '^PermitRootLogin', line: 'PermitRootLogin no'}
        - {regexp: '^PasswordAuthentication', line: 'PasswordAuthentication no'}
        - {regexp: '^PubkeyAuthentication', line: 'PubkeyAuthentication yes'}
        - {regexp: '^X11Forwarding', line: 'X11Forwarding no'}
        - {regexp: '^MaxAuthTries', line: 'MaxAuthTries 3'}
        - {regexp: '^ClientAliveInterval', line: 'ClientAliveInterval 300'}
        - {regexp: '^ClientAliveCountMax', line: 'ClientAliveCountMax 0'}
    
    - name: 3. 禁用不必要的服务
      systemd:
        name: "{{ item }}"
        enabled: no
        state: stopped
      loop:
        - avahi-daemon
        - cups
        - rpcbind
        - nfs-server
    
    - name: 4. 内核参数加固
      sysctl:
        name: "{{ item.name }}"
        value: "{{ item.value }}"
        sysctl_set: yes
      loop:
        - {name: 'net.ipv4.ip_forward', value: '0'}
        - {name: 'net.ipv4.conf.all.rp_filter', value: '1'}
        - {name: 'net.ipv4.conf.all.accept_source_route', value: '0'}
        - {name: 'net.ipv4.tcp_syncookies', value: '1'}
        - {name: 'kernel.exec-shield', value: '1'}
        - {name: 'kernel.randomize_va_space', value: '2'}
    
    - name: 5. 文件权限加固
      file:
        path: "{{ item.path }}"
        mode: "{{ item.mode }}"
      loop:
        - {path: '/etc/shadow', mode: '0600'}
        - {path: '/etc/gshadow', mode: '0600'}
        - {path: '/etc/passwd', mode: '0644'}
        - {path: '/etc/group', mode: '0644'}
```

### 3. 合规自动化工具

```bash
# OpenSCAP — 自动化合规检查
# 安装
sudo apt-get install openscap-scanner scap-security-guide

# 检查 CIS 基准
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --results scan-results.xml \
  --report scan-report.html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu-latest-xccdf.xml

# 查看结果
oscap xccdf generate report scan-results.xml > report.html
# 打开 report.html 查看详细结果

# InSpec — 基础设施合规测试
# 安装
gem install inspec

# 运行基线检查
inspec exec https://github.com/dev-sec/linux-baseline

# 自定义 InSpec 测试
cat > cis_windows_baseline.rb << 'EOF'
control "cis-1.1.1" do
  title "Ensure 'Enforce password history' is set to '24 or more passwords'"
  desc "This policy setting determines the number of unique new passwords..."
  impact 1.0
  
  describe security_policy do
    its('PasswordHistorySize') { should be >= 24 }
  end
end

control "cis-2.2.1" do
  title "Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"
  desc "This security setting is used by Credential Manager during backup and restore."
  impact 1.0
  
  describe security_policy do
    its('SeTrustedCredManAccessPrivilege') { should eq [] }
  end
end
EOF

# 运行 Windows 基线检查
inspec exec cis_windows_baseline.rb -t winrm://administrator@hostname

# 生成 JUnit 报告
inspec exec cis_windows_baseline.rb --reporter junit:report.xml
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| CIS Benchmarks | 安全配置基准 | https://www.cisecurity.org/cis-benchmarks/ |
| OpenSCAP | 自动化合规扫描 | https://www.open-scap.org/ |
| InSpec | 基础设施测试 | https://www.chef.io/products/inspec |
| Microsoft Security Baselines | 微软基线 | https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-baselines |
| Ansible Hardening | 自动化加固 | https://github.com/dev-sec/ansible-collection-hardening |

## 参考资源

- [CIS Controls v8](https://www.cisecurity.org/controls/v8)
- [NIST SP 800-53 — Security Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST SP 800-128 — Security Configuration Management](https://csrc.nist.gov/publications/detail/sp/800-128/final)
- [Windows Security Baselines — Microsoft](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-baselines)
- [DevSec Linux Baseline](https://dev-sec.io/baselines/linux/)
