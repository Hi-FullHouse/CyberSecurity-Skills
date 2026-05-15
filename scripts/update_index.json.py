#!/usr/bin/env python3
"""Update index.json with modules 17-26"""
import json
import sys

with open('index.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

new_modules = [
    {
        "id": 17,
        "name_cn": "云安全",
        "name_en": "Cloud Security",
        "emoji": "☁️",
        "path": "17-云安全-CloudSecurity",
        "skill_count": 8,
        "skills": [
            {"name": "AWS安全评估", "file": "AWS安全评估-AWSSecurityAssessment.md", "difficulty": "★★★★"},
            {"name": "Azure安全评估", "file": "Azure安全评估-AzureSecurityAssessment.md", "difficulty": "★★★★"},
            {"name": "GCP安全评估", "file": "GCP安全评估-GCPSecurityAssessment.md", "difficulty": "★★★★"},
            {"name": "云IAM权限与访问控制审计", "file": "云IAM权限与访问控制审计-CloudIAMAudit.md", "difficulty": "★★★"},
            {"name": "云存储安全配置审计", "file": "云存储安全配置审计-CloudStorageSecurity.md", "difficulty": "★★★"},
            {"name": "云网络与WAF安全", "file": "云网络与WAF安全-CloudNetworkWAF.md", "difficulty": "★★★★"},
            {"name": "无服务器架构安全", "file": "无服务器架构安全-ServerlessSecurity.md", "difficulty": "★★★★"},
            {"name": "多云安全策略评估", "file": "多云安全策略评估-MultiCloudSecurity.md", "difficulty": "★★★★★"}
        ]
    },
    {
        "id": 18,
        "name_cn": "安全开发运维",
        "name_en": "DevSecOps",
        "emoji": "🔄",
        "path": "18-安全开发运维-DevSecOps",
        "skill_count": 6,
        "skills": [
            {"name": "CI/CD管道安全审计", "file": "CI-CD管道安全审计-CICDPipelineSecurity.md", "difficulty": "★★★★"},
            {"name": "IaC安全扫描", "file": "IaC安全扫描-InfrastructureAsCodeSecurity.md", "difficulty": "★★★"},
            {"name": "SAST静态应用安全测试", "file": "SAST静态应用安全测试-SAST.md", "difficulty": "★★★★"},
            {"name": "DAST动态应用安全测试", "file": "DAST动态应用安全测试-DAST.md", "difficulty": "★★★★"},
            {"name": "软件供应链安全", "file": "软件供应链安全-SoftwareSupplyChainSecurity.md", "difficulty": "★★★★"},
            {"name": "安全需求与威胁建模", "file": "安全需求与威胁建模-ThreatModeling.md", "difficulty": "★★★★"}
        ]
    },
    {
        "id": 19,
        "name_cn": "工控安全",
        "name_en": "ICS/OT Security",
        "emoji": "🏭",
        "path": "19-工控安全-ICS-OT-Security",
        "skill_count": 6,
        "skills": [
            {"name": "SCADA系统安全评估", "file": "SCADA系统安全评估-SCADASecurityAssessment.md", "difficulty": "★★★★"},
            {"name": "PLC与RTU安全测试", "file": "PLC与RTU安全测试-PLC-RTU-SecurityTesting.md", "difficulty": "★★★★★"},
            {"name": "工控网络协议安全", "file": "工控网络协议安全-ICS-NetworkProtocolSecurity.md", "difficulty": "★★★★"},
            {"name": "工控安全合规审计（IEC 62443）", "file": "工控安全合规审计-IEC62443-Audit.md", "difficulty": "★★★★"},
            {"name": "工控安全应急预案", "file": "工控安全应急预案-ICS-IncidentResponse.md", "difficulty": "★★★★★"},
            {"name": "工业防火墙与网络分段", "file": "工业防火墙与网络分段-Industrial-Firewall-Segmentation.md", "difficulty": "★★★★"}
        ]
    },
    {
        "id": 20,
        "name_cn": "区块链/Web3安全",
        "name_en": "Blockchain/Web3 Security",
        "emoji": "🔗",
        "path": "20-区块链安全-Blockchain-Web3-Security",
        "skill_count": 6,
        "skills": [
            {"name": "智能合约安全审计", "file": "智能合约安全审计-SmartContractAudit.md", "difficulty": "★★★★★"},
            {"name": "DeFi协议安全评估", "file": "DeFi协议安全评估-DeFiSecurityAssessment.md", "difficulty": "★★★★★"},
            {"name": "共识机制安全分析", "file": "共识机制安全分析-ConsensusSecurityAnalysis.md", "difficulty": "★★★★"},
            {"name": "Web3前端与钱包安全", "file": "Web3前端与钱包安全-Web3WalletSecurity.md", "difficulty": "★★★★"},
            {"name": "区块链节点安全加固", "file": "区块链节点安全加固-BlockchainNodeHardening.md", "difficulty": "★★★★"},
            {"name": "MEV与跨链桥安全", "file": "MEV与跨链桥安全-MEV-CrossChainBridgeSecurity.md", "difficulty": "★★★★★"}
        ]
    },
    {
        "id": 21,
        "name_cn": "物联网安全",
        "name_en": "IoT Security",
        "emoji": "📡",
        "path": "21-物联网安全-IoT-Security",
        "skill_count": 6,
        "skills": [
            {"name": "固件逆向与分析", "file": "固件逆向与分析-FirmwareReverseEngineering.md", "difficulty": "★★★★★"},
            {"name": "BLE/Zigbee/Z-Wave无线安全测试", "file": "BLE-Zigbee-Z-Wave无线安全测试-WirelessProtocolSecurity.md", "difficulty": "★★★★"},
            {"name": "物联网通信协议安全", "file": "物联网通信协议安全-IoTCommunicationSecurity.md", "difficulty": "★★★★"},
            {"name": "嵌入式设备硬件安全测试", "file": "嵌入式设备硬件安全测试-EmbeddedHardwareSecurity.md", "difficulty": "★★★★★"},
            {"name": "物联网平台与云安全", "file": "物联网平台与云安全-IoTPlatformCloudSecurity.md", "difficulty": "★★★★"},
            {"name": "智能家居与车联网安全", "file": "智能家居与车联网安全-SmartHomeConnectedVehicleSecurity.md", "difficulty": "★★★★"}
        ]
    },
    {
        "id": 22,
        "name_cn": "数据安全与隐私保护",
        "name_en": "Data Security & Privacy",
        "emoji": "🔐",
        "path": "22-数据安全与隐私-DataSecurityPrivacy",
        "skill_count": 6,
        "skills": [
            {"name": "数据防泄露（DLP）", "file": "数据防泄露-DLP.md", "difficulty": "★★★★"},
            {"name": "数据分类与分级", "file": "数据分类与分级-DataClassification.md", "difficulty": "★★★"},
            {"name": "数据库安全", "file": "数据库安全-DatabaseSecurity.md", "difficulty": "★★★★"},
            {"name": "数据脱敏与加密", "file": "数据脱敏与加密-DataMaskingEncryption.md", "difficulty": "★★★"},
            {"name": "GDPR与隐私合规", "file": "GDPR隐私合规-GDPRPrivacyCompliance.md", "difficulty": "★★★★"},
            {"name": "隐私影响评估（PIA）", "file": "隐私影响评估-PIA.md", "difficulty": "★★★★"}
        ]
    },
    {
        "id": 23,
        "name_cn": "社会工程学",
        "name_en": "Social Engineering",
        "emoji": "🎭",
        "path": "23-社会工程学-SocialEngineering",
        "skill_count": 5,
        "skills": [
            {"name": "钓鱼邮件模拟", "file": "钓鱼邮件模拟-PhishingSimulation.md", "difficulty": "★★★"},
            {"name": "电话诈骗与Vishing测试", "file": "电话诈骗与Vishing测试-VishingTesting.md", "difficulty": "★★★★"},
            {"name": "物理渗透与社会工程", "file": "物理渗透与社会工程-PhysicalSocialEngineering.md", "difficulty": "★★★★"},
            {"name": "钓鱼基础设施搭建", "file": "钓鱼基础设施搭建-PhishingInfrastructure.md", "difficulty": "★★★★"},
            {"name": "员工安全意识评估", "file": "员工安全意识评估-SecurityAwarenessAssessment.md", "difficulty": "★★★"}
        ]
    },
    {
        "id": 24,
        "name_cn": "红蓝对抗",
        "name_en": "Red/Blue Team",
        "emoji": "⚔️",
        "path": "24-红蓝对抗-RedBlueTeam",
        "skill_count": 5,
        "skills": [
            {"name": "红队评估方法论", "file": "红队评估方法论-RedTeamAssessment.md", "difficulty": "★★★★★"},
            {"name": "蓝队防御与检测", "file": "蓝队防御与检测-BlueTeamDefense.md", "difficulty": "★★★★"},
            {"name": "紫队协作评估", "file": "紫队协作评估-PurpleTeamExercise.md", "difficulty": "★★★★★"},
            {"name": "BAS攻击模拟平台", "file": "BAS攻击模拟平台-BreachAttackSimulation.md", "difficulty": "★★★★"},
            {"name": "闭环防御改进", "file": "闭环防御改进-DefenseImprovementCycle.md", "difficulty": "★★★★"}
        ]
    },
    {
        "id": 25,
        "name_cn": "供应链安全",
        "name_en": "Supply Chain Security",
        "emoji": "🔗",
        "path": "25-供应链安全-SupplyChainSecurity",
        "skill_count": 6,
        "skills": [
            {"name": "SBOM生成与验证", "file": "SBOM生成与验证-SBOMGeneration.md", "difficulty": "★★★"},
            {"name": "软件依赖与开源合规审计", "file": "软件依赖与开源合规审计-DependencyLicenseCompliance.md", "difficulty": "★★★"},
            {"name": "代码签名与供应链完整性", "file": "代码签名与供应链完整性-CodeSigningIntegrity.md", "difficulty": "★★★★"},
            {"name": "容器镜像安全扫描", "file": "容器镜像安全扫描-ContainerImageScan.md", "difficulty": "★★★"},
            {"name": "第三方供应商风险评估", "file": "第三方供应商风险评估-ThirdPartyVendorRisk.md", "difficulty": "★★★★"},
            {"name": "供应链攻击检测与响应", "file": "供应链攻击检测与响应-SupplyChainAttackResponse.md", "difficulty": "★★★★"}
        ]
    },
    {
        "id": 26,
        "name_cn": "漏洞管理",
        "name_en": "Vulnerability Management",
        "emoji": "🛡️",
        "path": "26-漏洞管理-VulnerabilityManagement",
        "skill_count": 6,
        "skills": [
            {"name": "漏洞情报与CVE查询", "file": "漏洞情报与CVE查询-VulnerabilityIntelligence.md", "difficulty": "★★★"},
            {"name": "漏洞验证与PoC测试", "file": "漏洞验证与PoC测试-VulnerabilityVerification.md", "difficulty": "★★★★"},
            {"name": "漏洞优先级与风险评估", "file": "漏洞优先级与风险评估-VulnerabilityPrioritization.md", "difficulty": "★★★★"},
            {"name": "漏洞修复与补丁管理", "file": "漏洞修复与补丁管理-VulnerabilityRemediation.md", "difficulty": "★★★★"},
            {"name": "漏洞生命周期闭环管理", "file": "漏洞生命周期闭环管理-VulnerabilityLifecycle.md", "difficulty": "★★★★"},
            {"name": "漏洞奖励计划与安全众测", "file": "漏洞奖励计划与安全众测-BugBountyCrowdsourcedTesting.md", "difficulty": "★★★"}
        ]
    }
]

data["modules"].extend(new_modules)
data["meta"]["total_modules"] = 26
data["meta"]["total_skills"] = 146
data["meta"]["version"] = "2.2.0"

with open('index.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)

print(f"Updated: total_modules={data['meta']['total_modules']}, total_skills={data['meta']['total_skills']}")
module_names = [m['name_cn'] for m in data['modules']]
print(f"Modules ({len(module_names)}): {', '.join(module_names)}")
