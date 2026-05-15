---
id: 21-005
title: "☁️ 物联网平台与云安全 (IoT Platform & Cloud Security)"
category: 物联网安全
category_en: "IoT Security"
difficulty: ★★★★
tools: "AWS IoT Auditor, Azure IoT Hub Security, GCP IoT Core, TLS Notary"
last_updated: 2025-07
tags: ["iot-security", "firmware", "embedded", "ble", "zigbee", "hardware-security"]
subdomain: iot-security
nist_csf: ["PR.AC-01", "PR.DS-03", "PR.PT-01"]
mitre_attack: ["T1465", "T1559", "T1524"]
---
# ☁️ 物联网平台与云安全 (IoT Platform & Cloud Security)

## 概述
评估主流IoT云平台的安全性，包括AWS IoT Core、Azure IoT Hub、GCP IoT Core的认证机制、设备影子安全、OTA更新策略和规则引擎配置。

## 核心技能

### 1. AWS IoT Core安全评估

```bash
# AWS IoT Core认证检查
# 1. 检查X.509证书颁发
aws iot list-ca-certificates
aws iot list-certificates
aws iot list-policies

# 2. 检查IoT策略
aws iot list-policies --query 'policies[*].policyName'
aws iot get-policy --policy-name <policy-name>

# 3. 检查IoT策略中的权限 - 最小权限原则
aws iot get-policy --policy-name <policy-name> --query 'policyDocument'

# 安全自定义策略示例
cat << 'POLICY' > iot_policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iot:Connect"
      ],
      "Resource": [
        "arn:aws:iot:us-east-1:123456789:client/${iot:ClientId}"
      ],
      "Condition": {
        "Bool": {
          "iot:Connection.Thing.IsAttached": ["true"]
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": [
        "iot:Publish",
        "iot:Receive"
      ],
      "Resource": [
        "arn:aws:iot:us-east-1:123456789:topic/${iot:ClientId}/telemetry"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "iot:Subscribe"
      ],
      "Resource": [
        "arn:aws:iot:us-east-1:123456789:topicfilter/${iot:ClientId}/commands"
      ]
    }
  ]
}
POLICY

# 4. 检查设备影子权限
aws iot get-topic-rule --rule-name <rule-name>

# 5. 检查TLS连接
# IoT Core要求: TLS 1.2+ (仅支持)
# 支持的密码套件: ECDHE-based (Forward Secrecy)
```

### 2. Azure IoT Hub安全评估

```bash
# Azure IoT Hub安全检查
# 1. 检查IoT Hub SKU和规模
az iot hub show --name <hub-name> --query "sku"

# 2. 检查内置终结点
az iot hub show --name <hub-name> --query "properties.eventHubEndpoints"

# 3. 检查IP过滤器
az iot hub show --name <hub-name> --query "properties.ipFilterRules"

# 4. 检查路由配置
az iot hub route list --hub-name <hub-name>

# 5. 检查设备身份验证
az iot hub device-identity list --hub-name <hub-name> --query "[].{deviceId:deviceId, auth:authentication}"

# 6. 检查设备孪生的所需属性
az iot hub device-twin show --device-id <device-id> --hub-name <hub-name>

# 7. 检查IoT Hub私有端点
az network private-endpoint list --query "[?contains(??,'Microsoft.Devices/IotHubs')]"

# Azure IoT Hub安全基线
# ✅ 使用SAS令牌 (非连接字符串)
# ✅ 启用TLS 1.2
# ✅ 使用设备预配服务 (DPS)
# ✅ 使用IP过滤器
# ✅ 启用诊断日志
# ❌ 避免使用共享访问策略的完全控制权限
```

### 3. 设备身份X.509证书管理

```bash
# 自签CA证书配置 (AWS IoT)
# 1. 创建CA证书
openssl genrsa -out ca-key.pem 2048
openssl req -x509 -new -nodes -key ca-key.pem \
  -sha256 -days 3650 -out ca-cert.pem \
  -subj "/C=CN/CN=MyIoTCA"

# 2. 注册CA证书到IoT Core
aws iot register-ca-certificate \
  --ca-certificate file://ca-cert.pem \
  --verification-certificate file://verification-cert.pem \
  --set-as-active

# 3. 为设备创建设备证书
openssl genrsa -out device-key.pem 2048
openssl req -new -key device-key.pem \
  -out device-csr.pem \
  -subj "/C=CN/CN=device-01"
openssl x509 -req -in device-csr.pem \
  -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out device-cert.pem \
  -days 365 -sha256

# 4. 激活设备证书
aws iot register-certificate-without-ca \
  --certificate-pem file://device-cert.pem \
  --status ACTIVE

# 5. 附加IoT策略到证书
aws iot attach-policy \
  --policy-name "IoTDevicePolicy" \
  --target "arn:aws:iot:region:account:cert/<cert-id>"
```

### 4. OTA更新安全

```bash
# OTA更新安全基线
# AWS IoT Jobs OTA更新
# 1. 固件签名
openssl dgst -sha256 -sign private-key.pem \
  -out firmware.bin.sig firmware.bin

# 2. 创建OTA更新任务
aws iot create-job \
  --job-id "firmware-v2.0.1" \
  --targets "arn:aws:iot:region:account:thing/device-01" \
  --document file://ota-document.json \
  --description "安全OTA更新 v2.0.1"

# 3. OTA文档示例
cat << 'JSON' > ota-document.json
{
  "url": "https://s3.amazonaws.com/ota-bucket/firmware-v2.0.1.bin",
  "version": "2.0.1",
  "fileSize": 1048576,
  "hash": "sha256:f123...",
  "signature": "base64-encoded-signature",
  "signatureAlgorithm": "SHA256-RSA"
}
JSON

# 4. 设备端验证
# 下载固件 -> 验证哈希 -> 验证签名 -> 写入Flash
```

### 5. IoT云安全基线

| # | 检查项 | 严重程度 | 建议 |
|:---:|:---|:---:|:---|
| 1 | IoT策略仅为通配符(iot:*) | 🔴 严重 | 严格遵守最小权限 |
| 2 | 设备证书未激活/过期 | 🟠 高危 | 证书吊销机制 |
| 3 | 设备影子允许修改敏感属性 | 🟠 高危 | 限制影子写入权限 |
| 4 | 规则引擎直接访问数据库 | 🔴 严重 | 使用IAM角色限制 |
| 5 | MQTT主题过于宽泛(#) | 🟠 高危 | 按设备ID隔离主题 |
| 6 | 无TLS 1.2+强制 | 🔴 严重 | 仅允许TLS 1.2+连接 |
| 7 | 固件未签名OTA | 🔴 严重 | 实施代码签名验证 |
| 8 | 无设备预置认证 | 🟠 高危 | 使用DPS + X.509 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| AWS CLI (IoT模块) | AWS IoT管理 | https://awscli.amazonaws.com/ |
| Azure CLI (IoT扩展) | Azure IoT管理 | https://learn.microsoft.com/cli/azure/iot |
| MQTTX | MQTT客户端工具 | https://mqttx.app/ |
| TLS Notary | TLS通信验证 | https://tlsnotary.org/ |
| OpenSSL | 证书管理 | https://www.openssl.org/ |

## 参考资源
- [AWS IoT Security Best Practices](https://docs.aws.amazon.com/iot/latest/developerguide/security-best-practices.html)
- [Azure IoT Hub Security](https://learn.microsoft.com/azure/iot-hub/iot-hub-security-overview)
- [GCP IoT Core Security](https://cloud.google.com/iot-core/docs/security)
- [OTA Security Best Practices](https://www.mender.io/guides/ota-update-security)
- [NIST IR 8259B — IoT Device Security](https://csrc.nist.gov/publications/detail/ir/8259b/final)
