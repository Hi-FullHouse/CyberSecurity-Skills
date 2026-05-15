---
id: 16-005
title: "🔒 LLM数据泄露与隐私保护 (Data Leakage & Privacy Protection)"
category: 大模型安全
category_en: "LLM Security"
difficulty: ★★★★
tools: "数据脱敏工具, 隐私检测, Presidio, 差分隐私库"
last_updated: 2025-07
tags: ["llm-security", "ai-security", "prompt-injection", "model-security", "ai-agent"]
subdomain: llm-security
nist_csf: ["PR.AC-01", "PR.DS-01", "DE.CM-01"]
mitre_attack: []
---
# 🔒 LLM数据泄露与隐私保护 (Data Leakage & Privacy Protection)

## 概述
大语言模型在训练、推理和部署各阶段都可能发生数据泄露（OWASP LLM-06）。本技能覆盖模型训练数据记忆泄露、推理时敏感信息泄露、第三方API数据外泄、差分隐私保护等核心议题，参照 **GDPR**、**中国个人信息保护法**、**NIST Privacy Framework** 等法规标准。

## 核心技能

### 1. 训练数据记忆泄露 (Training Data Memorization)

LLM可能记忆并复现训练数据中的敏感信息。

```python
# 训练数据提取攻击
import requests
from typing import List

class MemorizationAttack:
    """测试模型是否记忆了训练数据中的敏感信息"""
    
    def __init__(self, model_endpoint: str):
        self.endpoint = model_endpoint
    
    def extract_pii(self, prefix_prompts: List[str]) -> List[str]:
        """通过前缀提示提取可能的PII"""
        extracted = []
        for prefix in prefix_prompts:
            response = requests.post(
                self.endpoint,
                json={
                    "prompt": prefix,
                    "max_tokens": 100,
                    "temperature": 0.7
                }
            )
            text = response.json()["text"]
            # 检测是否包含PII
            if self._contains_pii(text):
                extracted.append({"prefix": prefix, "extracted": text})
        return extracted
    
    def _contains_pii(self, text: str) -> bool:
        """检测是否包含PII信息"""
        import re
        pii_patterns = [
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b\d{17}[\dXx]\b',  # 中国身份证号
            r'\b1[3-9]\d{9}\b',  # 中国手机号
        ]
        return any(re.search(p, text) for p in pii_patterns)
```

### 2. 推理时敏感信息泄露

模型在推理过程中可能无意泄露策略、API密钥或用户数据。

```python
# 测试LLM端点信息泄露
class InferenceLeakageTest:
    """测试推理API是否存在敏感信息泄露"""
    
    def test_api_key_leakage(self, endpoint: str):
        """测试是否在错误响应中泄露API配置"""
        # 发送恶意请求触发错误
        payloads = [
            {"invalid": True},
            {"prompt": "A" * 100000},  # 超长输入
            {"prompt": "../../../etc/passwd"},  # 路径遍历
        ]
        for payload in payloads:
            response = requests.post(endpoint, json=payload)
            # 检查响应
            if response.status_code in [400, 500]:
                body = response.text.lower()
                leaked_signals = ["api_key", "secret", "token", 
                                 "password", "endpoint", "internal"]
                for signal in leaked_signals:
                    if signal in body:
                        print(f"⚠️ 可能泄露: {signal} 在错误响应中")
```

### 3. 日志与中间数据泄露

```python
# 检查LLM应用日志安全
class LLMLogAuditor:
    """审计LLM应用的日志策略"""
    
    def check_log_risks(self, log_file_path: str):
        """检查日志文件中的潜在泄露"""
        risks = []
        with open(log_file_path, 'r') as f:
            for line in f:
                # 检查prompt是否被完整记录
                if '"prompt"' in line and len(line) > 500:
                    risks.append("完整Prompt被记录到日志")
                # 检查API Key是否出现在日志
                if 'sk-' in line or 'api_key' in line.lower():
                    risks.append("API凭证出现在日志中")
                # 检查用户个人信息
                if '@' in line and '.' in line.split('@')[1]:
                    risks.append("邮箱地址出现在日志中")
        return risks
```

### 4. 数据脱敏与匿名化

```python
from typing import Dict, Any
import re
import hashlib

class LLMDataSanitizer:
    """LLM输入输出数据脱敏器"""
    
    def __init__(self):
        self.patterns = {
            "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "phone": r'\b1[3-9]\d{9}\b',
            "id_card": r'\b\d{17}[\dXx]\b',
            "ip": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            "api_key": r'\b(sk-[a-zA-Z0-9]{20,}|[A-Za-z0-9]{32,})\b',
        }
    
    def mask_pii(self, text: str, mask_char: str = "*") -> str:
        """掩码处理PII"""
        masked = text
        for pii_type, pattern in self.patterns.items():
            masked = re.sub(pattern, lambda m: self._mask_match(m, mask_char), masked)
        return masked
    
    def _mask_match(self, match, mask_char):
        """保留前缀，其余掩码"""
        matched = match.group()
        if len(matched) <= 4:
            return mask_char * len(matched)
        return matched[:2] + mask_char * (len(matched) - 4) + matched[-2:]
    
    def hash_pii(self, text: str, salt: str = "") -> str:
        """使用哈希替换PII（不可逆）"""
        hashed = text
        for pii_type, pattern in self.patterns.items():
            def _replace_with_hash(m):
                return f"[{pii_type}]{hashlib.sha256((m.group()+salt).encode()).hexdigest()[:8]}[/{pii_type}]"
            hashed = re.sub(pattern, _replace_with_hash, hashed)
        return hashed
```

### 5. 差分隐私训练

```python
import numpy as np

class DifferentialPrivacyTrainer:
    """DP-SGD差分隐私训练模拟"""
    
    def __init__(self, epsilon: float = 8.0, delta: float = 1e-5, 
                 clipping_norm: float = 1.0):
        self.epsilon = epsilon
        self.delta = delta
        self.clipping_norm = clipping_norm
    
    def apply_gradient_clipping(self, gradients: np.ndarray) -> np.ndarray:
        """梯度裁剪，限制单个样本影响"""
        norms = np.linalg.norm(gradients, axis=-1, keepdims=True)
        scale = np.minimum(1.0, self.clipping_norm / (norms + 1e-8))
        return gradients * scale
    
    def add_noise(self, gradients: np.ndarray) -> np.ndarray:
        """添加高斯噪声实现差分隐私"""
        sensitivity = 2.0 * self.clipping_norm
        noise_scale = sensitivity * np.sqrt(2 * np.log(1.25 / self.delta)) / self.epsilon
        noise = np.random.normal(0, noise_scale, gradients.shape)
        return gradients + noise
    
    def private_train_step(self, gradients: np.ndarray) -> np.ndarray:
        """差分隐私训练步骤"""
        clipped_grads = self.apply_gradient_clipping(gradients)
        private_grads = self.add_noise(clipped_grads)
        return private_grads
```

### 6. 隐私合规检查清单

```text
# LLM应用隐私合规检查清单

## 数据收集阶段
[ ] 是否明确告知用户数据将用于模型训练？
[ ] 是否获得用户明确同意？
[ ] 是否提供数据删除/遗忘权利？
[ ] 是否限制了最小必要数据收集？

## 数据处理阶段
[ ] 训练数据是否经过脱敏处理？
[ ] 是否实施了差分隐私训练？
[ ] 数据存储是否加密（AES-256）？
[ ] 是否限制了内部人员的数据访问权限？

## 推理阶段
[ ] 用户输入是否不落盘或定期清理？
[ ] 是否实现了数据最小化输出？
[ ] 推理日志是否脱敏？
[ ] 是否支持用户删除历史记录？

## API/第三方
[ ] API传输是否使用TLS 1.3？
[ ] 第三方API是否签署了数据保护协议？
[ ] 是否定期审计第三方数据处理方式？
[ ] 跨境数据传输是否符合法规要求？

## 合规标准映射
- GDPR: Art. 5, 17, 32, 44-49
- 中国个人信息保护法: Art. 6, 13-17, 38-43
- CCPA: Section 1798.100-1798.199
- NIST Privacy Framework: 核心功能P1-P5
```

### 7. 数据泄露应急响应

```python
class LLMDataBreachResponse:
    """LLM数据泄露应急响应"""
    
    def __init__(self, notification_channel: str):
        self.notification_channel = notification_channel
        self.breach_log = []
    
    def detect_breach(self, model_output: str, user_input: str) -> dict:
        """检测输出中是否包含不应泄露的数据"""
        alert = {"breach": False, "type": None, "severity": "low"}
        
        # 检测训练数据记忆
        if self._is_memorized_data(model_output):
            alert = {"breach": True, "type": "memorization", "severity": "high"}
        
        # 检测SQL/PII泄露
        if self._contains_sensitive_data(model_output):
            alert = {"breach": True, "type": "pii_leak", "severity": "critical"}
        
        if alert["breach"]:
            self.breach_log.append(alert)
            self._trigger_response(alert)
        
        return alert
    
    def _trigger_response(self, alert: dict):
        """触发自动响应"""
        print(f"🚨 数据泄露事件: {alert['type']} (严重程度: {alert['severity']})")
        # 响应步骤
        print("1. 阻断该次响应输出")
        print("2. 记录完整上下文用于分析")
        print("3. 通知安全团队")
        if alert["severity"] == "critical":
            print("4. 暂停该模型的推理服务")
            print("5. 启动数据泄露调查流程")
            print("6. 评估监管通报义务")
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Presidio | 数据脱敏和PII检测 | https://github.com/microsoft/presidio |
| Faker | 合成数据生成（替代真实PII） | https://github.com/joke2k/faker |
| Opacus | PyTorch差分隐私库 | https://opacus.ai/ |
| TensorFlow Privacy | TF差分隐私训练 | https://github.com/tensorflow/privacy |
| ARX | 数据匿名化工具 | https://arx.deidentifier.org/ |
| Greenery | LLM隐私风险评估 | https://github.com/ethz-privsec/greenery |

## 参考资源

- [OWASP LLM Top 10 — LLM06: Sensitive Information Disclosure](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NIST Privacy Framework: A Tool for Improving Privacy](https://www.nist.gov/privacy-framework)
- [GDPR — 数据保护影响评估 (DPIA)](https://gdpr-info.eu/art-35-gdpr/)
- [中国个人信息保护法全文](https://www.gov.cn/xinwen/2021-08/20/content_5632486.htm)
- [OWASP Top 10 Privacy Risks](https://owasp.org/www-project-top-10-privacy-risks/)
