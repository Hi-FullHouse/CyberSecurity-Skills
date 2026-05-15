---
id: 16-002
title: "📦 AI供应链安全 (AI Supply Chain Security)"
category: 大模型安全
category_en: "LLM Security"
difficulty: ★★★
tools: "SBOM工具, SLSA框架, Snyk, Trivy"
last_updated: 2025-07
tags: ["llm-security", "ai-security", "prompt-injection", "model-security", "ai-agent"]
subdomain: llm-security
nist_csf: ["PR.AC-01", "PR.DS-01", "DE.CM-01"]
mitre_attack: []
---
# 📦 AI供应链安全 (AI Supply Chain Security)

## 概述
AI供应链安全涵盖模型托管、第三方API依赖、开源组件、训练数据、部署基础设施等环节的安全风险（OWASP LLM-05）。攻击者可能通过污染预训练模型、投毒训练数据、篡改推理管道等方式实施供应链攻击。本技能参照 **SLSA**、**SBOM**、**NIST SSDF**、**CNCF Software Supply Chain Best Practices** 等标准。

## 核心技能

### 1. 模型来源验证与完整性校验

```bash
# 验证模型文件的数字签名和哈希
# Hugging Face 模型验证
pip install huggingface_hub

# 下载模型并校验SHA256
curl -L -o model.safetensors https://huggingface.co/meta-llama/Llama-2-7b/resolve/main/model.safetensors
sha256sum model.safetensors > model.sha256
cat model.sha256

# 验证模型卡中的DPO签名（模型可信发布）
huggingface-cli verify-repo-signatures meta-llama/Llama-2-7b

# GPG签名验证
gpg --verify model.safetensors.asc model.safetensors
```

```python
# 模型完整性校验自动化
import hashlib
import requests
from typing import Dict, Optional

class ModelIntegrityVerifier:
    """模型文件完整性验证器"""
    
    def __init__(self):
        self.trusted_registries = [
            "huggingface.co",
            "github.com",
            "pytorch.org",
            "tensorflow.org",
        ]
    
    def verify_model_hash(self, model_path: str, expected_hash: str, 
                          algorithm: str = "sha256") -> bool:
        """验证模型文件哈希"""
        h = hashlib.new(algorithm)
        with open(model_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        actual_hash = h.hexdigest()
        return actual_hash == expected_hash
    
    def check_model_registry(self, model_url: str) -> Dict:
        """检查模型来源是否可信"""
        risk_assessment = {
            "url": model_url,
            "trusted": False,
            "risks": []
        }
        
        # 检查来源
        if not any(registry in model_url for registry in self.trusted_registries):
            risk_assessment["risks"].append("非可信模型托管平台")
        
        # 检查HTTPS
        if not model_url.startswith("https://"):
            risk_assessment["risks"].append("不使用HTTPS传输")
        
        # 检查是否包含版本锁定
        if "@" not in model_url and "v" not in model_url.split("/")[-1]:
            risk_assessment["risks"].append("未锁定版本，易受恶意更新攻击")
        
        risk_assessment["trusted"] = len(risk_assessment["risks"]) == 0
        return risk_assessment
```

### 2. SBOM (AI Bill of Materials) 生成与分析

```python
import json
from datetime import datetime
from typing import List, Dict

class AISBOMGenerator:
    """AI供应链SBOM生成器（基于CycloneDX格式）"""
    
    def generate_model_sbom(self, model_info: Dict) -> Dict:
        """生成模型SBOM"""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "component": {
                    "type": "application",
                    "name": model_info.get("name"),
                    "version": model_info.get("version"),
                    "model": model_info.get("model_type"),
                    "description": "AI Model Supply Chain Bill of Materials"
                }
            },
            "components": self._collect_components(model_info)
        }
        return sbom
    
    def _collect_components(self, model_info: Dict) -> List[Dict]:
        """收集所有供应链组件"""
        components = []
        
        # 训练框架
        components.append({
            "type": "framework",
            "name": model_info.get("framework", "unknown"),
            "version": model_info.get("framework_version", "unknown")
        })
        
        # 训练数据集
        for dataset in model_info.get("datasets", []):
            components.append({
                "type": "data",
                "name": dataset.get("name"),
                "version": dataset.get("version"),
                "licenses": dataset.get("license"),
                "evidence": dataset.get("source_url")
            })
        
        # Python依赖
        for dep in model_info.get("dependencies", []):
            components.append({
                "type": "library",
                "name": dep.get("name"),
                "version": dep.get("version"),
                "purl": dep.get("purl")  # Package URL
            })
        
        # 基础模型（如果是微调模型）
        if model_info.get("base_model"):
            components.append({
                "type": "model",
                "name": model_info["base_model"]["name"],
                "version": model_info["base_model"]["version"],
                "bundled": True
            })
        
        return components
```

### 3. 依赖漏洞扫描

```bash
# Python ML依赖安全扫描
pip install safety
safety check

# 扫描requirements.txt
safety check -r requirements.txt --full-report

# Trivy - 容器和依赖扫描
trivy fs --severity HIGH,CRITICAL --exit-code 1 /path/to/project

# Snyk - AI项目依赖扫描
snyk test --all-projects --severity-threshold=high

# GitHub Dependabot配置 (.github/dependabot.yml)
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    labels:
      - "security"
      - "dependencies"
```

### 4. 训练数据投毒检测

```python
import numpy as np
from typing import List, Tuple

class DataPoisoningDetector:
    """训练数据投毒检测"""
    
    def __init__(self, clean_data_sample: np.ndarray):
        self.clean_stats = self._compute_statistics(clean_data_sample)
    
    def _compute_statistics(self, data: np.ndarray) -> Dict:
        return {
            "mean": np.mean(data, axis=0),
            "std": np.std(data, axis=0),
            "min": np.min(data),
            "max": np.max(data)
        }
    
    def detect_outliers(self, suspicious_data: np.ndarray, 
                        threshold: float = 3.0) -> np.ndarray:
        """检测异常数据点（潜在投毒）"""
        z_scores = np.abs(
            (suspicious_data - self.clean_stats["mean"]) / self.clean_stats["std"]
        )
        return np.any(z_scores > threshold, axis=1)
    
    def detect_label_flipping(self, features: np.ndarray, 
                              labels: np.ndarray) -> List[int]:
        """检测标签翻转攻击"""
        from sklearn.ensemble import IsolationForest
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        
        # 特征-标签组合检测
        X_combined = np.concatenate([features, labels.reshape(-1, 1)], axis=1)
        anomalies = iso_forest.fit_predict(X_combined)
        
        return np.where(anomalies == -1)[0].tolist()
```

### 5. 供应链攻击场景

```text
# AI供应链攻击典型场景

## 场景1：模型权重投毒
攻击者在公开模型权重中植入后门
→ 当输入包含特定触发器时，模型执行恶意行为
→ 防御：校验模型哈希、使用可信源、权重签名验证

## 场景2：Python依赖劫持
攻击者注册与流行ML库相似的恶意包（Typosquatting）
例如：tensorfl0w (数字0代替o)
→ 防御：锁定依赖版本、使用private PyPI镜像、包名验证

## 场景3：Hugging Face恶意模型
攻击者上传含恶意代码的模型
→ 模型加载时执行任意代码（利用了pickle反序列化漏洞）
→ 防御：使用safetensors格式、模型沙箱加载、审查模型代码

## 场景4：训练数据污染
攻击者向公开数据集注入含毒样本
→ 模型在特定输入下产生预设的错误输出
→ 防御：数据来源验证、离群值检测、差分隐私训练

## 场景5：CI/CD管道劫持
攻击者通过篡改CI/CD配置注入恶意模型
→ 每次部署都自动加载被篡改的模型
→ 防御：CI/CD配置签名、SBOM验证、部署审批流程
```

### 6. 安全配置检查清单

```text
# AI供应链安全配置检查清单

## 模型获取
[ ] 模型来源是否来自可信注册表？
[ ] 是否校验模型文件哈希和签名？
[ ] 是否使用safetensors而非pickle格式？
[ ] 是否对模型进行了安全审计？

## 依赖管理
[ ] 是否使用requirements.lock / poetry.lock锁定版本？
[ ] 是否定期扫描依赖漏洞？
[ ] 是否使用private PyPI / conda镜像？
[ ] 是否移除了不必要的依赖？

## 部署安全
[ ] 模型是否运行在沙箱/隔离环境中？
[ ] 推理API是否有速率限制和鉴权？
[ ] 是否实施了模型完整性运行时监控？
[ ] 是否启用了模型访问审计日志？

## 持续监控
[ ] 是否实施了SBOM自动生成？
[ ] 是否有依赖变更告警机制？
[ ] 是否定期审查第三方模型行为？
[ ] 是否有供应链安全事件响应计划？
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Trivy | 容器/依赖漏洞扫描 | https://github.com/aquasecurity/trivy |
| Safety | Python依赖安全扫描 | https://github.com/pyupio/safety |
| Snyk | 开源依赖安全 | https://snyk.io/ |
| CycloneDX | SBOM标准化工具 | https://github.com/CycloneDX |
| Hugging Face Hub | 模型托管（有安全检查） | https://huggingface.co/ |
| PickleScan | 检测恶意pickle文件 | https://github.com/mmaitre314/picklescan |
| SLSA Framework | 供应链安全级别框架 | https://slsa.dev/ |

## 参考资源

- [OWASP LLM Top 10 — LLM05: Supply Chain Vulnerabilities](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [SLSA — Supply-chain Levels for Software Artifacts](https://slsa.dev/)
- [NIST SSDF — Secure Software Development Framework](https://csrc.nist.gov/publications/detail/sp/800-218/final)
- [CNCF Software Supply Chain Best Practices](https://github.com/cncf/tag-security/tree/main/supply-chain-security)
- [Hugging Face Security Policy](https://huggingface.co/docs/hub/security)
- [OpenSSF Scorecard](https://securityscorecards.dev/)
