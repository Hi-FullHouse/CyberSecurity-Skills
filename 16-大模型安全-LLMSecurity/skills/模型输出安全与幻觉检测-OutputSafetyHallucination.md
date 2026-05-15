---
id: 16-009
title: "📝 模型输出安全与幻觉检测 (Output Safety & Hallucination Detection)"
category: 大模型安全
category_en: "LLM Security"
difficulty: ★★★
tools: "Guardrails, Nemo Guardrails, 幻觉检测模型"
last_updated: 2025-07
tags: ["llm-security", "ai-security", "prompt-injection", "model-security", "ai-agent"]
subdomain: llm-security
nist_csf: ["PR.AC-01", "PR.DS-01", "DE.CM-01"]
mitre_attack: []
---
# 📝 模型输出安全与幻觉检测 (Output Safety & Hallucination Detection)

## 概述
LLM输出安全涵盖有害内容生成、事实幻觉、版权侵权（OWASP LLM-02: Insecure Output Handling）等问题。本技能覆盖输出过滤、幻觉检测、事实一致性验证、内容安全审核等关键技术。

## 核心技能

### 1. 输出内容安全过滤

```python
import re
from typing import List, Dict, Tuple

class OutputSafetyFilter:
    """LLM输出安全过滤器"""
    
    def __init__(self):
        self.content_policies = {
            "violence": [
                r"(?i)((kill|hurt|attack|stab|shoot|bomb)\s+(them|people|someone))",
                r"(?i)(how\s+to\s+make\s+(weapon|bomb|explosive|poison))",
            ],
            "hate_speech": [
                r"(?i)(hate|discriminate|racist|sexist)\s+(against|the\s+|all\s+)",
            ],
            "sexual": [
                r"(?i)(explicit|pornographic|sexual\s+content|adult\s+material)",
            ],
            "illegal": [
                r"(?i)(how\s+to\s+(steal|hack|cheat|fraud|traffick))",
            ],
            "personal_info": [
                r"\b\d{17}[\dXx]\b",  # 中国身份证
                r"\b1[3-9]\d{9}\b",   # 手机号
            ]
        }
    
    def filter_output(self, text: str) -> Dict:
        """过滤输出内容"""
        violations = {}
        for category, patterns in self.content_policies.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, text)
                if found:
                    matches.append(found[:3])  # 最多记录3个
            if matches:
                violations[category] = matches
        
        return {
            "text": text,
            "safe": len(violations) == 0,
            "violations": violations,
            "action": "block" if violations else "allow"
        }
    
    def redact_sensitive(self, text: str) -> str:
        """自动打码敏感信息"""
        redacted = text
        redaction_rules = [
            (r'\b\d{17}[\dXx]\b', '[身份证号已隐藏]'),
            (r'\b1[3-9]\d{9}\b', '[手机号已隐藏]'),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[邮箱已隐藏]'),
            (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '[IP已隐藏]'),
        ]
        for pattern, replacement in redaction_rules:
            redacted = re.sub(pattern, replacement, redacted)
        return redacted
```

### 2. 事实幻觉检测

```python
import requests
from typing import List, Optional

class HallucinationDetector:
    """幻觉检测器 - 基于多源验证"""
    
    def __init__(self, verification_sources: List[str]):
        self.sources = verification_sources
    
    def detect_factual_hallucination(self, claim: str, 
                                     context: Optional[str] = None) -> Dict:
        """检测事实性幻觉"""
        # 1. 提取可验证的声明
        claims = self._extract_verifiable_claims(claim)
        
        # 2. 多源交叉验证
        verification_results = []
        for c in claims:
            evidence = self._verify_claim(c)
            verification_results.append({
                "claim": c,
                "verified": evidence["verified"],
                "evidence": evidence["source"],
                "confidence": evidence["confidence"]
            })
        
        # 3. 计算幻觉率
        total = len(verification_results)
        hallucinated = sum(1 for r in verification_results if not r["verified"])
        hallucination_rate = hallucinated / total if total > 0 else 0
        
        return {
            "total_claims": total,
            "hallucinated_claims": hallucinated,
            "hallucination_rate": hallucination_rate,
            "severity": "high" if hallucination_rate > 0.3 else 
                       "medium" if hallucination_rate > 0.1 else "low",
            "details": verification_results
        }
    
    def _extract_verifiable_claims(self, text: str) -> List[str]:
        """从文本中提取可验证的事实性声明"""
        # 使用NLP提取命名实体、数据、统计等
        import re
        
        claims = []
        # 提取统计数字
        stats = re.findall(r'\d+[%\%]|\d+\.\d+\s*(million|billion|trillion)', text)
        if stats:
            claims.extend([f"数据指标: {s}" for s in stats])
        
        # 提取引用
        citations = re.findall(r'(?:according to|source:|reference:)\s*([^.]+)', text)
        claims.extend(citations)
        
        # 提取日期、人名、地名等（简化示例）
        dates = re.findall(r'\b(20\d{2})年?\b', text)
        if dates:
            claims.extend([f"时间陈述: {d}" for d in dates])
        
        return claims
    
    def _verify_claim(self, claim: str) -> Dict:
        """验证单个声明（模拟多源验证）"""
        # 在真实场景中，这里会调用搜索API、知识图谱等
        # 这里给出一个简化实现
        import hashlib
        claim_hash = hashlib.md5(claim.encode()).hexdigest()
        # 根据哈希的某位决定验证结果（仅为演示）
        verified = int(claim_hash[0], 16) > 8
        
        return {
            "verified": verified,
            "source": self.sources[0] if verified else "无法验证",
            "confidence": 0.75 if verified else 0.3
        }
```

### 3. 语义一致性检查

```python
class SemanticConsistencyCheck:
    """跨轮对话语义一致性检查"""
    
    def __init__(self, embedding_model=None):
        self.embedding_model = embedding_model
        self.history = []
    
    def check_consistency(self, new_response: str, 
                          conversation_history: List[Dict]) -> Dict:
        """检查新响应与历史对话的一致性"""
        issues = []
        
        # 1. 事实一致性
        prev_facts = self._extract_stated_facts(conversation_history)
        new_facts = self._extract_stated_facts([{"content": new_response}])
        
        for fact in new_facts:
            if fact in prev_facts:
                prev_value = prev_facts[fact]
                new_value = new_facts[fact]
                if prev_value != new_value:
                    issues.append({
                        "type": "contradiction",
                        "fact": fact,
                        "previous": prev_value,
                        "current": new_value
                    })
        
        # 2. 语义相似度（使用嵌入）
        if self.embedding_model and len(self.history) > 0:
            similarity = self._compute_semantic_similarity(
                self.history[-1], new_response
            )
            if similarity < 0.3:
                issues.append({
                    "type": "semantic_drift",
                    "similarity": float(similarity)
                })
        
        self.history.append(new_response)
        
        return {
            "consistent": len(issues) == 0,
            "issues": issues,
            "risk_level": "high" if any(i["type"] == "contradiction" for i in issues) 
                         else "low"
        }
```

### 4. 幻觉自动化评估基准

```bash
# 使用TruthfulQA评估模型幻觉
pip install lm-evaluation-harness

# 评估LLM在TruthfulQA上的表现
lm_eval --model hf --model_args pretrained=meta-llama/Llama-2-7b \
  --tasks truthfulqa_mc --num_fewshot 0

# 使用HaluEval评估
pip install halu-eval
python -m halueval.evaluate --model gpt-3.5-turbo --benchmark all

# 评估指标
# - Truthfulness Score: 模型回答的真实性
# - Informativeness Score: 回答的信息丰富度
# - Hallucination Rate: 幻觉比例
```

### 5. 安全输出配置

```python
class SafeOutputConfig:
    """安全输出配置管理"""
    
    DEFAULT_POLICIES = {
        "max_output_tokens": 2048,
        "temperature": 0.7,        # 低温度减少创造性幻觉
        "top_p": 0.9,
        "frequency_penalty": 0.2,   # 抑制重复
        "presence_penalty": 0.0,
        
        # 输出安全
        "enable_safety_filter": True,
        "enable_hallucination_detection": True,
        "hallucination_threshold": 0.3,
        "require_citation": False,
        
        # 速率限制
        "max_requests_per_minute": 60,
        "max_requests_per_user_per_hour": 100,
    }
    
    def __init__(self, custom_policies: Optional[Dict] = None):
        self.policies = {**self.DEFAULT_POLICIES, **(custom_policies or {})}
    
    def apply_output_restrictions(self, response: str) -> Dict:
        """应用输出限制"""
        
        # 长度限制
        if len(response) > self.policies["max_output_tokens"] * 4:  # 粗略换算
            response = response[:self.policies["max_output_tokens"] * 4]
        
        result = {
            "response": response,
            "restrictions_applied": []
        }
        
        # 安全过滤
        if self.policies["enable_safety_filter"]:
            filter_result = OutputSafetyFilter().filter_output(response)
            if not filter_result["safe"]:
                result["restrictions_applied"].append("safety_filter_blocked")
                result["response"] = "[安全策略拦截: 输出包含受限内容]"
        
        return result
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| TruthfulQA | 幻觉评估基准 | https://github.com/sylinrl/TruthfulQA |
| HaluEval | 幻觉检测评估 | https://github.com/RUCAIBox/HaluEval |
| SelfCheckGPT | 无监督幻觉检测 | https://github.com/potsawee/selfcheckgpt |
| NeMo Guardrails | 输出安全护栏 | https://github.com/NVIDIA/NeMo-Guardrails |
| LLM Guard | 输入/输出安全过滤器 | https://github.com/protectai/llm-guard |
| Guardrails AI | 结构化输出验证 | https://github.com/guardrails-ai/guardrails |

## 参考资源

- [OWASP LLM Top 10 — LLM02: Insecure Output Handling](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NIST AI 600-1 — AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [TruthfulQA — Measuring How Models Mimic Human Falsehoods](https://arxiv.org/abs/2109.07958)
- [SelfCheckGPT — Zero-Resource Hallucination Detection](https://arxiv.org/abs/2303.08896)
- [OpenAI — Content Policy & Safety](https://platform.openai.com/docs/guides/safety-best-practices)
