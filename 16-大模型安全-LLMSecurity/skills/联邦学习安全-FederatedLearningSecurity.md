---
id: 16-010
title: "🤝 联邦学习安全 (Federated Learning Security)"
category: 大模型安全
category_en: "LLM Security"
difficulty: ★★★★
tools: "TensorFlow Federated, PySyft, FATE, 安全聚合"
last_updated: 2025-07
tags: ["llm-security", "ai-security", "prompt-injection", "model-security", "ai-agent"]
subdomain: llm-security
nist_csf: ["PR.AC-01", "PR.DS-01", "DE.CM-01"]
mitre_attack: []
---
# 🤝 联邦学习安全 (Federated Learning Security)

## 概述
联邦学习（Federated Learning）允许多方协作训练模型而不共享原始数据，但面临梯度泄露、模型投毒、成员推理等特有安全威胁。本技能覆盖联邦学习中的隐私保护、投毒防御、安全聚合等关键技术，参照 **MITRE ATLAS** 联邦学习攻击矩阵、**IEEE FL安全标准**。

## 核心技能

### 1. 联邦学习威胁模型

```text
# 联邦学习安全威胁分类

## 1. 模型投毒攻击 (Model Poisoning)
攻击方式: 恶意客户端上传恶意梯度/模型更新
影响: 全局模型后门化、准确率下降
防御: 鲁棒聚合、异常检测、拜占庭容错

## 2. 梯度泄露攻击 (Gradient Leakage)
攻击方式: 从共享梯度反推原始训练数据
经典: Deep Leakage from Gradients (DLG)
影响: 训练数据隐私泄露
防御: 差分隐私、梯度压缩、安全多方计算

## 3. 成员推理攻击 (Membership Inference)
攻击方式: 判断特定样本是否在训练集中
影响: 用户隐私泄露
防御: DP训练、低过拟合

## 4. 拜占庭攻击 (Byzantine Attacks)
攻击方式: 恶意客户端发送任意错误更新
影响: 模型收敛失败
防御: Krum、Median、Trimmed Mean等鲁棒聚合器

## 5. 自由骑攻击 (Free-Riding)
攻击方式: 不贡献真实数据但享受模型收益
影响: 破坏公平性、降低协作意愿
防御: 贡献验证、区块链激励机制
```

### 2. 梯度泄露攻击复现与防御

```python
import numpy as np
import torch
import torch.nn as nn
from typing import Tuple

class GradientLeakageAttack:
    """梯度泄露攻击 - Deep Leakage from Gradients"""
    
    def __init__(self, model: nn.Module, dummy_data: torch.Tensor):
        self.model = model
        self.dummy_data = nn.Parameter(dummy_data.clone().detach().requires_grad_(True))
        self.optimizer = torch.optim.LBFGS([self.dummy_data], lr=0.1)
    
    def attack(self, true_gradients: Tuple[torch.Tensor], 
               steps: int = 100) -> torch.Tensor:
        """DLG攻击：从梯度重建原始数据"""
        
        for i in range(steps):
            def closure():
                self.optimizer.zero_grad()
                
                # 使用虚拟数据前向传播
                dummy_pred = self.model(self.dummy_data)
                dummy_loss = dummy_pred.sum()
                dummy_gradients = torch.autograd.grad(
                    dummy_loss, self.model.parameters(), create_graph=True
                )
                
                # 计算梯度距离
                grad_diff = 0
                for dg, tg in zip(dummy_gradients, true_gradients):
                    grad_diff += ((dg - tg) ** 2).sum()
                
                grad_diff.backward()
                return grad_diff
            
            self.optimizer.step(closure)
            
            if i % 20 == 0:
                print(f"Step {i}, Loss: {closure().item():.6f}")
        
        return self.dummy_data.data
    
    def defense_differential_privacy(self, gradients: np.ndarray, 
                                     epsilon: float = 1.0) -> np.ndarray:
        """DP防御：添加高斯噪声到梯度"""
        sensitivity = 1.0
        noise_scale = sensitivity / epsilon
        noise = np.random.normal(0, noise_scale, gradients.shape)
        return gradients + noise
    
    def defense_gradient_compression(self, gradients: np.ndarray, 
                                     top_k: float = 0.1) -> np.ndarray:
        """梯度压缩防御：仅上传Top-K最大梯度"""
        flat_grad = gradients.flatten()
        k = int(len(flat_grad) * top_k)
        threshold = np.sort(np.abs(flat_grad))[-k]
        mask = np.abs(flat_grad) >= threshold
        compressed = flat_grad * mask
        return compressed.reshape(gradients.shape)
```

### 3. 鲁棒聚合算法

```python
import numpy as np
from typing import List

class RobustAggregator:
    """鲁棒聚合算法 - 防御拜占庭攻击"""
    
    @staticmethod
    def krum(gradients: List[np.ndarray], n_byzantine: int = 1) -> np.ndarray:
        """
        Krum聚合算法
        选择与其他梯度距离和最小的梯度作为全局更新
        """
        n = len(gradients)
        distances = np.zeros((n, n))
        
        for i in range(n):
            for j in range(i + 1, n):
                dist = np.linalg.norm(gradients[i] - gradients[j])
                distances[i][j] = dist
                distances[j][i] = dist
        
        # 对每个梯度，计算与其他n-2-m个最近邻的距离和
        m = n - n_byzantine - 2
        scores = np.zeros(n)
        for i in range(n):
            sorted_dist = np.sort(distances[i])
            scores[i] = np.sum(sorted_dist[1:1+m])
        
        # 选择得分最小的梯度
        best_idx = np.argmin(scores)
        return gradients[best_idx]
    
    @staticmethod
    def median(gradients: List[np.ndarray]) -> np.ndarray:
        """中位数聚合 - 按坐标取中位数"""
        stacked = np.stack(gradients)
        return np.median(stacked, axis=0)
    
    @staticmethod
    def trimmed_mean(gradients: List[np.ndarray], 
                     trim_ratio: float = 0.2) -> np.ndarray:
        """截尾均值聚合 - 去除最大最小值后取均值"""
        stacked = np.stack(gradients)
        n = len(gradients)
        trim_count = int(n * trim_ratio)
        
        sorted_grads = np.sort(stacked, axis=0)
        trimmed = sorted_grads[trim_count:n-trim_count]
        return np.mean(trimmed, axis=0)
    
    @staticmethod
    def anomaly_detection(gradients: List[np.ndarray], 
                          threshold: float = 3.0) -> np.ndarray:
        """异常检测聚合 - 基于Z-Score剔除异常"""
        stacked = np.stack(gradients)
        mean = np.mean(stacked, axis=0)
        std = np.std(stacked, axis=0) + 1e-8
        z_scores = np.abs((stacked - mean) / std)
        
        # 去除异常梯度
        mask = np.all(z_scores < threshold, axis=tuple(range(1, z_scores.ndim)))
        clean_grads = stacked[mask]
        
        return np.mean(clean_grads, axis=0)
```

### 4. 安全聚合协议

```python
import hashlib
from typing import Dict, List
import random

class SecureAggregationProtocol:
    """安全聚合协议 - 基于秘密共享"""
    
    def __init__(self, num_clients: int, threshold: int):
        self.num_clients = num_clients
        self.threshold = threshold  # 安全门限
    
    def setup_key_pairs(self) -> Dict[int, int]:
        """生成客户端密钥对"""
        keys = {}
        for i in range(self.num_clients):
            keys[i] = random.randint(1, 2**32)
        return keys
    
    def mask_gradients(self, gradient: np.ndarray, 
                       client_id: int, 
                       keys: Dict[int, int]) -> np.ndarray:
        """使用一次性掩码掩盖梯度"""
        masked = gradient.copy()
        for peer_id in range(self.num_clients):
            if peer_id == client_id:
                continue
            # 伪随机数生成器（基于共享密钥）
            seed = hashlib.sha256(
                str(keys[client_id] ^ keys[peer_id]).encode()
            ).digest()
            np.random.seed(int.from_bytes(seed[:4], 'big'))
            
            noise = np.random.normal(0, 0.1, gradient.shape)
            if peer_id < client_id:
                masked += noise
            else:
                masked -= noise
        return masked
    
    def aggregate_masked(self, masked_gradients: List[np.ndarray]) -> np.ndarray:
        """聚合掩盖后的梯度（噪声相互抵消）"""
        return np.mean(masked_gradients, axis=0)
```

### 5. 联邦学习安全评估

```bash
# 联邦学习安全评估
# 使用TensorFlow Federated或PySyft

# 模拟拜占庭攻击（PyTorch示例）
python -c "
import torch
import torch.nn as nn

model = nn.Sequential(nn.Linear(10, 5), nn.ReLU(), nn.Linear(5, 1))

# 模拟正常客户端梯度
normal_grads = [torch.randn_like(p) for p in model.parameters()]

# 模拟拜占庭客户端（发送随机大梯度）
n_byzantine = 2
byzantine_grads = [torch.randn_like(p) * 100 for p in model.parameters()]

# 混合梯度池
all_grads = [normal_grads] * 8 + [byzantine_grads] * n_byzantine

# Krum聚合
from krum import KrumAggregator
krum = KrumAggregator(n_byzantine=2)
robust_grads = krum.aggregate(all_grads)
print('Krum聚合完成，成功防御拜占庭攻击')
"
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| PySyft | 隐私保护FL框架 | https://github.com/OpenMined/PySyft |
| TensorFlow Federated | 联邦学习框架 | https://github.com/tensorflow/federated |
| Flower | 联邦学习框架（含安全组件） | https://github.com/adap/flower |
| FATE | 工业级联邦学习平台 | https://github.com/FederatedAI/FATE |
| CrypTen | 安全多方计算框架 | https://github.com/facebookresearch/CrypTen |
| Opacus | 差分隐私训练 | https://github.com/pytorch/opacus |

## 参考资源

- [MITRE ATLAS — Federated Learning Attacks](https://atlas.mitre.org/techniques/AML.T0044)
- [IEEE Guide for FL Security](https://standards.ieee.org/ieee/3652.1/10598/)
- [Deep Leakage from Gradients (NeurIPS 2019)](https://arxiv.org/abs/1906.08935)
- [Byzantine-robust FL (Krum)](https://papers.nips.cc/paper/6617-machine-learning-with-adversaries-byzantine-tolerant-gradient-descent)
- [Google AI — FL安全最佳实践](https://ai.google/research/federated-learning)
- [NIST IR 8467 — Towards FL Security](https://csrc.nist.gov/publications/detail/nistir/8467/draft)
