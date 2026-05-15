---
id: 16-003
title: "⚙️ AI应用安全配置审计 (AI Application Security Configuration Audit)"
category: 大模型安全
category_en: "LLM Security"
difficulty: ★★★
tools: "OWASP ASVS, CIS AI Benchmarks, Semgrep"
last_updated: 2025-07
tags: ["llm-security", "ai-security", "prompt-injection", "model-security", "ai-agent"]
subdomain: llm-security
nist_csf: ["PR.AC-01", "PR.DS-01", "DE.CM-01"]
mitre_attack: []
---
# ⚙️ AI应用安全配置审计 (AI Application Security Configuration Audit)

## 概述
AI应用安全配置审计涵盖LLM服务部署、API端点、模型推理服务、向量数据库等基础设施的安全基线检查。参照 **OWASP ASVS (Application Security Verification Standard)**、**CIS AI Benchmarks**、**CSA Cloud Controls Matrix (CCM) for AI** 等标准。

## 核心技能

### 1. LLM API端点安全审计

```python
import requests
from typing import Dict, List

class LLMAPIAuditor:
    """LLM API安全审计"""
    
    def __init__(self, endpoint: str, api_key: str = None):
        self.endpoint = endpoint
        self.api_key = api_key
        self.findings = []
    
    def audit_authentication(self) -> Dict:
        """审计认证机制"""
        checks = {}
        
        # 1. 未认证访问
        r = requests.get(self.endpoint)
        checks["no_auth_allowed"] = {
            "vulnerable": r.status_code == 200,
            "status_code": r.status_code,
            "detail": "API端点未要求认证" if r.status_code == 200 else "已正确要求认证"
        }
        
        # 2. API Key泄露检测
        if self.api_key:
            # 检查Key是否在URL中传输
            checks["api_key_in_url"] = {
                "vulnerable": "?" in self.endpoint and "api_key=" in self.endpoint,
                "detail": "API Key应在Header中传输，不应在URL中"
            }
            
            # 检查有无速率限制
            responses = []
            for _ in range(10):
                r = requests.post(
                    self.endpoint,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={"messages": [{"role": "user", "content": "test"}]}
                )
                responses.append(r.status_code)
            
            has_rate_limit = 429 in responses or 403 in responses
            checks["rate_limiting"] = {
                "vulnerable": not has_rate_limit,
                "detail": "缺少速率限制" if not has_rate_limit else "已启用速率限制"
            }
        
        return checks
    
    def audit_tls_configuration(self) -> Dict:
        """审计TLS配置"""
        import ssl
        import socket
        
        hostname = self.endpoint.split("://")[1].split("/")[0] if "//" in self.endpoint else self.endpoint
        
        checks = {}
        
        # 检查HTTPS
        checks["uses_https"] = {
            "vulnerable": not self.endpoint.startswith("https://"),
            "detail": "应用使用TLS加密" if self.endpoint.startswith("https://") else "未使用HTTPS！"
        }
        
        # 检查TLS版本
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    tls_version = ssock.version()
                    checks["tls_version"] = {
                        "vulnerable": tls_version < "TLSv1.2",
                        "detail": f"使用 {tls_version}"
                    }
        except Exception as e:
            checks["tls_version"] = {"error": str(e)}
        
        return checks
```

### 2. 推理服务配置基线

```bash
# 检查LLM推理服务安全配置

# Nginx反向代理配置检查
cat /etc/nginx/sites-enabled/llm-api | grep -E "
  (limit_req|limit_conn|client_max_body_size|ssl_protocols|access_log|error_log)
"

# 安全Nginx配置示例
cat << 'EOF' > /etc/nginx/conf.d/llm-api-safe.conf
upstream llm_backend {
    server 127.0.0.1:8000;
    # 限制连接数
    zone llm_backend 64k;
}

server {
    listen 443 ssl http2;
    server_name llm-api.example.com;
    
    # TLS加固
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5:!DH:!RC4;
    ssl_prefer_server_ciphers on;
    
    # 速率限制 - 每IP每分钟60请求
    limit_req_zone $binary_remote_addr zone=llm_api:10m rate=60r/m;
    limit_req zone=llm_api burst=20 nodelay;
    
    # 请求体大小限制（防止大Prompt攻击）
    client_max_body_size 128k;
    
    location /v1/chat/completions {
        # IP白名单
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        deny all;
        
        proxy_pass http://llm_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        
        # 超时设置
        proxy_read_timeout 120s;
        proxy_send_timeout 30s;
    }
    
    access_log /var/log/nginx/llm_api_access.log;
    error_log /var/log/nginx/llm_api_error.log;
}
EOF
```

### 3. 向量数据库安全审计

```python
class VectorDBAuditor:
    """向量数据库安全审计"""
    
    def __init__(self, db_config: Dict):
        self.config = db_config
    
    def audit_authentication(self) -> Dict:
        """审计数据库认证配置"""
        issues = []
        
        # 检查默认凭据
        default_creds = [
            {"user": "admin", "pass": "admin"},
            {"user": "root", "pass": ""},
            {"user": "default", "pass": "default"},
        ]
        
        current_creds = {
            "user": self.config.get("user"),
            "pass": self.config.get("password")
        }
        
        if current_creds in default_creds:
            issues.append("使用默认凭据！")
        
        # 检查是否启用认证
        if not self.config.get("authentication_enabled", True):
            issues.append("未启用数据库认证！")
        
        # 检查TLS
        if not self.config.get("tls_enabled", False):
            issues.append("数据库连接未使用TLS加密")
        
        return {
            "secure": len(issues) == 0,
            "issues": issues,
            "severity": "critical" if any("未" in i for i in issues) else "medium"
        }
    
    def audit_access_control(self) -> Dict:
        """审计访问控制"""
        issues = []
        
        # 网络暴露
        bind_ip = self.config.get("bind", "127.0.0.1")
        if bind_ip == "0.0.0.0":
            issues.append("向量数据库监听所有网络接口，存在数据泄露风险")
        
        # Embedding API访问权限
        if not self.config.get("embedding_api_restricted", False):
            issues.append("Embedding API未设置访问限制")
        
        return {
            "secure": len(issues) == 0,
            "issues": issues
        }
```

### 4. AI应用安全配置清单

```text
# AI应用安全配置审计检查清单

## 1. API安全
[ ] 所有API端点是否需要认证？
[ ] 是否实施速率限制（Rate Limiting）？
[ ] 是否使用HTTPS（TLS 1.2+）？
[ ] API Key是否在Header中传输（非URL）？
[ ] 是否实施了请求体大小限制？
[ ] 是否记录了完整的API审计日志？

## 2. 模型安全
[ ] 模型文件是否校验了完整性（SHA256）？
[ ] 模型推理是否在沙箱环境中运行？
[ ] 是否实施了输入验证和过滤？
[ ] 模型输出是否经过安全检查？
[ ] 是否限制了单次推理的最大Token数？

## 3. 数据安全
[ ] 用户输入是否不落盘或定期清理？
[ ] 训练数据和Prompt是否脱敏？
[ ] 向量数据库是否加密存储？
[ ] 数据库连接是否使用TLS？

## 4. 基础设施
[ ] 推理服务器是否配置了防火墙规则？
[ ] 是否启用了WAF（Web Application Firewall）？
[ ] 是否实现了日志监控和告警？
[ ] 是否定期进行安全补丁更新？

## 5. 合规要求
[ ] 是否满足GDPR/CCPA/个保法要求？
[ ] 用户是否被告知AI交互？
[ ] 是否有数据删除机制？
[ ] 是否保留了必要的审计日志？

## CIS AI安全基准参考
- CIS Google Cloud AI Platform Benchmark v1.0
- CIS AWS SageMaker Benchmark v1.0
- CIS Azure AI Services Benchmark v1.0
```

### 5. 自动化审计脚本

```bash
# AI应用安全配置自动化审计
# 使用 OpenSCAP 检查基准

# 检查Docker容器的安全配置
docker run --rm -it \
  -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image --severity HIGH,CRITICAL your-llm-image:latest

# 检查Kubernetes部署安全
kube-bench run --targets master,node --version 1.24

# 检查云服务安全配置（以AWS SageMaker为例）
prowler -s sagemaker

# IaC安全检查（Terraform/CloudFormation）
checkov -d . --framework terraform
tfsec .
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Trivy | 容器/依赖漏洞扫描 | https://github.com/aquasecurity/trivy |
| Checkov | IaC安全检查 | https://github.com/bridgecrewio/checkov |
| Prowler | AWS安全审计 | https://github.com/prowler-cloud/prowler |
| kube-bench | K8s安全基准检查 | https://github.com/aquasecurity/kube-bench |
| OpenSCAP | 安全合规扫描 | https://www.open-scap.org/ |
| Lynis | 系统安全审计 | https://github.com/CISOfy/lynis |
| ScoutSuite | 多云安全审计 | https://github.com/nccgroup/ScoutSuite |

## 参考资源

- [OWASP ASVS — Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [CIS Benchmarks for AI/ML](https://www.cisecurity.org/benchmark/ai_ml)
- [CSA CCM for AI](https://cloudsecurityalliance.org/research/cloud-controls-matrix/)
- [NIST SP 800-53 — Security and Privacy Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [OWASP Cheat Sheet — API Security](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
