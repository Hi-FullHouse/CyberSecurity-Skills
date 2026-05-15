---
id: 12-001
title: "🤖 AI Agent代码审计 (AI Agent Code Audit)"
category: 代码审计
category_en: "Code Audit"
difficulty: ★★★★
tools: "Semgrep, Bandit, CodeQL, Garak"
last_updated: 2025-07
tags: ["code-audit", "static-analysis", "php-audit", "java-audit", "javascript-audit"]
subdomain: code-audit
nist_csf: ["PR.IP-12", "ID.RA-01"]
mitre_attack: []
---
# 🤖 AI Agent代码审计 (AI Agent Code Audit)

## 概述
AI Agent代码审计关注AI智能体系统在工具函数实现、Agent编排、Prompt模板、RAG管道等环节的代码安全。结合传统代码审计技术与AI特有安全风险，覆盖LangChain、AutoGPT、CrewAI等主流框架。

## 核心技能

### 1. LangChain应用审计

```python
from typing import List, Dict
import ast
import re

class LangChainAuditor:
    """LangChain代码安全审计"""
    
    # 危险函数模式
    DANGEROUS_PATTERNS = [
        # 直接代码执行
        r"\.exec\(|eval\(|exec\(|compile\(",
        # 不安全的反序列化
        r"pickle\.loads|yaml\.load[^s]",
        # Shell命令执行
        r"subprocess\.|os\.system|os\.popen|shutil\.",
        # 危险LLMChain配置
        r"verbose\s*=\s*True",
    ]
    
    def audit_llmchain(self, source_code: str) -> List[Dict]:
        """审计LLMChain配置"""
        findings = []
        tree = ast.parse(source_code)
        
        for node in ast.walk(tree):
            # 检查LLMChain实例化
            if isinstance(node, ast.Call) and hasattr(node.func, 'attr'):
                if 'Chain' in str(node.func.attr):
                    kwargs = {kw.arg: ast.dump(kw.value) for kw in node.keywords if kw.arg}
                    
                    # 检查verbose模式
                    if kwargs.get('verbose') == 'True':
                        findings.append({
                            "type": "verbose_mode",
                            "line": node.lineno,
                            "risk": "调试模式下可能泄露Prompt和内部数据",
                            "severity": "medium"
                        })
                    
                    # 检查未验证的输出
                    if kwargs.get('return_only_outputs') == 'False':
                        findings.append({
                            "type": "unvalidated_output",
                            "line": node.lineno,
                            "risk": "LLM输出未经验证直接返回",
                            "severity": "high"
                        })
        
        return findings
    
    def audit_tool_implementation(self, tool_code: str) -> List[Dict]:
        """审计Tool实现中的安全风险"""
        findings = []
        
        # 检查危险函数使用
        for pattern in self.DANGEROUS_PATTERNS:
            matches = re.finditer(pattern, tool_code, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "type": "dangerous_function",
                    "match": match.group(),
                    "risk": f"使用了危险函数: {match.group()}",
                    "severity": "critical"
                })
        
        return findings
    
    def audit_prompt_template(self, template_code: str) -> List[Dict]:
        """审计Prompt模板安全性"""
        issues = []
        
        # 检查用户输入直接拼接到Prompt
        if re.search(r'\{input\}|\{user_input\}|\{query\}', template_code):
            issues.append({
                "type": "direct_user_input",
                "risk": "用户输入直接拼接到Prompt模板，可导致提示注入",
                "severity": "high",
                "fix": "在拼接前进行输入验证和转义"
            })
        
        # 检查系统Prompt是否暴露内部配置
        if re.search(r'\{api_key\}|\{secret\}|\{password\}|sk-', template_code):
            issues.append({
                "type": "credential_exposure",
                "risk": "Prompt模板中可能包含凭据占位符",
                "severity": "critical"
            })
        
        return issues
```

### 2. Agent编排安全

```python
class AgentOrchestrationAuditor:
    """Agent编排配置安全审计"""
    
    def audit_agent_config(self, config: Dict) -> List[str]:
        """审计Agent配置安全性"""
        issues = []
        
        # 检查Agent角色权限
        if config.get("allow_delegation", False):
            issues.append("Agent允许委派任务给其他Agent - 可能导致权限扩散")
        
        # 检查最大迭代次数
        max_iterations = config.get("max_iterations", 15)
        if max_iterations > 50:
            issues.append(f"最大迭代次数过高({max_iterations}) - 可能导致无限循环")
        
        # 检查工具权限
        tools = config.get("tools", [])
        dangerous_tools = ["shell", "executor", "code_interpreter", "file_writer"]
        for tool in tools:
            if any(dt in tool.lower() for dt in dangerous_tools):
                issues.append(f"Agent注册了高危工具: {tool}")
        
        # 检查内存访问权限
        if config.get("memory", {}).get("shared", False):
            issues.append("Agent使用共享内存 - 可能导致Agent间数据泄露")
        
        return issues
```

### 3. 常见安全漏洞模式

```text
# AI Agent代码审计常见漏洞

## 1. Prompt模板注入漏洞
危险模式: 用户输入直接嵌入Prompt
```python
# ❌ 危险: 直接拼接
prompt = f"回答用户的问题: {user_input}"
```

## 2. 工具函数命令注入
危险模式: 未验证的工具参数拼接Shell命令
```python
# ❌ 危险: 参数直接传shell
def run_command(cmd):
    return subprocess.check_output(cmd, shell=True)
# ✅ 安全: 参数白名单+参数化
def run_command_safe(cmd):
    ALLOWED = ["ls", "pwd", "whoami"]
    if cmd.split()[0] not in ALLOWED:
        raise ValueError("Command not allowed")
```

## 3. 敏感信息泄露
危险模式: 错误信息包含凭据
```python
# ❌ 危险: 异常信息包含敏感数据
except Exception as e:
    return f"API Error: {api_key}, {str(e)}"
```

## 4. Agent权限失控
危险模式: Agent可以创建/修改其他Agent
```python
# ❌ 危险: 无权限控制
agent.create_child_agent("malicious_agent", tools=["all"])
```

## 5. 循环调用未限制
危险模式: Agent可无限调用自身或其他Agent
```python
# ❌ 危险: 无调用深度限制
while not task_complete:
    result = await agent.run(task)
    task = result.next_task  # 可能无限循环
```
```

### 4. 审计检查清单

```text
# AI Agent代码审计检查清单

## Tool实现
[ ] 工具函数是否对输入参数进行了验证？
[ ] 是否使用了参数化查询（vs字符串拼接）？
[ ] 执行Shell命令是否使用了白名单？
[ ] 文件操作路径是否进行了规范化检查？
[ ] API调用是否有速率限制？

## Prompt安全
[ ] Prompt模板是否对用户输入进行了转义？
[ ] 系统Prompt是否包含敏感信息？
[ ] 是否实现了输入过滤和安全守卫？
[ ] 输出是否经过了安全验证？

## Agent配置
[ ] 是否遵循了最小权限原则？
[ ] 是否限制了Agent的迭代次数？
[ ] Agent间通信是否加密和认证？
[ ] 是否记录了完整的操作审计日志？

## 依赖安全
[ ] 是否锁定了依赖版本？
[ ] 是否定期扫描依赖漏洞？
[ ] 是否移除了不必要的依赖？
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Semgrep | 代码安全规则扫描 | https://semgrep.dev/ |
| Bandit | Python安全扫描 | https://github.com/PyCQA/bandit |
| CodeQL | 代码QL查询 | https://github.com/github/codeql |
| LangChain | Agent框架 | https://github.com/langchain-ai/langchain |
| Guardrails AI | LLM输出验证 | https://github.com/guardrails-ai/guardrails |

## 参考资源

- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)
- [LangChain Security Best Practices](https://python.langchain.com/docs/security/)
- [AutoGPT Security Guidelines](https://github.com/Significant-Gravitas/AutoGPT)
- [OWASP LLM Application Security](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
