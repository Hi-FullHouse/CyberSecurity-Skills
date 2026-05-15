---
id: 16-001
title: "🔐 AI Agent权限与访问控制 (Agent Authorization & Access Control)"
category: 大模型安全
category_en: "LLM Security"
difficulty: ★★★★
tools: "OAuth 2.0, OIDC, RBAC, OWASP LLM-08"
last_updated: 2025-07
tags: ["llm-security", "ai-security", "prompt-injection", "model-security", "ai-agent"]
subdomain: llm-security
nist_csf: ["PR.AC-01", "PR.DS-01", "DE.CM-01"]
mitre_attack: []
---
# 🔐 AI Agent权限与访问控制 (Agent Authorization & Access Control)

## 概述
AI智能体（AI Agent）具有执行工具调用、访问外部资源、处理敏感数据的能力（OWASP LLM-08: Excessive Agency）。不当的权限控制可能导致Agent越权操作，造成严重安全事件。本技能覆盖Agent权限模型设计、工具函数授权、最小权限原则、人机确认机制等核心议题。

## 核心技能

### 1. Agent权限模型设计

```python
from enum import Enum, auto
from typing import List, Dict, Optional, Callable
import time

class Permission(Enum):
    """Agent权限枚举"""
    READ_ONLY = auto()      # 只读权限
    READ_WRITE = auto()     # 读写权限
    ADMIN = auto()          # 管理权限
    DESTRUCTIVE = auto()    # 破坏性操作（需确认）

class ToolCategory(Enum):
    """工具分类"""
    INFORMATION = auto()    # 信息查询
    FILE_SYSTEM = auto()    # 文件系统
    DATABASE = auto()       # 数据库
    NETWORK = auto()        # 网络操作
    EXECUTION = auto()      # 代码执行
    ADMINISTRATION = auto() # 管理操作

class AgentPermissionModel:
    """Agent权限模型"""
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.permissions: Dict[ToolCategory, Permission] = {}
        self.resource_allowlist: List[str] = []
        self.operation_log: List[Dict] = []
    
    def grant_permission(self, category: ToolCategory, permission: Permission):
        """授予权限"""
        self.permissions[category] = permission
    
    def check_permission(self, category: ToolCategory, 
                         required: Permission) -> bool:
        """检查权限"""
        granted = self.permissions.get(category, Permission.READ_ONLY)
        # Permission级别对比
        permission_level = {
            Permission.READ_ONLY: 1,
            Permission.READ_WRITE: 2,
            Permission.ADMIN: 3,
            Permission.DESTRUCTIVE: 4
        }
        return permission_level[granted] >= permission_level[required]
    
    def add_resource_allowlist(self, resource: str):
        """添加资源白名单"""
        self.resource_allowlist.append(resource)
    
    def log_operation(self, operation: Dict):
        """记录操作审计日志"""
        self.operation_log.append({
            **operation,
            "timestamp": time.time(),
            "agent_id": self.agent_id
        })
```

### 2. 最小权限原则实现

```python
class LeastPrivilegeAgent:
    """实现最小权限原则的Agent"""
    
    def __init__(self, task_description: str):
        self.task = task_description
        self.required_permissions = self._analyze_task_permissions(task_description)
        self.granted_permissions = {}
    
    def _analyze_task_permissions(self, task: str) -> Dict[ToolCategory, Permission]:
        """根据任务描述分析最低所需权限"""
        from openai import OpenAI
        
        client = OpenAI()
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{
                "role": "system",
                "content": """
                分析以下任务所需的最小权限集。
                按工具分类返回所需最低权限：
                - INFORMATION: read_only / read_write
                - FILE_SYSTEM: read_only / read_write / admin
                - DATABASE: read_only / read_write / destructive
                - NETWORK: read_only / read_write / admin
                - EXECUTION: none / specific_commands / admin
                - ADMINISTRATION: none / read_only / admin
                """
            }, {
                "role": "user",
                "content": task
            }]
        )
        return self._parse_permission_analysis(response.choices[0].message.content)
    
    def create_sandboxed_environment(self):
        """创建沙箱环境，仅开放必要权限"""
        sandbox_config = {
            "allow_network": ToolCategory.NETWORK in self.required_permissions,
            "allow_filesystem": ToolCategory.FILE_SYSTEM in self.required_permissions,
            "allow_execution": ToolCategory.EXECUTION in self.required_permissions,
            "restricted_paths": ["/etc", "/sys", "/proc", "/root"] if 
                ToolCategory.FILE_SYSTEM in self.required_permissions else ["/"],
            "max_tokens": 4096,
            "timeout_seconds": 30,
        }
        return sandbox_config
```

### 3. 工具函数安全调用框架

```python
import json
from typing import Any, Dict, List
from functools import wraps

class SecureToolFramework:
    """安全工具调用框架"""
    
    def __init__(self):
        self.tools = {}
        self.approval_required = set()  # 需要人工确认的工具
        self.rate_limits = {}
        self.audit_log = []
    
    def register_tool(self, name: str, func: Callable, 
                      category: ToolCategory, 
                      required_permission: Permission,
                      require_approval: bool = False,
                      rate_limit: Optional[int] = None):
        """注册安全工具"""
        self.tools[name] = {
            "func": func,
            "category": category,
            "required_permission": required_permission,
            "require_approval": require_approval
        }
        if require_approval:
            self.approval_required.add(name)
        if rate_limit:
            self.rate_limits[name] = {"limit": rate_limit, "calls": []}
    
    def call_tool(self, agent: AgentPermissionModel, tool_name: str, 
                  **kwargs) -> Dict[str, Any]:
        """安全调用工具（含权限检查）"""
        # 1. 工具存在检查
        if tool_name not in self.tools:
            return {"error": f"Tool '{tool_name}' not found"}
        
        tool = self.tools[tool_name]
        
        # 2. 权限检查
        if not agent.check_permission(tool["category"], tool["required_permission"]):
            agent.log_operation({
                "type": "permission_denied",
                "tool": tool_name,
                "reason": "权限不足"
            })
            return {"error": "Permission denied: insufficient privileges"}
        
        # 3. 速率限制
        if tool_name in self.rate_limits:
            now = time.time()
            tool_calls = self.rate_limits[tool_name]["calls"]
            # 移除1分钟前的记录
            tool_calls = [t for t in tool_calls if now - t < 60]
            if len(tool_calls) >= self.rate_limits[tool_name]["limit"]:
                return {"error": "Rate limit exceeded"}
            tool_calls.append(now)
        
        # 4. 人工确认（高风险操作）
        if tool["require_approval"]:
            approval = self._request_human_approval(tool_name, kwargs)
            if not approval:
                agent.log_operation({
                    "type": "rejected",
                    "tool": tool_name,
                    "params": kwargs
                })
                return {"error": "Operation rejected by human approver"}
        
        # 5. 执行并记录
        try:
            result = tool["func"](**kwargs)
            agent.log_operation({
                "type": "tool_call",
                "tool": tool_name,
                "params": kwargs,
                "result_truncated": str(result)[:200]
            })
            return {"success": True, "result": result}
        except Exception as e:
            agent.log_operation({
                "type": "error",
                "tool": tool_name,
                "error": str(e)
            })
            return {"error": f"Tool execution failed: {str(e)}"}
```

### 4. 敏感操作分级确认机制

```python
class HumanApprovalWorkflow:
    """人工确认工作流"""
    
    APPROVAL_LEVELS = {
        "info": {
            "requires_approval": False,
            "description": "仅信息查询，无需确认"
        },
        "moderate": {
            "requires_approval": True,
            "notification": "slack_message",
            "timeout": 300,  # 5分钟超时
        },
        "critical": {
            "requires_approval": True,
            "notification": "phone_call",
            "timeout": 60,
            "require_two_person": True,  # 双人确认
        }
    }
    
    def __init__(self):
        self.pending_approvals = {}
    
    def request_approval(self, agent_name: str, action: str, 
                         details: Dict, level: str = "moderate") -> str:
        """发起审批请求"""
        import uuid
        request_id = str(uuid.uuid4())[:8]
        
        self.pending_approvals[request_id] = {
            "agent": agent_name,
            "action": action,
            "details": details,
            "level": level,
            "status": "pending",
            "created_at": time.time()
        }
        
        # 通知审批人
        approval_config = self.APPROVAL_LEVELS[level]
        print(f"""
🔐 需要人工确认 - [{level.upper()}]
请求ID: {request_id}
Agent: {agent_name}
操作: {action}
详情: {json.dumps(details, ensure_ascii=False)}
审批超时: {approval_config['timeout']}秒
        """)
        
        return request_id
    
    def approve(self, request_id: str, approver: str) -> Dict:
        """批准操作"""
        if request_id in self.pending_approvals:
            self.pending_approvals[request_id]["status"] = "approved"
            self.pending_approvals[request_id]["approved_by"] = approver
            return {"success": True, "request_id": request_id}
        return {"error": "Request not found"}
    
    def reject(self, request_id: str, approver: str, reason: str) -> Dict:
        """拒绝操作"""
        if request_id in self.pending_approvals:
            self.pending_approvals[request_id]["status"] = "rejected"
            self.pending_approvals[request_id]["rejected_by"] = approver
            self.pending_approvals[request_id]["reason"] = reason
            return {"success": True, "request_id": request_id}
        return {"error": "Request not found"}
```

### 5. Agent越权攻击场景

```text
# Agent越权攻击典型场景

## 场景1：工具调用链攻击
攻击者使Agent递归调用工具，绕过单次权限检查
示例: Agent调用"读取文件"工具 → 读取到脚本 → 自动执行脚本
防御: 禁止工具调用链中的权限升级，扁平化调用栈

## 场景2：参数混淆攻击
攻击者通过构造特殊参数，使工具执行非预期操作
示例: Agent调用"删除文件(file_path)"，攻击者传入 "../../etc/passwd"
防御: 参数白名单、路径规范化检查

## 场景3：权限提升攻击
攻击者利用Agent的写权限修改自身配置文件
防御: Agent配置不可变，运行时权限只降不升

## 场景4：社会工程间接注入
攻击者通过对话使Agent主动调用高风险工具
防御: 高风险操作始终需要人工确认
```

### 6. 安全Agent架构设计原则

```text
# AI Agent安全架构设计原则

## 1. 最小权限（Least Privilege）
- 每个Agent仅获得完成任务所需的最小权限集
- 使用动态权限析，根据当前任务上下文授予权限
- 任务完成后立即回收权限

## 2. 纵深防御（Defense in Depth）
输入层: Prompt过滤 → 指令验证
权限层: 权限检查 → 资源白名单
执行层: 沙箱隔离 → 操作审计
输出层: 内容过滤 → 数据脱敏

## 3. 人工参与（Human-in-the-Loop）
- 高风险操作必须人工确认
- 关键决策保留人类审批节点
- 设置操作超时和自动回滚

## 4. 可审计（Auditability）
- 所有Agent操作记录完整审计日志
- 日志包含: 时间戳、Agent ID、操作类型、参数、结果
- 审计日志不可篡改（区块链或Write-Once存储）

## 5. 故障安全（Fail-Safe）
- Agent出错时默认拒绝（Deny by Default）
- 设置操作边界和资源配额
- 实现断路器模式，异常时自动熔断
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| LangChain | Agent框架（含安全组件） | https://github.com/langchain-ai/langchain |
| AutoGPT | 自主Agent（权限控制示例） | https://github.com/Significant-Gravitas/AutoGPT |
| CrewAI | 多Agent协作框架 | https://github.com/joaomdmoura/crewAI |
| OpenAI Function Calling | 工具调用权限控制 | https://platform.openai.com/docs/guides/function-calling |
| OWASP LLM Verification | LLM安全验证标准 | https://owasp.org/www-project-llm-verification-standard/ |

## 参考资源

- [OWASP LLM Top 10 — LLM08: Excessive Agency](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Anthropic — Responsible LLM Agent Design](https://www.anthropic.com/news/designing-responsible-agents)
- [Google — AI Agent安全白皮书](https://ai.google/responsibility/agent-safety/)
- [NIST AI RMF — 治理与控制](https://www.nist.gov/itl/ai-risk-management-framework)
- [LangSmith — Agent监控与审计](https://www.langchain.com/langsmith)
