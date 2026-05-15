---
id: "33-003"
title: "容器运行时安全 (Container Runtime Security with Falco)"
category: "容器安全"
category_en: "Container Security"
difficulty: "★★★★"
tools: "Falco, tracee, Sysdig, Cilium Tetragon, Seccomp"
last_updated: "2026-05"
tags: [container-security, runtime-security, falco, syscall-monitoring, threat-detection]
subdomain: container-security
nist_csf: [DE.CM-01, DE.CM-08, PR.PT-01, PR.PT-03]
mitre_attack: [T1525, T1578, T1610, T1611]
---

# 容器运行时安全 (Container Runtime Security with Falco)

## 概述

容器运行时安全关注容器运行时的行为监控和威胁检测。与镜像扫描不同，运行时安全检测的是容器在运行过程中产生的异常行为。本技能覆盖 Falco 规则引擎、系统调用监控、tracee/eBPF 分析和运行时异常检测。

## 核心技能

### 1. Falco 部署配置

```bash
# Falco 安装
# 使用 Helm 安装到 Kubernetes
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# 安装 Falco
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set falco.driver.kind=modern_ebpf \
  --set falco.json_output=true \
  --set falco.file_output.enabled=true

# Docker 单机部署
docker run -d --name falco \
  --privileged \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v /proc:/host/proc:ro \
  -v /boot:/host/boot:ro \
  -v /lib/modules:/host/lib/modules:ro \
  -v /usr:/host/usr:ro \
  -v /etc/falco:/etc/falco \
  falcosecurity/falco:latest

# 检查 Falco 状态
falco --version
kubectl logs -n falco -l app.kubernetes.io/name=falco

# Falco 输出示例
# 23:45:12.345678901: Critical Shell spawned in container (user=root container_id=abc123 image=nginx)
```

### 2. Falco 规则编写

```yaml
# Falco 规则文件: /etc/falco/falco_rules.local.yaml

# 基础结构
- rule: Terminal Shell in Container
  desc: Detect shell spawned inside a container
  condition: >
    spawned_process and container
    and shell_procs
    and not user_expected_shell_container
  output: >
    Shell spawned in container
    (user=%user.name container_id=%container.id image=%container.image)
  priority: WARNING
  tags: [container, shell, mitre_execution]

# 自定义规则
- rule: Crypto Mining Detection
  desc: Detect cryptocurrency mining processes
  condition: >
    spawned_process and container
    and proc.name in (str_miner_procs)
  output: >
    Crypto mining process detected
    (user=%user.name container=%container.name proc=%proc.name)
  priority: CRITICAL
  tags: [container, crypto, mitre_impact]

- rule: Unexpected Network Connection
  desc: Detect unexpected outbound connections
  condition: >
    outbound and container
    and not allowed_outbound_destinations
  output: >
    Unexpected outbound connection
    (proc=%proc.name connection=%fd.name container=%container.id)
  priority: WARNING
  tags: [network, container, mitre_exfiltration]

# 宏定义
- macro: str_miner_procs
  condition: proc.name in (str_miner_procs)
- list: str_miner_procs
  items: ["xmrig", "minerd", "cgminer", "bfgminer", "cpuminer"]

- macro: allowed_outbound_destinations
  condition: >
    fd.sip in ("8.8.8.8", "1.1.1.1", "169.254.169.254")
    or fd.sport in (53, 443)

- macro: user_expected_shell_container
  condition: >
    container.image.repository in ("ubuntu", "alpine", "debian", "centos")
    and proc.name = "bash"
    and (evt.arg.flags bincontains "i" or evt.arg.flags bincontains "l")
```

### 3. tracee/eBPF 分析

```bash
# tracee — eBPF 运行时安全与取证

# 安装 tracee
docker run --name tracee --rm \
  --privileged \
  --pid=host \
  -v /lib/modules/:/lib/modules/:ro \
  -v /usr/src:/usr/src:ro \
  -v /tmp/tracee:/tmp/tracee \
  aquasec/tracee:latest

# 输出特定事件
docker run --name tracee --rm \
  --privileged --pid=host \
  -v /lib/modules/:/lib/modules/:ro \
  -v /usr/src:/usr/src:ro \
  aquasec/tracee:latest \
  --events execve,openat,connect

# 按容器过滤
docker run --name tracee --rm \
  --privileged --pid=host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /lib/modules/:/lib/modules/:ro \
  -v /usr/src:/usr/src:ro \
  aquasec/tracee:latest \
  --capture \
  --filter container=abc123

# 输出 JSON 格式
docker run --name tracee --rm \
  --privileged --pid=host \
  -v /lib/modules/:/lib/modules/:ro \
  -v /usr/src:/usr/src:ro \
  aquasec/tracee:latest \
  --output json \
  --events security_file_open,connect

# tracee 规则检测
# tracee 支持 signature-based detection
# - 标准规则: 标准违规检测
# - 签名规则: 基于行为的攻击检测

# Cilium Tetragon — eBPF 安全监控
# 部署 Tetragon
helm repo add cilium https://helm.cilium.io
helm install tetragon cilium/tetragon -n kube-system

# 监控进程执行
kubectl exec -n kube-system ds/tetragon -c tetragon -- \
  tetra getevents -o compact --process

# 监控网络连接
kubectl exec -n kube-system ds/tetragon -c tetragon -- \
  tetra getevents -o compact --network
```

```python
"""Falco 事件处理与分析"""

import json
import subprocess
from datetime import datetime

class FalcoEventHandler:
    """Falco 事件处理"""
    
    def __init__(self):
        self.events = []
        self.alert_handlers = {
            "CRITICAL": self._handle_critical,
            "WARNING": self._handle_warning,
            "NOTICE": self._handle_notice
        }
    
    def process_event(self, event_json):
        """处理单个 Falco 事件"""
        event = json.loads(event_json) if isinstance(event_json, str) else event_json
        
        priority = event.get("priority", "NOTICE")
        rule = event.get("rule", "unknown")
        output = event.get("output", "")
        
        # 记录事件
        self.events.append({
            "timestamp": event.get("time", datetime.now().isoformat()),
            "rule": rule,
            "priority": priority,
            "output": output,
            "container": event.get("container", {}),
            "process": {
                "name": event.get("proc", {}).get("name", ""),
                "pid": event.get("proc", {}).get("pid", 0)
            }
        })
        
        # 调用对应级别处理器
        handler = self.alert_handlers.get(priority, self._handle_unknown)
        handler(event)
        
        return self.events[-1]
    
    def _handle_critical(self, event):
        """严重事件 — 即时响应"""
        print(f"[CRITICAL] {event['rule']}: {event['output']}")
        # 触发 SOAR 工作流
        # - 隔离容器
        # - 阻断网络
        # - 通知 SOC
        self._trigger_soar_workflow(event)
    
    def _handle_warning(self, event):
        """警告事件 — 记录分析"""
        print(f"[WARNING] {event['rule']}: {event['output']}")
        # 记录到 SIEM
        self._send_to_siem(event)
    
    def _handle_notice(self, event):
        """通知事件 — 记录"""
        print(f"[NOTICE] {event['rule']}: {event['output']}")
    
    def _handle_unknown(self, event):
        print(f"[INFO] {event['rule']}: {event['output']}")
    
    def _trigger_soar_workflow(self, event):
        """触发 SOAR 响应"""
        print(f"  → SOAR: Isolating container {event.get('container', {}).get('id', 'unknown')}")
    
    def _send_to_siem(self, event):
        """发送到 SIEM"""
        print(f"  → SIEM: Forwarding event {event['rule']}")
    
    def get_stats(self):
        """获取事件统计"""
        stats = {"total": len(self.events), "by_priority": {}}
        for event in self.events:
            p = event["priority"]
            stats["by_priority"][p] = stats["by_priority"].get(p, 0) + 1
        return stats

# 使用示例
handler = FalcoEventHandler()
handler.process_event({
    "priority": "CRITICAL",
    "rule": "Terminal Shell in Container",
    "output": "Shell spawned in container (user=root container_id=abc image=nginx)",
    "container": {"id": "abc", "image": "nginx"},
    "proc": {"name": "bash", "pid": 1234}
})
print(handler.get_stats())
```

### 4. 运行时安全策略

```yaml
# Seccomp 配置文件 — 限制容器系统调用

# 默认 seccomp (RuntimeDefault)
# 路径: /var/lib/docker/containers/<container-id>/seccomp.json

# 自定义 seccomp — 白名单系统调用
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["read", "write", "open", "close", "stat", "fstat",
                "mmap", "munmap", "brk", "exit_group", "nanosleep",
                "recvmsg", "sendmsg", "connect", "bind"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}

# Docker 运行 with seccomp
docker run --security-opt seccomp=./custom-seccomp.json nginx

# Kubernetes 配置 seccomp
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: app:1.0
    securityContext:
      seccompProfile:
        type: Localhost
        localhostProfile: profiles/custom-seccomp.json

# AppArmor 配置
# 加载 AppArmor 策略
apparmor_parser -r /etc/apparmor.d/container-deny-write

# Docker 配置
docker run --security-opt "apparmor=container-deny-write" ubuntu bash

# Kubernetes 配置
apiVersion: v1
kind: Pod
metadata:
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: localhost/k8s-deny-write
spec:
  containers:
  - name: app
    image: ubuntu:22.04
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Falco | 容器运行时安全 | https://falco.org/ |
| tracee | eBPF 运行时检测 | https://github.com/aquasecurity/tracee |
| Cilium Tetragon | eBPF 安全监控 | https://github.com/cilium/tetragon |
| Sysdig | 容器监控与安全 | https://sysdig.com/ |
| Seccomp | 系统调用过滤 | https://docs.docker.com/engine/security/seccomp/ |

## 参考资源

- [Falco Rule Writing Guide](https://falco.org/docs/rules/)
- [Falco Rules Repository](https://github.com/falcosecurity/rules)
- [Container Runtime Security — SANS](https://www.sans.org/white-papers/container-runtime-security/)
- [eBPF for Security — Cilium](https://ebpf.io/)
- [NIST SP 800-190 — Container Security](https://csrc.nist.gov/publications/detail/sp/800-190/final)
