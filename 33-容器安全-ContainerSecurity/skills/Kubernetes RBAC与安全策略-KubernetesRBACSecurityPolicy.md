---
id: "33-002"
title: "Kubernetes RBAC与安全策略 (Kubernetes RBAC & Security Policy)"
category: "容器安全"
category_en: "Container Security"
difficulty: "★★★★"
tools: "kubectl, OPA/Gatekeeper, Kyverno, kube-bench, kube-hunter"
last_updated: "2026-05"
tags: [kubernetes, rbac, security-policy, admission-controller, pod-security]
subdomain: container-security
nist_csf: [PR.AC-01, PR.AC-04, PR.DS-03, DE.CM-08]
mitre_attack: [T1525, T1578, T1610, T1613]
---

# Kubernetes RBAC与安全策略 (Kubernetes RBAC & Security Policy)

## 概述

Kubernetes 安全的核心在于 RBAC 访问控制、Pod 安全策略和网络策略。错误配置的 RBAC 是 K8s 环境中最常见的安全漏洞。本技能覆盖 K8s RBAC 最小权限配置、Pod Security Standards、OPA/Gatekeeper 策略即代码和审计日志分析。

## 核心技能

### 1. Kubernetes RBAC 配置

```bash
# RBAC 角色与绑定

# 创建命名空间
kubectl create namespace security-demo

# 创建 ServiceAccount
kubectl create serviceaccount app-sa -n security-demo

# 创建角色（Role — 命名空间级别）
cat > app-role.yaml << 'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: security-demo
  name: app-reader
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list"]
EOF

kubectl apply -f app-role.yaml

# 创建角色绑定
kubectl create rolebinding app-reader-binding \
  --role=app-reader \
  --serviceaccount=security-demo:app-sa \
  -n security-demo

# 创建集群角色（ClusterRole — 集群级别）
cat > cluster-admin-role.yaml << 'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: security-viewer
rules:
- apiGroups: ["security.kubernetes.io"]
  resources: ["podsecuritypolicies"]
  verbs: ["get", "list"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "clusterroles", "rolebindings", "clusterrolebindings"]
  verbs: ["get", "list"]
EOF

kubectl apply -f cluster-admin-role.yaml

# 最小权限原则验证
# 模拟 API 访问
kubectl auth can-i list pods --as=system:serviceaccount:security-demo:app-sa
kubectl auth can-i delete pods --as=system:serviceaccount:security-demo:app-sa
kubectl auth can-i create deployments --as=system:serviceaccount:security-demo:app-sa
```

```bash
# RBAC 审计与攻击检测

# 检查哪些 ServiceAccount 有危险权限
# 1. 查找有 delete pods 权限的用户
kubectl get rolebindings --all-namespaces -o yaml | grep "delete"

# 2. 检查哪些用户有 secrets 读取权限
kubectl get clusterrolebindings -o yaml | grep -A5 "secrets"

# 3. 检查通配符权限
kubectl get clusterrole -o yaml | grep '"*"' -B5

# 4. 检查 secrets 访问
for crb in $(kubectl get clusterrolebinding -o name); do
    role=$(kubectl get $crb -o jsonpath='{.roleRef.name}')
    kubectl describe clusterrole $role 2>/dev/null | grep -q "secrets" && echo "Risk: $crb can access secrets"
done

# 5. RBAC 审计建议
# - 禁止通配符 (*) 权限
# - 避免绑定 cluster-admin 给非管理员
# - 使用 Role 代替 ClusterRole（尽量限制范围）
# - 定期审查未使用的 ServiceAccount
```

### 2. Pod 安全策略 (PSA/PSS)

```yaml
# Kubernetes Pod Security Standards (PSS)
# 三级安全标准: Privileged → Baseline → Restricted

# Namespace 标签强制 Pod 安全级别
apiVersion: v1
kind: Namespace
metadata:
  name: prod-critical
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
# 违反策略的 Pod 将被拒绝
# 符合 Restricted 级别的 Pod 示例:
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
  containers:
  - name: app
    image: app:1.0
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      readOnlyRootFilesystem: true
      runAsNonRoot: true
```

### 3. OPA/Gatekeeper 策略即代码

```yaml
# OPA Gatekeeper — 策略即代码
# 安装 Gatekeeper
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml

# 禁止特权容器策略
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspprivilegedcontainer
spec:
  crd:
    spec:
      names:
        kind: K8sPSPPrivilegedContainer
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8spspprivileged
      violation[{"msg": msg}] {
        container := input.review.object.spec.containers[_]
        container.securityContext.privileged
        msg := sprintf("Privileged container '%v' is not allowed", [container.name])
      }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPPrivilegedContainer
metadata:
  name: no-privileged-containers
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
    namespaces:
    - "production"
```

```yaml
# Kyverno — K8s 原生策略引擎
# 安装 Kyverno
kubectl create -f https://raw.githubusercontent.com/kyverno/kyverno/main/config/install.yaml

# Kyverno 策略 — 禁止 latest 镜像标签
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-latest-tag
spec:
  validationFailureAction: enforce
  rules:
  - name: require-image-tag
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Using 'latest' tag for image is not allowed"
      pattern:
        spec:
          containers:
          - image: "!*:latest"
---
# Kyverno 策略 — 要求只读根文件系统
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-readonly-rootfs
spec:
  validationFailureAction: audit
  rules:
  - name: check-readonly-fs
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Containers must have readOnlyRootFilesystem set to true"
      pattern:
        spec:
          containers:
          - securityContext:
              readOnlyRootFilesystem: true
```

### 4. K8s 安全审计与加固

```bash
# kube-bench — CIS Kubernetes 基准检查
# 安装 kube-bench
curl -L https://github.com/aquasecurity/kube-bench/releases/latest/download/kube-bench_linux_amd64.tar.gz -o kube-bench.tar.gz
tar xzf kube-bench.tar.gz

# 运行 CIS 基准检查
./kube-bench --config-dir cfg --config cfg/config.yaml

# 仅检查主节点
./kube-bench run --targets master

# 仅检查工作节点
./kube-bench run --targets node

# 输出 JSON 报告
./kube-bench --json -o results.json

# kube-hunter — K8s 安全漏洞扫描
# 安装
pip install kube-hunter

# 扫描集群内部
kube-hunter

# 扫描指定 IP
kube-hunter --remote 10.0.0.100

# 快速扫描
kube-hunter --quick

# 网络策略示例
# 默认拒绝所有入站流量
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
---
# 只允许特定 Pod 访问
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app-access
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api-server
  ingress:
  - from:
    - podSelector:
        matchLabels:
          role: frontend
    ports:
    - port: 8080
```

```python
"""K8s 安全自动化审计"""

import json

class K8sSecurityAudit:
    """K8s 安全审计"""
    
    def __init__(self, cluster_resources):
        self.resources = cluster_resources
    
    def audit_rbac(self):
        """审计 RBAC 配置"""
        findings = []
        
        for role in self.resources.get("clusterroles", []):
            for rule in role.get("rules", []):
                # 检测通配符权限
                if "*" in rule.get("resources", []) or "*" in rule.get("verbs", []):
                    findings.append({
                        "type": "wide_permission",
                        "severity": "HIGH",
                        "resource": role["name"],
                        "issue": "ClusterRole 包含通配符权限",
                        "rules": rule
                    })
        
        for binding in self.resources.get("clusterrolebindings", []):
            if binding.get("roleRef", {}).get("name") == "cluster-admin":
                for subject in binding.get("subjects", []):
                    if subject.get("kind") != "User" or \
                       not subject.get("name", "").startswith("admin"):
                        findings.append({
                            "type": "excessive_privilege",
                            "severity": "CRITICAL",
                            "resource": binding["name"],
                            "issue": f"非管理员主体绑定了 cluster-admin: {subject}"
                        })
        
        return findings
    
    def audit_pod_security(self):
        """审计 Pod 安全配置"""
        findings = []
        
        for pod in self.resources.get("pods", []):
            containers = pod.get("spec", {}).get("containers", [])
            
            for c in containers:
                sec = c.get("securityContext", {})
                pod_sec = pod.get("spec", {}).get("securityContext", {})
                
                if sec.get("privileged"):
                    findings.append({
                        "type": "privileged_container",
                        "severity": "CRITICAL",
                        "resource": f"{pod['metadata']['namespace']}/{pod['metadata']['name']}",
                        "issue": f"容器 {c['name']} 运行在特权模式"
                    })
                
                if not pod_sec.get("runAsNonRoot"):
                    findings.append({
                        "type": "run_as_root",
                        "severity": "HIGH",
                        "resource": f"{pod['metadata']['namespace']}/{pod['metadata']['name']}",
                        "issue": "Pod 允许以 root 运行"
                    })
        
        return findings
    
    def generate_report(self):
        """生成审计报告"""
        rbac_findings = self.audit_rbac()
        pod_findings = self.audit_pod_security()
        
        return {
            "summary": {
                "rbac_issues": len(rbac_findings),
                "pod_security_issues": len(pod_findings),
                "total_findings": len(rbac_findings) + len(pod_findings)
            },
            "rbac_findings": rbac_findings,
            "pod_security_findings": pod_findings
        }

# 使用示例
auditor = K8sSecurityAudit({
    "clusterroles": [{"name": "admin-role", "rules": [{"resources": ["*"], "verbs": ["*"]}]}],
    "clusterrolebindings": [{"name": "dev-bind", "roleRef": {"name": "cluster-admin"}, "subjects": [{"kind": "ServiceAccount", "name": "dev-sa"}]}],
    "pods": []
})
report = auditor.generate_report()
print(json.dumps(report, indent=2))
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| OPA Gatekeeper | K8s 策略引擎 | https://github.com/open-policy-agent/gatekeeper |
| Kyverno | K8s 原生策略引擎 | https://kyverno.io/ |
| kube-bench | CIS 基准检查 | https://github.com/aquasecurity/kube-bench |
| kube-hunter | K8s 安全扫描 | https://github.com/aquasecurity/kube-hunter |
| kubescape | K8s 安全态势 | https://github.com/kubescape/kubescape |

## 参考资源

- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NSA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.1_20220829.PDF)
- [OPA Gatekeeper Documentation](https://open-policy-agent.github.io/gatekeeper/website/docs/)
- [Kyverno Policy Gallery](https://kyverno.io/policies/)
