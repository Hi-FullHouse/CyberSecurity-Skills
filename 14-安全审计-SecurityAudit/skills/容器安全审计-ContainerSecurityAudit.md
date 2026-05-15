---
id: 14-004
title: "🐳 容器安全审计 (Container Security Audit)"
category: 安全审计
category_en: "Security Audit"
difficulty: ★★★
tools: "Trivy, Dockle, kube-bench, Falco, Dagda"
last_updated: 2025-07
tags: ["security-audit", "compliance", "cloud-audit", "container-audit", "network-audit"]
subdomain: security-audit
nist_csf: ["ID.GV-01", "ID.RM-01", "ID.SC-01"]
mitre_attack: []
---
# 🐳 容器安全审计 (Container Security Audit)

## 概述
对容器化环境（Docker、Kubernetes、容器镜像仓库）进行安全审计，覆盖容器镜像漏洞扫描、运行时安全、K8s集群安全配置、网络策略、RBAC权限等。

## 核心技能

### 1. Docker安全审计

**Docker守护进程安全配置：**
```bash
# 检查Docker守护进程配置
cat /etc/docker/daemon.json

# 推荐安全配置
{
  "icc": false,                    # 禁止容器间通信
  "log-driver": "json-file",
  "log-opts": {"max-size": "10m", "max-file": "3"},
  "userns-remap": "default",       # 用户命名空间隔离
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "seccomp-profile": "/etc/docker/seccomp.json"
}
```

**Docker运行时安全检查：**
```bash
# 检查容器运行状态
docker ps --quiet | xargs docker inspect --format '{{.Id}}: User={{.Config.User}}'

# 检查特权容器
docker ps --quiet | xargs docker inspect --format '{{.Id}}: Privileged={{.HostConfig.Privileged}}'

# 检查容器挂载的敏感目录
docker ps --quiet | xargs docker inspect --format '{{.Id}}: Mounts={{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}'

# 检查容器资源限制
docker ps --quiet | xargs docker inspect --format '{{.Id}}: Memory={{.HostConfig.Memory}} CPU={{.HostConfig.CpuShares}}'

# 使用Dockle进行安全审计
dockle nginx:latest
dockle --exit-code 1 nginx:latest
```

### 2. 容器镜像安全扫描

**Trivy - 漏洞扫描：**
```bash
# 扫描镜像
trivy image nginx:1.21
trivy image --severity CRITICAL,HIGH nginx:1.21

# 扫描文件系统
trivy filesystem --severity CRITICAL /path/to/project

# 扫描仓库
trivy repo https://github.com/org/repo

# 生成HTML报告
trivy image --format html --output report.html nginx:1.21

# 扫描SBOM
trivy sbom ./sbom.spdx.json
```

**Dockerfile安全审计：**
```dockerfile
# 不安全的Dockerfile示例
FROM ubuntu:latest                  # 使用latest标签
RUN apt-get update && apt-get install -y curl vim  # 不必要的调试工具
COPY id_rsa /root/.ssh/             # 泄露密钥
USER root                           # 使用root用户
EXPOSE 22                           # 开放SSH
CMD ["/usr/sbin/sshd", "-D"]        # 运行SSH服务

# 安全的Dockerfile示例
FROM ubuntu:22.04@sha256:xxx        # 固定base镜像摘要
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*  # 清理缓存减小体积
COPY --chown=appuser:appuser app /app
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser                        # 使用非root用户
EXPOSE 8080
HEALTHCHECK --interval=30s CMD curl -f http://localhost:8080/ || exit 1
```

### 3. Kubernetes安全审计

**kube-bench - CIS Benchmark检查：**
```bash
# 运行kube-bench
kube-bench run
kube-bench run --targets master
kube-bench run --targets node
kube-bench run --check 1.1.1,1.1.2,1.2.1

# JSON格式输出
kube-bench run --json > results.json

# 修复建议
kube-bench run --config-dir ./cfg
```

**K8s RBAC审计：**
```bash
# 检查集群角色绑定
kubectl get clusterrolebindings -o wide
kubectl describe clusterrolebinding cluster-admin

# 检查ServiceAccount权限
kubectl get serviceaccounts --all-namespaces
kubectl get rolebindings --all-namespaces

# 检查是否有通配权限
kubectl get clusterroles -o json | jq '.items[] | select(.rules[].resources[]? | contains("*"))'

# 使用kubectl-who-can检查
kubectl who-can create pods
kubectl who-can delete deployments
```

**Pod安全审计：**
```yaml
# 安全的Pod配置
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: app:1.0
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    resources:
      limits:
        memory: "256Mi"
        cpu: "500m"
```

### 4. 容器网络审计

```bash
# 检查K8s网络策略
kubectl get networkpolicies --all-namespaces
kubectl describe networkpolicy -n default deny-all

# 检查是否存在默认拒绝策略
kubectl get networkpolicies -A | wc -l

# Calico网络策略
calicoctl get networkpolicy --all-namespaces
calicoctl get profiles

# 服务网格mTLS检查（Istio）
istioctl authz check <pod-name>
istioctl proxy-status
```

### 5. 容器运行时安全

**Falco - 运行时威胁检测：**
```bash
# 安装Falco
falco

# 自定义规则
cat /etc/falco/falco_rules.yaml

# 检测规则示例
规则: 容器内启动Shell
规则: 容器挂载敏感目录 /etc/hostname
规则: 容器内使用kubectl
规则: 容器网络连接外部IP
```

**Security Context Constraint (SCC)/Pod Security Standards：**
```text
Privileged    - 非受限（仅可信工作负载）
Baseline      - 基本安全（适用于大多数Pod）
Restricted    - 严格受限（最安全）
```

## 常用工具
| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Trivy | 容器镜像漏洞扫描 | https://github.com/aquasecurity/trivy |
| kube-bench | K8s CIS基准检查 | https://github.com/aquasecurity/kube-bench |
| kube-hunter | K8s渗透测试 | https://github.com/aquasecurity/kube-hunter |
| Dockle | Docker镜像安全审计 | https://github.com/goodwithtech/dockle |
| Falco | 容器运行时安全 | https://falco.org/ |
| Popeye | K8s集群健康检查 | https://github.com/derailed/popeye |
| Kyverno | K8s策略引擎 | https://kyverno.io/ |

## 参考资源
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes/)
- [NIST SP 800-190 容器安全](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [OWASP Docker Security](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/)
