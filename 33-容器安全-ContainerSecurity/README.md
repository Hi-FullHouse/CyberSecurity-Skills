# 容器安全 (Container Security)

## 概述

容器和 Kubernetes 已成为现代应用部署的标准，但其安全挑战不容忽视。本模块覆盖容器镜像安全、Kubernetes RBAC 与安全策略、运行时安全（Falco）以及容器逃逸检测与防御。

## 技能列表

| # | 技能名称 | 难度 |
|:---:|---------|:---:|
| 1 | [容器镜像安全与漏洞扫描](skills/容器镜像安全与漏洞扫描-ContainerImageSecurityScanning.md) | ★★★ |
| 2 | [Kubernetes RBAC与安全策略](skills/Kubernetes RBAC与安全策略-KubernetesRBACSecurityPolicy.md) | ★★★★ |
| 3 | [容器运行时安全(Falco)](skills/容器运行时安全-Falco-ContainerRuntimeSecurityFalco.md) | ★★★★ |
| 4 | [容器逃逸检测与防御](skills/容器逃逸检测与防御-ContainerEscapeDetectionDefense.md) | ★★★★★ |

## 关键工具

- Trivy / Grype — 漏洞扫描
- Falco / tracee — 运行时安全
- OPA / Kyverno — 策略引擎
- kube-bench / kube-hunter — 集群安全审计
- Cosign — 镜像签名
