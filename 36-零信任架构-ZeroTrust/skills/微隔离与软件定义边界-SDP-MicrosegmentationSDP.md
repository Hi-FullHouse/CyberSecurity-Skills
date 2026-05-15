---
id: "36-002"
title: "微隔离与软件定义边界 (Microsegmentation & Software-Defined Perimeter)"
category: "零信任架构"
category_en: "Zero Trust Architecture"
difficulty: "★★★★"
tools: "Illumio, NSX, Calico, Tailscale, WireGuard"
last_updated: "2026-05"
tags: [zero-trust, microsegmentation, sdp, network-security, east-west-traffic]
subdomain: zero-trust
nist_csf: [PR.AC-04, PR.AC-05, PR.PT-01, PR.PT-03]
mitre_attack: [T1046, T1090, T1557]
---

# 微隔离与软件定义边界 (Microsegmentation & Software-Defined Perimeter)

## 概述

微隔离（Microsegmentation）是零信任网络的核心技术，将数据中心/云网络分为细粒度的安全段，限制东西向流量。软件定义边界（SDP）隐藏网络基础设施，只有经过认证的用户才能访问。本技能覆盖微隔离策略设计、SDP 部署和网络可视化。

## 核心技能

### 1. 微隔离策略设计

```python
"""微隔离策略引擎"""

class MicrosegmentationPolicy:
    """微隔离策略"""
    
    POLICY_TYPES = {
        "whitelist": "默认拒绝，仅允许规则定义的流量",
        "blacklist": "默认允许，阻断特定流量",
        "hybrid": "基于标签的动态策略"
    }
    
    def __init__(self):
        self.policies = []
        self.labels = {}
    
    def add_policy(self, name, source, dest, protocol, ports, action="deny"):
        """添加微隔离策略"""
        policy = {
            "name": name,
            "source": source,
            "destination": dest,
            "protocol": protocol,
            "ports": ports,
            "action": action
        }
        self.policies.append(policy)
        return policy
    
    def generate_kubernetes_network_policy(self):
        """生成 Kubernetes NetworkPolicy"""
        policies = []
        for p in self.policies:
            np = {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"name": p["name"]},
                "spec": {
                    "podSelector": {
                        "matchLabels": p["destination"]
                    },
                    "policyTypes": ["Ingress"],
                    "ingress": [{
                        "from": [{
                            "podSelector": {
                                "matchLabels": p["source"]
                            }
                        }],
                        "ports": [{"port": port, "protocol": p["protocol"].upper()}
                                  for port in p["ports"]]
                    }]
                }
            }
            policies.append(np)
        return policies
    
    def generate_nsg_rules(self):
        """生成云网络安全组规则"""
        nsg_rules = []
        for p in self.policies:
            rule = {
                "name": p["name"],
                "priority": 100 + len(nsg_rules),
                "direction": "Inbound",
                "access": p["action"],
                "protocol": p["protocol"],
                "source_address_prefix": p["source"].get("ip", "*"),
                "destination_port_range": ",".join(map(str, p["ports"]))
            }
            nsg_rules.append(rule)
        return nsg_rules
    
    def analyze_traffic_flow(self, flows):
        """分析流量合规性"""
        violations = []
        for flow in flows:
            allowed = False
            for policy in self.policies:
                if self._match_flow(flow, policy):
                    allowed = policy["action"] == "allow"
                    break
            
            if not allowed:
                violations.append({
                    "flow": f"{flow['src']} → {flow['dst']}:{flow.get('port', '*')}",
                    "status": "blocked - no matching allow policy"
                })
        
        return violations
    
    def _match_flow(self, flow, policy):
        """检查流量是否匹配策略"""
        # 简化的匹配逻辑
        return True

# 使用示例
mg = MicrosegmentationPolicy()
mg.add_policy("app-to-db", {"app": "frontend"}, {"app": "database"}, 
              "tcp", [3306], "allow")
mg.add_policy("deny-all-other", {"*": "*"}, {"app": "database"},
              "any", [0], "deny")

np = mg.generate_kubernetes_network_policy()
print("K8s NetworkPolicy generated")
```

### 2. SDP 部署与配置

```bash
# WireGuard — 轻量级 VPN/SDP
# 安装
sudo apt-get install wireguard

# 生成密钥对
wg genkey | tee private.key | wg pubkey > public.key

# 配置服务器 (wg0.conf)
cat > /etc/wireguard/wg0.conf << 'EOF'
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = <server-private-key>

# 客户端配置
[Peer]
PublicKey = <client-public-key>
AllowedIPs = 10.0.0.2/32
EOF

# 启动 WireGuard
wg-quick up wg0
systemctl enable wg-quick@wg0

# 客户端配置
cat > client.conf << 'EOF'
[Interface]
Address = 10.0.0.2/24
PrivateKey = <client-private-key>
DNS = 10.0.0.1

[Peer]
PublicKey = <server-public-key>
Endpoint = vpn.company.com:51820
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
EOF

# Tailscale — 基于 WireGuard 的 SDP
# 安装
curl -fsSL https://tailscale.com/install.sh | sh

# 启动连接
sudo tailscale up --authkey tskey-auth-xxxx

# 检查状态
tailscale status

# ACL 配置
cat > tailscale-acl.hujson << 'EOF'
{
  "acls": [
    {"action": "accept", "src": ["tag:dev"], "dst": ["tag:dev-server:*"]},
    {"action": "accept", "src": ["tag:ops"], "dst": ["*:*"]},
  ],
  "tagOwners": {
    "tag:dev": ["alice@company.com"],
    "tag:dev-server": ["bob@company.com"],
    "tag:ops": ["admin@company.com"],
  }
}
EOF

# Calico — Kubernetes 网络策略
# 安装 Calico
kubectl create -f https://docs.projectcalico.org/manifests/tigera-operator.yaml

# 全局网络策略
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: security.default-deny
spec:
  selector: all()
  types:
  - Ingress
  - Egress
---
# 允许特定命名空间间通信
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-api
  namespace: production
spec:
  selector: app == 'api-server'
  ingress:
  - action: Allow
    protocol: TCP
    source:
      namespaceSelector: role == 'frontend'
    destination:
      ports:
      - '8080'
```

### 3. 微隔离可视化

```python
"""微隔离可视化引擎"""

class MicrosegVisualizer:
    """微隔离流量可视化"""
    
    def __init__(self):
        self.connections = []
        self.workloads = set()
    
    def add_connection(self, source, dest, port, protocol, bytes_transferred):
        """添加连接记录"""
        self.connections.append({
            "source": source,
            "destination": dest,
            "port": port,
            "protocol": protocol,
            "bytes": bytes_transferred,
            "timestamp": datetime.now().isoformat()
        })
        self.workloads.add(source)
        self.workloads.add(dest)
    
    def build_dependency_graph(self):
        """构建依赖关系图"""
        graph = {w: {"dependents": set(), "dependencies": set()} for w in self.workloads}
        
        for conn in self.connections:
            graph[conn["source"]]["dependencies"].add(conn["destination"])
            graph[conn["destination"]]["dependents"].add(conn["source"])
        
        return graph
    
    def find_unintended_connections(self, allowed_connections):
        """查找未授权的连接"""
        actual = set()
        for conn in self.connections:
            actual.add((conn["source"], conn["destination"], conn["port"]))
        
        allowed = set()
        for conn in allowed_connections:
            allowed.add((conn["source"], conn["dest"], conn["port"]))
        
        return actual - allowed
    
    def analyze_risk(self):
        """分析连接风险"""
        high_risk = []
        for conn in self.connections:
            port = conn["port"]
            risk = "low"
            
            # 高危端口检查
            if port in [22, 3389, 5985, 5986]:
                risk = "high" if not conn.get("encrypted") else "medium"
            elif port == 3306 and conn["source"] != "app-server":
                risk = "high"  # 非预期的数据库访问
            
            high_risk.append({
                "connection": f"{conn['source']} → {conn['destination']}:{port}",
                "protocol": conn["protocol"],
                "risk": risk
            })
        
        return high_risk

# 使用示例
viz = MicrosegVisualizer()
viz.add_connection("frontend", "api", 8080, "tcp", 1024)
viz.add_connection("api", "db", 3306, "tcp", 4096)
viz.add_connection("unknown", "db", 3306, "tcp", 512)  # 未授权

unintended = viz.find_unintended_connections([
    {"source": "frontend", "dest": "api", "port": 8080},
    {"source": "api", "dest": "db", "port": 3306}
])
print(f"Unintended connections: {len(unintended)}")
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Tailscale | SDP/ZTN 网络 | https://tailscale.com/ |
| WireGuard | 安全 VPN 隧道 | https://www.wireguard.com/ |
| Calico | K8s 网络策略 | https://www.tigera.io/project-calico/ |
| Illumio | 微隔离平台 | https://www.illumio.com/ |
| VMware NSX | 网络虚拟化与微分段 | https://www.vmware.com/products/nsx.html |

## 参考资源

- [CISA Microsegmentation Guide](https://www.cisa.gov/zero-trust-maturity-model)
- [SDP Specification — CSA](https://cloudsecurityalliance.org/research/working-groups/software-defined-perimeter/)
- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [WireGuard Protocol](https://www.wireguard.com/protocol/)
- [NIST SP 800-207 — Microsegmentation](https://csrc.nist.gov/publications/detail/sp/800-207/final)
