---
id: 25-003
title: "📝 代码签名与供应链完整性 (Code Signing & Supply Chain Integrity)"
category: 供应链安全
category_en: "Supply Chain Security"
difficulty: ★★★★
tools: "cosign, sigstore, GnuPG, notary, in-toto, TUF"
last_updated: 2025-07
tags: ["supply-chain-security", "sbom", "dependency-check", "container-image", "third-party-risk"]
subdomain: supply-chain-security
nist_csf: ["ID.SC-01", "ID.SC-02", "PR.DS-10"]
mitre_attack: ["T1195", "T1525"]
---
# 📝 代码签名与供应链完整性 (Code Signing & Supply Chain Integrity)

## 概述

代码签名确保软件的**来源真实性**和**完整性**。通过数字签名、透明日志和可验证构建，构建从开发到部署的信任链。核心技术包括 **Sigstore**、**SLSA** 框架和 **in-toto** 元数据。

## 核心技能

### 1. Sigstore/cosign 容器签名

```bash
# Sigstore/cosign 安装与使用
# 安装 cosign
wget https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
chmod +x /usr/local/bin/cosign

# 使用密钥对签名
cosign generate-key-pair
cosign sign --key cosign.key my-registry/my-image:latest

# 使用密钥验证
cosign verify --key cosign.pub my-registry/my-image:latest

# 使用密钥对签名（blob/二进制文件）
cosign sign-blob --key cosign.key my-binary.tar.gz > my-binary.tar.gz.sig
cosign verify-blob --key cosign.pub --signature my-binary.tar.gz.sig my-binary.tar.gz

# 无密钥签名（Keyless Signing - 使用OIDC身份）
cosign sign my-registry/my-image:latest
# 弹出浏览器进行身份验证（GitHub/GitLab/Google等）
# 签名与OIDC身份绑定，记录到Rekor透明日志

# 无密钥验证
cosign verify my-registry/my-image:latest

# 使用Cosign验证SBOM附件
cosign verify-attestation --type cyclonedx my-registry/my-image:latest

# 查询透明日志
rekor-cli search --artifact sha256:artifact-digest
rekor-cli get --log-index 123456

# GitHub Actions中集成cosign
# actions/cosign 已预装
cosign sign --yes ${{ env.IMAGE_URL }}
```

### 2. SLSA 框架实施

```yaml
# SLSA (Supply-chain Levels for Software Artifacts) 框架

# SLSA Level 1 - 构建流程文档化
build:
  script:
    - make build
  provenance: false

# SLSA Level 2 - 有来源验证
build:
  script:
    - make build
  provenance:
    enabled: true
    type: "SLSA v1"
    
# SLSA Level 3 - 隔离构建（无外部影响）
# GitHub Actions 隔离构建
name: SLSA Level 3 Builder
on:
  workflow_dispatch:
  release:
    types: [published]

jobs:
  build:
    permissions:
      id-token: write
      contents: read
    uses: slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@v1.9.0
    with:
      go-version: 1.21
      evaluated-envs: "GOOS=linux GOARCH=amd64"

# SLSA Level 4 - 双人审查 + 可重现构建
# 使用 hermetic 构建（无网络、固定版本）
build:
  hermetic: true
  command: "docker build --network=none -t my-image:latest ."
  reproducible: true
  attestations:
    - "SLSA Build L3"
    - "Code Review"
```

### 3. in-toto 供应链元数据

```bash
# in-toto 安装与使用
pip install in-toto

# 创建密钥
in-toto-keygen my-project
# 生成: my-project.private-key, my-project.public-key

# 定义布局（描述供应链步骤）
in-toto-record start --step-name "clone" --key my-project.private-key --materials .
git clone https://github.com/owner/repo.git
in-toto-record stop --step-name "clone" --key my-project.private-key --products repo/

in-toto-record start --step-name "build" --key my-project.private-key --materials repo/
cd repo && make build
in-toto-record stop --step-name "build" --key my-project.private-key --products "repo/dist/*"

in-toto-record start --step-name "test" --key my-project.private-key --materials "repo/"
cd repo && make test
in-toto-record stop --step-name "test" --key my-project.private-key

# 验证整个供应链
in-toto-verify --layout root.layout --layout-keys my-project.public-key

# in-toto attestation
cat << 'EOF' > predicate.json
{
  "predicateType": "https://in-toto.io/attestation/release/v0.1",
  "subject": [{"name": "my-app", "digest": {"sha256": "abc123..."}}],
  "predicate": {
    "metadata": {
      "repository": "github.com/owner/repo",
      "commit": "abc123def456",
      "version": "v1.2.3"
    }
  }
}
EOF

# 创建in-toto attestation
in-toto-attestation --predicate predicate.json --key my-project.private-key
```

### 4. TUF (The Update Framework) 实现

```bash
# TUF 用于安全的软件更新分发
# 安装TUF
pip install tuf

# 创建仓库结构
python3 << 'EOF'
from tuf.api.metadata import Metadata, Root, Targets, Snapshot, Timestamp
from securesystemslib.formats import encode_canonical
import json

# 初始化TUF仓库
root = Root()
root.add_key(Root.type, "root-key-id", 
             {"keytype": "ed25519", "scheme": "ed25519", 
              "keyval": {"public": "..."}})
root.add_role("root", {"keyids": ["root-key-id"], "threshold": 1})
root.add_role("targets", {"keyids": ["targets-key-id"], "threshold": 1})
root.add_role("snapshot", {"keyids": ["snapshot-key-id"], "threshold": 1})
root.add_role("timestamp", {"keyids": ["timestamp-key-id"], "threshold": 1})

# 设置过期时间
root.snapshot.expires = "2026-01-01T00:00:00Z"
root.targets.expires = "2026-01-01T00:00:00Z"

# 保存
Metadata(Root.type, root).to_file("metadata/root.json")
print("TUF仓库初始化完成")
EOF

# TUF客户端更新
from tuf.ngclient import Updater

updater = Updater(
    metadata_dir="/path/to/metadata",
    metadata_base_url="https://example.com/metadata/",
    target_base_url="https://example.com/targets/",
    client_key="client-key"
)
updater.refresh()
updater.download_target("my-app.tar.gz")
```

### 5. 完整性验证检查清单

```yaml
# 供应链完整性检查清单
supply_chain_integrity_checks:
  # 代码层面
  code:
    - signed_commits: true
    - gpg_tags_sign: true
    - required_reviews: 2
    - branch_protection: true
    
  # 构建层面
  build:
    - hermetic_build: true
    - slsa_level: 3
    - build_attestation: true
    - isolated_environment: true
    
  # 分发层面
  distribution:
    - container_signature: true
    - sbom_attached: true
    - tuf_metadata: true
    - verifiable_provenance: true
    
  # 部署层面
  deployment:
    - admission_control: true
    - policy_verification: true
    - runtime_attestation: true
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Sigstore/cosign | 容器签名&代码签名 | https://www.sigstore.dev/ |
| in-toto | 供应链元数据框架 | https://in-toto.io/ |
| TUF | 安全更新框架 | https://theupdateframework.io/ |
| Notary | 容器信任框架 | https://github.com/notaryproject/notary |
| Grafeas | 供应链元数据API | https://grafeas.io/ |
| Witness | 供应链验证平台 | https://github.com/in-toto/witness |

## 参考资源

- [SLSA Framework](https://slsa.dev/)
- [Sigstore Security Model](https://docs.sigstore.dev/security/)
- [CNCF Supply Chain Security](https://www.cncf.io/reports/)
- [NIST SP 800-204C — Secure Supply Chain](https://csrc.nist.gov/publications/detail/sp/800-204c/final)
- [CISA Software Supply Chain Security](https://www.cisa.gov/software-supply-chain-security)
