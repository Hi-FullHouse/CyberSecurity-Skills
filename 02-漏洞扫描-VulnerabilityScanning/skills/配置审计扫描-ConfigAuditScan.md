---
id: 02-007
title: "🔧 配置审计扫描 (Configuration Audit Scanning)"
category: 漏洞扫描
category_en: "Vulnerability Scanning"
difficulty: ★★★
tools: "Lynis, OpenSCAP, CIS-CAT, ScoutSuite"
last_updated: 2025-07
tags: ["vulnerability-scanning", "web-security", "network-security", "database-security"]
subdomain: vulnerability-scanning
nist_csf: ["ID.RA-01", "DE.CM-08", "PR.IP-12"]
mitre_attack: ["T1595", "T1589", "T1592"]
---
# 🔧 配置审计扫描 (Configuration Audit Scanning)

## 概述
检查系统和应用程序的安全配置，发现默认配置、弱密码、不必要的服务、权限配置不当等安全问题。

## 核心技能

### 1. Linux系统安全配置审计

```bash
# 用户和组审计
cat /etc/passwd | grep -E "/bin/bash|/bin/sh"  # 列出可登录用户
cat /etc/sudoers | grep -v "^#"                 # sudo权限检查
awk -F: '($3 == 0) {print}' /etc/passwd         # UID 0用户检查
lastlog | grep -v "Never"                       # 最近登录用户

# 文件权限审计
find / -perm -4000 -o -perm -2000 2>/dev/null   # SUID/SGID文件
find / -type f -perm -o+w 2>/dev/null           # 全局可写文件
find / -type d -perm -o+w 2>/dev/null           # 全局可写目录
ls -la /etc/shadow && ls -la /etc/passwd        # 关键文件权限

# 服务审计
systemctl list-units --type=service --state=running  # 运行中的服务
chkconfig --list                                    # SystemV服务
netstat -tlnp                                        # 监听端口
ss -tlnp                                             # 使用ss查看

# SSH配置审计
grep -E "^PermitRootLogin|^PasswordAuthentication|^Port" /etc/ssh/sshd_config

# 内核参数审计
sysctl kernel.randomize_va_space                    # ASLR
sysctl net.ipv4.conf.all.rp_filter                  # 反向路径过滤
sysctl net.ipv4.tcp_syncookies                      # SYN Cookies

# 日志审计
auditctl -l                                          # 查看审计规则
cat /etc/audit/rules.d/audit.rules                   # 审计规则配置
```

### 2. Windows系统安全配置审计

```powershell
# 用户和组审计
Get-LocalUser | Where-Object {$_.Enabled -eq $true}
Get-LocalGroupMember -Group Administrators
net user
net localgroup administrators

# 服务审计
Get-Service | Where-Object {$_.Status -eq "Running"}
Get-WmiObject win32_service | Select Name, PathName, StartName

# 注册表审计
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse"
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM"
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"

# 安全策略审计
secedit /export /cfg secpolicy.inf
# 检查密码策略、锁定策略、审计策略

# 审计策略检查
auditpol /get /category:*

# 共享权限检查
Get-SmbShare
net share
```

### 3. Web服务器配置审计

**Nginx配置审计：**
```bash
# 检查敏感信息泄露
grep -i "server_tokens\|server_info" /etc/nginx/nginx.conf

# 检查目录列表
grep -i "autoindex on" /etc/nginx/sites-enabled/*

# 检查SSL配置
grep -i "ssl_protocols\|ssl_ciphers" /etc/nginx/nginx.conf

# 检查请求限制
grep -i "limit_req\|limit_conn" /etc/nginx/sites-enabled/*

# 检查CORS配置
grep -i "add_header.*Access-Control" /etc/nginx/sites-enabled/*
```

**Apache配置审计：**
```bash
# 检查目录列表
grep -i "Options.*Indexes" /etc/apache2/apache2.conf

# 检查服务器信息
grep -i "ServerSignature\|ServerTokens" /etc/apache2/conf-enabled/security.conf

# 检查HTTPS强制跳转
grep -i "RewriteRule.*443" /etc/apache2/sites-enabled/*

# 检查HSTS头
grep -i "Header.*Strict-Transport-Security" /etc/apache2/sites-enabled/*
```

### 4. Docker容器安全审计

```bash
# 使用Docker Bench Security
docker run --rm --net host --pid host --userns host \
  --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /var/lib:/var/lib \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /etc:/etc \
  docker/docker-bench-security

# 检查特权容器
docker ps --quiet | xargs docker inspect --format '{{.Id}}: Privileged={{.HostConfig.Privileged}}'

# 检查容器挂载
for c in $(docker ps -q); do
  echo "Container: $c"
  docker inspect $c --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}'
done

# 检查容器Capabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock alpine \
  sh -c "apk add jq && docker inspect $(docker ps -q) | jq '.[].HostConfig.CapAdd'"

# 检查镜像漏洞（使用Trivy）
trivy image nginx:latest
trivy image --severity CRITICAL,HIGH alpine:latest
```

### 5. Kubernetes安全审计

```bash
# 使用kube-bench检查CIS基准
kube-bench run --targets master,node

# 检查RBAC配置
kubectl get clusterrolebindings -o wide
kubectl get rolebindings --all-namespaces -o wide

# 检查Pod安全策略
kubectl get psp --all-namespaces

# 检查Secret是否加密
kubectl get secrets --all-namespaces

# 检查特权容器
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.spec.containers[*].securityContext.privileged}{"\n"}{end}'

# 使用Popeye检查集群健康
popeye --namespace all
```

### 6. 云服务配置审计

**AWS审计：**
```bash
# 使用Prowler
prowler -M html -o results

# 检查S3存储桶权限
aws s3api list-buckets --query "Buckets[*].Name"
for bucket in $(aws s3api list-buckets --query "Buckets[*].Name" --output text); do
  aws s3api get-bucket-acl --bucket $bucket
done

# 检查安全组规则（过于开放的端口）
aws ec2 describe-security-groups \
  --filters Name=ip-permission.cidr,Values=0.0.0.0/0 \
  --query "SecurityGroups[*].{Name:GroupName,Id:GroupId,Ports:IpPermissions[?IpProtocol=='tcp'].FromPort}"
```

**阿里云审计：**
```bash
# 使用ActionTrail查看操作记录
aliyun osscmd listallobject

# 检查OSS Bucket权限
aliyun oss ls --all-buckets
aliyun oss get-bucket-acl oss://bucket-name

# 检查安全组规则
aliyun ecs DescribeSecurityGroupAttribute --SecurityGroupId sg-xxx
```

## CIS基准检查项

| 类别 | 检查项 | 风险等级 |
|:---|:---|:---:|
| 账户策略 | 密码复杂度启用 | 高 |
| 认证策略 | 禁止root远程SSH登录 | 高 |
| 文件系统 | /tmp独立分区 | 中 |
| 文件系统 | SUID文件最小化 | 高 |
| 网络配置 | 禁用IP转发 | 中 |
| 日志审计 | auditd已启用 | 中 |
| 服务管理 | 移除不必要服务 | 低 |
| 内核参数 | ASLR已启用 | 中 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Lynis | Linux安全审计 | https://github.com/CISOfy/lynis |
| OpenSCAP | 合规性扫描 | https://www.open-scap.org/ |
| Docker Bench | Docker安全基准 | https://github.com/docker/docker-bench-security |
| kube-bench | K8s CIS基准 | https://github.com/aquasecurity/kube-bench |
| Prowler | AWS安全审计 | https://github.com/prowler-cloud/prowler |
| ScoutSuite | 多云审计 | https://github.com/nccgroup/ScoutSuite |
| Trivy | 容器镜像扫描 | https://github.com/aquasecurity/trivy |

## 参考资源
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [OWASP Configuration Guide](https://cheatsheetseries.owasp.org/cheatsheets/Configuration_Cheat_Sheet.html)
- [Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
