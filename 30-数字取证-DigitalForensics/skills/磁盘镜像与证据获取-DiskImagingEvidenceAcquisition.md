---
id: "30-001"
title: "磁盘镜像与证据获取 (Disk Imaging & Evidence Acquisition)"
category: "数字取证"
category_en: "Digital Forensics"
difficulty: "★★★"
tools: "dd, dcfldd, guymager, FTK Imager, Sleuth Kit, Autopsy, Plaso, Photorec"
last_updated: "2026-05"
tags: [forensics, disk-imaging, evidence-acquisition, chain-of-custody, hash-verification]
subdomain: digital-forensics
nist_csf: [DE.CM-07, DE.AE-05, ID.RA-01]
mitre_attack: [T1003, T1552, T1560]
---

# 磁盘镜像与证据获取 (Disk Imaging & Evidence Acquisition)

## 概述

证据获取是数字取证的第一步，也是最关键的一步。任何取证分析的质量都取决于原始证据的完整性。本技能覆盖磁盘镜像工具的使用、写保护技术、证据保管链管理、哈希校验、文件系统分析、Windows/Linux痕迹取证与文件恢复。

## 核心技能

### 1. 磁盘镜像工具

```bash
# dd — 基础磁盘镜像
# 查看磁盘列表
sudo fdisk -l
sudo lsblk

# 创建原始镜像（推荐块大小 4M 提高速度）
sudo dd if=/dev/sda of=/evidence/case001/image.dd bs=4M conv=noerror,sync status=progress

# 使用 dcfldd（增强版 dd，支持哈希和分块）
dcfldd if=/dev/sda of=/evidence/case001/image.dd \
  bs=4M \
  hash=sha256 \
  hashlog=/evidence/case001/image.hash \
  hashwindow=1G \
  status=on \
  conv=noerror,sync

# dcfldd 分块镜像
dcfldd if=/dev/sda \
  of=/evidence/case001/image.dd \
  ofsplit=2G \
  bs=4M \
  hash=sha256 \
  hashlog=/evidence/case001/hash.log

# 通过网络传输镜像
dcfldd if=/dev/sda bs=4M | nc forensic-server 9999
# 接收端: nc -l -p 9999 > image.dd
```

```bash
# guymager — GUI 镜像工具
# 安装
sudo apt-get install guymager

# 启动
sudo guymager

# 使用 EnCase 格式（E01）压缩镜像
# guymager 支持:
# - Raw/DD 格式
# - EnCase E01 格式（支持压缩和元数据）
# - 验证写入（AFF 格式）

# FTK Imager (Windows CLI)
# 创建磁盘镜像
ftkimager.exe \\.\PhysicalDrive0 \
  C:\Evidence\case001.E01 \
  --e01 --compress 2 \
  --case-number "CASE-001" \
  --evidence-number "E01" \
  --description "Suspect Laptop HDD"

# FTK Imager GUI 操作: File → Create Disk Image → 选择源 → 选择格式(DD/E01) → 保存
```

### 2. 写保护技术

```bash
# 硬件写保护 — 使用取证桥接器
# Tableau T35u/Rocky 5 等硬件写保护器
# 连接后检查设备状态

# 确认写保护生效
sudo hdparm -r /dev/sdb
# 返回: readonly = 1 (on) 确认写保护

# 软件写保护 — Linux
# 使用 mount 只读挂载
sudo mount -o ro,noexec /dev/sdb1 /mnt/evidence

# 使用 blkdiscard 验证
# 尝试写入测试（不应成功）
sudo dd if=/dev/zero of=/dev/sdb bs=512 count=1
dd: error writing '/dev/sdb': Operation not permitted

# macOS 软件写保护
# 使用 asr 命令
sudo asr imagescan --source /dev/disk2
sudo asr --source /dev/disk2 --target /tmp/forensic_image.dmg --erase
```

### 3. 文件系统分析

```bash
# Autopsy — 开源数字取证平台（Sleuth Kit GUI）
# 创建案例 → 添加镜像 → 自动分析

# Sleuth Kit 命令行
# 查看磁盘分区表
mmls /mnt/evidence/disk_image.dd

# 列出文件和目录
fls -f ntfs -o 2048 /mnt/evidence/disk_image.dd  # o:分区偏移

# 递归列出所有文件
fls -r -f ntfs -o 2048 /mnt/evidence/disk_image.dd > file_list.txt

# 使用icat提取特定文件
icat -f ntfs -o 2048 /mnt/evidence/disk_image.dd 12345-123 > extracted_file.dll

# 查看文件元数据（MAC时间）
istat -f ntfs -o 2048 /mnt/evidence/disk_image.dd 12345
```

### 4. 证据保管链

```python
"""证据保管链管理"""

import json
from datetime import datetime

class ChainOfCustody:
    """数字证据保管链"""
    
    def __init__(self, case_id, evidence_id):
        self.case_id = case_id
        self.evidence_id = evidence_id
        self.evidence = {
            "case_id": case_id,
            "evidence_id": evidence_id,
            "description": "",
            "source": "",
            "acquisition_method": "",
            "hash_sha256": "",
            "hash_md5": "",
            "size_bytes": 0,
            "acquisition_date": None,
            "acquirer": "",
            "transfers": []
        }
    
    def record_acquisition(self, device, method, acquirer, hash_value):
        """记录证据获取"""
        self.evidence.update({
            "device": device,
            "acquisition_method": method,
            "hash_sha256": hash_value,
            "acquisition_date": datetime.now().isoformat(),
            "acquirer": acquirer
        })
        self.add_transfer("acquisition", acquirer, 
                         f"Evidence acquired from {device}")
    
    def add_transfer(self, custodian, reason, location=""):
        """记录证据转移"""
        transfer = {
            "from": self.evidence["transfers"][-1]["to"] 
                if self.evidence["transfers"] else "crime_scene",
            "to": custodian,
            "date": datetime.now().isoformat(),
            "reason": reason,
            "location": location or self.evidence.get("location", "lab")
        }
        self.evidence["transfers"].append(transfer)
    
    def verify_integrity(self, current_hash):
        """验证证据完整性"""
        original = self.evidence["hash_sha256"]
        is_intact = original == current_hash
        return {
            "original_hash": original,
            "current_hash": current_hash,
            "intact": is_intact,
            "verified_at": datetime.now().isoformat()
        }
    
    def export_report(self):
        """导出保管链报告"""
        report = f"""
        ================================================
        证据保管链报告
        ================================================
        案件编号: {self.evidence['case_id']}
        证据编号: {self.evidence['evidence_id']}
        获取时间: {self.evidence['acquisition_date']}
        获取人: {self.evidence['acquirer']}
        SHA256: {self.evidence['hash_sha256'][:32]}...
        
        转移记录:
        """
        for t in self.evidence["transfers"]:
            report += f"\n  {t['date']} | {t['from']} → {t['to']} | {t['reason']}"
        
        return report

# 使用示例
coc = ChainOfCustody("CASE-2026-001", "E01")
coc.record_acquisition(
    device="/dev/sda (500GB HDD)",
    method="dcfldd raw image",
    acquirer="Jack Chen",
    hash_value="a1b2c3d4..."
)
coc.add_transfer("forensic_lab", "Transported to lab", "Lab-1")
print(coc.export_report())
```

### 5. 镜像格式与哈希验证

```bash
# 取证镜像格式对比
# Raw (.dd/.raw/.img): 最基础，无压缩
# E01 (EnCase): 支持压缩、元数据、校验和
# AFF (Advanced Forensic Format): 开源压缩格式

# 转换镜像格式
# Raw → E01
sudo apt-get install libewf-tools
ewfacquire /evidence/image.dd \
  --format encase6 \
  --compress 2 \
  --case-number "CASE-001" \
  -C /evidence/case001.E01

# E01 → Raw
ewfexport /evidence/case001.E01 \
  --format raw \
  -t /evidence/exported_image.dd

# 哈希验证 — 镜像创建时
sha256sum /evidence/image.dd > /evidence/image.hash

# 验证镜像完整性
sha256sum -c /evidence/image.hash

# 验证 E01 内嵌校验
ewfinfo /evidence/case001.E01 | grep -i hash

# 挂载镜像进行只读访问
# 使用 mount -o loop
sudo mount -o loop,ro /evidence/image.dd /mnt/forensic

# 使用 xmount（自动转换格式）
sudo xmount --in dd --out vdi /evidence/image.dd /mnt/virtual
```

```python
"""取证镜像哈希验证"""

import hashlib
import sys

class ForensicHashVerifier:
    """取证哈希校验器"""
    
    @staticmethod
    def calculate_hash(filepath, algorithms=["sha256"]):
        """计算文件哈希"""
        hashers = {alg: hashlib.new(alg) for alg in algorithms}
        block_size = 65536
        
        with open(filepath, 'rb') as f:
            while True:
                block = f.read(block_size)
                if not block:
                    break
                for hasher in hashers.values():
                    hasher.update(block)
        
        return {alg: h.hexdigest() for alg, h in hashers.items()}
    
    @staticmethod
    def verify_image_segments(segment_pattern, total_segments):
        """验证分段镜像"""
        combined = hashlib.sha256()
        for i in range(total_segments):
            path = f"{segment_pattern}.{i:03d}"
            with open(path, 'rb') as f:
                while True:
                    data = f.read(65536)
                    if not data:
                        break
                    combined.update(data)
        return combined.hexdigest()

# 使用示例
verifier = ForensicHashVerifier()
hashes = verifier.calculate_hash("/evidence/image.dd", 
                                  algorithms=["sha256", "md5"])
print(f"SHA256: {hashes['sha256']}")
print(f"MD5: {hashes['md5']}")
```

### 6. Windows痕迹分析

```bash
# Prefetch (程序执行记录) — C:\Windows\Prefetch
# 工具: PECmd (Eric Zimmerman)
PECmd.exe -d "C:\Windows\Prefetch" --csv "output.csv"

# Jump Lists (用户操作记录)
# C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\
# 工具: JLECmd
JLECmd.exe -d "C:\Users\admin\AppData\Roaming\Microsoft\Windows\Recent" --csv output.csv

# AmCache (程序执行历史) — C:\Windows\AppCompat\Programs\Amcache.hve
# 工具: AmcacheParser
AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" --csv output.csv

# ShimCache (AppCompatCache) — 注册表中
# 位置: SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
# 工具: AppCompatCacheParser
AppCompatCacheParser.exe --csv output.csv

# 回收站分析 — C:\$Recycle.Bin\<SID>\
# 工具: RBCmd
RBCmd.exe -d "C:\$Recycle.Bin"

# 浏览器历史
# Chrome: C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\History
# 工具: Hindsight
hindsight -i "C:\Users\admin\AppData\Local\Google\Chrome\User Data" -o output
# Edge/Firefox 类似
```

### 7. Linux痕迹分析

```bash
# Bash历史
cat ~/.bash_history
for user in $(ls /home/); do
    echo "=== $user ==="
    cat /home/$user/.bash_history 2>/dev/null
done

# 检查SSH后门
cat ~/.ssh/authorized_keys
cat /etc/ssh/sshd_config | grep -v "^#" | grep -v "^$"

# 检查计划任务
ls -la /var/spool/cron/crontabs/
cat /etc/crontab
ls -la /etc/cron.d/

# 检查systemd服务后门
cat /etc/systemd/system/*.service
systemctl list-units --type=service --state=running

# 登录历史
last -100 > login_history.txt

# 检查SUID/SGID文件（提权痕迹）
find / -perm -4000 -ls 2>/dev/null
find / -perm -2000 -ls 2>/dev/null

# 最近修改文件（攻击时间线）
find /etc -mtime -7 -ls 2>/dev/null
find /var/www -mtime -7 -ls 2>/dev/null
```

### 8. 文件恢复

```bash
# Photorec — 恢复已删除文件（支持多种文件系统）
sudo photorec /dev/sda

# extundelete — ext3/ext4文件系统恢复
sudo extundelete /dev/sda2 --restore-all --output-dir /recovery/

# 恢复指定目录
sudo extundelete /dev/sda2 --restore-directory /home/user/documents/

# NTFS删除文件恢复
# 使用Autopsy的文件浏览功能 → 按"Deleted Files"过滤
```

### 9. 文件特征分析

```bash
# 识别文件类型（不依赖扩展名）
file suspicious_file
file --mime-type suspicious_file

# 提取EXIF信息
exiftool image.jpg

# 查看PE文件头信息
# 工具: Exeinfo PE, PEStudio, DIE (Detect It Easy)

# 计算哈希值（威胁情报关联）
sha256sum suspicious_file
md5sum suspicious_file
```

### 10. 取证时间线

```bash
# 使用Plaso (log2timeline) 自动化时间线
log2timeline.py --parsers ntfs,filestat,pe,chrome_cache,prefetch timeline.dump /mnt/evidence/disk_image.dd

# 时间线分析
psort.py timeline.dump -o l2tcsv -w timeline.csv

# 关键时间节点：
# ● 恶意文件首次出现时间
# ● 系统文件被篡改时间
# ● 计划任务创建时间
# ● 用户登录/登出时间
# ● 数据外传Zip包的创建时间
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| dcfldd | 增强磁盘镜像 | https://sourceforge.net/projects/dcfldd/ |
| guymager | GUI 取证镜像 | https://guymager.sourceforge.io/ |
| FTK Imager | Windows 取证镜像 | https://www.exterro.com/digital-forensics-software/ftk-imager |
| EnCase | 商业取证平台 | https://www.opentext.com/products/encase-forensic |
| libewf | E01 格式工具集 | https://github.com/libyal/libewf |
| Autopsy | 开源数字取证平台 | https://www.autopsy.com/ |
| Sleuth Kit | 命令行取证工具集 | https://www.sleuthkit.org/ |
| Plaso (log2timeline) | 超级取证时间线 | https://github.com/log2timeline/plaso |
| Eric Zimmerman Tools | Windows取证工具集 | https://ericzimmerman.github.io/ |
| Photorec | 文件恢复 | https://www.cgsecurity.org/wiki/PhotoRec |
| Hindsight | 浏览器历史取证 | https://github.com/obsidianforensics/hindsight |

## 参考资源

- [NIST SP 800-86 — Forensic Techniques](https://csrc.nist.gov/publications/detail/sp/800-86/final)
- [SANS Forensic Acquisition Guidelines](https://www.sans.org/white-papers/forensic-acquisition/)
- [SANS FOR500 — Windows Forensic Analysis](https://www.sans.org/for500/)
- [SANS FOR508 — Advanced Forensic Analysis](https://www.sans.org/for508/)
- [DFIR Wizard — 取证速查表](https://www.dfirwizard.com/)
- [ForensicArtifacts.com — 数字痕迹百科](https://forensicartifacts.com/)
