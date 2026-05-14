---
id: "15-012"
title: "💾 磁盘取证与数据恢复 (Disk Forensics & Data Recovery)"
category: "应急响应"
category_en: "Incident Response"
difficulty: "★★★★"
tools: "FTK Imager, Autopsy, dd, Guymager"
last_updated: "2025-07"
---
# 💾 磁盘取证与数据恢复 (Disk Forensics & Data Recovery)

## 概述
磁盘取证是对存储介质（硬盘、SSD、USB等）进行镜像获取、文件系统分析和文件恢复的过程，是应急响应中还原攻击路径、提取关键证据的重要手段。

## 核心技能

### 1. 证据获取 — 磁盘镜像

**取证黄金法则：永不直接在原始介质上操作，始终在副本上分析。**

```bash
# 使用dd创建完整磁盘镜像 (Linux)
# 物理镜像
sudo dd if=/dev/sda of=/mnt/evidence/disk_image.dd bs=4M conv=noerror,sync status=progress

# 计算哈希值（证据链完整性验证）
sudo sha256sum /dev/sda > /mnt/evidence/disk_hash.txt
sudo sha256sum /mnt/evidence/disk_image.dd >> /mnt/evidence/disk_hash.txt

# 使用dcfldd（增强版dd，含哈希）
sudo dcfldd if=/dev/sda of=/mnt/evidence/disk_image.dd bs=4M hash=sha256 hashlog=hash.log

# 使用Guymager（GUI取证镜像工具）
sudo guymager
```

**Windows取证镜像：**

```bash
# FTK Imager — 最常用的取证工具
# 操作: File → Create Disk Image → 选择源 → 选择格式(DD/E01) → 保存

# 使用E01格式（包含压缩、哈希、元数据）
# 更小体积、内置校验
```

### 2. 文件系统分析

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

### 3. Windows痕迹分析

#### 预取文件 (Prefetch) — 程序执行记录
```bash
# Prefetch文件位置: C:\Windows\Prefetch
# 格式: 文件名-HASH.pf
# 分析谁在什么时间运行了什么程序
# 工具: PECmd (Eric Zimmerman)
PECmd.exe -d "C:\Windows\Prefetch" --csv "output.csv"
```

#### Jump Lists — 用户操作记录
```bash
# Jump Lists位置:
# C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\
# C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations
# 工具: JLECmd
JLECmd.exe -d "C:\Users\admin\AppData\Roaming\Microsoft\Windows\Recent" --csv output.csv
```

#### AmCache & ShimCache — 程序执行历史
```bash
# AmCache位置: C:\Windows\AppCompat\Programs\Amcache.hve
# 包含所有已执行程序的SHA1、路径、时间
# 工具: AmcacheParser
AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" --csv output.csv

# ShimCache (AppCompatCache) — 注册表中
# 位置: SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
# 工具: AppCompatCacheParser
AppCompatCacheParser.exe --csv output.csv
```

#### 回收站分析
```bash
# 位置: C:\$Recycle.Bin\<SID>\
# 查看已删除但还在回收站的文件
# 工具: RBCmd
RBCmd.exe -d "C:\$Recycle.Bin"
```

#### 浏览器历史
```bash
# Chrome: C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\History
# 工具: Hindsight
hindsight -i "C:\Users\admin\AppData\Local\Google\Chrome\User Data" -o output

# Edge: 类似Chrome路径
# Firefox: C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\
# 工具: Zircolite
```

### 4. Linux痕迹分析

```bash
# Bash历史
cat ~/.bash_history
cat ~/.zsh_history

# 提取所有用户的历史记录
for user in $(ls /home/); do
    echo "=== $user ==="
    cat /home/$user/.bash_history 2>/dev/null
done

# 检查SSH配置文件中的后门
cat ~/.ssh/authorized_keys
ls -la ~/.ssh/
cat /etc/ssh/sshd_config | grep -v "^#" | grep -v "^$"

# 检查计划任务
ls -la /var/spool/cron/crontabs/
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.*

# 检查systemd服务中的后门
cat /etc/systemd/system/*.service
systemctl list-units --type=service --state=running

# 查看登录历史
last -100 > login_history.txt

# 检查suid/sgid文件（提权痕迹）
find / -perm -4000 -ls 2>/dev/null
find / -perm -2000 -ls 2>/dev/null

# 检查最近修改的文件（攻击时间线）
find /etc -mtime -7 -ls 2>/dev/null
find /var/www -mtime -7 -ls 2>/dev/null
```

### 5. 文件恢复

```bash
# Photorec — 恢复已删除文件（支持多种文件系统）
sudo photorec /dev/sda

# 恢复到恢复目录
# 按文件类型分类恢复（jpg, pdf, zip等）

# extundelete — ext3/ext4文件系统恢复
sudo extundelete /dev/sda2 --restore-all --output-dir /recovery/

# 恢复指定目录
sudo extundelete /dev/sda2 --restore-directory /home/user/documents/

# NTFS删除文件恢复
# 使用Autopsy的文件浏览功能 → 按"Deleted Files"过滤
# 使用Recuva (Windows GUI工具)
```

### 6. 文件特征分析

```bash
# 识别文件类型（不依赖扩展名）
file suspicious_file
file --mime-type suspicious_file

# 提取EXIF信息
exiftool image.jpg

# 查看PE文件头信息（Windows可执行文件）
# 工具: Exeinfo PE, PEStudio, DIE (Detect It Easy)

# 计算哈希值（用于威胁情报关联）
sha256sum suspicious_file
md5sum suspicious_file
```

### 7. 取证时间线

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
| Autopsy | 开源数字取证平台 | https://www.autopsy.com/ |
| FTK Imager | 磁盘镜像与预览 | https://www.exterro.com/ftk-imager |
| Sleuth Kit | 命令行取证工具集 | https://www.sleuthkit.org/ |
| Plaso (log2timeline) | 超级取证时间线 | https://github.com/log2timeline/plaso |
| Eric Zimmerman Tools | Windows取证工具集 | https://ericzimmerman.github.io/ |
| Photorec | 文件恢复 | https://www.cgsecurity.org/wiki/PhotoRec |
| Hindsight | 浏览器历史取证 | https://github.com/obsidianforensics/hindsight |

## 参考资源

- [SANS FOR500 — Windows Forensic Analysis](https://www.sans.org/for500/)
- [SANS FOR508 — Advanced Forensic Analysis](https://www.sans.org/for508/)
- [DFIR Wizard — 取证速查表](https://www.dfirwizard.com/)
- [ForensicArtifacts.com — 数字痕迹百科](https://forensicartifacts.com/)
- [13Cubed DFIR 视频教程](https://www.youtube.com/c/13Cubed)
