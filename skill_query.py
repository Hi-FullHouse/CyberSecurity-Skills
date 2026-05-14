#!/usr/bin/env python3
"""
CyberSecurity-Skills - AI Agent 技能查询与验证 API
=====================================================
为 AI Agent 提供结构化查询能力，支持：
  - list-modules   列出所有安全模块
  - list-skills    列出指定模块的技能
  - get-skill      读取单个技能的完整内容
  - search         按关键词搜索技能
  - resolve        解析技能文件的绝对路径
  - validate       验证 index.json 与实际文件的一致性

使用:
  python skill_query.py <command> [options]

示例:
  python skill_query.py list-modules
  python skill_query.py list-skills --module 15
  python skill_query.py get-skill --id 15-001
  python skill_query.py search --keyword SQL注入
  python skill_query.py validate
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Optional

# --- Windows GBK 编码兼容 ---
try:
    sys.stdout.reconfigure(encoding='utf-8')
except (AttributeError, ValueError):
    pass
_utf8 = os.environ.get("PYTHONIOENCODING") and True
_utf8 = _utf8 or (getattr(sys.stdout, "encoding", "").upper() in ("UTF-8", "UTF8"))
if not _utf8:
    try:
        sys.stdout.encoding
        _utf8 = True
    except Exception:
        pass

OK    = "\u2705" if _utf8 else "[OK]"
FAIL  = "\u274c" if _utf8 else "[FAIL]"
WARN  = "\u26a0\ufe0f" if _utf8 else "[WARN]"
SEARCH= "\U0001f50d" if _utf8 else "[SEARCH]"
FILE  = "\U0001f4c4" if _utf8 else "[FILE]"
PKG   = "\U0001f4e6" if _utf8 else "[PKG]"
ERR   = FAIL

# --- 路径常量 ---
PROJECT_ROOT = Path(__file__).resolve().parent
INDEX_PATH = PROJECT_ROOT / "index.json"


def load_index() -> dict:
    """加载 index.json"""
    if not INDEX_PATH.exists():
        print(f"{ERR} 错误: 未找到索引文件 {INDEX_PATH}", file=sys.stderr)
        sys.exit(1)
    with open(INDEX_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _find_skill_file(module_path: str, filename: str) -> Optional[Path]:
    """在模块目录下查找技能文件"""
    skills_dir = PROJECT_ROOT / module_path / "skills"
    target = skills_dir / filename
    if target.exists():
        return target
    for f in skills_dir.iterdir():
        if f.name.lower() == filename.lower():
            return f
    return None


def cmd_list_modules(index: dict):
    """列出所有安全模块"""
    meta = index["meta"]
    print()
    print("=" * 60)
    print(f"  {meta['title']}")
    print(f"  版本: {meta['version']} | 技能总数: {meta['total_skills']} | 模块: {meta['total_modules']}")
    print("=" * 60)
    print()
    print(f"{'ID':<5} {'中文名称':<16} {'英文名称':<28} {'技能数':<8} {'目录路径'}")
    print(f"{'-'*5} {'-'*16} {'-'*28} {'-'*8} {'-'*30}")
    for mod in index["modules"]:
        print(f"{mod['id']:<5} {mod['name_cn']:<16} {mod['name_en']:<28} {mod['skill_count']:<8} {mod['path']}")
    print()


def cmd_list_skills(index: dict, module_id: int = None):
    """列出指定模块的技能"""
    modules = index["modules"]
    if module_id:
        modules = [m for m in modules if m["id"] == module_id]
        if not modules:
            print(f"{FAIL} 错误: 未找到模块 ID {module_id}")
            sys.exit(1)
    for mod in modules:
        print()
        print(f"[{mod['name_cn']}] ({mod['name_en']}) - {mod['skill_count']} 个技能")
        print("=" * 60)
        print(f"{'#':<4} {'技能名称':<30} {'文件名':<34} {'难度'}")
        print(f"{'-'*4} {'-'*30} {'-'*34} {'-'*6}")
        for i, skill in enumerate(mod["skills"], 1):
            print(f"{i:<4} {skill['name']:<30} {skill['file']:<34} {skill['difficulty']}")
        print()


def cmd_get_skill(index: dict, skill_id: str):
    """读取并输出单个技能的完整内容"""
    skill_id = skill_id.upper()
    for mod in index["modules"]:
        prefix = f"{mod['id']:02d}"
        if skill_id.startswith(prefix):
            for skill in mod["skills"]:
                filepath = _find_skill_file(mod["path"], skill["file"])
                if filepath:
                    print()
                    print(f"{FILE} {skill['name']}")
                    print(f"   路径: {filepath}")
                    print(f"   难度: {skill['difficulty']}")
                    print("=" * 60)
                    print()
                    with open(filepath, "r", encoding="utf-8") as f:
                        content = f.read()
                    content_clean = re.sub(r'^---\n.*?\n---\n', '', content, flags=re.DOTALL)
                    print(content_clean)
                    return
    print(f"{FAIL} 错误: 未找到技能 ID {skill_id}")


def cmd_search(index: dict, keyword: str):
    """按关键词搜索技能"""
    kw = keyword.lower()
    results = []
    for mod in index["modules"]:
        for skill in mod["skills"]:
            if kw in skill["name"].lower():
                results.append((mod, skill, "名称"))
                continue
            if kw in skill["file"].lower():
                results.append((mod, skill, "文件名"))
                continue
            if kw in mod["name_cn"].lower() or kw in mod["name_en"].lower():
                results.append((mod, skill, "模块名"))

    if not results:
        print(f"{SEARCH} 未找到包含 '{keyword}' 的技能")
        return

    print()
    print(f"{SEARCH} 搜索 '{keyword}' - 共 {len(results)} 个结果")
    print()
    print(f"{'匹配方式':<8} {'模块':<20} {'技能名称':<30} {'难度':<6}")
    print(f"{'-'*8} {'-'*20} {'-'*30} {'-'*6}")
    for mod, skill, match_type in results:
        print(f"{match_type:<8} {mod['name_cn']:<20} {skill['name']:<30} {skill['difficulty']:<6}")
    print()


def cmd_resolve(index: dict, module_id: int, skill_name: str):
    """解析技能文件的绝对路径"""
    for mod in index["modules"]:
        if mod["id"] == module_id:
            for skill in mod["skills"]:
                if skill_name.lower() in skill["name"].lower() or skill_name.lower() in skill["file"].lower():
                    filepath = _find_skill_file(mod["path"], skill["file"])
                    if filepath:
                        print(str(filepath.resolve()))
                        return
                    print(f"{FAIL} 错误: 文件不存在 {skill['file']}", file=sys.stderr)
                    sys.exit(1)
    print(f"{FAIL} 错误: 未找到匹配的技能", file=sys.stderr)
    sys.exit(1)


def cmd_validate(index: dict):
    """验证 index.json 与实际文件的一致性"""
    errors = []
    warnings = []

    meta = index.get("meta", {})
    if not meta.get("title"):
        errors.append("meta.title 缺失")

    actual_count = 0
    declared_count = meta.get("total_skills", 0)

    for mod in index["modules"]:
        mod_path = PROJECT_ROOT / mod["path"]
        skills_dir = mod_path / "skills"

        if not mod_path.exists():
            errors.append(f"模块 '{mod['name_cn']}' 路径不存在: {mod['path']}")
            continue
        if not skills_dir.exists():
            errors.append(f"模块 '{mod['name_cn']}' skills 目录不存在: {mod['path']}/skills")
            continue

        actual_files = sorted([
            f.name for f in skills_dir.iterdir()
            if f.is_file() and f.suffix == ".md"
        ])
        declared_files = [s["file"] for s in mod["skills"]]

        for f in declared_files:
            if f not in actual_files:
                errors.append(f"  [{mod['name_cn']}] index.json 声明了但实际缺失: {f}")

        for f in actual_files:
            if f not in declared_files:
                warnings.append(f"  [{mod['name_cn']}] 实际存在但 index.json 未声明: {f}")

        actual_count += len(actual_files)

        if mod["skill_count"] != len(mod["skills"]):
            errors.append(f"  [{mod['name_cn']}] skill_count ({mod['skill_count']}) 与 skills 数组长度 ({len(mod['skills'])}) 不一致")

    if declared_count != actual_count:
        errors.append(f"meta.total_skills ({declared_count}) 与实际技能文件数 ({actual_count}) 不一致")

    print()
    print("=" * 60)
    print(f"  技能库一致性验证报告")
    print("=" * 60)
    print()
    print(f"  声明技能数: {declared_count}")
    print(f"  实际文件数: {actual_count}")
    print()

    if not errors and not warnings:
        print(f"  {OK} 完全一致! 无错误, 无警告。")
        print()
        return

    if errors:
        print(f"  {FAIL} 发现 {len(errors)} 个错误:")
        for e in errors:
            print(f"    * {e}")
        print()

    if warnings:
        print(f"  {WARN} 发现 {len(warnings)} 个警告:")
        for w in warnings:
            print(f"    * {w}")
        print()

    if errors:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="CyberSecurity-Skills AI Agent 查询与验证工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  %(prog)s list-modules
  %(prog)s list-skills --module 15
  %(prog)s get-skill --id 15-001
  %(prog)s search --keyword SQL
  %(prog)s resolve --module 3 --skill SQL注入
  %(prog)s validate"""
    )
    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    subparsers.add_parser("list-modules", help="列出所有安全模块")
    p_ls = subparsers.add_parser("list-skills", help="列出指定模块的技能")
    p_ls.add_argument("--module", "-m", type=int, help="模块ID")

    p_gs = subparsers.add_parser("get-skill", help="获取单个技能的完整内容")
    p_gs.add_argument("--id", required=True, help="技能ID (如 15-001)")

    p_sr = subparsers.add_parser("search", help="按关键词搜索技能")
    p_sr.add_argument("--keyword", "-k", required=True, help="搜索关键词")

    p_rs = subparsers.add_parser("resolve", help="解析技能文件的绝对路径")
    p_rs.add_argument("--module", "-m", type=int, required=True, help="模块ID")
    p_rs.add_argument("--skill", "-s", required=True, help="技能名称或文件名")

    subparsers.add_parser("validate", help="验证 index.json 与实际文件的一致性")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    index = load_index()

    if args.command == "list-modules":
        cmd_list_modules(index)
    elif args.command == "list-skills":
        cmd_list_skills(index, getattr(args, "module", None))
    elif args.command == "get-skill":
        cmd_get_skill(index, args.id)
    elif args.command == "search":
        cmd_search(index, args.keyword)
    elif args.command == "resolve":
        cmd_resolve(index, args.module, args.skill)
    elif args.command == "validate":
        cmd_validate(index)


if __name__ == "__main__":
    main()
