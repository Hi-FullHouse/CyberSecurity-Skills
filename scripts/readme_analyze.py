#!/usr/bin/env python3
"""Count lines and find sections in README.md"""
import os, sys
os.environ['PYTHONIOENCODING'] = 'utf-8'

with open('README.md', 'r', encoding='utf-8') as f:
    content = f.read()
lines = content.split('\n')
print(f'Total lines: {len(lines)}')
# Find stage sections
for i, line in enumerate(lines):
    if '## 阶段' in line or '## 阶段' in line:
        print(f'Line {i+1}: {line[:100]}')
    # Also find the last content before end
    if i > 280 and line.strip():
        print(f'Line {i+1}: {line[:100]}')
