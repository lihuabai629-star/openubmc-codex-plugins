#!/usr/bin/env python3
"""
doc-documentation-product-consistency-tester prescan.py

文档与产品一致性的静态预扫描：
1. 从 Markdown 文档中提取参数名（如 --foo、-f、/foo=bar）
2. 提取版本号、缺省值、端口号等配置信息
3. 提取命令代码块中展示的预期输出关键词（与实际输出对比的依据）
4. 提取"示例"代码块中出现的产品名称/CLI 工具名

不执行任何命令，不发起网络请求。
"""

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../../../../../skills/openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)

import re
import os
import sys
import json
from collections import Counter


# 参数名匹配模式
# GNU 长参数: --foo-bar, --foo_bar, --foo=bar, --foo value
# GNU 短参数: -f, -fvalue, -f value
# Windows/PowerShell 风格: /Foo=bar, -Foo:bar, -Foo value
RE_LONG_PARAM = re.compile(r'(?<!\w)--[a-zA-Z][a-zA-Z0-9_-]*(?:=[\w\-\.:\$\/]*)?')
RE_SHORT_PARAM = re.compile(r'(?<![\w\-/])-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+\w+)?')
RE_WIN_PARAM = re.compile(r'(?<!\w)/[A-Za-z][A-Za-z0-9_\-]*(?:[:=][\w\-\.:\$\/]*)?')

# 版本号: X.Y(.Z)、vX.Y、release-X.Y
RE_VERSION = re.compile(r'\b(v?\d+(?:\.\d+){1,3}(?:[\.\-_][A-Za-z0-9\-\._]+)*)\b')

# 端口号: port=1234, listen on 8080, :8080, 默认端口 443
RE_PORT_PATTERN = re.compile(
    r'(?:port(?:\s*number)?|端口)[\s:=]*(\d{2,5})|'
    r'(?:listen|binding|bind)[^\n]{0,50}?(\d{2,5})',
    re.IGNORECASE
)

# 代码块围栏
RE_CODE_FENCE = re.compile(r'^(```+|~~~+)(.*)$')

# 常见命令/工具名（用于从代码块中识别 CLI 工具）
CLI_NAME_HINTS = [
    'nginx', 'apache', 'mysql', 'postgres', 'docker', 'kubectl', 'git',
    'python', 'python3', 'java', 'node', 'npm', 'go', 'cargo',
    'systemctl', 'dnf', 'yum', 'apt', 'iptables',
]


def extract_params_from_text(text):
    """从文本中提取所有参数名"""
    params = Counter()
    for m in RE_LONG_PARAM.findall(text):
        # 去除 =value 部分，只保留参数名
        name = m.split('=')[0]
        params[name] += 1
    for m in RE_WIN_PARAM.findall(text):
        name = re.split(r'[:=]', m)[0]
        params[name] += 1
    return params


def extract_versions_from_text(text):
    """从文本中提取版本号"""
    versions = Counter()
    for m in RE_VERSION.findall(text):
        versions[m] += 1
    return versions


def extract_code_blocks(content):
    """从 Markdown 文本中提取所有代码块，返回列表:
    [{ 'lineno_start': int, 'lineno_end': int, 'language': str, 'content': str }, ...]
    """
    lines = content.split('\n')
    blocks = []
    in_block = False
    current = None
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        fence = RE_CODE_FENCE.match(stripped)
        if fence:
            if not in_block:
                in_block = True
                current = {
                    'fence_start_line': lineno,
                    'language': fence.group(2).strip() or '',
                    'lines': [],
                }
            else:
                if current:
                    current['fence_end_line'] = lineno
                    current['content'] = '\n'.join(current['lines'])
                    current['total_lines'] = len(current['lines'])
                    del current['lines']
                    blocks.append(current)
                current = None
                in_block = False
            continue
        if in_block and current is not None:
            current['lines'].append(line)
    return blocks


def extract_cli_candidates(content, blocks):
    """从代码块的第一行命令中提取可能的 CLI 工具名"""
    candidates = Counter()
    for block in blocks:
        first_lines = [l for l in block['content'].split('\n')[:5] if l.strip()]
        if not first_lines:
            continue
        # 去除 shell prompt
        for line in first_lines:
            stripped = line.strip()
            # 去除 $/# 前缀
            if re.match(r'^[\$#>]\s+', stripped):
                stripped = re.sub(r'^[\$#>]\s+', '', stripped)
            first_token = stripped.split()[0] if stripped.split() else ''
            # 去除路径前缀
            first_token = first_token.split('/')[-1]
            if first_token and len(first_token) < 50 and not first_token.startswith('-'):
                candidates[first_token] += 1
    return candidates


def scan_file(file_path):
    """对单个 Markdown 文件进行扫描"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        return {'file': file_path, 'error': str(e)}

    blocks = extract_code_blocks(content)
    cmd_blocks = [b for b in blocks if b['language'] in {
        'bash', 'sh', 'shell', 'cmd', 'console', 'powershell', 'zsh', '',
    } or b['language'] is None]

    # 从全文文本中提取
    params_in_text = extract_params_from_text(content)
    versions_in_text = extract_versions_from_text(content)

    # 从命令代码块中提取参数和预期输出关键词
    params_in_code = Counter()
    for block in cmd_blocks:
        params_in_code.update(extract_params_from_text(block['content']))

    # 从代码块中提取 CLI 候选名
    cli_candidates = extract_cli_candidates(content, cmd_blocks)

    # 端口号提取
    ports = Counter()
    for m in RE_PORT_PATTERN.finditer(content):
        port = m.group(1) or m.group(2)
        if port and 1 <= int(port) <= 65535:
            ports[port] += 1

    return {
        'file': file_path,
        'total_lines': len(content.split('\n')),
        'total_code_blocks': len(blocks),
        'cmd_code_blocks': len(cmd_blocks),
        'params_in_text_most_common': params_in_text.most_common(30),
        'params_in_codeblocks_most_common': params_in_code.most_common(30),
        'versions_most_common': versions_in_text.most_common(20),
        'ports_most_common': ports.most_common(10),
        'cli_candidates_most_common': cli_candidates.most_common(20),
    }


def main(targets):
    """对一个或多个文件/目录进行扫描"""
    files = []
    for t in targets:
        if os.path.isdir(t):
            for root, _, fnames in os.walk(t):
                for fn in fnames:
                    if fn.lower().endswith('.md'):
                        files.append(os.path.join(root, fn))
        elif os.path.isfile(t):
            files.append(t)

    results = []
    for f in files:
        res = scan_file(f)
        results.append(res)

    # 汇总
    all_params = Counter()
    all_versions = Counter()
    all_ports = Counter()
    all_cli = Counter()
    for r in results:
        if 'error' in r:
            continue
        for param, cnt in r['params_in_text_most_common']:
            all_params[param] += cnt
        for param, cnt in r['params_in_codeblocks_most_common']:
            all_params[param] += cnt
        for v, cnt in r['versions_most_common']:
            all_versions[v] += cnt
        for p, cnt in r['ports_most_common']:
            all_ports[p] += cnt
        for c, cnt in r['cli_candidates_most_common']:
            all_cli[c] += cnt

    return {
        'scanned_files': len(files),
        'summary': {
            'total_params_types': len(all_params),
            'total_version_tokens': len(all_versions),
            'total_port_tokens': len(all_ports),
            'total_cli_candidates': len(all_cli),
        },
        'params_most_common': all_params.most_common(50),
        'versions_most_common': all_versions.most_common(20),
        'ports_most_common': all_ports.most_common(10),
        'cli_candidates_most_common': all_cli.most_common(20),
        'per_file': results,
    }


if __name__ == '__main__':
    targets = sys.argv[1:] if len(sys.argv) > 1 else ['.']
    result = main(targets)
    print(json.dumps(result, ensure_ascii=False, indent=2))
