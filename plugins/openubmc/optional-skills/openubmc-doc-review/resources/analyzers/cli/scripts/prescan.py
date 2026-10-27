#!/usr/bin/env python3
"""
doc-cli-tester prescan.py - 文档命令行提取与静态分类扫描

从 Markdown 文档中提取所有命令代码块（bash/sh/shell/cmd/console 等），
对每个命令执行静态分类（只读/变更/交互/专有/不可自动化）。

不执行任何命令 - 仅做静态分析。
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

# 命令代码块的语言标签（会被识别为命令代码块）
CMD_LANG_TAGS_LOWER = {
    'bash', 'sh', 'shell', 'cmd', 'command', 'console',
    'powershell', 'ps', 'zsh', 'fish', 'ksh', 'csh', 'tcsh',
    'terminal', 'term',
}

# 只读命令白名单（只对这些命令在 RUN_MODE=unsafe 时允许执行）
READONLY_CMDS = {
    # 文件查看
    'cat', 'head', 'tail', 'less', 'more', 'nl', 'wc', 'file', 'stat', 'ls',
    # 基本信息查询
    'uname', 'whoami', 'id', 'groups', 'hostname', 'echo', 'printf',
    # 系统信息
    'lscpu', 'lsblk', 'lspci', 'lsusb', 'free', 'df', 'du', 'uptime', 'date',
    # 网络信息（只读）
    'ip', 'ifconfig', 'nmcli', 'ss', 'netstat',
    # 文本处理
    'grep', 'egrep', 'fgrep', 'sort', 'uniq', 'cut', 'paste', 'awk', 'sed',
    # 目录导航
    'pwd', 'cd', 'dirname', 'basename', 'find',
    # 环境查询
    'env', 'printenv', 'set',
    # 工具存在性
    'which', 'whereis', 'type',
    # 软件包查询（只读）
    'rpm', 'dpkg',  # 注意：rpm -q / dpkg -l 是只读，但 rpm -i 是变更
}

# 变更类命令（一律禁止脚本自动执行）
WRITE_CMDS = {
    'dnf', 'yum', 'apt', 'apt-get', 'aptitude', 'zypper', 'pacman',
    'systemctl', 'service', 'chkconfig', 'update-rc.d',
    'rpm', 'dpkg', 'pip', 'pip3', 'npm', 'yarn', 'pnpm',
    'mkdir', 'rm', 'rmdir', 'touch', 'cp', 'mv', 'ln',
    'chmod', 'chown', 'chgrp', 'chattr',
    'mount', 'umount', 'fsck',
    'fdisk', 'parted', 'mkfs', 'mkswap',
    'useradd', 'userdel', 'groupadd', 'groupdel',
    'passwd', 'usermod',
    'kill', 'killall', 'pkill',
    'firewall-cmd', 'iptables', 'ip6tables',
    'selinux', 'setsebool',
    'curl', 'wget',
    'scp', 'sftp', 'rsync',
    'tar', 'zip', 'unzip', 'gzip', 'gunzip',
    'make', 'cmake', 'gcc', 'g++', 'cc', 'clang',
    'git',
    'bash', 'sh', 'zsh', 'sudo', 'su',
}

# 交互式命令（在非交互环境中无法验证）
INTERACTIVE_CMDS = {
    'vim', 'vi', 'nano', 'emacs', 'ed',
    'top', 'htop', 'glances',
    'nmtui', 'tmux', 'screen',
    'ssh',
}

# 专有/项目自定义 CLI（无法通用验证）
PROPRIETARY_CMDS = {
    'bingo', 'repo',
}

# 不可自动化操作关键词（出现在命令或上下文中）
NOT_AUTOMATED_KEYWORDS = [
    'BIOS', 'UEFI', 'iBMC', 'IPMI',
    'grub', 'reboot', 'shutdown', 'poweroff', 'init',
    '图形界面', 'GUI', '图形', '点击', '双击', '鼠标',
    '虚拟机', 'VMware', 'VirtualBox', 'KVM',
]


def is_cmd_code_block(lang):
    """判断代码块语言标签是否为命令代码块"""
    if not lang:
        return False
    return lang.strip().lower() in CMD_LANG_TAGS_LOWER


def looks_like_command_line(line):
    """启发式判断一行看起来像不像命令行（用于无语言标签的代码块）"""
    stripped = line.strip()
    if not stripped:
        return False
    if re.match(r'^[\$#>]\s+', stripped):
        return True
    first = stripped.split()[0] if stripped.split() else ''
    first_lower = first.lower()
    return first_lower in READONLY_CMDS or first_lower in WRITE_CMDS


def classify_command(cmd_line):
    """对单行命令进行分类

    返回: (category, is_shell_prompt, raw_command, notes)
    category: 'read' | 'write' | 'interactive' | 'proprietary'
              | 'not_automated' | 'comment' | 'output' | 'blank' | 'unknown'
    """
    raw = cmd_line.rstrip('\n')
    stripped = raw.strip()

    # 空行
    if not stripped:
        return ('blank', False, raw, '空行')

    # 注释行（shell/python/powershell 等常见注释风格）
    if (stripped.startswith('#') or stripped.startswith('//')
            or stripped.upper().startswith('REM ')
            or stripped.startswith(';')):
        return ('comment', False, raw, '注释/说明')

    # 预期输出行（不以 $/# 开头，也不以常见命令开头）- 后续结合上下文判断
    # 先去除常见 shell prompt 前缀
    is_prompt = False
    cmd_content = stripped
    prompt_match = re.match(r'^[\$#>]\s+(.+)$', stripped)
    if prompt_match:
        cmd_content = prompt_match.group(1)
        is_prompt = True

    # 取第一个 token（命令名）
    first_token = cmd_content.split()[0] if cmd_content.split() else ''
    first_cmd = first_token.split('/')[-1].lower()  # 去除路径前缀

    # 不可自动化关键词
    for kw in NOT_AUTOMATED_KEYWORDS:
        if kw.lower() in stripped.lower():
            return ('not_automated', is_prompt, raw, f'涉及不可自动化操作: {kw}')

    # 交互式命令
    if first_cmd in INTERACTIVE_CMDS:
        return ('interactive', is_prompt, raw, f'交互式命令: {first_cmd}')

    # 专有工具
    if first_cmd in PROPRIETARY_CMDS:
        return ('proprietary', is_prompt, raw, f'项目自定义工具: {first_cmd}')

    # 变更类命令
    if first_cmd in WRITE_CMDS:
        return ('write', is_prompt, raw, f'变更类命令: {first_cmd}')

    # 只读命令
    if first_cmd in READONLY_CMDS:
        return ('read', is_prompt, raw, f'只读命令: {first_cmd} (在白名单内)')

    # 未知命令（可能是用户自定义 CLI 或文档特定的命令）
    if first_cmd:
        return ('unknown', is_prompt, raw, f'未知命令: {first_cmd}，建议用户确认后执行')

    return ('blank', is_prompt, raw, '无法识别的命令格式')


def scan_file(file_path):
    """对单个 Markdown 文件进行命令扫描"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        return {'file': file_path, 'error': str(e), 'blocks': []}

    lines = content.split('\n')
    code_blocks = []
    current_block = None

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()

        fence_match = re.match(r'^(```+|~~~+)(.*)$', stripped)

        if fence_match:
            fence = fence_match.group(1)
            lang = fence_match.group(2).strip()

            if current_block is None:
                current_block = {
                    'fence_start_line': lineno,
                    'language': lang,
                    'raw_content': [],
                }
            else:
                current_block['fence_end_line'] = lineno
                is_cmd = is_cmd_code_block(current_block['language'])

                if not is_cmd and not current_block['language']:
                    # 无语言标注: 启发式判断
                    non_empty = [l for l in current_block['raw_content'] if l.strip()]
                    if non_empty:
                        cmd_like = sum(1 for l in non_empty if looks_like_command_line(l))
                        is_cmd = (cmd_like / len(non_empty)) >= 0.3

                current_block['is_command_block'] = is_cmd
                current_block['content'] = '\n'.join(current_block['raw_content'])
                current_block['total_lines'] = len(current_block['raw_content'])
                del current_block['raw_content']

                line_analyses = []
                for idx, raw in enumerate(current_block['content'].split('\n'), 0):
                    cat, is_prompt, raw_line, notes = classify_command(raw)
                    actual_lineno = current_block['fence_start_line'] + 1 + idx
                    line_analyses.append({
                        'lineno_in_file': actual_lineno,
                        'lineno_in_block': idx + 1,
                        'raw': raw_line,
                        'category': cat,
                        'is_shell_prompt': is_prompt,
                        'is_in_whitelist': (cat == 'read'),
                        'notes': notes,
                    })
                current_block['line_analyses'] = line_analyses

                categories = {}
                for la in line_analyses:
                    cat = la['category']
                    categories[cat] = categories.get(cat, 0) + 1
                current_block['summary_by_category'] = categories

                code_blocks.append(current_block)
                current_block = None
            continue

        if current_block is not None:
            current_block['raw_content'].append(line)

    result = {'file': file_path, 'blocks': code_blocks}
    return result


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

    all_blocks = []
    errors = []
    for f in files:
        res = scan_file(f)
        if 'error' in res:
            errors.append(res)
        else:
            for b in res['blocks']:
                b['file'] = f  # 文件级元信息带入 block
            all_blocks.extend(res['blocks'])

    # 全量统计
    by_category_total = {}
    for block in all_blocks:
        for cat, count in block.get('summary_by_category', {}).items():
            by_category_total[cat] = by_category_total.get(cat, 0) + count

    # LLM/agent 可直接消费的简化视图
    commands_flat = []
    for block in all_blocks:
        if not block.get('is_command_block'):
            continue
        for la in block['line_analyses']:
            if la['category'] in ('blank', 'comment'):
                continue
            commands_flat.append({
                'file': block.get('file', 'unknown'),
                'lineno': la['lineno_in_file'],
                'raw_command': la['raw'],
                'category': la['category'],
                'in_whitelist': la['is_in_whitelist'],
                'notes': la['notes'],
            })

    return {
        'scanned_files': len(files),
        'total_blocks': len(all_blocks),
        'command_blocks': sum(1 for b in all_blocks if b.get('is_command_block')),
        'by_category_total': by_category_total,
        'total_read_commands': by_category_total.get('read', 0),
        'total_write_commands': by_category_total.get('write', 0),
        'total_interactive_commands': by_category_total.get('interactive', 0),
        'total_proprietary_commands': by_category_total.get('proprietary', 0),
        'total_not_automated': by_category_total.get('not_automated', 0),
        'total_unknown_commands': by_category_total.get('unknown', 0),
        'blocks': all_blocks,
        'commands_flat': commands_flat,
        'errors': errors,
    }


if __name__ == '__main__':
    targets = sys.argv[1:] if len(sys.argv) > 1 else ['.']
    result = main(targets)
    print(json.dumps(result, ensure_ascii=False, indent=2))
