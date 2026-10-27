#!/usr/bin/env python3
"""
doc-links-tester v1.0 prescan script
脚本确定性扫描层 — 对 Markdown 文档进行链接与导航质量的机械化扫描
覆盖维度：L1 (断链/锚点)、L3 (链接文本)、L3.5 (应加链接)、L4 (格式)、L6 (版本)、L8 (锚点唯一性)
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
import glob
from urllib.parse import urlparse


# ==================== 基础工具：豁免区域识别 ====================

def get_code_block_lines(text):
    """返回所有代码块行号集合（含围栏行）"""
    code_lines = set()
    in_block = False
    for i, line in enumerate(text.split('\n'), 1):
        stripped = line.strip()
        if stripped.startswith('```') or stripped.startswith('~~~'):
            in_block = not in_block
            code_lines.add(i)
            continue
        if in_block:
            code_lines.add(i)
    return code_lines


def get_frontmatter_end(lines):
    if not lines or not lines[0].strip().startswith('---'):
        return 0
    for i in range(1, len(lines)):
        if lines[i].strip().startswith('---'):
            return i + 1
    return 0


def is_in_inline_code(line, pos):
    return line[:pos].count('`') % 2 == 1


def slugify_github(text):
    """GitHub 风格的 slug 生成：小写、去标点、空格转-，保留中文"""
    s = text.lower().strip()
    # 移除 Markdown 强调符号
    s = re.sub(r'[`*_~]', '', s)
    # 去除标点（保留 - 和中文）
    s = re.sub(r'[^\w\u4e00-\u9fff\s\-]', '', s)
    # 空格转 -
    s = re.sub(r'\s+', '-', s)
    s = s.strip('-')
    return s


# ==================== 链接提取 ====================

# Markdown 链接：[text](url) — 排除图片 ![alt](url)
RE_MD_LINK = re.compile(r'(?<!\!)\[([^\]\n]*?)\]\(([^)\n]+?)\)')
# Markdown 图片：![alt](url)
RE_MD_IMG = re.compile(r'!\[([^\]\n]*?)\]\(([^)\n]+?)\)')
# 引用式链接定义：[ref]: url
RE_REF_DEF = re.compile(r'^\s*\[([^\]]+)\]:\s*(\S+)', re.MULTILINE)
# 引用式链接使用：[text][ref]
RE_REF_USE = re.compile(r'\[([^\]\n]+?)\]\[([^\]\n]*?)\]')
# 裸 URL（行内未被 [] 包裹）
RE_BARE_URL = re.compile(r'(?<![\(\[<"\'`])(https?://[^\s<>"\'\)`\u4e00-\u9fff，。；：！？]+)')
# HTML 锚点
RE_HTML_ANCHOR = re.compile(r'<a\s+(?:name|id)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
# HTML 媒体标签
RE_HTML_MEDIA = re.compile(r'<(?:img|video|audio|source)\s[^>]*src\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
# HTML <a href>
RE_HTML_A = re.compile(r'<a\s[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>([^<]*)</a>', re.IGNORECASE)


def extract_headings(text, code_lines):
    """提取所有 Markdown 标题及其 slug"""
    headings = []
    lines = text.split('\n')
    for i, line in enumerate(lines, 1):
        if i in code_lines:
            continue
        m = re.match(r'^(#{1,6})\s+(.+?)\s*#*\s*$', line)
        if m:
            level = len(m.group(1))
            title = m.group(2).strip()
            slug = slugify_github(title)
            headings.append({'lineno': i, 'level': level, 'title': title, 'slug': slug})
    return headings


# ==================== L1：断链检查 ====================

# 豁免域名（示例域名、占位符）
EXEMPT_HOSTS = {
    'example.com', 'example.org', 'example.net', 'localhost',
    '127.0.0.1', '0.0.0.0', 'placeholder.com', '<your-domain>',
}
# 豁免 URL 模式（占位符、版本变量）
EXEMPT_URL_PATTERNS = [
    re.compile(r'\{[^}]+\}'),     # {version}
    re.compile(r'<[^>]+>'),       # <your-token>
    re.compile(r'\$\{[^}]+\}'),   # ${VAR}
]


def is_exempt_url(url):
    """判断 URL 是否应豁免"""
    if not url or url.startswith('#'):
        return False
    for pat in EXEMPT_URL_PATTERNS:
        if pat.search(url):
            return True
    if url.startswith('mailto:') or url.startswith('ftp:') or url.startswith('file:'):
        return True
    try:
        parsed = urlparse(url)
        if parsed.hostname and parsed.hostname.lower() in EXEMPT_HOSTS:
            return True
    except Exception:
        pass
    return False


def check_l1_broken_links(text, file_path, lines, code_lines, headings):
    """L1: 检查同文件锚点、相对路径文件存在性"""
    hits = []
    slug_set = {h['slug'] for h in headings}
    file_dir = os.path.dirname(os.path.abspath(file_path)) if file_path else None

    for lineno, line in enumerate(lines, 1):
        if lineno in code_lines:
            continue
        for m in RE_MD_LINK.finditer(line):
            link_text, url = m.group(1), m.group(2).strip()
            url = url.split(' ')[0].strip('<>')  # 移除 title 部分
            if is_exempt_url(url):
                continue
            # 内部锚点
            if url.startswith('#'):
                anchor = url[1:]
                if anchor and anchor not in slug_set:
                    hits.append({
                        'lineno': lineno, 'rule': 'L1', 'rule_name': '断链：未知锚点',
                        'severity': 'Required', 'confidence': 'high',
                        'error': url, 'correction': f'应匹配文档中的某个标题 slug',
                        'matched_text': line.strip()[:80],
                    })
            # 相对路径文件
            elif not url.startswith(('http://', 'https://')) and file_dir:
                # 去除 ?query 和 #fragment
                clean_path = url.split('#')[0].split('?')[0]
                if not clean_path:
                    continue
                # 自动 .html → .md
                check_paths = [clean_path]
                if clean_path.endswith('.html'):
                    check_paths.append(clean_path[:-5] + '.md')
                target = os.path.normpath(os.path.join(file_dir, clean_path))
                if not any(os.path.exists(os.path.normpath(os.path.join(file_dir, p))) for p in check_paths):
                    hits.append({
                        'lineno': lineno, 'rule': 'L1', 'rule_name': '断链：文件不存在',
                        'severity': 'Required', 'confidence': 'high',
                        'error': clean_path, 'correction': '确认文件路径',
                        'matched_text': line.strip()[:80],
                    })
    # 图片链接
    for lineno, line in enumerate(lines, 1):
        if lineno in code_lines:
            continue
        for m in RE_MD_IMG.finditer(line):
            alt, url = m.group(1), m.group(2).strip().split(' ')[0]
            if is_exempt_url(url):
                continue
            if not url.startswith(('http://', 'https://', 'data:')) and file_dir:
                clean = url.split('#')[0].split('?')[0]
                if clean and not os.path.exists(os.path.normpath(os.path.join(file_dir, clean))):
                    hits.append({
                        'lineno': lineno, 'rule': 'L1', 'rule_name': '断链：图片不存在',
                        'severity': 'Required', 'confidence': 'high',
                        'error': clean, 'correction': '确认图片路径',
                        'matched_text': line.strip()[:80],
                    })
    return hits


# ==================== L8：锚点唯一性 ====================

def check_l8_duplicate_anchors(text, lines, code_lines, headings):
    """L8: 检查重复的 slug 和 HTML id/name"""
    hits = []
    slug_lines = {}
    for h in headings:
        slug_lines.setdefault(h['slug'], []).append((h['lineno'], h['title']))
    for slug, occurrences in slug_lines.items():
        if len(occurrences) > 1:
            for lineno, title in occurrences[1:]:  # 第一个不报，后续重复报
                hits.append({
                    'lineno': lineno, 'rule': 'L8', 'rule_name': '锚点重复：标题 slug',
                    'severity': 'Required', 'confidence': 'high',
                    'error': slug, 'correction': '修改标题使 slug 唯一',
                    'matched_text': title[:80],
                })
    # HTML id/name 重复（豁免表格内的工具生成模式）
    html_anchors = {}
    in_table = False
    for lineno, line in enumerate(lines, 1):
        if lineno in code_lines:
            continue
        stripped = line.strip()
        if stripped.startswith('|') and '|' in stripped[1:]:
            in_table = True
        elif not stripped:
            in_table = False
        # 表格内的 HTML 锚点豁免
        if in_table:
            continue
        for m in RE_HTML_ANCHOR.finditer(line):
            name = m.group(1)
            html_anchors.setdefault(name, []).append(lineno)
    for name, occurrences in html_anchors.items():
        if len(occurrences) > 1:
            for ln in occurrences[1:]:
                hits.append({
                    'lineno': ln, 'rule': 'L8', 'rule_name': '锚点重复：HTML id/name',
                    'severity': 'Required', 'confidence': 'high',
                    'error': name, 'correction': '修改 HTML 锚点使其唯一',
                    'matched_text': f'<a name="{name}">',
                })
    return hits


# ==================== L3：链接文本质量 ====================

GENERIC_LINK_TEXTS = {
    '点击此处', '点击这里', '这里', '此处', '此页面', '此链接',
    '更多', '详情', '查看', '链接',
    'click here', 'here', 'this page', 'this link', 'learn more', 'read more', 'more', 'link', 'details',
}

URL_SHORTENERS = {
    'bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly',
}


def check_l3_link_text_quality(text, lines, code_lines):
    """L3: 裸 URL、通用锚文本、URL 缩短服务"""
    hits = []
    for lineno, line in enumerate(lines, 1):
        if lineno in code_lines:
            continue
        # 裸 URL
        for m in RE_BARE_URL.finditer(line):
            if is_in_inline_code(line, m.start()):
                continue
            url = m.group(1)
            hits.append({
                'lineno': lineno, 'rule': 'L3', 'rule_name': '裸 URL',
                'severity': 'Required', 'confidence': 'high',
                'error': url, 'correction': f'用 Markdown 链接包裹：[描述性文本]({url})',
                'matched_text': line.strip()[:80],
            })
        # 通用锚文本
        for m in RE_MD_LINK.finditer(line):
            link_text = m.group(1).strip()
            url = m.group(2).strip().split(' ')[0].strip('<>')
            if link_text.lower() in {t.lower() for t in GENERIC_LINK_TEXTS}:
                hits.append({
                    'lineno': lineno, 'rule': 'L3', 'rule_name': '通用锚文本',
                    'severity': 'Required', 'confidence': 'high',
                    'error': link_text, 'correction': '使用描述目标内容的链接文本',
                    'matched_text': line.strip()[:80],
                })
            # URL 缩短服务
            try:
                parsed = urlparse(url)
                if parsed.hostname and parsed.hostname.lower() in URL_SHORTENERS:
                    hits.append({
                        'lineno': lineno, 'rule': 'L3', 'rule_name': 'URL 缩短服务',
                        'severity': 'Required', 'confidence': 'high',
                        'error': url, 'correction': '使用原始 URL，避免短链接',
                        'matched_text': line.strip()[:80],
                    })
            except Exception:
                pass
    return hits


# ==================== L3.5：应加链接 ====================

GUIDE_KEYWORDS = ['参照', '参见', '参考', '详见', '请见', '点击查看', '请参阅', '请参考']
# 紧跟以下字符则豁免（"参见以下""详见下表"等）
GUIDE_SKIP_NEXT = re.compile(r'^(以下|如下|下面|下表|下图|表|\||<|[，。；：！？\n])')


def check_l3_5_missing_links(text, lines, code_lines):
    """L3.5: 书名号《》缺链接、引导关键词后缺链接"""
    hits = []
    fm_end = get_frontmatter_end(lines)
    for lineno, line in enumerate(lines, 1):
        if lineno in code_lines:
            continue
        if 1 <= lineno <= fm_end:
            continue
        if line.lstrip().startswith('#'):  # 标题豁免
            continue
        if line.lstrip().startswith('|'):  # 表格豁免
            continue
        # 书名号《...》
        for m in re.finditer(r'《([^》\n]+)》', line):
            pos = m.start()
            if is_in_inline_code(line, pos):
                continue
            # 检查是否已在链接中
            # 简化：若《》前已有 [ 或后有 ]( 则豁免
            context_before = line[max(0, pos-3):pos]
            if '[' in context_before:
                continue
            hits.append({
                'lineno': lineno, 'rule': 'L3.5', 'rule_name': '书名号内容缺链接',
                'severity': 'Required', 'confidence': 'medium',
                'error': f'《{m.group(1)}》', 'correction': '为书名号内容添加链接',
                'matched_text': line.strip()[:80],
            })
        # 引导关键词
        for kw in GUIDE_KEYWORDS:
            idx = 0
            while True:
                pos = line.find(kw, idx)
                if pos == -1:
                    break
                if is_in_inline_code(line, pos):
                    idx = pos + 1
                    continue
                after = line[pos + len(kw):pos + len(kw) + 10]
                if GUIDE_SKIP_NEXT.match(after):
                    idx = pos + len(kw)
                    continue
                # 检查后面 30 字符内是否有 Markdown 链接
                window = line[pos + len(kw):pos + len(kw) + 60]
                if '](' in window or '<' in window:  # 已有链接或 HTML
                    idx = pos + len(kw)
                    continue
                # 检查是否已在某链接的文本中
                hits.append({
                    'lineno': lineno, 'rule': 'L3.5', 'rule_name': f'引导词「{kw}」后缺链接',
                    'severity': 'Required', 'confidence': 'medium',
                    'error': kw, 'correction': '在引导词后添加对应链接',
                    'matched_text': line.strip()[:80],
                })
                idx = pos + len(kw)
    return hits


# ==================== L4：交叉引用格式 ====================

def check_l4_format(text, lines, code_lines, headings):
    """L4: 内部锚点缺#前缀、图片缺alt、引用式定义完整性、裸域名"""
    hits = []
    slug_set = {h['slug'] for h in headings}

    # 图片缺 alt
    for lineno, line in enumerate(lines, 1):
        if lineno in code_lines:
            continue
        for m in RE_MD_IMG.finditer(line):
            alt = m.group(1).strip()
            if not alt:
                hits.append({
                    'lineno': lineno, 'rule': 'L4', 'rule_name': '图片缺少 alt 文本',
                    'severity': 'Required', 'confidence': 'high',
                    'error': '![](...)', 'correction': '为图片提供描述性 alt 文本',
                    'matched_text': line.strip()[:80],
                })

    # 引用式链接定义完整性
    ref_defs = {m.group(1).lower(): m.group(2) for m in RE_REF_DEF.finditer(text)}
    ref_def_lines = {}
    for m in RE_REF_DEF.finditer(text):
        ln = text[:m.start()].count('\n') + 1
        ref_def_lines.setdefault(m.group(1).lower(), []).append(ln)
    for lineno, line in enumerate(lines, 1):
        if lineno in code_lines:
            continue
        for m in RE_REF_USE.finditer(line):
            ref = m.group(2).strip() or m.group(1).strip()
            if ref.lower() not in ref_defs:
                hits.append({
                    'lineno': lineno, 'rule': 'L4', 'rule_name': '引用式链接定义缺失',
                    'severity': 'Required', 'confidence': 'high',
                    'error': f'[{ref}]', 'correction': '在文档底部添加 [ref]: URL',
                    'matched_text': line.strip()[:80],
                })
    # 重复的引用定义
    for ref, lns in ref_def_lines.items():
        if len(lns) > 1:
            for ln in lns[1:]:
                hits.append({
                    'lineno': ln, 'rule': 'L4', 'rule_name': '引用式定义重复',
                    'severity': 'Required', 'confidence': 'high',
                    'error': f'[{ref}]:', 'correction': '删除重复定义',
                    'matched_text': '',
                })

    # 内部锚点缺 # 前缀：[文本](some-slug) 且 some-slug 看起来像 slug
    for lineno, line in enumerate(lines, 1):
        if lineno in code_lines:
            continue
        for m in RE_MD_LINK.finditer(line):
            url = m.group(2).strip().split(' ')[0].strip('<>')
            # 模式：纯 slug（小写字母-数字-连字符），且不含路径分隔符和协议
            if (re.fullmatch(r'[a-z0-9\-]+', url) and '/' not in url and '.' not in url
                    and url in slug_set):
                hits.append({
                    'lineno': lineno, 'rule': 'L4', 'rule_name': '内部锚点缺少 # 前缀',
                    'severity': 'Required', 'confidence': 'high',
                    'error': url, 'correction': f'改为 #{url}',
                    'matched_text': line.strip()[:80],
                })
    return hits


# ==================== L6：版本一致性 ====================

# 代码托管平台域名（必须 HTTPS）
CODE_HOSTING_HOSTS = {
    'github.com', 'gitlab.com', 'bitbucket.org',
    'gitee.com', 'gitcode.com', 'gitcode.net', 'atomgit.com',
}

# 硬编码版本号模式：/v1.2.3/  /v1.2/  /4.15/  /release-1.0/
RE_VERSIONED_PATH = re.compile(r'/(v?\d+(?:\.\d+){1,3}|release-\d+(?:\.\d+)*)/')


def check_l6_version_consistency(text, lines, code_lines):
    """L6: 硬编码版本号、代码托管平台 HTTP→HTTPS"""
    hits = []
    for lineno, line in enumerate(lines, 1):
        if lineno in code_lines:
            continue
        for m in RE_MD_LINK.finditer(line):
            url = m.group(2).strip().split(' ')[0].strip('<>')
            if not url.startswith(('http://', 'https://')):
                continue
            try:
                parsed = urlparse(url)
            except Exception:
                continue
            host = (parsed.hostname or '').lower()
            # 代码托管平台必须 HTTPS
            if host in CODE_HOSTING_HOSTS and url.startswith('http://'):
                hits.append({
                    'lineno': lineno, 'rule': 'L6', 'rule_name': '代码托管平台应使用 HTTPS',
                    'severity': 'Required', 'confidence': 'high',
                    'error': url, 'correction': url.replace('http://', 'https://', 1),
                    'matched_text': line.strip()[:80],
                })
            # 硬编码版本号（仅对产品文档域名提示）
            if RE_VERSIONED_PATH.search(parsed.path or ''):
                hits.append({
                    'lineno': lineno, 'rule': 'L6', 'rule_name': '硬编码版本号',
                    'severity': 'Suggestion', 'confidence': 'medium',
                    'error': url, 'correction': '建议改为 /latest/ 或使用变量',
                    'matched_text': line.strip()[:80],
                })
        # 裸 URL 中的 HTTP 协议
        for m in RE_BARE_URL.finditer(line):
            url = m.group(1)
            try:
                parsed = urlparse(url)
            except Exception:
                continue
            host = (parsed.hostname or '').lower()
            if host in CODE_HOSTING_HOSTS and url.startswith('http://'):
                hits.append({
                    'lineno': lineno, 'rule': 'L6', 'rule_name': '代码托管平台应使用 HTTPS',
                    'severity': 'Required', 'confidence': 'high',
                    'error': url, 'correction': url.replace('http://', 'https://', 1),
                    'matched_text': line.strip()[:80],
                })
    return hits


# ==================== 主入口 ====================

REVIEW_CRITERIA = {
    'L3.5': '判断该位置是否真应添加链接。若上下文已说明该术语或不是对外引用，可豁免。',
    'L1_fuzzy': '判断该锚点是否为目标锚点的拼写错误（Levenshtein 接近）。',
    'L6_version': '判断该硬编码版本号是否有意保留（如指向历史版本文档）。',
}


def scan_file(file_path, text=None):
    """对单个文件进行扫描"""
    if text is None:
        with open(file_path, 'r', encoding='utf-8') as f:
            text = f.read()
    lines = text.split('\n')
    code_lines = get_code_block_lines(text)
    headings = extract_headings(text, code_lines)

    all_hits = []
    all_hits.extend(check_l1_broken_links(text, file_path, lines, code_lines, headings))
    all_hits.extend(check_l3_link_text_quality(text, lines, code_lines))
    all_hits.extend(check_l3_5_missing_links(text, lines, code_lines))
    all_hits.extend(check_l4_format(text, lines, code_lines, headings))
    all_hits.extend(check_l6_version_consistency(text, lines, code_lines))
    all_hits.extend(check_l8_duplicate_anchors(text, lines, code_lines, headings))

    # 附加文件路径
    for h in all_hits:
        h['file'] = file_path

    return all_hits, len(headings)


def main(targets):
    """对一个文件或目录进行扫描"""
    files = []
    for t in targets:
        if os.path.isdir(t):
            for root, _, fnames in os.walk(t):
                for fn in fnames:
                    if fn.endswith('.md'):
                        files.append(os.path.join(root, fn))
        elif os.path.isfile(t):
            files.append(t)

    all_hits = []
    total_headings = 0
    for f in files:
        try:
            hits, n_headings = scan_file(f)
            all_hits.extend(hits)
            total_headings += n_headings
        except Exception as e:
            print(f'[WARN] {f}: {e}', file=sys.stderr)

    # 排序
    all_hits.sort(key=lambda x: (x.get('file', ''), x['lineno'], x['rule']))

    # 分流
    confirmed = []
    pending = []
    for h in all_hits:
        if h['confidence'] == 'high':
            confirmed.append(h)
        else:
            hp = dict(h)
            hp['review_criteria'] = REVIEW_CRITERIA.get(
                h['rule'], '请根据上下文判断该命中是否为真实问题。'
            )
            hp['review_decision'] = None
            pending.append(hp)

    # 统计
    by_rule = {}
    by_severity = {'Required': 0, 'Suggestion': 0}
    for h in all_hits:
        by_rule[h['rule']] = by_rule.get(h['rule'], 0) + 1
        by_severity[h['severity']] = by_severity.get(h['severity'], 0) + 1

    return {
        'scanned_files': len(files),
        'total_headings': total_headings,
        'violations': all_hits,
        'violations_confirmed': confirmed,
        'violations_pending_review': pending,
        'violation_stats': {
            'total': len(all_hits),
            'total_confirmed': len(confirmed),
            'total_pending_review': len(pending),
            'by_severity': by_severity,
            'by_rule': by_rule,
        },
    }


if __name__ == '__main__':
    targets = sys.argv[1:] if len(sys.argv) > 1 else ['.']
    result = main(targets)
    print(json.dumps(result, ensure_ascii=False, indent=2))
