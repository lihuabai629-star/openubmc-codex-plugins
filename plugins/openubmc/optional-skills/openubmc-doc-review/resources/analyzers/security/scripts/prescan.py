#!/usr/bin/env python3
"""
doc-security-sensitive-tester v1.0 预扫描脚本
确定层 — 对 Markdown 文档进行安全与敏感信息泄露的机械化扫描
覆盖维度：D2 PII、D3 凭证、D4 网络、D5 客户、D6 合规、D7 元数据
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


# ==================== 豁免区域识别 ====================

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


def get_frontmatter_lines(lines):
    """返回 frontmatter 范围 (start_lineno, end_lineno)，若无返回 (0, 0)"""
    if not lines or not lines[0].strip().startswith('---'):
        return (0, 0)
    for i in range(1, len(lines)):
        if lines[i].strip().startswith('---'):
            return (1, i + 1)
    return (0, 0)


def is_in_inline_code(line, pos):
    return line[:pos].count('`') % 2 == 1


def sanitize_context(line, max_len=40):
    """返回脱敏的上下文片段，用于代替原始行内容。
    策略（按顺序执行，确保高置信度脱敏）：
    1. IPv4 地址 → [IP]
    2. 连续数字序列（>=3 位）→ ***
    3. 长 token（>=12 位字母数字混合串）→ ***
    4. 域名中的内部域（如 .internal / .corp）→ [internal-domain]
    5. 最长保留 max_len 字符，超过部分截断
    产出结构形如 "prefix***suffix"，不包含原文可识别片段
    """
    if not line:
        return ''
    text = line.strip()
    # IPv4
    text = re.sub(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', '[IP]', text)
    # 内部域名
    text = re.sub(r'\b[\w\-]+\.(?:internal|corp|lan|intranet)\b',
                  '[internal-domain]', text, flags=re.IGNORECASE)
    # 由斜杠、下划线、短横线连接的密钥串（AWS Secret Key / JWT 等长 token 分隔形式）
    text = re.sub(r'[A-Za-z0-9+/=_\-]{8,}(?:[/_\-][A-Za-z0-9+/=]+){1,}',
                  '***', text)
    # 数字序列（>=3位）
    text = re.sub(r'[0-9]{3,}', '***', text)
    # 长字母数字 token（>=12 位，常为密钥/ID）
    text = re.sub(r'[A-Za-z0-9_\-]{12,}', '***', text)
    if len(text) > max_len:
        text = text[:max_len] + '...'
    return text


# ==================== 豁免数据 ====================

# 示例域名（RFC 2606、RFC 6761）
EXAMPLE_EMAIL_DOMAINS = {
    'example.com', 'example.org', 'example.net',
    'test.com', 'sample.com', 'localhost',
    'your-domain.com', 'your-company.com', 'mycompany.com',
}

# 示例手机号
EXAMPLE_PHONES = {
    '13800138000', '13800138001', '13800138002', '12345678901',
    '13900000000', '18888888888',
}

# 示例身份证号
EXAMPLE_ID_CARDS = {
    '110101199003079999', '110101199003070000', '110101200001019999',
}

# 安全占位符模式
PLACEHOLDER_PATTERNS = [
    re.compile(r'<[A-Z_]+>'),                   # <YOUR_API_KEY>
    re.compile(r'\$\{[A-Z_]+\}'),               # ${API_KEY}
    re.compile(r'\$[A-Z_]+'),                    # $API_KEY
    re.compile(r'(?i)your[_\-]?\w+'),           # your_password
    re.compile(r'(?i)<password>|<token>|<api_key>|<secret_key>|<access_key>'),
    re.compile(r'(?i)placeholder|example|sample|xxx{3,}|\*{3,}'),
    re.compile(r'(?i)replace_me|change_me|todo|fixme'),
]


def is_placeholder(value):
    """判断给定值是否为占位符"""
    if not value:
        return True
    v = value.strip().strip('\'"')
    if len(v) < 6:
        return True
    for p in PLACEHOLDER_PATTERNS:
        if p.search(v):
            return True
    return False


# ==================== IP 地址处理 ====================

# RFC 5737 示例 IP
RE_EXAMPLE_IP = re.compile(r'^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)')
# 回环
RE_LOOPBACK = re.compile(r'^127\.|^0\.0\.0\.0$|^::1$')
# 私有 IP（RFC 1918）
RE_PRIVATE_IP = re.compile(
    r'^(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3})$'
)
# 通用 IPv4
RE_IPV4 = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')


def classify_ip(ip):
    """返回 IP 类别：example / loopback / private / public"""
    if RE_EXAMPLE_IP.match(ip):
        return 'example'
    if RE_LOOPBACK.match(ip):
        return 'loopback'
    if RE_PRIVATE_IP.match(ip):
        return 'private'
    # 验证 IPv4 合法性
    parts = ip.split('.')
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return 'public'
    return 'invalid'


# ==================== D2: PII 检查 ====================

RE_PHONE = re.compile(r'(?<![A-Za-z0-9_])1[3-9]\d{9}(?![A-Za-z0-9_])')
RE_ID_CARD = re.compile(r'(?<![A-Za-z0-9_])[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![A-Za-z0-9_])')
RE_EMAIL = re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')
RE_BANK_CARD = re.compile(r'(?<![A-Za-z0-9_])\d{16,19}(?![A-Za-z0-9_])')


def luhn_check(card):
    """Luhn 算法校验银行卡号"""
    s = 0
    for i, d in enumerate(reversed(card)):
        x = int(d)
        if i % 2 == 1:
            x *= 2
            if x > 9:
                x -= 9
        s += x
    return s % 10 == 0


def check_pii(text, lines, code_lines, fm_range):
    hits = []
    fm_start, fm_end = fm_range
    for lineno, line in enumerate(lines, 1):
        if lineno in code_lines:
            continue
        # frontmatter 内仅检查邮箱（其他字段豁免）
        in_fm = fm_start <= lineno <= fm_end

        if not in_fm:
            # 手机号
            for m in RE_PHONE.finditer(line):
                phone = m.group()
                if phone in EXAMPLE_PHONES:
                    continue
                if is_in_inline_code(line, m.start()):
                    continue
                hits.append({
                    'lineno': lineno, 'rule': 'D2', 'rule_name': '手机号泄露',
                    'severity': 'Required', 'confidence': 'high',
                    'error': phone, 'correction': phone[:3] + '****' + phone[7:],
                    'matched_text_safe': sanitize_context(line),
                })
            # 身份证号
            for m in RE_ID_CARD.finditer(line):
                idc = m.group(0)
                if idc in EXAMPLE_ID_CARDS:
                    continue
                if is_in_inline_code(line, m.start()):
                    continue
                hits.append({
                    'lineno': lineno, 'rule': 'D2', 'rule_name': '身份证号泄露',
                    'severity': 'Critical', 'confidence': 'high',
                    'error': idc, 'correction': idc[:6] + '********' + idc[-1],
                    'matched_text_safe': sanitize_context(line),
                })
            # 银行卡号（含 Luhn 校验）
            for m in RE_BANK_CARD.finditer(line):
                card = m.group()
                # 排除身份证号已命中的位置
                if is_in_inline_code(line, m.start()):
                    continue
                if RE_ID_CARD.match(card):
                    continue
                if luhn_check(card):
                    hits.append({
                        'lineno': lineno, 'rule': 'D2', 'rule_name': '银行卡号泄露',
                        'severity': 'Critical', 'confidence': 'medium',
                        'error': card, 'correction': card[:6] + '****' + card[-4:],
                        'matched_text_safe': sanitize_context(line),
                    })
        # 邮箱（即使在 frontmatter 中也检查）
        for m in RE_EMAIL.finditer(line):
            email = m.group()
            domain = email.split('@', 1)[1].lower()
            if domain in EXAMPLE_EMAIL_DOMAINS:
                continue
            if is_in_inline_code(line, m.start()):
                continue
            # frontmatter author 字段：medium 置信度（可能是团队邮箱）
            conf = 'medium' if in_fm else 'high'
            hits.append({
                'lineno': lineno, 'rule': 'D2', 'rule_name': '邮箱泄露',
                'severity': 'Required', 'confidence': conf,
                'error': email, 'correction': '使用团队邮箱或示例邮箱（@example.com）',
                'matched_text_safe': sanitize_context(line),
            })
    return hits


# ==================== D3: 密钥与凭证检查 ====================

RE_AWS_AKID = re.compile(r'\bAKIA[0-9A-Z]{16}\b')
RE_GITHUB_TOKEN = re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36}\b')
RE_GITLAB_TOKEN = re.compile(r'\bglpat-[A-Za-z0-9\-]{20}\b')
RE_GOOGLE_API = re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b')
RE_JWT = re.compile(r'\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b')
RE_SLACK = re.compile(r'\bxox[bpoa]-[A-Za-z0-9\-]{10,}\b')
RE_STRIPE = re.compile(r'\bsk_(live|test)_[A-Za-z0-9]{24,}\b')
RE_PEM = re.compile(r'-----BEGIN (RSA |DSA |EC |OPENSSH |ENCRYPTED |)?PRIVATE KEY-----')
# var=value 形式
RE_KEY_VALUE = re.compile(
    r'(?i)\b(api[_\-]?key|apikey|secret[_\-]?key|access[_\-]?key|password|passwd|pwd|token|client[_\-]?secret|encryption[_\-]?key)\s*[=:]\s*[\'"]?([^\'"\s,;]+)[\'"]?'
)
# 数据库连接串
RE_DB_CONN = re.compile(
    r'(?i)\b(mysql|postgres(?:ql)?|redis|mongodb|jdbc:mysql|jdbc:postgresql)://([^:\s]+):([^@\s]+)@([^/\s:]+)(?::(\d+))?'
)


def check_secrets(text, lines, code_lines, fm_range):
    hits = []
    fm_start, fm_end = fm_range

    # 高置信度特定模式
    patterns = [
        (RE_AWS_AKID, 'AWS Access Key ID', 'Critical'),
        (RE_GITHUB_TOKEN, 'GitHub Token', 'Critical'),
        (RE_GITLAB_TOKEN, 'GitLab Token', 'Critical'),
        (RE_GOOGLE_API, 'Google API Key', 'Critical'),
        (RE_JWT, 'JWT Token', 'Critical'),
        (RE_SLACK, 'Slack Token', 'Critical'),
        (RE_STRIPE, 'Stripe Key', 'Critical'),
    ]
    for lineno, line in enumerate(lines, 1):
        if fm_start <= lineno <= fm_end:
            continue
        for pat, name, severity in patterns:
            for m in pat.finditer(line):
                hits.append({
                    'lineno': lineno, 'rule': 'D3', 'rule_name': f'{name} 明文暴露',
                    'severity': severity, 'confidence': 'high',
                    'error': m.group()[:20] + '...', 'correction': f'替换为 <YOUR_{name.upper().replace(" ", "_")}> 或环境变量',
                    'matched_text_safe': sanitize_context(line),
                })
    # PEM 私钥
    for lineno, line in enumerate(lines, 1):
        if RE_PEM.search(line):
            hits.append({
                'lineno': lineno, 'rule': 'D3', 'rule_name': 'PEM 私钥泄露',
                'severity': 'Critical', 'confidence': 'high',
                'error': 'BEGIN PRIVATE KEY', 'correction': '删除私钥内容，仅保留路径引用',
                'matched_text_safe': sanitize_context(line),
            })
    # var=value 形式（排除占位符）
    for lineno, line in enumerate(lines, 1):
        if lineno in code_lines and lineno not in code_lines:  # 代码块内也扫描密钥
            pass
        for m in RE_KEY_VALUE.finditer(line):
            var_name = m.group(1)
            value = m.group(2)
            if is_placeholder(value):
                continue
            # 排除明显是文档示例的（如包含 example）
            if 'example' in value.lower() or 'sample' in value.lower():
                continue
            hits.append({
                'lineno': lineno, 'rule': 'D3', 'rule_name': f'{var_name} 明文值',
                'severity': 'Critical', 'confidence': 'medium',
                'error': f'{var_name}={value[:8]}...', 'correction': f'{var_name}=<YOUR_{var_name.upper()}>',
                'matched_text_safe': sanitize_context(line),
            })
    # 数据库连接串
    for lineno, line in enumerate(lines, 1):
        for m in RE_DB_CONN.finditer(line):
            protocol, user, pwd, host, port = m.groups()
            if is_placeholder(pwd):
                continue
            if is_placeholder(user) and is_placeholder(host):
                continue
            hits.append({
                'lineno': lineno, 'rule': 'D3', 'rule_name': '数据库连接串含明文密码',
                'severity': 'Critical', 'confidence': 'high',
                'error': f'{protocol}://{user}:***@{host}',
                'correction': f'{protocol}://<USER>:<PASSWORD>@<HOST>:<PORT>/<DB>',
                'matched_text_safe': sanitize_context(line),
            })
    return hits


# ==================== D4: 网络信息检查 ====================

RE_INTERNAL_DOMAIN = re.compile(r'\b[a-zA-Z0-9\-]+\.(internal|local|intranet|corp|lan)\b', re.IGNORECASE)
RE_DB_ADDR = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(3306|5432|6379|27017|9200|9092|2181|5672|11211)\b')


def check_network(text, lines, code_lines, fm_range):
    hits = []
    fm_start, fm_end = fm_range
    for lineno, line in enumerate(lines, 1):
        if fm_start <= lineno <= fm_end:
            continue
        # IP 地址扫描
        for m in RE_IPV4.finditer(line):
            ip = m.group()
            cat = classify_ip(ip)
            if cat == 'private':
                if is_in_inline_code(line, m.start()):
                    pass  # 代码块中也扫描 IP
                hits.append({
                    'lineno': lineno, 'rule': 'D4', 'rule_name': '内网 IP 地址泄露',
                    'severity': 'Required', 'confidence': 'high',
                    'error': ip, 'correction': '使用 RFC 5737 示例 IP（如 192.0.2.1）或 <HOST> 占位符',
                    'matched_text_safe': sanitize_context(line),
                })
            elif cat == 'public':
                # 排除 lineno 中已是 markdown 链接的部分
                hits.append({
                    'lineno': lineno, 'rule': 'D4', 'rule_name': '公网 IP 地址泄露',
                    'severity': 'Required', 'confidence': 'medium',
                    'error': ip, 'correction': '确认是否为示例/已授权公开，否则使用域名或示例 IP',
                    'matched_text_safe': sanitize_context(line),
                })
        # 内部域名
        for m in RE_INTERNAL_DOMAIN.finditer(line):
            domain = m.group()
            hits.append({
                'lineno': lineno, 'rule': 'D4', 'rule_name': '内部域名泄露',
                'severity': 'Required', 'confidence': 'high',
                'error': domain, 'correction': '替换为 example.com 或 <DOMAIN> 占位符',
                'matched_text_safe': sanitize_context(line),
            })
        # 数据库地址
        for m in RE_DB_ADDR.finditer(line):
            full = m.group()
            ip = m.group(1)
            if classify_ip(ip) in ('private', 'public'):
                hits.append({
                    'lineno': lineno, 'rule': 'D4', 'rule_name': '数据库地址泄露',
                    'severity': 'Required', 'confidence': 'high',
                    'error': full, 'correction': '<DB_HOST>:<DB_PORT>',
                    'matched_text_safe': sanitize_context(line),
                })
    return hits


# ==================== D6: 敏感词与合规检查 ====================

# 商业机密标记
SECRET_MARKERS = ['绝密', '机密', '秘密', 'TOP SECRET', 'CONFIDENTIAL', 'SECRET', '内部', 'INTERNAL', '仅供内部', '仅供内部参考', 'DRAFT', '草稿']

# 中性表述建议
TERM_REPLACEMENTS = {
    '黑名单': 'blocklist / 阻止列表',
    '白名单': 'allowlist / 允许列表',
    '主从': '主备 / Leader-Follower',
    '暴力破解': '密码猜测攻击',
    '非法入侵': '未授权访问',
}

# 绝对化声明
RE_ABSOLUTE = re.compile(r'(100%\s*(安全|可靠|稳定|准确)|绝对(安全|可靠|不会|完美)|永远不会|从不出错)')


def check_compliance(text, lines, code_lines, fm_range):
    hits = []
    fm_start, fm_end = fm_range
    for lineno, line in enumerate(lines, 1):
        if fm_start <= lineno <= fm_end:
            continue
        # 商业机密标记
        for marker in SECRET_MARKERS:
            if marker in line:
                # 排除代码注释中作为参数值的情况
                if marker in ('内部', 'INTERNAL', 'DRAFT', '草稿', 'SECRET'):
                    conf = 'medium'  # 此类词可能为业务术语
                else:
                    conf = 'high'
                hits.append({
                    'lineno': lineno, 'rule': 'D6', 'rule_name': f'商业机密标记「{marker}」',
                    'severity': 'Required', 'confidence': conf,
                    'error': marker, 'correction': '对外文档须删除该标记并确认内容可公开',
                    'matched_text_safe': sanitize_context(line),
                })
                break  # 同行多个标记只报一次
        # 中性表述建议
        for old_term, new_term in TERM_REPLACEMENTS.items():
            if old_term in line:
                if is_in_inline_code(line, line.find(old_term)):
                    continue
                hits.append({
                    'lineno': lineno, 'rule': 'D6', 'rule_name': f'歧视性/不当用语「{old_term}」',
                    'severity': 'Suggestion', 'confidence': 'medium',
                    'error': old_term, 'correction': new_term,
                    'matched_text_safe': sanitize_context(line),
                })
        # 绝对化声明
        for m in RE_ABSOLUTE.finditer(line):
            hits.append({
                'lineno': lineno, 'rule': 'D6', 'rule_name': '绝对化声明',
                'severity': 'Required', 'confidence': 'high',
                'error': m.group(), 'correction': '使用相对化表述（如"多层安全防护""高可靠"）',
                'matched_text_safe': sanitize_context(line),
            })
    return hits


# ==================== D7: 元数据与隐藏信息检查 ====================

RE_HTML_COMMENT = re.compile(r'<!--(.+?)-->', re.DOTALL)
RE_INTERNAL_LINK = re.compile(r'(?i)(https?://)?(wiki\.internal|jira\.[\w\-]+|confluence\.[\w\-]+|[\w\-]+\.internal|[\w\-]+\.intranet|[\w\-]+\.corp)[/\w\-#?=&%.]*')
RE_TODO_MARK = re.compile(r'\b(TODO|FIXME|HACK|XXX)\b[:：]?\s*(.{0,80})')
RE_ZERO_WIDTH = re.compile(r'[\u200B\u200C\u200D\uFEFF]')


def check_metadata(text, lines, code_lines, fm_range):
    hits = []
    fm_start, fm_end = fm_range
    for lineno, line in enumerate(lines, 1):
        # HTML 注释
        for m in RE_HTML_COMMENT.finditer(line):
            content = m.group(1).strip()
            if not content:
                continue
            hits.append({
                'lineno': lineno, 'rule': 'D7', 'rule_name': 'HTML 注释（可能含敏感信息）',
                'severity': 'Required', 'confidence': 'medium',
                'error': f'<!-- {content[:40]} -->', 'correction': '审查注释内容，删除内部备注/TODO',
                'matched_text_safe': sanitize_context(line),
            })
        # 内部链接
        for m in RE_INTERNAL_LINK.finditer(line):
            link = m.group()
            hits.append({
                'lineno': lineno, 'rule': 'D7', 'rule_name': '内部链接泄露',
                'severity': 'Required', 'confidence': 'high',
                'error': link, 'correction': '替换为公开链接或删除',
                'matched_text_safe': sanitize_context(line),
            })
        # TODO/FIXME
        for m in RE_TODO_MARK.finditer(line):
            marker = m.group(1)
            hits.append({
                'lineno': lineno, 'rule': 'D7', 'rule_name': f'{marker} 标记',
                'severity': 'Suggestion', 'confidence': 'high',
                'error': m.group(0)[:50], 'correction': '发布前清理 TODO/FIXME 标记',
                'matched_text_safe': sanitize_context(line),
            })
        # 零宽字符
        if RE_ZERO_WIDTH.search(line):
            hits.append({
                'lineno': lineno, 'rule': 'D7', 'rule_name': '零宽字符（隐藏文本）',
                'severity': 'Required', 'confidence': 'high',
                'error': 'U+200B/200C/200D/FEFF', 'correction': '清理零宽字符（可能是水印或恶意注入）',
                'matched_text_safe': sanitize_context(line),
            })
    return hits


# ==================== 主入口 ====================

REVIEW_CRITERIA = {
    'D2_email_fm': 'frontmatter 中的邮箱可能是团队邮箱（如 docs-team@company.com），判断是否为个人邮箱泄露。',
    'D2_bank_card': 'Luhn 校验通过的数字可能是真实银行卡号，也可能是符合 Luhn 的示例。结合上下文判断。',
    'D3_key_value': '判断该 var=value 是否为真实凭证。若为脱敏后的示例或文档片段，可豁免。',
    'D4_public_ip': '判断该公网 IP 是否为已授权公开（如自有云服务的公网域名解析）。否则须脱敏。',
    'D6_marker_soft': '"内部""INTERNAL""DRAFT" 可能为业务术语（如"内部服务"），结合上下文判断。',
    'D6_term': '判断该词在当前上下文中是否需要替换为中性表述。技术架构术语可保留。',
    'D7_html_comment': 'HTML 注释中可能包含内部信息（评审记录、TODO、链接）。判断是否含敏感内容。',
}

DIM_NAMES = {
    'D2': '个人数据与隐私',
    'D3': '明文密钥与凭证',
    'D4': '公网信息与内部地址',
    'D5': '局点与客户信息',
    'D6': '敏感词与合规风险',
    'D7': '元数据与隐藏信息',
}


def scan_file(file_path, text=None):
    if text is None:
        with open(file_path, 'r', encoding='utf-8') as f:
            text = f.read()
    lines = text.split('\n')
    code_lines = get_code_block_lines(text)
    fm_range = get_frontmatter_lines(lines)

    all_hits = []
    all_hits.extend(check_pii(text, lines, code_lines, fm_range))
    all_hits.extend(check_secrets(text, lines, code_lines, fm_range))
    all_hits.extend(check_network(text, lines, code_lines, fm_range))
    all_hits.extend(check_compliance(text, lines, code_lines, fm_range))
    all_hits.extend(check_metadata(text, lines, code_lines, fm_range))

    for h in all_hits:
        h['file'] = file_path
        h['dimension_name'] = DIM_NAMES.get(h['rule'], 'Unknown')

    return all_hits


def main(targets):
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
    for f in files:
        try:
            all_hits.extend(scan_file(f))
        except Exception as e:
            print(f'[WARN] {f}: {e}', file=sys.stderr)

    all_hits.sort(key=lambda x: (x.get('file', ''), x['lineno'], x['rule']))

    confirmed = []
    pending = []
    for h in all_hits:
        if h['confidence'] == 'high':
            confirmed.append(h)
        else:
            hp = dict(h)
            # 选择最匹配的复核标准
            criteria_key = f"{h['rule']}_{h['rule_name'][:10]}"
            hp['review_criteria'] = REVIEW_CRITERIA.get(
                criteria_key,
                '请根据上下文判断该命中是否为真实敏感信息。脱敏数据/示例数据可豁免。'
            )
            hp['review_decision'] = None
            pending.append(hp)

    by_rule = {}
    by_severity = {'Critical': 0, 'Required': 0, 'Suggestion': 0}
    for h in all_hits:
        by_rule[h['rule']] = by_rule.get(h['rule'], 0) + 1
        by_severity[h['severity']] = by_severity.get(h['severity'], 0) + 1

    return {
        'scanned_files': len(files),
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


def scan_text(text, file_path='stdin'):
    lines = text.split('\n')
    code_lines = get_code_block_lines(text)
    fm_range = get_frontmatter_lines(lines)

    all_hits = []
    all_hits.extend(check_pii(text, lines, code_lines, fm_range))
    all_hits.extend(check_secrets(text, lines, code_lines, fm_range))
    all_hits.extend(check_network(text, lines, code_lines, fm_range))
    all_hits.extend(check_compliance(text, lines, code_lines, fm_range))
    all_hits.extend(check_metadata(text, lines, code_lines, fm_range))

    for h in all_hits:
        h['file'] = file_path
        h['dimension_name'] = DIM_NAMES.get(h['rule'], 'Unknown')

    return all_hits


if __name__ == '__main__':
    if len(sys.argv) > 1:
        targets = sys.argv[1:]
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
        for f in files:
            try:
                with open(f, 'r', encoding='utf-8') as fp:
                    all_hits.extend(scan_text(fp.read(), f))
            except Exception as e:
                print(f'[WARN] {f}: {e}', file=sys.stderr)
    else:
        text = sys.stdin.read()
        all_hits = scan_text(text, 'stdin')

    all_hits.sort(key=lambda x: (x.get('file', ''), x['lineno'], x['rule']))

    confirmed = []
    pending = []
    for h in all_hits:
        if h['confidence'] == 'high':
            confirmed.append(h)
        else:
            hp = dict(h)
            criteria_key = f"{h['rule']}_{h['rule_name'][:10]}"
            hp['review_criteria'] = REVIEW_CRITERIA.get(
                criteria_key,
                '请根据上下文判断该命中是否为真实敏感信息。脱敏数据/示例数据可豁免。'
            )
            hp['review_decision'] = None
            pending.append(hp)

    by_rule = {}
    by_severity = {'Critical': 0, 'Required': 0, 'Suggestion': 0}
    for h in all_hits:
        by_rule[h['rule']] = by_rule.get(h['rule'], 0) + 1
        by_severity[h['severity']] = by_severity.get(h['severity'], 0) + 1

    result = {
        'scanned_files': len(files) if len(sys.argv) > 1 else 1,
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
    print(json.dumps(result, ensure_ascii=False, indent=2))
