#!/usr/bin/env python3
"""
doc-typo-tester v1.0 预扫描脚本
确定层 — 基于 references/ 字典对中文文档进行确定性错别字扫描
覆盖 10 大维度：拼音输入、技术术语、词序颠倒、重复字、漏字、形近字、易混词、简繁混用、英文术语、术语一致性
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

REF_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'references')


def parse_table(text, col_a=0, col_b=1):
    """解析 Markdown 表格，返回 col_b -> col_a 的映射（错误 -> 正确）"""
    mapping = {}
    in_table = False
    for line in text.split('\n'):
        stripped = line.strip()
        if not stripped.startswith('|'):
            in_table = False
            continue
        cells = [c.strip() for c in stripped.split('|')[1:-1]]
        if not cells:
            continue
        if not in_table:
            in_table = True
            continue
        if all(re.match(r'^[:\-\s]+$', c) for c in cells):
            continue
        if len(cells) > max(col_a, col_b):
            correct = cells[col_a].strip()
            wrong_raw = cells[col_b].strip()
            for wrong in re.split(r'[,，/]', wrong_raw):
                wrong = wrong.strip()
                wrong = re.sub(r'（.*?）', '', wrong).strip()
                if wrong and correct and wrong != correct and len(wrong) >= 2:
                    mapping[wrong] = correct
    return mapping


def load_dictionaries():
    dicts = {}
    files = {
        'pinyin': 'pinyin-errors.md',
        'tech_terms': 'tech-terms.md',
        'word_order': 'word-order-errors.md',
        'dup_missing': 'dup-missing-chars.md',
        'simp_trad': 'simplified-traditional.md',
        'english_terms': 'english-term-errors.md',
        'confusing': 'confusing-words.md',
        'look_alike': 'look-alike-chars.md',
    }
    for key, fname in files.items():
        path = os.path.join(REF_DIR, fname)
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                dicts[key] = parse_table(f.read())
        else:
            dicts[key] = {}
    return dicts


# ==================== 豁免区域识别 ====================

def get_code_block_lines(text):
    """返回所有代码块行号的集合"""
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
    """返回 frontmatter 结束行号（0 表示无 frontmatter）"""
    if not lines or not lines[0].strip().startswith('---'):
        return 0
    for i in range(1, len(lines)):
        if lines[i].strip().startswith('---'):
            return i + 1
    return 0


def is_in_inline_code(line, pos):
    """判断位置是否在行内代码中"""
    return line[:pos].count('`') % 2 == 1


def is_in_url_or_path(line, pos):
    """判断位置是否在 URL/路径/Markdown 链接中"""
    # 检查是否在 markdown link 的 url 部分 [text](url)
    before = line[:pos]
    last_open = before.rfind('](')
    if last_open != -1:
        after_close = line.find(')', last_open)
        if after_close == -1 or pos < after_close:
            return True
    # 裸 URL
    for m in re.finditer(r'https?://\S+|file://\S+|/[a-zA-Z0-9_/\.\-]+', line):
        if m.start() <= pos < m.end():
            return True
    return False


# ==================== 扫描函数 ====================

# 评分说明：
# high   — 字典精确匹配的纯拼音/词序/重复/简繁/英文术语错误，可直接确认
# medium — 形近字、易混词、漏字、术语一致性等需要 LLM 上下文复核
HIGH_DIMS = {'pinyin', 'tech_terms', 'word_order', 'dup_missing_repeat', 'simp_trad', 'english_terms'}
MEDIUM_DIMS = {'look_alike', 'confusing', 'dup_missing_omit', 'consistency'}

REVIEW_CRITERIA = {
    'look_alike': '判断该字在当前上下文中是否为形近字误用。需根据语义判断（如"己/已/巳"）。若用法正确则豁免。',
    'confusing': '判断该词在当前上下文中是否为易混词误用（如"必须/必需""制定/制订"）。须结合语法位置和语义判断。',
    'dup_missing_omit': '判断该词是否真为漏字错误（如"推理服务"是否应为"推理服务器"）。需根据上下文判断。',
    'consistency': '判断该术语表述是否真不一致。同一概念在全文中应统一表述。',
    'pinyin': '判断该词是否真为拼音输入错误。少数情况下错误形式可能在特定语境中合法（如"缺省"在港台文档中正确）。',
}


def scan_dictionary(text, dicts):
    """对全文按字典扫描"""
    lines = text.split('\n')
    code_lines = get_code_block_lines(text)
    fm_end = get_frontmatter_end(lines)

    rule_map = {
        'pinyin': ('6.2', '拼音输入错误', 'high', 'Required'),
        'tech_terms': ('7.2', '技术术语误写', 'high', 'Required'),
        'word_order': ('6.4', '词序颠倒', 'high', 'Required'),
        'simp_trad': ('5', '简繁混用', 'high', 'Required'),
        'english_terms': ('7.3', '英文术语拼写', 'high', 'Required'),
        'confusing': ('4', '易混词', 'medium', 'Required'),
        'look_alike': ('3', '形近字混淆', 'medium', 'Required'),
    }

    hits = []
    for dim, mapping in dicts.items():
        if dim not in rule_map:
            continue
        rule, rule_name, confidence, severity = rule_map[dim]
        # 按长度降序，避免短词命中长词的子串
        sorted_wrong = sorted(mapping.keys(), key=len, reverse=True)

        for lineno, line in enumerate(lines, 1):
            if lineno in code_lines:
                continue
            if 1 <= lineno <= fm_end:
                continue

            for wrong in sorted_wrong:
                idx = 0
                while True:
                    pos = line.find(wrong, idx)
                    if pos == -1:
                        break
                    # 豁免检查
                    if is_in_inline_code(line, pos):
                        idx = pos + 1
                        continue
                    if is_in_url_or_path(line, pos):
                        idx = pos + 1
                        continue
                    # 命中
                    hits.append({
                        'lineno': lineno,
                        'rule': rule,
                        'rule_name': rule_name,
                        'severity': severity,
                        'dimension': dim,
                        'error': wrong,
                        'correction': mapping[wrong],
                        'matched_text': line[max(0, pos-10):min(len(line), pos+len(wrong)+10)].strip(),
                        'confidence': confidence,
                    })
                    idx = pos + len(wrong)
                    break  # 同一词同一行只报一次
    return hits


def scan_duplicate_chars(text):
    """扫描重复字错误（如"用户户""参数数"）"""
    lines = text.split('\n')
    code_lines = get_code_block_lines(text)
    fm_end = get_frontmatter_end(lines)

    # 已知的重复字模式：A B B 形式（如"用户户"中 户 重复）
    known_words = {
        '用户': '户', '参数': '数', '配置': '配', '安装': '装',
        '运行': '行', '系统': '统', '服务': '务', '环境': '境',
        '设置': '置', '部署': '署',
    }

    hits = []
    for lineno, line in enumerate(lines, 1):
        if lineno in code_lines:
            continue
        if 1 <= lineno <= fm_end:
            continue
        for word, last_char in known_words.items():
            pattern = word + last_char
            idx = 0
            while True:
                pos = line.find(pattern, idx)
                if pos == -1:
                    break
                if is_in_inline_code(line, pos) or is_in_url_or_path(line, pos):
                    idx = pos + 1
                    continue
                hits.append({
                    'lineno': lineno,
                    'rule': '6.5',
                    'rule_name': '重复字',
                    'severity': 'Required',
                    'dimension': 'dup_missing_repeat',
                    'error': pattern,
                    'correction': word,
                    'matched_text': line[max(0, pos-8):min(len(line), pos+len(pattern)+8)].strip(),
                    'confidence': 'high',
                })
                idx = pos + len(pattern)
    return hits


def scan_missing_chars(text, dicts):
    """扫描漏字错误（如"服务"应为"服务器"、"布式"应为"分布式"）"""
    lines = text.split('\n')
    code_lines = get_code_block_lines(text)
    fm_end = get_frontmatter_end(lines)

    # 从 dup_missing 字典中提取漏字映射（错误 -> 正确）
    # dup_missing 字典格式：错误形式 -> 正确形式
    missing_mapping = dicts.get('dup_missing', {})

    hits = []
    for lineno, line in enumerate(lines, 1):
        if lineno in code_lines:
            continue
        if 1 <= lineno <= fm_end:
            continue

        # 按长度降序，避免短词命中长词的子串
        sorted_wrong = sorted(missing_mapping.keys(), key=len, reverse=True)

        for wrong in sorted_wrong:
            correct = missing_mapping[wrong]
            idx = 0
            while True:
                pos = line.find(wrong, idx)
                if pos == -1:
                    break
                # 豁免检查
                if is_in_inline_code(line, pos):
                    idx = pos + 1
                    continue
                if is_in_url_or_path(line, pos):
                    idx = pos + 1
                    continue

                # 检查是否是真正的漏字（后面不是正确的后续字符）
                # 例如："服务"后面如果是"器"，则不是漏字
                after_pos = pos + len(wrong)
                if after_pos < len(line):
                    # 检查错误词后面是否跟着正确词的后续字符
                    # 如"服务"后面跟着"器"，则不是漏字
                    correct_suffix = correct[len(wrong):]
                    if correct_suffix and line[after_pos:after_pos+len(correct_suffix)] == correct_suffix:
                        idx = pos + 1
                        continue

                # 命中
                hits.append({
                    'lineno': lineno,
                    'rule': '6.5',
                    'rule_name': '漏字',
                    'severity': 'Required',
                    'dimension': 'dup_missing_omit',
                    'error': wrong,
                    'correction': correct,
                    'matched_text': line[max(0, pos-10):min(len(line), pos+len(wrong)+10)].strip(),
                    'confidence': 'medium',
                })
                idx = pos + len(wrong)
                break  # 同一词同一行只报一次
    return hits


def scan_consistency(text):
    """术语表述一致性扫描"""
    lines = text.split('\n')
    code_lines = get_code_block_lines(text)

    # 检测同时出现「推理服务器」与「推理服务」（非"推理服务器"的孤立"推理服务"）
    pairs = [
        ('推理服务器', '推理服务'),
        ('训练服务器', '训练服务'),
    ]

    hits = []
    for full_term, partial_term in pairs:
        full_count = 0
        partial_lines = []
        for lineno, line in enumerate(lines, 1):
            if lineno in code_lines:
                continue
            if full_term in line:
                full_count += line.count(full_term)
            # 找出"推理服务"且后面不是"器"的位置
            idx = 0
            while True:
                pos = line.find(partial_term, idx)
                if pos == -1:
                    break
                after_pos = pos + len(partial_term)
                if after_pos < len(line) and line[after_pos] == '器':
                    idx = pos + 1
                    continue
                if is_in_inline_code(line, pos) or is_in_url_or_path(line, pos):
                    idx = pos + 1
                    continue
                partial_lines.append((lineno, line, pos))
                idx = pos + len(partial_term)

        # 若同时出现 full_term 和孤立的 partial_term，标记一致性问题
        if full_count > 0 and partial_lines:
            for lineno, line, pos in partial_lines:
                hits.append({
                    'lineno': lineno,
                    'rule': '7.4',
                    'rule_name': '术语表述一致性',
                    'severity': 'Suggestion',
                    'dimension': 'consistency',
                    'error': partial_term,
                    'correction': full_term,
                    'matched_text': line[max(0, pos-10):min(len(line), pos+len(partial_term)+10)].strip(),
                    'confidence': 'medium',
                })
    return hits


def main(text):
    dicts = load_dictionaries()

    all_hits = []
    all_hits.extend(scan_dictionary(text, dicts))
    all_hits.extend(scan_duplicate_chars(text))
    all_hits.extend(scan_missing_chars(text, dicts))
    all_hits.extend(scan_consistency(text))

    # 按行号、规则排序
    all_hits.sort(key=lambda x: (x['lineno'], x['rule']))

    # 分流到 confirmed / pending_review
    confirmed = []
    pending = []
    for h in all_hits:
        if h['confidence'] == 'high':
            confirmed.append(h)
        else:
            h_pending = dict(h)
            h_pending['review_criteria'] = REVIEW_CRITERIA.get(
                h['dimension'], '请根据上下文判断该命中是否为真实错别字。'
            )
            h_pending['review_decision'] = None
            pending.append(h_pending)

    # 统计
    rule_counts = {}
    severity_counts = {'Required': 0, 'Suggestion': 0}
    for h in all_hits:
        rule_counts[h['rule']] = rule_counts.get(h['rule'], 0) + 1
        severity_counts[h['severity']] = severity_counts.get(h['severity'], 0) + 1

    return {
        'dictionary_stats': {k: len(v) for k, v in dicts.items()},
        'violations': all_hits,
        'violations_confirmed': confirmed,
        'violations_pending_review': pending,
        'violation_stats': {
            'total': len(all_hits),
            'total_confirmed': len(confirmed),
            'total_pending_review': len(pending),
            'by_severity': severity_counts,
            'by_rule': rule_counts,
        },
    }


if __name__ == '__main__':
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r', encoding='utf-8') as f:
            text = f.read()
    else:
        text = sys.stdin.read()
    result = main(text)
    print(json.dumps(result, ensure_ascii=False, indent=2))
