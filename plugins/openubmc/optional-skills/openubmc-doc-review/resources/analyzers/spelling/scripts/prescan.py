"""
doc-spelling-tester v1.0 预扫描脚本
确定层 — 基于字典的确定性拼写扫描，输出标准化 violations 数组
工作流程：
  1. 解析 references/ 下的对照表，构建错误→正确的字典
  2. 逐行扫描文档，在豁免区域外匹配已知拼写错误
  3. 输出 violations_confirmed(high) + violations_pending_review(medium)
     pending_review 每条附加 review_criteria 字段，强制模型逐条复核
"""

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../../../../../skills/openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)

import re
import json
import os
import sys

# ==================== 字典构建 ====================

def parse_markdown_table(text):
    """解析 Markdown 表格，提取正确拼写→常见错误列表的映射"""
    mapping = {}
    lines = text.split('\n')
    in_table = False
    headers = []
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith('|'):
            in_table = False
            continue
        cells = [c.strip() for c in stripped.split('|')[1:-1]]
        if not cells:
            continue
        if not in_table:
            # 表头行
            headers = cells
            in_table = True
            continue
        # 忽略分隔行（全是 - 或 :）
        if all(re.match(r'^[:\-\s]+$', c) for c in cells):
            continue
        # 数据行：尝试按列位置推断含义
        if len(cells) >= 2:
            correct = cells[0].strip()
            wrong_raw = cells[1].strip()
            # 处理 multiple common errors separated by comma
            wrong_list = [w.strip() for w in re.split(r'[,，/]', wrong_raw) if w.strip()]
            for wrong in wrong_list:
                if wrong and correct.lower() != wrong.lower():
                    mapping[wrong] = correct
    return mapping

def parse_tech_terms_table(text):
    """解析技术术语表，提取错误→正确的映射"""
    mapping = {}
    lines = text.split('\n')
    in_table = False
    for line in lines:
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
        if len(cells) >= 2:
            correct = cells[0].strip()
            wrong_raw = cells[1].strip()
            wrong_list = [w.strip() for w in re.split(r'[,，/]', wrong_raw) if w.strip()]
            for wrong in wrong_list:
                if wrong and correct.lower() != wrong.lower():
                    mapping[wrong] = correct
    return mapping

def parse_brand_case_table(text):
    """解析品牌名/协议名大小写表，提取错误→正确的映射"""
    mapping = {}
    lines = text.split('\n')
    in_table = False
    for line in lines:
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
        if len(cells) >= 2:
            correct = cells[0].strip()
            wrong_raw = cells[1].strip()
            wrong_list = [w.strip() for w in re.split(r'[,，/]', wrong_raw) if w.strip()]
            for wrong in wrong_list:
                if wrong and correct.lower() != wrong.lower():
                    mapping[wrong] = correct
    return mapping

def parse_confusable_table(text):
    """解析易混词表 — 这里我们提取的是 pairs 关系，不做简单替换"""
    pairs = []
    lines = text.split('\n')
    in_table = False
    for line in lines:
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
        if len(cells) >= 4:
            word_a = cells[0].strip()
            word_b = cells[1].strip()
            usage_a = cells[2].strip()
            pairs.append((word_a, word_b, usage_a, cells[3].strip()))
    return pairs

def parse_american_british_table(text):
    """解析美式/英式对照表，提取英式→美式的映射"""
    uk_to_us = {}
    lines = text.split('\n')
    in_table = False
    section = ''
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('## '):
            section = stripped
            in_table = False
            continue
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
        if len(cells) >= 2:
            us = cells[0].strip()
            uk = cells[1].strip()
            if us and uk and us != uk:
                uk_to_us[uk] = us
    return uk_to_us


def build_dictionaries(ref_dir):
    """构建所有字典"""
    dictionaries = {}

    # 1. 高频拼写错误字典
    misspellings_path = os.path.join(ref_dir, 'common-misspellings.md')
    if os.path.exists(misspellings_path):
        with open(misspellings_path, 'r', encoding='utf-8') as f:
            dictionaries['misspellings'] = parse_markdown_table(f.read())
    else:
        dictionaries['misspellings'] = {}

    # 2. 技术术语字典
    tech_terms_path = os.path.join(ref_dir, 'tech-terms.md')
    if os.path.exists(tech_terms_path):
        with open(tech_terms_path, 'r', encoding='utf-8') as f:
            text = f.read()
            dictionaries['tech_terms'] = parse_tech_terms_table(text)
            # 品牌名大小写也从中解析
            brand_section = text.split('## 品牌名/产品名大小写')
            if len(brand_section) > 1:
                protocol_section = brand_section[1].split('## 协议/标准名大小写')
                dictionaries['brand_case'] = parse_brand_case_table(brand_section[0])
                if len(protocol_section) > 1:
                    dictionaries['protocol_case'] = parse_brand_case_table(protocol_section[0])
            else:
                dictionaries['brand_case'] = {}
                dictionaries['protocol_case'] = {}
    else:
        dictionaries['tech_terms'] = {}
        dictionaries['brand_case'] = {}
        dictionaries['protocol_case'] = {}

    # 3. 易混词 pairs（用于中等置信度扫描）
    confusable_path = os.path.join(ref_dir, 'confusing-words.md')
    if os.path.exists(confusable_path):
        with open(confusable_path, 'r', encoding='utf-8') as f:
            dictionaries['confusable_pairs'] = parse_confusable_table(f.read())
    else:
        dictionaries['confusable_pairs'] = []

    # 4. 美式/英式字典
    ame_brit_path = os.path.join(ref_dir, 'american-british.md')
    if os.path.exists(ame_brit_path):
        with open(ame_brit_path, 'r', encoding='utf-8') as f:
            dictionaries['uk_to_us'] = parse_american_british_table(f.read())
    else:
        dictionaries['uk_to_us'] = {}

    # 合并所有错误→正确的映射（按优先级：misspellings > tech_terms > brand_case > protocol_case）
    combined = {}
    for key in ['misspellings', 'tech_terms', 'brand_case', 'protocol_case']:
        for wrong, correct in dictionaries.get(key, {}).items():
            # 不覆盖更高优先级的映射
            if wrong not in combined:
                combined[wrong] = correct

    dictionaries['combined'] = combined
    return dictionaries


# ==================== 豁免区域识别 ====================

def get_code_block_lines(text):
    """返回所有代码块行号的集合（含围栏行本身）"""
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

def is_inline_code(text, pos):
    """判断给定位置是否在行内代码中"""
    # 简单实现：扫描到位置前的反引号对
    before = text[:pos]
    # 计算未匹配的 ` 数量
    count = before.count('`')
    return count % 2 == 1

def is_in_url(text, pos):
    """判断给定位置是否在 URL 中"""
    line_start = text.rfind('\n', 0, pos) + 1
    if line_start == 0:
        line_start = 0
    line = text[line_start:text.find('\n', pos) if text.find('\n', pos) != -1 else len(text)]
    # 检查是否在 Markdown 链接的 URL 部分：](...) 内
    before_in_line = text[max(line_start, pos - 200):pos]
    # 找到最近的 ](
    last_link_start = before_in_line.rfind('](')
    if last_link_start != -1 and last_link_start > before_in_line.rfind('\n'):
        # 在链接 URL 中
        after_part = text[pos:pos+200]
        in_url_before = ')' not in before_in_line[last_link_start+2:pos]
        closing_in_after = ')' in after_part
        if in_url_before and closing_in_after:
            return True
    # 检查是否在裸 URL 中
    url_pattern = re.compile(r'https?://[^\s\)）】<>"\'\]\u4e00-\u9fff]+')
    for m in url_pattern.finditer(line):
        if m.start() <= pos - line_start < m.end():
            return True
    return False

def is_in_frontmatter(text, lineno, lines):
    """判断是否在 YAML frontmatter 中"""
    if not lines or not lines[0].strip().startswith('---'):
        return False
    # 找到第一个 --- 之后
    end_line = -1
    for i in range(1, len(lines)):
        if lines[i].strip().startswith('---'):
            end_line = i + 1
            break
    if end_line == -1:
        return False
    return 1 <= lineno <= end_line

def is_in_markdown_link(text, pos):
    """判断是否在 Markdown 链接文本 [text] 中"""
    before = text[:pos]
    # 查找最近的 [ 和 ]
    last_open = before.rfind('[')
    last_close = before.rfind(']')
    if last_open > last_close and last_open != -1:
        # 检查后面是否有 ](url)
        after = text[pos:pos+200]
        close_pos = after.find('](')
        if close_pos != -1:
            return True
    return False


# ==================== 扫描函数 ====================

# 额外的高频错误模式（不在 reference 字典中但技术文档常见）
EXTRA_PATTERNS = [
    # 常见字母顺序颠倒
    (r'(?<![a-zA-Z0-9_])(Pyhton)(?![a-zA-Z0-9_])', 'Python', 'high'),
    (r'(?<![a-zA-Z0-9_])(funciton)(?![a-zA-Z0-9_])', 'function', 'high'),
    (r'(?<![a-zA-Z0-9_])(directroy)(?![a-zA-Z0-9_])', 'directory', 'high'),
    (r'(?<![a-zA-Z0-9_])(paramter)(?![a-zA-Z0-9_])', 'parameter', 'high'),
    (r'(?<![a-zA-Z0-9_])(downlod)(?![a-zA-Z0-9_])', 'download', 'high'),
    (r'(?<![a-zA-Z0-9_])(htps)(?![a-zA-Z0-9_])', 'https', 'high'),
    (r'(?<![a-zA-Z0-9_])(continer)(?![a-zA-Z0-9_])', 'container', 'high'),
    (r'(?<![a-zA-Z0-9_])(depoly)(?![a-zA-Z0-9_])', 'deploy', 'high'),
    (r'(?<![a-zA-Z0-9_])(mangment)(?![a-zA-Z0-9_])', 'management', 'high'),
    (r'(?<![a-zA-Z0-9_])(Prdfix)(?![a-zA-Z0-9_])', 'Prefix', 'high'),
    (r'(?<![a-zA-Z0-9_])(reedme)(?![a-zA-Z0-9_])', 'readme', 'high'),
    (r'(?<![a-zA-Z0-9_])(Debain)(?![a-zA-Z0-9_])', 'Debian', 'high'),
    (r'(?<![a-zA-Z0-9_])(messges)(?![a-zA-Z0-9_])', 'messages', 'high'),
    (r'(?<![a-zA-Z0-9_])(confgiure)(?![a-zA-Z0-9_])', 'configure', 'high'),
    (r'(?<![a-zA-Z0-9_])(specifiction)(?![a-zA-Z0-9_])', 'specification', 'high'),
    (r'(?<![a-zA-Z0-9_])(Atempting)(?![a-zA-Z0-9_])', 'Attempting', 'high'),
    (r'(?<![a-zA-Z0-9_])(intsall)(?![a-zA-Z0-9_])', 'install', 'high'),
    (r'(?<![a-zA-Z0-9_])(enviroment)(?![a-zA-Z0-9_])', 'environment', 'high'),
    (r'(?<![a-zA-Z0-9_])(configration)(?![a-zA-Z0-9_])', 'configuration', 'high'),
    (r'(?<![a-zA-Z0-9_])(seperate)(?![a-zA-Z0-9_])', 'separate', 'high'),
    (r'(?<![a-zA-Z0-9_])(arguement)(?![a-zA-Z0-9_])', 'argument', 'high'),
    (r'(?<![a-zA-Z0-9_])(ClLUSTER)(?![a-zA-Z0-9_])', 'CLUSTER', 'high'),
    (r'(?<![a-zA-Z0-9_])(service_paramter)(?![a-zA-Z0-9_])', 'service_parameter', 'high'),
    (r'(?<![a-zA-Z0-9_])(htpsEnabled)(?![a-zA-Z0-9_])', 'httpsEnabled', 'high'),
    # 产品名常见错误
    (r'(?<![a-zA-Z0-9_])(MindSpere)(?![a-zA-Z0-9_])', 'MindSpore', 'high'),
    (r'(?<![a-zA-Z0-9_])(Linus)(?![a-zA-Z0-9_])', 'Linux', 'high'),
    (r'(?<![a-zA-Z0-9_])(Pytorch)(?![a-zA-Z0-9_])', 'PyTorch', 'high'),
    (r'(?<![a-zA-Z0-9_])(kubetl)(?![a-zA-Z0-9_])', 'kubectl', 'high'),
    # 连字符/空格
    (r'(?<![a-zA-Z0-9_])(opensource)(?![a-zA-Z0-9_])', 'open source', 'medium'),
    (r'(?<![a-zA-Z0-9_])(OrderdReady)(?![a-zA-Z0-9_])', 'OrderedReady', 'high'),
]

def scan_with_dictionary(text, dictionaries):
    """使用字典进行确定性拼写扫描"""
    lines = text.split('\n')
    code_lines = get_code_block_lines(text)

    # 检查 frontmatter
    frontmatter_end = -1
    if lines and lines[0].strip().startswith('---'):
        for i in range(1, len(lines)):
            if lines[i].strip().startswith('---'):
                frontmatter_end = i + 1
                break

    combined = dictionaries['combined']
    hits = []

    # 构建单词边界匹配模式（按长度降序，避免短词匹配到长词的一部分）
    sorted_wrong = sorted(combined.keys(), key=len, reverse=True)

    def word_boundary_pattern(word):
        """构建适用于中英文混合的单词边界模式"""
        # 中文是 \w，但中英之间没有自然边界，所以用 (?<![a-zA-Z0-9_])
        # 以及 (?![a-zA-Z0-9_]) 来确保是独立单词
        return r'(?<![a-zA-Z0-9_])' + re.escape(word) + r'(?![a-zA-Z0-9_])'

    for lineno, line in enumerate(lines, 1):
        # 豁免：代码块、frontmatter
        if lineno in code_lines:
            continue
        if 1 <= lineno <= frontmatter_end:
            continue

        # 先检查 extra patterns
        for pattern, correction, confidence in EXTRA_PATTERNS:
            for m in re.finditer(pattern, line):
                prev_lines = '\n'.join(lines[:lineno-1])
                abs_pos = len(prev_lines) + 1 + m.start() if prev_lines else m.start()
                if is_inline_code(text, abs_pos) or is_in_url(text, abs_pos):
                    continue
                hits.append({
                    'lineno': lineno,
                    'error': m.group(1),
                    'correction': correction,
                    'matched_text': line[max(0, m.start()-15):min(len(line), m.end()+15)].strip(),
                    'confidence': confidence,
                })
                break

        for wrong in sorted_wrong:
            correct = combined[wrong]
            pattern = word_boundary_pattern(wrong)
            for m in re.finditer(pattern, line):
                prev_lines = '\n'.join(lines[:lineno-1])
                abs_pos = len(prev_lines) + 1 + m.start() if prev_lines else m.start()

                # 检查豁免区域
                if is_inline_code(text, abs_pos):
                    continue
                if is_in_url(text, abs_pos):
                    continue

                hits.append({
                    'lineno': lineno,
                    'error': wrong,
                    'correction': correct,
                    'matched_text': line[max(0, m.start()-15):min(len(line), m.end()+15)].strip(),
                    'confidence': 'high',
                })
                break  # 每行只报告第一个匹配

    return hits


def scan_capitalization(text):
    """扫描大小写问题 — 针对已知产品名/协议名的大小写变体"""
    # 常见大小写违规模式
    patterns = [
        # Kubernetes 全小写 → 首字母大写
        (r'(?<![a-zA-Z0-9_])(kubernetes)(?![a-zA-Z0-9_])', 'Kubernetes', 'brand_case', 'high',
         'Kubernetes 首字母应大写'),
        # PyTorch 大小写错误
        (r'(?<![a-zA-Z0-9_])(Pytorch)(?![a-zA-Z0-9_])', 'PyTorch', 'brand_case', 'high',
         'PyTorch 应使用官方大小写'),
        # Linux 全小写 → 首字母大写（作为产品名时）
        (r'(?<![a-zA-Z0-9_])(linux)(?![a-zA-Z0-9_])', 'Linux', 'brand_case', 'medium',
         'Linux 作为产品名时首字母应大写'),
    ]

    lines = text.split('\n')
    code_lines = get_code_block_lines(text)
    hits = []

    for lineno, line in enumerate(lines, 1):
        if lineno in code_lines:
            continue
        # 跳过 frontmatter
        if lineno == 1 and line.strip().startswith('---'):
            continue

        # 检查 URL 豁免：整行包含 URL 时，URL 部分不检查
        for pattern, correction, dim, confidence, hint in patterns:
            for m in re.finditer(pattern, line):
                # 计算绝对位置
                prev_lines = '\n'.join(lines[:lineno-1])
                abs_pos = len(prev_lines) + 1 + m.start() if prev_lines else m.start()

                # 跳过 URL 中的匹配
                if is_in_url(text, abs_pos):
                    continue
                # 跳过行内代码中的匹配
                if is_inline_code(text, abs_pos):
                    continue

                actual = correction(m) if callable(correction) else correction
                if m.group(1) != actual:
                    hits.append({
                        'lineno': lineno,
                        'error': m.group(1),
                        'correction': actual,
                        'matched_text': line[max(0, m.start()-15):min(len(line), m.end()+15)].strip(),
                        'dimension': dim,
                        'confidence': confidence,
                        'hint': hint,
                    })
    return hits


def scan_confusable_words(text, dictionaries):
    """扫描易混词 — 中等置信度，需要 LLM 复核上下文"""
    pairs = dictionaries.get('confusable_pairs', [])
    if not pairs:
        return []

    lines = text.split('\n')
    code_lines = get_code_block_lines(text)
    hits = []

    # 构建关注词集合（常见易混词对）
    focus_words = {
        'affect': 'effect', 'effect': 'affect',
        'its': "it's", "it's": 'its',
        'their': 'there', 'there': 'their', "they're": 'their',
        'then': 'than', 'than': 'then',
        'your': "you're", "you're": 'your',
        'lose': 'loose', 'loose': 'lose',
        'ensure': 'insure', 'insure': 'ensure',
        'except': 'accept', 'accept': 'except',
        'precede': 'proceed', 'proceed': 'precede',
        'complement': 'compliment', 'compliment': 'complement',
        'through': 'thorough', 'thorough': 'through',
        'timeout': 'time out', 'time out': 'timeout',
    }

    for lineno, line in enumerate(lines, 1):
        if lineno in code_lines:
            continue

        # 只扫描纯英文段落（至少80%为英文字符），中文为主的段落跳过
        en_chars = len(re.findall(r'[a-zA-Z]', line))
        zh_chars = len(re.findall(r'[\u4e00-\u9fff]', line))
        total_chars = en_chars + zh_chars
        if total_chars > 0 and zh_chars / total_chars > 0.3:
            continue

        for word, alternative in focus_words.items():
            pattern = r'\b' + re.escape(word) + r'\b'
            for m in re.finditer(pattern, line, re.IGNORECASE):
                hits.append({
                    'lineno': lineno,
                    'error': m.group(),
                    'correction': alternative,
                    'matched_text': line[max(0, m.start()-20):min(len(line), m.end()+20)].strip(),
                    'confidence': 'medium',
                    'dimension': 'confusable',
                    'hint': f'可能为易混词「{word}」与「{alternative}」的误用，需根据上下文判断',
                })
                break
    return hits


def scan_american_british(text, dictionaries):
    """扫描美式/英式不一致 — 需要 LLM 判定文档风格基线"""
    uk_to_us = dictionaries.get('uk_to_us', {})
    if not uk_to_us:
        return []

    lines = text.split('\n')
    code_lines = get_code_block_lines(text)
    hits = []

    uk_words_found = []
    us_words_found = []

    for lineno, line in enumerate(lines, 1):
        if lineno in code_lines:
            continue
        for uk_word, us_word in uk_to_us.items():
            # 查找英式拼写
            if re.search(r'\b' + re.escape(uk_word) + r'\b', line, re.IGNORECASE):
                uk_words_found.append((lineno, uk_word, us_word))
            # 查找美式拼写
            if re.search(r'\b' + re.escape(us_word) + r'\b', line, re.IGNORECASE):
                us_words_found.append((lineno, us_word, uk_word))

    # 如果同时有美式和英式拼写，报告
    if uk_words_found and us_words_found:
        for lineno, uk_word, us_word in uk_words_found:
            hits.append({
                'lineno': lineno,
                'error': uk_word,
                'correction': us_word,
                'matched_text': uk_word,
                'confidence': 'medium',
                'dimension': 'american_british',
                'hint': f'英式拼写「{uk_word}」，若文档基线为美式应改为「{us_word}」',
            })

    return hits


# ==================== 主入口 ====================

REVIEW_CRITERIA = {
    'brand_case': '判断该大小写是否为品牌/产品名的官方写法。若为合法变体（如 PostgreSQL/Postgres）则豁免；若确实不规范则保留。',
    'confusable': '判断该词在当前上下文中是否为正确用词。需根据句子含义判断（如 affect vs effect、its vs it\'s）。若用法正确则豁免。',
    'american_british': '判断文档整体的英语风格基线。若文档统一使用英式则豁免；若美式/英式混用则需统一。',
}

def main(text):
    """主入口"""
    ref_dir = os.path.join(os.path.dirname(__file__), '..', 'references')
    dictionaries = build_dictionaries(ref_dir)

    violations = []

    # 1. 字典确定性扫描（高置信度）
    dict_hits = scan_with_dictionary(text, dictionaries)
    for hit in dict_hits:
        violations.append({
            'lineno': hit['lineno'],
            'rule': '§2',
            'rule_name': '高频拼写错误',
            'severity': 'Required',
            'condition': 'dictionary_match',
            'error': hit['error'],
            'correction': hit['correction'],
            'matched_text': hit['matched_text'],
            'confidence': hit['confidence'],
        })

    # 2. 大小写扫描
    cap_hits = scan_capitalization(text)
    for hit in cap_hits:
        violations.append({
            'lineno': hit['lineno'],
            'rule': '§6',
            'rule_name': '大小写与专有名词规范',
            'severity': 'Required',
            'condition': hit.get('dimension', 'capitalization'),
            'error': hit['error'],
            'correction': hit['correction'],
            'matched_text': hit['matched_text'],
            'confidence': hit['confidence'],
            'hint': hit.get('hint', ''),
        })

    # 3. 易混词扫描（中等置信度）
    conf_hits = scan_confusable_words(text, dictionaries)
    for hit in conf_hits:
        violations.append({
            'lineno': hit['lineno'],
            'rule': '§3',
            'rule_name': '易混词检查',
            'severity': 'Required',
            'condition': hit['dimension'],
            'error': hit['error'],
            'correction': hit['correction'],
            'matched_text': hit['matched_text'],
            'confidence': hit['confidence'],
            'hint': hit.get('hint', ''),
        })

    # 4. 美式/英式扫描（中等置信度）
    ame_hits = scan_american_british(text, dictionaries)
    for hit in ame_hits:
        violations.append({
            'lineno': hit['lineno'],
            'rule': '§5',
            'rule_name': '美式/英式一致性检查',
            'severity': 'Suggestion',
            'condition': hit['dimension'],
            'error': hit['error'],
            'correction': hit['correction'],
            'matched_text': hit['matched_text'],
            'confidence': hit['confidence'],
            'hint': hit.get('hint', ''),
        })

    # 按 lineno 排序
    violations.sort(key=lambda x: (x['lineno'] if x['lineno'] > 0 else 999999, x['rule']))

    # 分为 confirmed(high) 和 pending_review(medium)
    violations_confirmed = []
    violations_pending_review = []
    for v in violations:
        if v.get('confidence') == 'high':
            violations_confirmed.append(v)
        else:
            v_with_criteria = dict(v)
            condition = v.get('condition', '')
            v_with_criteria['review_criteria'] = REVIEW_CRITERIA.get(
                condition, '判断该命中是否为真实拼写错误。若为正确用法则豁免。'
            )
            v_with_criteria['review_decision'] = None
            violations_pending_review.append(v_with_criteria)

    all_violations = violations_confirmed + violations_pending_review

    rule_counts = {}
    severity_counts = {'Required': 0, 'Suggestion': 0}
    for v in all_violations:
        rule_counts[v['rule']] = rule_counts.get(v['rule'], 0) + 1
        severity_counts[v['severity']] += 1

    return {
        "dictionary_stats": {
            "total_entries": len(dictionaries['combined']),
            "misspellings": len(dictionaries['misspellings']),
            "tech_terms": len(dictionaries['tech_terms']),
            "brand_case": len(dictionaries['brand_case']),
            "protocol_case": len(dictionaries['protocol_case']),
            "confusable_pairs": len(dictionaries['confusable_pairs']),
            "uk_to_us": len(dictionaries['uk_to_us']),
        },
        "violations": all_violations,
        "violations_confirmed": violations_confirmed,
        "violations_pending_review": violations_pending_review,
        "violation_stats": {
            "total": len(all_violations),
            "total_confirmed": len(violations_confirmed),
            "total_pending_review": len(violations_pending_review),
            "by_severity": severity_counts,
            "by_rule": rule_counts,
        },
    }


if __name__ == "__main__":
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r', encoding='utf-8') as f:
            text = f.read()
    else:
        text = sys.stdin.read()
    result = main(text)
    print(json.dumps(result, ensure_ascii=False, indent=2))
