"""
doc-punctuation-tester v3.4 标准预扫描脚本
判定层 - 输出标准化违规清单 violations 数组
v3.4: 将 violations 拆分为 violations_confirmed(high) + violations_pending_review(medium)
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

# ==================== 公共工具 ====================

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

def strip_excluded_regions(text):
    """剥离不参与4.1/5.1/3.10等统计的区域"""
    text = re.sub(r'```[\s\S]*?```', '', text)
    text = re.sub(r'~~~[\s\S]*?~~~', '', text)
    text = re.sub(r'`[^`\n]+`', '', text)
    text = re.sub(r'https?://[^\s\)）】]+', '', text)
    text = re.sub(r'\]\([^\)]+\)', ']', text)
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'(?:^|\s)[/\\][\w/\\.\-]+', ' ', text)
    return text

# ==================== 基础感知层 ====================

def scan_zh_en_adjacency(text):
    cleaned = strip_excluded_regions(text)
    no_space_zh_en = len(re.findall(r'[\u4e00-\u9fff][A-Za-z0-9]', cleaned))
    no_space_en_zh = len(re.findall(r'[A-Za-z0-9][\u4e00-\u9fff]', cleaned))
    with_space_zh_en = len(re.findall(r'[\u4e00-\u9fff] [A-Za-z0-9]', cleaned))
    with_space_en_zh = len(re.findall(r'[A-Za-z0-9] [\u4e00-\u9fff]', cleaned))
    total_no_space = no_space_zh_en + no_space_en_zh
    total_with_space = with_space_zh_en + with_space_en_zh
    total = total_no_space + total_with_space
    no_space_ratio = (total_no_space / total) if total > 0 else 0
    return {
        "zh_followed_by_en_no_space": no_space_zh_en,
        "zh_followed_by_en_with_space": with_space_zh_en,
        "en_followed_by_zh_no_space": no_space_en_zh,
        "en_followed_by_zh_with_space": with_space_en_zh,
        "total_no_space": total_no_space,
        "total_with_space": total_with_space,
        "no_space_ratio": round(no_space_ratio, 3),
        "mixing_detected_3plus": total_no_space >= 3 and total_with_space >= 3,
    }

def detect_tech_doc(text):
    has_code_block = bool(re.search(r'```|~~~', text))
    inline_code_count = len(re.findall(r'`[^`\n]+`', text))
    tech_keywords = ['install', 'config', 'API', 'SDK', 'Docker', 'Linux',
                     'Windows', 'Kubernetes', 'Python', 'Go ', 'JavaScript',
                     '版本', '配置', '部署', '命令', '安装']
    has_keyword = any(kw in text for kw in tech_keywords)
    return has_code_block or inline_code_count >= 3 or has_keyword

def determine_baseline(stats, is_tech_doc):
    if is_tech_doc:
        return "加空格"
    ratio = stats["no_space_ratio"]
    if ratio >= 0.80:
        return "不加空格"
    elif ratio >= 0.60:
        return "不加空格"
    else:
        return "加空格"

def scan_quotes(text):
    cleaned = strip_excluded_regions(text)
    quote_chars = {
        '\u0022': '英文直双引号',
        '\u0027': '英文直单引号',
        '\u201C': '中文左弯引号',
        '\u201D': '中文右弯引号',
        '\u2018': '中文左弯单引号',
        '\u2019': '中文右弯单引号',
        '\u300C': '直角左引号',
        '\u300D': '直角右引号',
    }
    result = {name: 0 for name in quote_chars.values()}
    for ch in cleaned:
        if ch in quote_chars:
            result[quote_chars[ch]] += 1
    return result

def scan_block_titles(text):
    """6.5 块标题强制 grep 匹配"""
    code_lines = get_code_block_lines(text)
    hits = []
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        if re.search(r'^\s*>\s*(?:!\[.*?\]\([^)]*\)\s*)?\*\*[^*]+[:\uff1a]\*\*', line):
            hits.append((lineno, 'pattern_1_blockquote_bold_colon', line.strip()))
        elif re.search(r'^\s*>\s*\[!\w+\][^*]*[:\uff1a]', line):
            hits.append((lineno, 'pattern_3_github_alert_colon', line.strip()))
        elif re.search(r'^\s*\*\*[^*]+[:\uff1a]\*\*\s*$', line):
            hits.append((lineno, 'pattern_4_standalone_bold_colon', line.strip()))
    return hits

def scan_units(text):
    """3.13 数字+大写单位机械匹配"""
    code_lines = get_code_block_lines(text)
    pattern = r'\d+(GB|MB|KB|TB|PB|Hz|MHz|GHz|kHz|mm|cm|km|kg|°C|°F|ms|μs|ns)'
    hits = []
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        for m in re.finditer(pattern, line):
            hits.append((lineno, m.group(0)))
    return hits

# ==================== v3.2 新增扫描函数 ====================

def scan_trailing_whitespace(text):
    """5.1 行末多余空格"""
    code_lines = get_code_block_lines(text)
    hits = []
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        # 排除空行
        if not line.strip():
            continue
        # 去掉换行符后,与rstrip对比
        without_newline = line.rstrip('\n').rstrip('\r')
        if without_newline != without_newline.rstrip(' \t'):
            hits.append({
                'lineno': lineno,
                'condition': 'trailing_whitespace',
                'matched_text': without_newline[-20:],
                'confidence': 'high',
            })
    return hits

def scan_punct_with_space(text):
    """5.1 中文标点前后多余空格"""
    code_lines = get_code_block_lines(text)
    hits = []
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        # 全角逗号/句号/顿号/分号后多余空格（半角空格紧跟在全角标点后）
        for m in re.finditer(r'[，。、；：？！]\s+(?!$)', line):
            # 排除行末和注释行
            snippet = line[max(0, m.start()-10):min(len(line), m.end()+10)]
            hits.append({
                'lineno': lineno,
                'condition': 'space_after_fullwidth_punct',
                'matched_text': snippet.strip(),
                'confidence': 'high',
            })
        # 全角顿号/逗号/句号前多余空格
        for m in re.finditer(r'[A-Za-z0-9\u4e00-\u9fff]\s+[，。、；：？！]', line):
            snippet = line[max(0, m.start()-10):min(len(line), m.end()+5)]
            hits.append({
                'lineno': lineno,
                'condition': 'space_before_fullwidth_punct',
                'matched_text': snippet.strip(),
                'confidence': 'high',
            })
    return hits

def scan_halfwidth_paren_with_zh(text):
    """3.10 半角括号含中文"""
    code_lines = get_code_block_lines(text)
    hits = []
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        # 先剥离 Markdown 链接的 URL 部分，避免误报 ](url) 中的括号
        cleaned = re.sub(r'\]\([^)]+\)', ']', line)
        # 半角括号 (xxx) 内含中文
        for m in re.finditer(r'\(([^)]+)\)', cleaned):
            content = m.group(1)
            if re.search(r'[\u4e00-\u9fff]', content):
                hits.append({
                    'lineno': lineno,
                    'condition': 'halfwidth_paren_with_chinese',
                    'matched_text': m.group(0),
                    'confidence': 'high',
                })
        # 转义半角括号 \( xxx \) 内含中文
        for m in re.finditer(r'\\\(([^)]*?)\\\)', line):
            content = m.group(1)
            if re.search(r'[\u4e00-\u9fff]', content):
                hits.append({
                    'lineno': lineno,
                    'condition': 'escaped_halfwidth_paren_with_chinese',
                    'matched_text': m.group(0),
                    'confidence': 'high',
                })
    return hits

def scan_dunhao_list_end(text):
    """3.3 顿号末尾未用'和/或/等'（含路径分隔豁免）"""
    code_lines = get_code_block_lines(text)
    hits = []
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        # 跳过表格行内HTML
        if '<td' in line or '<li>' in line:
            continue
        # 匹配 A、B、C 三项及以上的并列
        for m in re.finditer(r'([\u4e00-\u9fffA-Za-z_0-9]+、){2,}[\u4e00-\u9fffA-Za-z_0-9]+', line):
            matched = m.group(0)
            # 检查并列项是否全部是路径（含 / 或 \）
            items = matched.split('、')
            if all('/' in item or '\\' in item for item in items):
                continue  # 1.9.3 路径分隔豁免
            # 检查最后一项后是否跟"和/或/等/中/。/，"
            after = line[m.end():m.end()+5]
            if after.startswith(('和', '或', '等', '中', '。', '，', '；', '：')):
                continue
            hits.append({
                'lineno': lineno,
                'condition': 'dunhao_missing_he_or_deng',
                'matched_text': matched,
                'confidence': 'high',
            })
    return hits

def scan_range_hyphen(text):
    """3.7 中文语境数值范围使用半角连字符"""
    code_lines = get_code_block_lines(text)
    hits = []
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        # 步骤 N - 步骤 M / 第 N - 第 M
        for m in re.finditer(r'(?:步骤|第)\s*\d+\s*-\s*(?:步骤|第)?\s*\d+', line):
            hits.append({
                'lineno': lineno,
                'condition': 'range_with_halfwidth_hyphen',
                'matched_text': m.group(0),
                'confidence': 'high',
            })
        # 通用：N-M 形式且前后为中文
        for m in re.finditer(r'[\u4e00-\u9fff]\s*\d+\s*-\s*\d+\s*[\u4e00-\u9fff]', line):
            hits.append({
                'lineno': lineno,
                'condition': 'range_with_halfwidth_hyphen',
                'matched_text': m.group(0),
                'confidence': 'medium',  # 可能是版本号、IP，模型最终复核
            })
    return hits

# 操作动词标准列表（按 v3.2 标准统一）
ACTION_VERBS = [
    '访问', '下载', '安装', '配置', '启动', '执行', '点击', '单击', '双击',
    '选择', '切换', '进入', '退出', '登录', '登出', '验证', '校验', '输入',
    '输出', '运行', '删除', '移除', '创建', '新增', '修改', '编辑', '调整',
    '保存', '提交', '打开', '关闭', '查看', '浏览', '卸载', '更新', '升级',
    '重启', '停止', '复制', '粘贴', '检查', '检测', '确认', '同意', '拒绝',
    '迁移', '备份', '恢复', '导入', '导出', '编译', '打包', '部署', '发布',
    '设置', '添加', '替换', '查找', '搜索', '过滤', '排序', '刷新', '同步',
    '绑定', '解绑', '关联', '取消', '开启', '启用', '禁用', '激活', '授权',
    '分配', '挂载', '映射', '连接', '断开', '配对', '注册', '注销', '上传',
    '预览', '移动', '剪切', '重命名', '压缩', '解压', '加密', '解密', '分享',
    '复制保存', '计算', '对比', '重定向', '解析', '跳过', '参考',
]

def scan_list_violations(text):
    """6.2 列表项决策树（完全机械化）"""
    code_lines = get_code_block_lines(text)
    lines = text.split('\n')
    hits = []
    for i, line in enumerate(lines):
        lineno = i + 1
        if lineno in code_lines:
            continue
        m = re.match(r'^(\s*)(\d+\.|-)\s+(.+)$', line.rstrip())
        if not m:
            continue
        indent = len(m.group(1))
        is_ordered = m.group(2).endswith('.')
        content = m.group(3).strip()
        if not content:
            continue
        # 跳过纯图片/嵌入行
        if content.startswith('!['):
            continue
        # 去掉 Markdown 链接的 URL 部分（仅作末尾字符判断）
        content_clean = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', content)
        content_clean = content_clean.rstrip()
        if not content_clean:
            continue
        tail = content_clean[-1]

        # 决策树步骤1：末尾已有句号
        if tail in '。.!?！？':
            continue

        # 决策树步骤2：冒号结尾且下一行有缩进子内容 → 通过
        if tail in ':：':
            has_sub = False
            for j in range(i+1, min(i+4, len(lines))):
                nl = lines[j]
                if not nl.strip():
                    continue
                ni = len(nl) - len(nl.lstrip())
                if ni > indent:
                    has_sub = True
                break
            if has_sub:
                continue
            # 冒号但无子内容 → 也豁免（可能是引导段）
            continue

        # 决策树步骤3a：有序列表
        if is_ordered:
            hits.append({
                'lineno': lineno,
                'condition': 'ordered_list_missing_period',
                'matched_text': content[:60],
                'confidence': 'high',
            })
            continue

        # 决策树步骤3b：（方式X）前缀
        if re.match(r'^\s*[（(]\s*方式[一二三四五六七八九十\d]', content_clean):
            hits.append({
                'lineno': lineno,
                'condition': 'way_prefix_missing_period',
                'matched_text': content[:60],
                'confidence': 'high',
            })
            continue

        # 决策树步骤3c：操作动词命中
        matched_verbs = [v for v in ACTION_VERBS if v in content_clean]
        if matched_verbs:
            hits.append({
                'lineno': lineno,
                'condition': 'action_verb_missing_period',
                'matched_text': content[:60],
                'matched_verbs': matched_verbs[:3],
                'confidence': 'high',
            })
            continue

        # 决策树步骤3d：完整句（含主谓宾，≥10字符且含逗号）
        if len(content_clean) >= 10 and ('，' in content_clean):
            hits.append({
                'lineno': lineno,
                'condition': 'full_sentence_missing_period',
                'matched_text': content[:60],
                'confidence': 'medium',  # 完整句判定有一定主观性
            })
            continue
        # 否则纯名词短语 → 通过
    return hits

def scan_zh_en_4_1_violations(text, baseline):
    """4.1 中英文之间空格违规（按基准生成违规清单）"""
    code_lines = get_code_block_lines(text)
    hits = []
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        # 1.9.1 豁免：图表标题
        if re.match(r'^\s*\*\*(图|表|Figure|Table)\s*\d+\*\*', line.strip()):
            continue
        # 剥离 Markdown 链接的 URL 部分
        cleaned = re.sub(r'\]\([^)]+\)', ']', line)
        cleaned = re.sub(r'<[^>]+>', '', cleaned)
        cleaned = re.sub(r'`[^`]+`', '', cleaned)
        # 跳过 YAML frontmatter 分隔符
        if cleaned.startswith('---'):
            continue

        if baseline == '加空格':
            # 违规 = 无空格的中英相邻
            for m in re.finditer(r'[\u4e00-\u9fff][A-Za-z0-9]|[A-Za-z0-9][\u4e00-\u9fff]', cleaned):
                hits.append({
                    'lineno': lineno,
                    'condition': 'missing_space_between_zh_en',
                    'matched_text': cleaned[max(0, m.start()-5):min(len(cleaned), m.end()+5)].strip(),
                    'confidence': 'high',
                })
        else:  # 基准为「不加空格」
            for m in re.finditer(r'[\u4e00-\u9fff] [A-Za-z0-9]|[A-Za-z0-9] [\u4e00-\u9fff]', cleaned):
                hits.append({
                    'lineno': lineno,
                    'condition': 'redundant_space_between_zh_en',
                    'matched_text': cleaned[max(0, m.start()-5):min(len(cleaned), m.end()+5)].strip(),
                    'confidence': 'high',
                })
    return hits

def scan_zh_invalid_quotes(text):
    """3.8 中文语境英文直引号违规（v3.2 修复：先剥离 HTML 标签和行内代码）"""
    code_lines = get_code_block_lines(text)
    hits = []
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        # 剥离 HTML 标签（避免 <th width="50%"> 中的引号被误报）
        cleaned = re.sub(r'<[^>]+>', '', line)
        # 剥离行内代码
        cleaned = re.sub(r'`[^`]+`', '', cleaned)
        # 剥离 Markdown 链接 URL 部分
        cleaned = re.sub(r'\]\([^)]+\)', ']', cleaned)
        # 跳过明显英文段落
        zh_count = len(re.findall(r'[\u4e00-\u9fff]', cleaned))
        if zh_count == 0:
            continue
        # 查找英文直双/单引号
        for m in re.finditer(r'["\']', cleaned):
            ch = m.group()
            # 检查前后是否为中文字符（确认是在中文语境内）
            before = cleaned[max(0, m.start()-3):m.start()]
            after = cleaned[m.end():min(len(cleaned), m.end()+3)]
            if re.search(r'[\u4e00-\u9fff]', before) or re.search(r'[\u4e00-\u9fff]', after):
                hits.append({
                    'lineno': lineno,
                    'condition': 'english_quote_in_chinese_context',
                    'matched_text': cleaned[max(0, m.start()-10):min(len(cleaned), m.end()+10)].strip(),
                    'quote_char': ch,
                    'confidence': 'high',
                })
    return hits

ZH_FULLWIDTH_PUNCT_IN_CODE = set('，。；：！？（）【】《》""''「」『』—…、～')

def _clean_line_for_zh_punct(line):
    cleaned = re.sub(r'`[^`]+`', '', line)
    cleaned = re.sub(r'\]\([^)]+\)', ']', cleaned)
    cleaned = re.sub(r'<[^>]+>', '', cleaned)
    cleaned = re.sub(r'https?://[^\s\)）】]+', '', cleaned)
    return cleaned

def scan_code_block_zh_punct(text):
    lines = text.split('\n')
    in_block = False
    fence_lang_seen = False
    hits = []
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith('```') or stripped.startswith('~~~'):
            if not in_block:
                in_block = True
                fence_lang_seen = len(stripped) > 3
                continue
            else:
                in_block = False
                continue
        if not in_block:
            continue
        if fence_lang_seen and not stripped:
            continue
        is_comment = False
        code_part = stripped
        for comment_prefix in ('#', '//', '/*', '*', '--', '"""', "'''"):
            if stripped.startswith(comment_prefix):
                is_comment = True
                break
        if is_comment:
            code_part = ''
        else:
            comment_match = re.search(r'[#//]', stripped)
            if comment_match:
                code_part = stripped[:comment_match.start()]
        in_string = False
        filtered = []
        i = 0
        while i < len(code_part):
            ch = code_part[i]
            if ch in ('"', "'") and (i == 0 or code_part[i-1] != '\\'):
                in_string = not in_string
                i += 1
                continue
            if not in_string:
                filtered.append(ch)
            i += 1
        code_no_strings = ''.join(filtered)
        for ch in code_no_strings:
            if ch in ZH_FULLWIDTH_PUNCT_IN_CODE:
                snippet = line.strip()[:80]
                hits.append({
                    'lineno': lineno,
                    'condition': 'fullwidth_punct_in_code_block',
                    'matched_text': snippet,
                    'punct_char': ch,
                    'confidence': 'high',
                })
                break
        if re.search(r'style\s*=\s*["\'][^"\']*[\uff00-\uffef]+["\']', stripped):
            for m in re.finditer(r'[\uff00-\uffef]', stripped):
                ch = m.group()
                if ch in ZH_FULLWIDTH_PUNCT_IN_CODE:
                    hits.append({
                        'lineno': lineno,
                        'condition': 'fullwidth_punct_in_html_attr',
                        'matched_text': line.strip()[:80],
                        'punct_char': ch,
                        'confidence': 'high',
                    })
                    break
    return hits

def scan_url_fullwidth_char(text):
    code_lines = get_code_block_lines(text)
    hits = []
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        for m in re.finditer(r'https?[：\uff1a]//', line):
            hits.append({
                'lineno': lineno,
                'condition': 'fullwidth_char_in_url',
                'matched_text': m.group(),
                'confidence': 'high',
            })
    return hits

def scan_halfwidth_period_in_zh(text):
    code_lines = get_code_block_lines(text)
    hits = []
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        cleaned = _clean_line_for_zh_punct(line)
        for m in re.finditer(r'[\u4e00-\u9fff]\.(?:\s|$)', cleaned):
            snippet = cleaned[max(0, m.start()-10):min(len(cleaned), m.end()+10)]
            hits.append({
                'lineno': lineno,
                'condition': 'halfwidth_period_after_chinese',
                'matched_text': snippet.strip(),
                'confidence': 'high',
            })
        for m in re.finditer(r'[\u4e00-\u9fff]\.(?=[\u4e00-\u9fff])', cleaned):
            snippet = cleaned[max(0, m.start()-10):min(len(cleaned), m.end()+10)]
            hits.append({
                'lineno': lineno,
                'condition': 'halfwidth_period_as_comma',
                'matched_text': snippet.strip(),
                'confidence': 'high',
            })
        for m in re.finditer(r'[A-Za-z]\.(?=[\u4e00-\u9fff])', cleaned):
            snippet = cleaned[max(0, m.start()-10):min(len(cleaned), m.end()+10)]
            hits.append({
                'lineno': lineno,
                'condition': 'halfwidth_period_as_comma_after_en',
                'matched_text': snippet.strip(),
                'confidence': 'high',
            })
        for m in re.finditer(r'[\u4e00-\u9fff]\.', cleaned):
            after_idx = m.end()
            after_char = cleaned[after_idx] if after_idx < len(cleaned) else ''
            if after_char.isdigit():
                before_start = max(0, m.start() - 5)
                before_text = cleaned[before_start:m.start()]
                if re.search(r'\d$', before_text):
                    continue
            already = any(h['lineno'] == lineno for h in hits)
            if not already:
                snippet = cleaned[max(0, m.start()-10):min(len(cleaned), m.end()+10)]
                hits.append({
                    'lineno': lineno,
                    'condition': 'halfwidth_period_after_chinese',
                    'matched_text': snippet.strip(),
                    'confidence': 'high',
                })
    return hits

def scan_zh_period_misuse(text):
    code_lines = get_code_block_lines(text)
    hits = []
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        cleaned = _clean_line_for_zh_punct(line)
        for m in re.finditer(r'[\u4e00-\u9fff]\u3002[\u4e00-\u9fffA-Za-z]', cleaned):
            snippet = cleaned[max(0, m.start()-10):min(len(cleaned), m.end()+10)]
            hits.append({
                'lineno': lineno,
                'condition': 'zh_period_between_chinese_chars',
                'matched_text': snippet.strip(),
                'confidence': 'medium',
            })
        for m in re.finditer(r'[A-Za-z]\u3002[\u4e00-\u9fff]', cleaned):
            snippet = cleaned[max(0, m.start()-10):min(len(cleaned), m.end()+10)]
            hits.append({
                'lineno': lineno,
                'condition': 'zh_period_between_en_zh',
                'matched_text': snippet.strip(),
                'confidence': 'medium',
            })
        for m in re.finditer(r'\d\u3002\d', cleaned):
            snippet = cleaned[max(0, m.start()-10):min(len(cleaned), m.end()+10)]
            hits.append({
                'lineno': lineno,
                'condition': 'zh_period_in_number',
                'matched_text': snippet.strip(),
                'confidence': 'high',
            })
        for m in re.finditer(r'\d\u3002\s', cleaned):
            snippet = cleaned[max(0, m.start()-10):min(len(cleaned), m.end()+10)]
            hits.append({
                'lineno': lineno,
                'condition': 'zh_period_after_number',
                'matched_text': snippet.strip(),
                'confidence': 'high',
            })
        for m in re.finditer(r'\d\u3001\d', cleaned):
            snippet = cleaned[max(0, m.start()-10):min(len(cleaned), m.end()+10)]
            hits.append({
                'lineno': lineno,
                'condition': 'zh_dunhao_in_number',
                'matched_text': snippet.strip(),
                'confidence': 'high',
            })
    return hits

def scan_halfwidth_comma_in_zh(text):
    code_lines = get_code_block_lines(text)
    hits = []
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        cleaned = _clean_line_for_zh_punct(line)
        has_hit = False
        for m in re.finditer(r'[\u4e00-\u9fff],[\u4e00-\u9fff]', cleaned):
            snippet = cleaned[max(0, m.start()-10):min(len(cleaned), m.end()+10)]
            hits.append({
                'lineno': lineno,
                'condition': 'halfwidth_comma_between_chinese',
                'matched_text': snippet.strip(),
                'confidence': 'high',
            })
            has_hit = True
            break
        if not has_hit:
            for m in re.finditer(r'[\u4e00-\u9fff],\s', cleaned):
                snippet = cleaned[max(0, m.start()-10):min(len(cleaned), m.end()+10)]
                hits.append({
                    'lineno': lineno,
                    'condition': 'halfwidth_comma_after_chinese',
                    'matched_text': snippet.strip(),
                    'confidence': 'high',
                })
                break
        if not has_hit:
            for m in re.finditer(r'[A-Za-z0-9_\-=]+,[\u4e00-\u9fff]', cleaned):
                before = cleaned[:m.start()]
                if re.search(r'[\u4e00-\u9fff]', before[-10:] if len(before) >= 10 else before):
                    snippet = cleaned[max(0, m.start()-10):min(len(cleaned), m.end()+10)]
                    already = any(h['lineno'] == lineno for h in hits)
                    if not already:
                        hits.append({
                            'lineno': lineno,
                            'condition': 'halfwidth_comma_before_chinese',
                            'matched_text': snippet.strip(),
                            'confidence': 'high',
                        })
                        break
    return hits

def scan_dunhao_missing_in_parallel(text):
    code_lines = get_code_block_lines(text)
    hits = []
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        if '<td' in line or '<li>' in line:
            continue
        cleaned = _clean_line_for_zh_punct(line)
        if re.search(r'[\u4e00-\u9fffA-Za-z0-9],[\u4e00-\u9fffA-Za-z0-9_\-.]+,[\u4e00-\u9fffA-Za-z0-9]', cleaned):
            if re.search(r'[\u4e00-\u9fff]', cleaned):
                for m in re.finditer(r'[\u4e00-\u9fffA-Za-z0-9],[\u4e00-\u9fffA-Za-z0-9]', cleaned):
                    snippet = cleaned[max(0, m.start()-10):min(len(cleaned), m.end()+10)]
                    hits.append({
                        'lineno': lineno,
                        'condition': 'halfwidth_comma_used_as_dunhao',
                        'matched_text': snippet.strip(),
                        'confidence': 'high',
                    })
                    break
        if re.search(r'[\u4e00-\u9fff]\uff0c[\u4e00-\u9fffA-Za-z0-9_\-.]+', cleaned) and re.search(r'\uff0c.*\uff0c', cleaned):
            items = re.split(r'\uff0c', cleaned)
            zh_items = [i for i in items if re.search(r'[\u4e00-\u9fff]', i)]
            if len(zh_items) >= 3:
                snippet = cleaned.strip()[:80]
                already = any(h['lineno'] == lineno for h in hits)
                if not already:
                    hits.append({
                        'lineno': lineno,
                        'condition': 'fullwidth_comma_used_as_dunhao',
                        'matched_text': snippet,
                        'confidence': 'medium',
                    })
    return hits

def scan_halfwidth_colon_in_zh(text):
    code_lines = get_code_block_lines(text)
    hits = []
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        cleaned = _clean_line_for_zh_punct(line)
        if re.search(r'[\u4e00-\u9fff\d]:', cleaned):
            snippet = cleaned.strip()[:80]
            hits.append({
                'lineno': lineno,
                'condition': 'halfwidth_colon_after_chinese',
                'matched_text': snippet,
                'confidence': 'high',
            })
        elif re.search(r':\s*[\u4e00-\u9fff]', line) and not re.search(r'https?://', line):
            if re.search(r'[A-Za-z0-9_\-\(\)]+\s*:\s*[\u4e00-\u9fff]', line):
                before = line[:line.index(':')].strip() if ':' in line else ''
                if re.search(r'[\u4e00-\u9fff]$', before) or re.search(r'[\u4e00-\u9fff]\s*$', before):
                    pass
                else:
                    snippet = line.strip()[:80]
                    hits.append({
                        'lineno': lineno,
                        'condition': 'halfwidth_colon_before_chinese_in_label',
                        'matched_text': snippet,
                        'confidence': 'medium',
                    })
    return hits

def scan_fullwidth_colon_in_code_context(text):
    code_lines = get_code_block_lines(text)
    hits = []
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        if re.search(r'\w+\([^)]*\)\uff1a', line):
            for m in re.finditer(r'\w+\([^)]*\)\uff1a', line):
                hits.append({
                    'lineno': lineno,
                    'condition': 'fullwidth_colon_after_code_like_expr',
                    'matched_text': m.group(),
                    'confidence': 'high',
                })
    return hits

def scan_halfwidth_semicolon_in_zh(text):
    code_lines = get_code_block_lines(text)
    hits = []
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        cleaned = _clean_line_for_zh_punct(line)
        for m in re.finditer(r'[\u4e00-\u9fff];[\u4e00-\u9fff]', cleaned):
            snippet = cleaned[max(0, m.start()-10):min(len(cleaned), m.end()+10)]
            hits.append({
                'lineno': lineno,
                'condition': 'halfwidth_semicolon_between_chinese',
                'matched_text': snippet.strip(),
                'confidence': 'high',
            })
    return hits

def scan_title_ending_period(text):
    code_lines = get_code_block_lines(text)
    hits = []
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        m = re.match(r'^(#{1,6})\s+(.+)$', line)
        if m:
            title = m.group(2).rstrip()
            if title and title[-1] in '。':
                hits.append({
                    'lineno': lineno,
                    'condition': 'title_ends_with_period',
                    'matched_text': title,
                    'confidence': 'high',
                })
    return hits

def scan_consecutive_punct(text):
    code_lines = get_code_block_lines(text)
    hits = []
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        cleaned = re.sub(r'`[^`]+`', '', line)
        cleaned = re.sub(r'\]\([^)]+\)', ']', cleaned)
        for m in re.finditer(r'([。，、；：！？])\1+', cleaned):
            snippet = cleaned[max(0, m.start()-5):min(len(cleaned), m.end()+5)]
            hits.append({
                'lineno': lineno,
                'condition': 'consecutive_punctuation',
                'matched_text': snippet.strip(),
                'confidence': 'high',
            })
        for m in re.finditer(r'[:：][^:\s"\']{0,5}[。；，]', cleaned):
            snippet = cleaned[max(0, m.start()-5):min(len(cleaned), m.end()+5)]
            hits.append({
                'lineno': lineno,
                'condition': 'punct_style_inconsistency',
                'matched_text': snippet.strip(),
                'confidence': 'medium',
            })
    return hits

def scan_intro_sentence_missing_colon(text):
    code_lines = get_code_block_lines(text)
    hits = []
    INTRO_PATTERNS = [
        r'[\u4e00-\u9fff]，分为以下',
        r'[\u4e00-\u9fff]，包括以下',
        r'[\u4e00-\u9fff]，支持以下',
        r'[\u4e00-\u9fff]，如下[：:]',
        r'[\u4e00-\u9fff]，[如有以]下\d+',
        r'[\u4e00-\u9fff]。\s*(?:此时|此时：|此时:)$',
    ]
    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue
        for pattern in INTRO_PATTERNS:
            if re.search(pattern, line):
                if re.search(r'[。！？]\s*$', line.strip()) or re.search(r'。$', line.strip()):
                    hits.append({
                        'lineno': lineno,
                        'condition': 'intro_sentence_should_end_with_colon',
                        'matched_text': line.strip()[:80],
                        'confidence': 'medium',
                    })
                    break
    return hits

def scan_ellipsis(text):
    """3.6 省略号规范扫描

    正确形式：……（两个 U+2026 HORIZONTAL ELLIPSIS）
    错误形式：
    - ...（三个 ASCII 句号）
    - ......（六个 ASCII 句号）
    - 。。。。。。（全角句号代替省略号）
    - 单个 …（一个 U+2026）在正文中使用
    """
    code_lines = get_code_block_lines(text)
    hits = []

    for lineno, line in enumerate(text.split('\n'), 1):
        if lineno in code_lines:
            continue

        # 剥离 Markdown 链接、行内代码、HTML 标签
        cleaned = _clean_line_for_zh_punct(line)

        # 1. 检测三个 ASCII 句号 ...
        for m in re.finditer(r'\.{3}', cleaned):
            # 排除 URL 中的省略号（如 http://example.com/...）
            before = cleaned[max(0, m.start()-10):m.start()]
            if 'http' in before or '://' in before:
                continue
            snippet = cleaned[max(0, m.start()-10):min(len(cleaned), m.end()+10)]
            hits.append({
                'lineno': lineno,
                'condition': 'ascii_dots_as_ellipsis',
                'matched_text': snippet.strip(),
                'error_form': '...',
                'correct_form': '……',
                'confidence': 'high',
            })
            break  # 同一行只报一次

        # 2. 检测六个 ASCII 句号 ......
        for m in re.finditer(r'\.{6}', cleaned):
            snippet = cleaned[max(0, m.start()-10):min(len(cleaned), m.end()+10)]
            hits.append({
                'lineno': lineno,
                'condition': 'six_ascii_dots_as_ellipsis',
                'matched_text': snippet.strip(),
                'error_form': '......',
                'correct_form': '……',
                'confidence': 'high',
            })
            break

        # 3. 检测全角句号代替省略号 。。。。。。（3个及以上）
        for m in re.finditer(r'。{3,}', cleaned):
            snippet = cleaned[max(0, m.start()-10):min(len(cleaned), m.end()+10)]
            hits.append({
                'lineno': lineno,
                'condition': 'fullwidth_period_as_ellipsis',
                'matched_text': snippet.strip(),
                'error_form': m.group(0),
                'correct_form': '……',
                'confidence': 'high',
            })
            break

        # 4. 检测单个省略号 …（U+2026）在正文中使用
        # 正确应该是两个省略号连用
        for m in re.finditer(r'(?<!\u2026)\u2026(?!\u2026)', cleaned):
            snippet = cleaned[max(0, m.start()-10):min(len(cleaned), m.end()+10)]
            hits.append({
                'lineno': lineno,
                'condition': 'single_ellipsis_char',
                'matched_text': snippet.strip(),
                'error_form': '…',
                'correct_form': '……',
                'confidence': 'high',
            })
            break

    return hits

# ==================== 违规等级映射表 ====================

RULE_SEVERITY = {
    '1.2': 'Required',
    '1.2.1': 'Required',
    '3.1': 'Required',
    '3.2': 'Required',
    '3.3': 'Required',
    '3.4': 'Required',
    '3.5': 'Required',
    '3.6': 'Required',
    '3.7': 'Required',
    '3.8': 'Required',
    '3.9': 'Suggestion',
    '3.10': 'Required',
    '3.13': 'Required',
    '4.1': 'Required',
    '5.1': 'Required',
    '5.2': 'Required',
    '6.1': 'Required',
    '6.2': 'Required',
    '6.5': 'Required',
}

RULE_NAMES = {
    '1.2': '豁免区域全角字符',
    '1.2.1': '代码块中文标点混入',
    '3.1': '句号（中文）',
    '3.2': '逗号（中文）',
    '3.3': '顿号（中文特有）',
    '3.4': '冒号（中文）',
    '3.5': '分号（中文）',
    '3.6': '省略号（中文）',
    '3.7': '破折号（中文）',
    '3.8': '引号（中文）',
    '3.9': '书名号（中文特有）',
    '3.10': '括号（中文）',
    '3.13': '单位规范（中文）',
    '4.1': '中英文之间的空格',
    '5.1': '标点符号前后空格',
    '5.2': '连续标点',
    '6.1': '标题',
    '6.2': '列表',
    '6.5': '块标题',
}

# ==================== 主入口（构建标准化 violations 数组） ====================

REVIEW_CRITERIA = {
    'zh_period_between_chinese_chars': '判断该句号是否为正常句末句号（前一句已完整结束）。若为句末句号则豁免；若为断句处误用则保留。',
    'zh_period_between_en_zh': '判断该句号是否为正常句末句号。若为句末句号则豁免；若为断句处误用则保留。',
    'fullwidth_comma_used_as_dunhao': '判断逗号是否用于并列名词/短语之间（应用顿号）。若为分句间、操作步骤间、条件结果间的逗号则豁免；若确实为并列名词间逗号则保留。',
    'halfwidth_colon_before_chinese_in_label': '判断半角冒号是否为代码/配置语境（如 label: value）。若为代码语境则豁免；若为中文正文中的冒号则保留。',
    'full_sentence_missing_period': '判断该列表项是否为完整陈述句（含主谓宾）。若为完整句则保留；若为短语/引导句则豁免。',
    'punct_style_inconsistency': '判断是否存在真实的标点风格不一致。若为合理的嵌套结构则豁免；若确实不一致则保留。',
    'intro_sentence_should_end_with_colon': '判断该句是否应引导后续列表/代码块。若后跟列表则保留；若为独立句则豁免。',
    'range_with_halfwidth_hyphen': '判断连字符是否表示数值范围。若为版本号(1.2-3)、IP段则豁免；若为数值范围(1-10)则保留。',
}

def build_violations(text):
    """构建标准化违规清单 - v3.4 渲染层的唯一输入"""
    is_tech = detect_tech_doc(text)
    adj_stats = scan_zh_en_adjacency(text)
    baseline = determine_baseline(adj_stats, is_tech)

    violations = []

    # 6.5 块标题
    for lineno, pattern, raw in scan_block_titles(text):
        violations.append({
            'lineno': lineno,
            'rule': '6.5',
            'rule_name': RULE_NAMES['6.5'],
            'severity': 'Required',
            'condition': pattern,
            'matched_text': raw,
            'suggestion_hint': '删除块标题末尾冒号',
            'confidence': 'high',
        })

    # 3.13 单位规范
    for lineno, unit in scan_units(text):
        violations.append({
            'lineno': lineno,
            'rule': '3.13',
            'rule_name': RULE_NAMES['3.13'],
            'severity': 'Required',
            'condition': 'missing_space_between_number_and_unit',
            'matched_text': unit,
            'suggestion_hint': f'数字与单位间加半角空格：{unit[:-2]} {unit[-2:]}' if len(unit) > 2 else f'加空格：{unit}',
            'confidence': 'high',
        })

    # 5.1 行末空格
    for hit in scan_trailing_whitespace(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '5.1',
            'rule_name': RULE_NAMES['5.1'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'suggestion_hint': '删除行尾多余空格',
            'confidence': hit['confidence'],
        })

    # 5.1 标点前后多余空格
    for hit in scan_punct_with_space(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '5.1',
            'rule_name': RULE_NAMES['5.1'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'suggestion_hint': '删除多余空格',
            'confidence': hit['confidence'],
        })

    # 3.10 半角括号含中文
    for hit in scan_halfwidth_paren_with_zh(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '3.10',
            'rule_name': RULE_NAMES['3.10'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'suggestion_hint': '括号内含中文，改用全角括号',
            'confidence': hit['confidence'],
        })

    # 3.3 顿号末尾
    for hit in scan_dunhao_list_end(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '3.3',
            'rule_name': RULE_NAMES['3.3'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'suggestion_hint': '最后一项前用"和/或"代替顿号；纯英文标识符并列改用半角逗号',
            'confidence': hit['confidence'],
        })

    # 3.7 范围连字符
    for hit in scan_range_hyphen(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '3.7',
            'rule_name': RULE_NAMES['3.7'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'suggestion_hint': '中文数值范围使用波浪号「～」代替半角连字符',
            'confidence': hit['confidence'],
        })

    # 6.2 列表项决策树
    for hit in scan_list_violations(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '6.2',
            'rule_name': RULE_NAMES['6.2'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'matched_verbs': hit.get('matched_verbs', []),
            'suggestion_hint': '列表项末尾加全角句号',
            'confidence': hit['confidence'],
        })

    # 4.1 中英文空格（仅当达到升级条件时计入）
    if adj_stats['mixing_detected_3plus']:
        raw_4_1 = scan_zh_en_4_1_violations(text, baseline)
        # 应用计数上限
        max_4_1_count = max(1, (len(text.split('\n')) + 19) // 20)  # ceil(行数/20)
        # 按行号分组（同一行同一规则合并为1条）
        seen_lines = {}
        for hit in raw_4_1:
            if hit['lineno'] not in seen_lines:
                seen_lines[hit['lineno']] = hit
        unique_hits = list(seen_lines.values())
        # 取前 max_4_1_count 条独立计数，剩余合并为汇总
        for hit in unique_hits[:max_4_1_count]:
            violations.append({
                'lineno': hit['lineno'],
                'rule': '4.1',
                'rule_name': RULE_NAMES['4.1'],
                'severity': 'Required',
                'condition': hit['condition'],
                'matched_text': hit['matched_text'],
                'suggestion_hint': f'按基准「{baseline}」修复中英相邻位置',
                'confidence': hit['confidence'],
            })
        if len(unique_hits) > max_4_1_count:
            violations.append({
                'lineno': 0,  # 0 表示全文汇总
                'rule': '4.1',
                'rule_name': RULE_NAMES['4.1'],
                'severity': 'Required',
                'condition': 'summary_overflow',
                'matched_text': f'{len(unique_hits)} 行命中，已独立计数 {max_4_1_count} 条，剩余 {len(unique_hits) - max_4_1_count} 条合并为汇总',
                'suggestion_hint': f'全文按基准「{baseline}」统一处理，建议使用 autocorrect/Prettier 等工具批量处理',
                'confidence': 'high',
            })

    # 3.8 中文语境英文直引号
    for hit in scan_zh_invalid_quotes(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '3.8',
            'rule_name': RULE_NAMES['3.8'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'quote_char': hit['quote_char'],
            'suggestion_hint': '中文语境下英文直引号改为中文全角弯引号',
            'confidence': hit['confidence'],
        })

    # 1.2.1 代码块中文全角标点混入
    for hit in scan_code_block_zh_punct(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '1.2.1',
            'rule_name': RULE_NAMES['1.2.1'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'punct_char': hit['punct_char'],
            'suggestion_hint': f'代码块中中文全角标点「{hit["punct_char"]}」应改为英文半角标点',
            'confidence': hit['confidence'],
        })

    # 3.1 中文语境半角句号违规
    for hit in scan_halfwidth_period_in_zh(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '3.1',
            'rule_name': RULE_NAMES['3.1'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'suggestion_hint': '中文语境下半角句号改为全角句号「。」',
            'confidence': hit['confidence'],
        })

    # 3.1 中文句号误用（断句/数字）
    for hit in scan_zh_period_misuse(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '3.1',
            'rule_name': RULE_NAMES['3.1'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'suggestion_hint': '中文句号误用：断句处改用逗号「，」；数字/版本号中改用半角句号「.」',
            'confidence': hit['confidence'],
        })

    # 3.2 中文语境半角逗号违规
    for hit in scan_halfwidth_comma_in_zh(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '3.2',
            'rule_name': RULE_NAMES['3.2'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'suggestion_hint': '中文语境下半角逗号改为全角逗号「，」',
            'confidence': hit['confidence'],
        })

    # 3.3 并列关系应使用顿号而使用了半角逗号
    for hit in scan_dunhao_missing_in_parallel(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '3.3',
            'rule_name': RULE_NAMES['3.3'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'suggestion_hint': '并列词语间应使用顿号「、」代替半角逗号',
            'confidence': hit['confidence'],
        })

    # 3.4 中文语境半角冒号违规
    for hit in scan_halfwidth_colon_in_zh(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '3.4',
            'rule_name': RULE_NAMES['3.4'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'suggestion_hint': '中文语境下半角冒号改为全角冒号「：」',
            'confidence': hit['confidence'],
        })

    # 3.4 代码语境中全角冒号（如 stream(stream)：应为 stream(stream):）
    for hit in scan_fullwidth_colon_in_code_context(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '3.4',
            'rule_name': RULE_NAMES['3.4'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'suggestion_hint': '代码语境中全角冒号改为半角冒号「:」',
            'confidence': hit['confidence'],
        })

    # 3.5 中文语境半角分号违规
    for hit in scan_halfwidth_semicolon_in_zh(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '3.5',
            'rule_name': RULE_NAMES['3.5'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'suggestion_hint': '中文语境下半角分号改为全角分号「；」',
            'confidence': hit['confidence'],
        })

    # 3.6 省略号规范
    for hit in scan_ellipsis(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '3.6',
            'rule_name': RULE_NAMES['3.6'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'error_form': hit.get('error_form', ''),
            'correct_form': hit.get('correct_form', '……'),
            'suggestion_hint': f'省略号应使用「{hit.get("correct_form", "……")}」（两个 U+2026），当前使用了「{hit.get("error_form", "")}」',
            'confidence': hit['confidence'],
        })

    # 5.2 连续标点符号
    for hit in scan_consecutive_punct(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '5.2',
            'rule_name': RULE_NAMES['5.2'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'suggestion_hint': '删除多余的连续标点符号',
            'confidence': hit['confidence'],
        })

    # 6.1 标题末尾不应有句号
    for hit in scan_title_ending_period(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '6.1',
            'rule_name': RULE_NAMES['6.1'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'suggestion_hint': '标题末尾删除句号',
            'confidence': hit['confidence'],
        })

    # 1.2 URL中全角字符
    for hit in scan_url_fullwidth_char(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '1.2',
            'rule_name': RULE_NAMES['1.2'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'suggestion_hint': 'URL中全角字符改为半角字符',
            'confidence': hit['confidence'],
        })

    # 6.5 引导句末尾应使用冒号
    for hit in scan_intro_sentence_missing_colon(text):
        violations.append({
            'lineno': hit['lineno'],
            'rule': '6.5',
            'rule_name': RULE_NAMES['6.5'],
            'severity': 'Required',
            'condition': hit['condition'],
            'matched_text': hit['matched_text'],
            'suggestion_hint': '引导句末尾应使用全角冒号「：」',
            'confidence': hit['confidence'],
        })

    # 按 lineno 排序输出（0 即全文汇总条目排到最后）
    violations.sort(key=lambda x: (x['lineno'] if x['lineno'] > 0 else 999999, x['rule']))

    return violations

def main(text):
    """v3.4 主入口"""
    is_tech = detect_tech_doc(text)
    adj_stats = scan_zh_en_adjacency(text)
    baseline = determine_baseline(adj_stats, is_tech)
    violations = build_violations(text)

    violations_confirmed = []
    violations_pending_review = []
    for v in violations:
        if v.get('confidence') == 'high':
            violations_confirmed.append(v)
        else:
            v_with_criteria = dict(v)
            condition = v.get('condition', '')
            v_with_criteria['review_criteria'] = REVIEW_CRITERIA.get(
                condition, '判断该命中是否为真实违规。若为正常用法则豁免；若确实违规则保留。'
            )
            v_with_criteria['review_decision'] = None
            violations_pending_review.append(v_with_criteria)

    all_violations = violations_confirmed + violations_pending_review
    rule_counts = {}
    severity_counts = {'Required': 0, 'Suggestion': 0}
    for v in all_violations:
        rule_counts[v['rule']] = rule_counts.get(v['rule'], 0) + 1
        severity_counts[v['severity']] += 1

    confirmed_rule_counts = {}
    for v in violations_confirmed:
        confirmed_rule_counts[v['rule']] = confirmed_rule_counts.get(v['rule'], 0) + 1
    pending_rule_counts = {}
    for v in violations_pending_review:
        pending_rule_counts[v['rule']] = pending_rule_counts.get(v['rule'], 0) + 1

    return {
        "is_tech_doc": is_tech,
        "adjacency_stats": adj_stats,
        "baseline_4_1": baseline,
        "quote_counts": scan_quotes(text),
        "list_items_summary": {
            "total": sum(1 for line in text.split('\n')
                        if re.match(r'^\s*(?:\d+\.|-)\s+', line)),
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
            "by_rule_confirmed": confirmed_rule_counts,
            "by_rule_pending": pending_rule_counts,
        },
    }

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r', encoding='utf-8') as f:
            text = f.read()
    else:
        text = sys.stdin.read()
    result = main(text)
    print(json.dumps(result, ensure_ascii=False, indent=2))