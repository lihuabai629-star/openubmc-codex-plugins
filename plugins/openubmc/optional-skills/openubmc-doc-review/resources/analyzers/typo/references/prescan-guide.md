# 预扫描脚本（prescan.py）说明

本文件包含 `scripts/prescan.py` 的详细功能说明、字典来源、运行方式、输出格式、豁免区域处理和置信度分级。

## 一、功能概述

`scripts/prescan.py` 是基于 references/ 目录中字典的确定性错别字扫描脚本，用于在 LLM 检查前先做一轮高置信度的机械化扫描。

## 二、字典来源

脚本自动解析 references/ 下的 8 个 Markdown 对照表，构建以下字典：

| 字典 | 来源文件 | 维度 | 置信度 |
|------|---------|------|--------|
| 拼音输入错误 | pinyin-errors.md | §6.2 | high |
| 技术术语误写 | tech-terms.md | §7.2 | high |
| 词序颠倒 | word-order-errors.md | §6.4 | high |
| 重复字 | dup-missing-chars.md（重复部分） | §6.5 | high |
| 简繁混用 | simplified-traditional.md | §5 | high |
| 英文术语拼写 | english-term-errors.md | §7.3 | high |
| 易混词 | confusing-words.md | §4 | medium |
| 形近字 | look-alike-chars.md | §3 | medium |
| 漏字 | dup-missing-chars.md（漏字部分） | §6.5 | medium |
| 术语一致性 | 内置规则（推理服务/推理服务器等） | §7.4 | medium |

## 三、运行方式

```bash
# 方式一：直接传入文件路径
python3 scripts/prescan.py <文档路径>

# 方式二：通过 stdin 传入文档内容
cat <文档路径> | python3 scripts/prescan.py
```

## 四、输出格式

```json
{
  "dictionary_stats": { "pinyin": 60, "tech_terms": 42, "word_order": 18, ... },
  "violations_confirmed": [
    {
      "lineno": 7, "rule": "§6.2", "rule_name": "拼音输入错误",
      "severity": "Required", "error": "按装", "correction": "安装",
      "confidence": "high", "matched_text": "请按装软件包"
    }
  ],
  "violations_pending_review": [
    {
      "lineno": 37, "rule": "§7.4", "rule_name": "术语表述一致性",
      "severity": "Suggestion", "error": "推理服务", "correction": "推理服务器",
      "confidence": "medium",
      "review_criteria": "判断该术语表述是否真不一致。同一概念在全文中应统一表述。",
      "review_decision": null
    }
  ],
  "violation_stats": {
    "total": 22, "total_confirmed": 20, "total_pending_review": 2,
    "by_severity": { "Required": 21, "Suggestion": 1 },
    "by_rule": { "§6.2": 5, "§6.4": 4, "§6.5": 3, "§7.2": 2, ... }
  }
}
```

## 五、豁免区域处理

prescan.py 内置豁免区域检测逻辑：
- 代码块（\`\`\` ... \`\`\` 和 ~~~ ... ~~~）中的内容跳过
- 行内代码（\`code\`）中的内容跳过
- Markdown 链接 URL 部分（[text](url)）中的内容跳过
- 裸 URL/绝对路径（https://... 或 /path/to/file）中的内容跳过
- YAML frontmatter 中的内容跳过

## 六、置信度分级

| 置信度 | 含义 | 处理方式 |
|--------|------|----------|
| high | 字典确定性匹配（如"按装→安装"） | 直接纳入 violations_confirmed |
| medium | 需上下文判断（如"必须/必需""推理服务/推理服务器"） | 纳入 violations_pending_review，LLM 逐条复核 |
