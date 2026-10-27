# 预扫描脚本（prescan.py）说明

本文件包含 `scripts/prescan.py` 的详细功能说明、覆盖检查项、运行方式、输出格式、豁免区域处理和 LLM 补充检查项。

## 一、功能概述

`scripts/prescan.py` 是基于正则、字典、Luhn 算法等的确定性安全扫描脚本，覆盖 D2-D7 维度的可机械化检查项，是安全审计的**第一道防线**。

## 二、覆盖检查项

| 维度 | 检查项 | 置信度 | LLM 复核 |
|------|--------|--------|----------|
| D2 PII | 手机号（排除示例号）、身份证号（校验位）、邮箱（排除示例域名）| **high** | 否 |
| D2 PII | 银行卡号（Luhn 校验通过） | medium | 是（结合上下文） |
| D2 PII | frontmatter 中的邮箱 | medium | 是（团队 vs 个人邮箱） |
| D3 凭证 | AWS Access Key (AKIA...) | **high/Critical** | 否 |
| D3 凭证 | GitHub Token (ghp_xxx) | **high/Critical** | 否 |
| D3 凭证 | GitLab Token (glpat-xxx) | **high/Critical** | 否 |
| D3 凭证 | Google API Key (AIza...) | **high/Critical** | 否 |
| D3 凭证 | JWT Token (eyJ...) | **high/Critical** | 否 |
| D3 凭证 | Slack Token (xox[bpoa]-...) | **high/Critical** | 否 |
| D3 凭证 | Stripe Key (sk_live_/sk_test_) | **high/Critical** | 否 |
| D3 凭证 | PEM 私钥（BEGIN PRIVATE KEY） | **high/Critical** | 否 |
| D3 凭证 | `var=value` 形式（排除占位符） | medium | 是 |
| D3 凭证 | 数据库连接串含明文密码 | **high/Critical** | 否 |
| D4 网络 | 内网 IP（RFC 1918：10/172.16-31/192.168） | **high** | 否 |
| D4 网络 | 公网 IP（排除 RFC 5737/回环） | medium | 是（是否已授权公开） |
| D4 网络 | 内部域名（.internal/.local/.corp/.intranet/.lan） | **high** | 否 |
| D4 网络 | 数据库端口地址（IP:3306/5432/6379 等） | **high** | 否 |
| D6 合规 | 商业机密标记（绝密/机密/CONFIDENTIAL/TOP SECRET）| **high** | 否 |
| D6 合规 | 软标记（内部/INTERNAL/DRAFT/草稿） | medium | 是（可能为业务术语） |
| D6 合规 | 绝对化声明（100%安全/绝对可靠等） | **high** | 否 |
| D6 合规 | 歧视性/不当用语（黑名单/主从/暴力破解等） | medium | 是（技术架构术语可保留） |
| D7 元数据 | HTML 注释 | medium | 是（注释内容是否敏感） |
| D7 元数据 | 内部链接（wiki.internal/jira.*.corp） | **high** | 否 |
| D7 元数据 | TODO/FIXME/HACK/XXX 标记 | **high** | 否 |
| D7 元数据 | 零宽字符（U+200B/200C/200D/FEFF） | **high** | 否 |

手机号、身份证号和银行卡号只匹配独立数字候选；ASCII 字母、数字或下划线标识符内部的数字不作为独立 PII。哈希旁同一行或 JSON 中的独立号码仍检查。

## 三、运行方式

```bash
# 扫描单个文件
python3 scripts/prescan.py path/to/doc.md

# 扫描整个目录（递归）
python3 scripts/prescan.py path/to/docs/

# 通过 stdin 传入
cat doc.md | python3 scripts/prescan.py
```

## 四、输出格式

```json
{
  "scanned_files": 23,
  "violations_confirmed": [
    {
      "file": "...", "lineno": 14, "rule": "D2", "rule_name": "身份证号泄露",
      "severity": "Critical", "confidence": "high",
      "dimension_name": "个人数据与隐私",
      "error": "110101199003071234", "correction": "110101********4",
      "matched_text": "..."
    }
  ],
  "violations_pending_review": [
    {
      "file": "...", "lineno": 25, "rule": "D3", "rule_name": "api_key 明文值",
      "severity": "Critical", "confidence": "medium",
      "review_criteria": "判断该 var=value 是否为真实凭证。若为脱敏后的示例或文档片段，可豁免。",
      "review_decision": null
    }
  ],
  "violation_stats": {
    "total": 23, "total_confirmed": 17, "total_pending_review": 6,
    "by_severity": { "Critical": 4, "Required": 17, "Suggestion": 2 },
    "by_rule": { "D2": 4, "D3": 3, "D4": 7, "D6": 5, "D7": 4 }
  }
}
```

## 五、豁免区域处理

prescan.py 内置：
- 代码块（``` ... ``` 和 ~~~ ... ~~~）跳过普通文本检查，但**密钥与 IP 仍扫描**（代码块中的密钥同样是泄露）
- 行内代码（`code`）中的 PII 跳过
- frontmatter 中跳过手机号/身份证号/银行卡号扫描，但**邮箱仍扫描**（标记为 medium，可能是团队邮箱）
- 示例域名（example.com/test.com/your-domain.com）、示例手机号（13800138000）、示例身份证号、占位符（`<YOUR_*>`/`${VAR}`/`your_*`）自动豁免

## 六、LLM 须补充的语义级检查

脚本无法覆盖、必须由 LLM 完成的部分：
- **D2** 真实姓名识别（"王建国"是真名还是示例？）
- **D5** 客户名称/项目代号识别（需企业知识库）
- **D5** 局点地址/部署架构（需上下文判断）
- **D6** 政治敏感词上下文（敏感词出现在历史叙述 vs 评论中含义不同）
- **D7** 修订历史/文件属性（需读取文件元数据）
