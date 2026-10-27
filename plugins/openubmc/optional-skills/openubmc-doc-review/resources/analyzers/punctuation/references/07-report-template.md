# 报告输出规范（doc-punctuation-tester）

本文件定义标点符号审查报告的完整模板、文件命名规则、格式强制要求。

## 9.1 报告文件生成要求

- [ ] 审查完成后，**必须**在原始文档所在目录下生成 Markdown 格式的报告文件
- [ ] 报告文件名**不得**与原始文档文件名相同，以避免覆盖原始文档
- [ ] 同一文档多次审查时，报告文件按序号递增命名，**不得覆盖**已有报告
- [ ] 必须包含SKILL版本号、执行流程完成情况、完整性自检完成状态三个元信息，缺少任意一项的报告视为无效报告

## 9.2 报告文件命名规则

文件名格式：`{原始文件名（不含扩展名）}-punctuation-report-{序号}.md`

- `{原始文件名（不含扩展名）}`：取原始文档的文件名（去掉 `.md` 扩展部分）
- `-punctuation-report-`：固定标识，表示标点符号审查报告
- `{序号}`：从 `001` 开始的三位序号，每次对同一文档执行审查时递增

**命名示例**：

| 原始文件 | 第几次审查 | 报告文件名 |
| --- | --- | --- |
| `bmc-studio-installation.md` | 第 1 次 | `bmc-studio-installation-punctuation-report-001.md` |
| `bmc-studio-installation.md` | 第 2 次 | `bmc-studio-installation-punctuation-report-002.md` |
| `bmc-studio-installation.md` | 第 3 次 | `bmc-studio-installation-punctuation-report-003.md` |
| `quick-start.md` | 第 1 次 | `quick-start-punctuation-report-001.md` |

## 9.3 序号递增逻辑

- [ ] 生成报告前，先扫描原始文档所在目录，查找匹配 `{原始文件名（不含扩展名）}-punctuation-report-*.md` 的现有报告文件
- [ ] 从已有报告文件名中提取最大序号，新报告序号 = 最大序号 + 1
- [ ] 若目录中无已有报告，则从 `001` 开始
- [ ] 序号格式为三位数字，零填充：`001`、`002`、…、`099`、`100`

## 9.4 报告文件内容结构（完整模板）

报告文件必须**严格**按以下模板生成，不得修改模板结构，不得添加模板之外的章节，不得使用 emoji。

```markdown
---
date: {审查日期，格式 YYYY/MM/DD，必须使用<env>中提供的Today's date}
source: {原始文档文件名}
language_type: {文档语言类型：纯中文 / 纯英文 / 中英混合}
skill_version: {使用的SKILL版本号，如 v3.4}
execution_checks: {执行校验清单完成状态，如 all_passed}
execution_details:
  step0: "版本校验通过，使用版本v{从SKILL.md头部读取的version字段值}"
  step1: "语言类型判定为{类型}，适用{XX}条规则"
  step1_8: "判定层执行完成，技术文档={is_tech_doc}，4.1基准={baseline_4_1}，violations_confirmed={X}条(high) + violations_pending_review={Y}条(medium，待复核)"
  step2: "渲染层复核完成，violations_confirmed {X}条（全部计入）+ violations_pending_review {Y}条（保留 {Z} 条，豁免 {W} 条）"
  step3: "3.9量化判定完成，新增{N}处Suggestion"
  step4: "报告组装完成，共写入{N}条违规"
  step5: "报告溯源校验通过，pending_review复核完成率100%"
  step5_5: "一致性基线核查通过，脚本输出完整性确认"
  step6: "报告生成成功"
traceability_stats:
  violations_confirmed: {X}  # confidence:high 全部计入
  violations_pending_review_kept: {Y}  # confidence:medium 经复核保留
  violations_pending_review_exempted: {Z}  # confidence:medium 经复核豁免
  model_independent_judgment: {V}  # 仅 3.9 量化判定允许
  pending_review_completion_rate: "100%"  # 必须为100%，否则报告无效
  total_required: {X+Y+V}
prescan_raw_summary:
  # 仅保留脚本统计摘要，禁止粘贴完整 JSON / 违规原文
  total_confirmed: {violations_confirmed 条目数}
  total_pending_review: {violations_pending_review 条目数}
  by_rule: {rule -> count 的分布摘要}
  baseline_4_1: {从脚本输出取值}
  is_tech_doc: {从脚本输出取值}
  raw_available: true  # 脚本输出完整 JSON 保存在本地临时文件，不在报告中携带
---

# 标点符号质量审查报告

**源文档**：{原始文档文件名}
**文档语言类型**：{文档语言类型}
**审查日期**：{审查日期，格式 YYYY/MM/DD}
**审查依据**：doc-punctuation-tester SKILL.md (版本 {技能版本号})

---

## 问题汇总

| 严重等级 | 数量 | 占比 |
|----------|------|------|
| **Required**（标点错误） | {数量} | {占比，保留整数%} |
| **Suggestion**（风格建议） | {数量} | {占比，保留整数%} |
| **合计** | {总数} | 100% |

## 问题详情

### Required（标点错误）
（按规则编号从小到大排序，同一规则内按行号从小到大排序。使用以下表格格式，不可修改列结构）

| 编号 | 行号 | 原文 | 引用规则 | 修复建议 |
|------|------|------|----------|----------|
| R1 | {行号} | {原文片段} | {规则编号，如 6.2} | {修复建议} |
| R2 | ... | ... | ... | ... |

### Suggestion（风格建议）
（按规则编号从小到大排序，同一规则内按行号从小到大排序。使用以下表格格式，不可修改列结构）

| 编号 | 行号 | 原文 | 引用规则 | 修复建议 |
|------|------|------|----------|----------|
| S1 | {行号} | {原文片段} | {规则编号，如 4.1} | {修复建议} |
| S2 | ... | ... | ... | ... |

## confidence:medium 复核记录（v3.4 强制段落）

（以下表格列出脚本 violations_pending_review 中的每一条命中，模型必须逐条填写复核结果。此段落缺失或 review_decision 含 null 值的，报告视为无效）

| 行号 | 规则 | 原文片段 | review_criteria | review_decision | review_reason |
|------|------|----------|-----------------|-----------------|---------------|
| {行号} | {规则编号} | {matched_text前40字符} | {来自脚本的review_criteria} | keep / exempt | {若exempt则填写原因，若keep则填写"确认违规"} |
| ... | ... | ... | ... | ... | ... |

（说明：review_decision=keep 的条目已计入上方"问题详情"表格；review_decision=exempt 的条目不计入问题数）

## 通过项
（必须使用表格格式，列出所有已检查的规则维度及其通过/未通过状态）

| 规则编号 | 规则名称 | 检查结果 |
|----------|----------|----------|
| 1.1 | 语言判定原则 | ✅ 通过 / ❌ 未通过 |
| 1.2 | 豁免区域 | ✅ 通过 |
| 1.2.1 | 代码块中文标点混入 | ✅ 通过 |
| 3.1 | 句号（中文） | ✅ 通过 / ❌ 未通过 |
| ... | ... | ... |
| 6.5 | 块标题 | ✅ 通过 / ❌ 未通过 |

## 评分

- Required 问题 {数量} 个 × 0.5 分 = 扣 {计算结果} 分
- Suggestion 问题 {数量} 个 × 0.2 分 = 扣 {计算结果} 分
- **得分**：max(0, 10 - {required扣分} - {suggestion扣分}) = **{最终得分} / 10**

## 修复优先级建议

1. **[紧急]** {最高优先级问题描述}（规则{编号}，{数量}处）
2. **[高]** {次高优先级问题描述}（规则{编号}，{数量}处）
3. **[中]** {中等优先级问题描述}（规则{编号}，{数量}处）
4. **[低]** {低优先级问题描述}（规则{编号}，{数量}处）

---

## v3.4 溯源统计（强制段落）

| 来源 | 数量 | 说明 |
|------|------|------|
| 脚本命中（violations_confirmed / confidence:high） | {X} 条 | 全部计入报告，不可豁免 |
| 脚本命中（violations_pending_review / confidence:medium） | {Y+Z} 条 | 模型逐条复核后保留 {Y} 条，豁免 {Z} 条 |
| 模型独立判定 | {V} 条 | 仅 3.9 量化判定允许 |
| **总计** | **{X+Y+V}** 条 | 与"问题汇总"表中 Required+Suggestion 一致 |

**pending_review 复核完成率**：{Y+Z}/{Y+Z} = 100%（每条 review_decision 已填写，无 null 残留）
```

## 9.4.1 格式强制要求

1. **frontmatter**：必须包含 `date`、`source`、`language_type`、`skill_version`、`execution_checks`、`traceability_stats`（含 `pending_review_completion_rate`）、`prescan_raw_summary` 字段，不得遗漏
2. **标题**：必须为 `# 标点符号质量审查报告`，不得添加 emoji 或其他修饰
3. **问题汇总表**：必须使用三列格式（严重等级 | 数量 | 占比），不得修改
4. **问题详情**：必须按规则编号排序，每个问题包含5列（编号 | 行号 | 原文 | 引用规则 | 修复建议），不得修改
5. **问题编号**：使用 `R1, R2, ...` 表示 required，`S1, S2, ...` 表示 suggestion，不得使用其他编号方式
6. **confidence:medium复核记录**（v3.4新增）：必须包含6列表格（行号 | 规则 | 原文片段 | review_criteria | review_decision | review_reason），每条 violations_pending_review 必须有对应行，review_decision 不得为 null。此段落缺失视为报告无效
7. **通过项**：必须使用表格格式，列出所有检查维度的通过/未通过状态，不得使用折叠框或其他格式
8. **评分**：必须计算评分，公式为 `max(0, 10 - required数 × 0.5 - suggestion数 × 0.2)`，不得使用其他评分算法
9. **行号引用**：行号必须为文档中的实际行号，格式为纯数字
10. **禁止使用 emoji**：报告全文不得使用任何 emoji 符号
11. **v3.4 溯源统计段落**：必须显示在"修复优先级建议"之后，必须包含 `pending_review 复核完成率` 行，缺失视为报告不完整

## 9.5 报告生成流程

1. 完成文档审查，整理所有问题
2. 扫描原始文档所在目录，确定下一个可用序号
3. 按命名规则生成报告文件名
4. 按内容结构模板填充报告内容
5. 将报告文件写入原始文档所在目录
6. 向用户输出审查摘要，并告知报告文件路径
