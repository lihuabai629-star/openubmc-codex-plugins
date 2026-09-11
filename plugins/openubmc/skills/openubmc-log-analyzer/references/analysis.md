# 日志解析说明

## 目标

说明 `scripts/pull_bundle.py --problem ...` 在本地分析一键日志包时，如何选日志、如何取证据、结果字段是什么意思。

这份文档描述的是当前 skill 的实现行为，不是 openUBMC 本身的产品协议。

## 输入

分析阶段最关键的输入有四个：

- `--problem`
  - 问题描述。用于命中 `references/logs.json` 的规则和关键词。
- `--analysis-since`
  - 只保留不早于该时间的证据。
- `--analysis-until`
  - 只保留不晚于该时间的证据。
- `--analysis-max-files` / `--analysis-max-lines`
  - 限制返回的日志类型数量和每类证据行数量。

## 日志选择规则

分析并不会默认扫描整个 bundle，而是按问题驱动做收敛：

1. 先读 `references/logs.json` 的 `rules`
2. 用 `problem` 文本命中 `match_keywords`
3. 把规则命中的日志放到最前面
4. 再结合每个日志项自己的 `keywords` 做补充排序

示例：

- `BMC 登录失败`
  - 优先命中 `security.log`、`operation.log`
- `对象不同步`
  - 优先命中 `rpc_records.log`、`sync_property_trace.log`、`mdb_info.log`
- `启动失败`
  - 优先命中 `framework.log`、`journalctl.log`

## 路径扩展规则

### 轮转日志

如果某个路径是普通日志文件，例如 `dump_info/LogDump/app.log`，分析时会自动把同目录下的轮转文件一起纳入：

- `app.log`
- `app.log.1.gz`
- `app.log.2.gz`

返回结果里不会专门标记“这是轮转文件”，但 `path` 会显示实际命中的文件路径。

### 通配路径

像 `dump_info/AppDump/*/mdb_info.log` 这类通配路径，会展开为多个组件目录下的实际文件。

如果问题文本里出现组件提示，例如 `cooling 对象不同步`，分析会优先排 `AppDump/cooling/` 这类更相关的路径，而不是简单取第一个命中文件。

## 证据行筛选规则

每个候选日志文件内部，证据提取遵循下面的优先级：

1. 同时命中问题关键词和故障词的行
2. 只命中问题关键词的行
3. 只命中通用故障词的行

通用故障词包括：

- `error`
- `failed`
- `failure`
- `exception`
- `crash`
- `失败`
- `告警`

另外会过滤低价值模板行，例如：

- 表头
- 统计标题
- 固定模板提示

## 证据排序规则

最终返回给用户的证据行，不是简单按文件顺序截取，而是做过排序：

1. 更直接的问题短语优先
  - 例如 `BMC 登录失败` 场景下，`login failed` 会优先于泛化的 `authentication failures`
  - `对象不同步`、`启动失败` 也会优先看更直接的失败短语
2. 更相关的文件路径优先
  - 例如 `AppDump/cooling/` 会优先于无关组件目录
3. 命中更多问题关键词的行优先
4. 带明确时间戳的行优先
5. 时间更新的行优先

## 时间窗行为

如果传了 `--analysis-since` 或 `--analysis-until`：

- 只有能解析出时间戳的日志行才会被纳入
- 超出时间窗的行会被丢弃
- 返回结果会额外带 `time_window`

示例：

```json
{
  "time_window": {
    "since": "2026-03-31T00:00:00",
    "until": "2026-03-31T23:59:59"
  }
}
```

## 输出字段说明

`result.analysis` 里最常用的字段如下：

- `summary`
  - 本次选了多少类日志、发现多少个实际文件、抓到了多少条证据。
- `selected_logs`
  - 每类日志的分析结果列表。

`selected_logs[]` 下的重要字段：

- `name`
  - 日志名，对应 `logs.json` 里的定义。
- `matched_keywords`
  - 这类日志是因哪些问题关键词被选中。
- `existing_paths`
  - 实际存在并参与分析的路径列表。
- `existing_path_count`
  - 实际命中的路径总数。
- `existing_paths_truncated`
  - 如果为 `true`，说明实际路径很多，输出里只截取了一部分。
- `evidence_lines`
  - 该日志类型下最终返回的证据行。

`evidence_lines[]` 下的重要字段：

- `path`
  - 证据来自哪个文件。
- `line_number`
  - 原始行号。
- `line`
  - 原始日志行。
- `timestamp`
  - 仅当该行能解析出时间时才会出现。

## 如何解读结果

- 第一条证据不一定是“最新的一行”，而是“当前问题下最值得先看的那一行”。
- `security.log` 和 `operation.log` 经常会同时返回，前者更偏直接失败原因，后者更偏审计和时间线。
- `existing_path_count` 很大时，不要误解为噪声很多；这通常只是通配路径展开后组件很多。
- 如果 `evidence_lines` 为空，但 `existing_paths` 不为空，说明：
  - 问题关键词没有在这些日志里打出来
  - 或者时间窗把候选证据过滤掉了

## 什么时候要补规则

出现下面情况时，优先更新 `references/logs.json`：

- 明明是常见问题，但没选到正确日志
- 证据总落在泛化日志，没落在更直接的日志
- 团队常用中文口语表达，但规则只有英文关键词

出现下面情况时，优先更新 `references/logs.md`：

- 新日志文件含义不清楚
- 同事不知道某类问题应该先看哪个日志
- 需要记录某个日志的直接证据和辅助证据边界

## Local resource limits

`extract_archive` accepts at most 10,000 members, 512 MiB of declared output
(including hard-link targets), and 576 MiB of decompressed tar data by default.
The stream limit also covers extended headers. Exceeding a limit removes the
partial extraction directory and returns `extract_budget_exceeded`. Hard links
must refer to an earlier regular file. Sparse members are rejected because their
expanded extents can disagree with their declared size. Existing path and tar
data filters apply. Member paths, including resolved link paths, are limited to
128 components so failure cleanup remains bounded.

`analyze_bundle` scans at most 64 MiB of decompressed log data, 512 files, and
20,000 directory entries, with a 64 KiB maximum line. Limits apply across selected
log types. Symbolic links are not followed during directory discovery. Evidence
retention is bounded both within each file and across rotations, preserving the
existing ranking rules. Public Python callers can lower or raise the limits via
`scan_max_bytes`, `scan_max_files`, `discovery_max_entries`, and `max_line_bytes`.

Always inspect `coverage.complete` and `coverage.reasons`. Byte, file, discovery,
and line limits or read failures make analysis incomplete; evidence collected
before the stop remains available. An empty evidence list with incomplete coverage
cannot exclude a fault. `scanned_bytes` counts decompressed bytes consumed, and
`scanned_files` counts opened files. Reaching the exact byte limit is conservatively
reported as incomplete when EOF has not been observed. Completeness covers only
the log types selected for the supplied problem, not every file in the bundle.
