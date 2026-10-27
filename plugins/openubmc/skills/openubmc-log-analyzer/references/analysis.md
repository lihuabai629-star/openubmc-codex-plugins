# 日志分析

本地分析与采集后分析共用 `openubmc-log-bundle-analyzer/scripts/log_bundle_analysis.py`。
输入、时间域、截断与证据语义见相邻资源的
[分析说明](../../openubmc-log-bundle-analyzer/references/analysis.md)。
采集 CLI 的 `result.analysis` 保留完整分析结果，并以 `coverage` 兼容投影提供扫描覆盖情况。
已有结果应直接复用；问题、时间窗或包内容变化时再补充分析。
