<!--
Copyright (c) 2026 Huawei Technologies Co., Ltd.
openUBMC is licensed under Mulan PSL v2.
You can use this software according to the terms and conditions of the Mulan PSL v2.
You may obtain a copy of Mulan PSL v2 at:
        http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.
-->

# R5 Lua 数值与 GC 边界

## 历史基线与证据范围

`6249b90fad9a699899e291424460fcaa5da09b85` 修改 `libraries/mcapp/src/expression/lua_expression_evaluator.cpp` 的 `push_variant_to_lua`，并在 `tests/test_expression_processor.cpp` 添加往返与 GC 回归用例。用 `git show <提交号> -- <文件>` 核对，保持当前 checkout。

补丁说明和用例注释指向带 64 位整数扩展的定制 LuaJIT/整数补丁运行时：很大的整数对象在 GC 遍历时引发 SIGSEGV。此依据来自修复注释与回归用例，不表示已检查该运行时内部 GC 实现，也不能推广为标准 Lua/LuaJIT 都有这个问题。

补丁对 int64 的 push 采取：严格满足 `-2^53 < n < 2^53` 用 `lua_pushinteger`，其余用 `lua_pushnumber`。边界 ±2^53 虽然走 number，binary64 仍能精确表示；±(2^53+1) 不能精确表示，测试接受舍入到 ±2^53。因此该历史策略包含**精度取舍**，不是所有业务的通用修复模板。

## 检测链

| 环节 | 核对内容 |
| --- | --- |
| 数据来源 | variant 的 int64/uint64/double，解析出的超大值、参数或动态表达式结果；证明触发值可达 |
| 编译与运行时 | 真实 lua 库与头文件是否对应、Lua 版本/定制补丁、`lua_Integer/lua_Number` 宽度与表示、现有绑定的整数扩展 |
| push | `lua_pushinteger` 之前是否已窄化，是否进入受影响大整数对象分支；`lua_pushnumber` 是否违反精确整数契约 |
| read | `lua_tonumber/lua_tointeger` 到 C++ 整数的转换是否有有限性、范围和整数性保护；确认该版本 API 语义 |
| GC | 是否经过实际 evaluator、缓存淘汰或显式 `lua_gc/collectgarbage`；覆盖增量与必要的完整 GC 路径 |

**确认运行时特定崩溃风险**需证明目标使用受影响实现、输入到达对应 push 路径且 GC 可消费该对象。运行时/补丁未知时作为待验证，提出需要的源码或复现证据；只看见 `lua_pushinteger` 就报 coredump 是误报。

数值窄化、超范围浮点转整数和精度损失可独立存在，分类为转换安全/正确性问题；源码证明后可确认该问题，仍不能把它们都称为该历史 GC 崩溃。

## 两侧转换与精度

```cpp
// 候选：需证明运行时整数宽度、输入范围与 GC 路径。
lua_pushinteger(L, static_cast<lua_Integer>(value.as_int64()));
```

检查 cast **之前**的原始值。先把 double 转整数再用“转回 double 是否相等”测试，不能防止第一次转换已经超范围；NaN/Inf 也需按输入契约处理。与 `INT64_MAX` 转成 double 的值比较时注意该上界可能向 2^63 舍入，边界判定必须对应真实可表示范围。

double 路径下的可精确整数范围应按实际 `lua_Number` 的表示核对。binary64 连续整数的边界为 ±2^53，边界以外仍有部分整数能精确表示，不能将“范围外”都称为溢出。C++ int64 的极值转换到 double 后可能在回读时超出 int64 范围，push 与 read 需要一起判断。

建议依运行时能力及业务契约选取已有的精确整数表示、拥有字符串/整数 userdata 路径、显式拒绝不支持值或允许的浮点表示。若业务要求精确主键/位字段，简单改成 double 即使避免 GC 崩溃也可能产生功能错误。不要修改 vendor runtime 或改变数据精度契约来绕过未证实问题。

## 回归与排除条件

历史用例覆盖 ±(2^53-1)、±2^53、±(2^53+1)、附近算术，以及至少跨越当时 64 次求值的增量 GC 触发间隔。目标实现的触发条件应重新读取，优先显式触发真实 GC，不把历史次数作为永久常量。

如需要检查读侧，追加 int64/uint64 边界、非整数浮点、NaN/Inf 与无法表示的结果；只加入符合用户数据契约的断言。分别核对“不崩溃”和“数值满足精度契约”，不能只跑小整数往返。

排除证据包括未受影响的实际运行时、已知有界输入与合法整数宽度、正确的精确整数扩展，以及完整保护的转换。标准 Lua 下通过或 mock 转换函数返回，不能验证定制实现的 GC 事故已被排除。测试专用命中与生产表达式入口分别记录。
