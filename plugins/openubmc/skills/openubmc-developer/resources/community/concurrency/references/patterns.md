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

# R1/R2 并发崩溃的检测依据

## 来源与适用范围

在 libmcpp 仓库中，用以下命令核对修复前后；不切换当前 checkout：

```bash
git show 84e621eb9ab9473eb94f5978a4652498925fb479 -- libraries/mcapp/include/mc/app/remote_persist/remote_persist_bridge.h libraries/mcapp/src/remote_persist/remote_persist_bridge.cpp
git show b5e17836c7bc4751d239a20b224852b2b719f8c2 -- libraries/mcdbus/src/signal.cpp
```

这里的修复事实来自提交差异。线程入口、对象生命期和其他依赖行为仍应按目标 revision 核对。截止技能生成时，当前缓存实现已进一步演进为 `shared_ptr<const class_persist_cache>`；不能只按原补丁中的 `copy_object_cache` 名称判断安全性。以下 C++ 片段为机制示意，并非新增公共 API。

## R1 共享缓存读写与引用生命周期

### 基线事实

`84e621eb` 修改 `remote_persist_bridge`：

| 访问点 | 修复前 | 修复后 |
| --- | --- | --- |
| `on_table_object_added` / `do_bind_object` | 锁外判重，锁外写 `m_obj_cache[&obj]` | 判重与插入放到 `m_mutex` 的同一临界区 |
| `on_table_object_removed` | 锁外 `m_obj_cache.erase(obj)` | 在 `m_mutex` 内删除 |
| `on_property_changed` | 锁外 `find`，持有 `auto& cache = obj_it->second` 后读取属性配置 | `copy_object_cache` 锁内查找/筛选并复制拥有数据的缓存，锁外继续工作 |
| 属性连接记录 | 锁外 `m_prop_connections.push_back` | 在 `m_mutex` 内追加 |
| `shutdown` | 直接遍历连接列表、清空缓存 | 锁内 swap 连接列表和 clear 缓存；锁外 disconnect |

补丁还增加 `m_recovering` 回环过滤，并使跳过代理初始化的 UT 仍然连接表信号。这些措施不能代替缓存同步。该提交的测试差异仅增加头文件，不能据此宣称已加入完整并发回归用例。

### 判定条件

同一个容器存在可重叠的结构修改与查询/遍历，且同步协议未覆盖其中一侧，即是 R1 的重点。即使删除的是另一个 key、仅读查找，仍须分析容器自身的并发要求。对固定大小容器的不同元素操作、线程安全容器或不可变数据，按实际实现另行判定。

锁内取得迭代器/引用后，锁外访问依然需要所有权证明：

```cpp
// 风险：读写使用同一个 map，却没有完整的同步关系。
auto it = m_cache.find(key);
if (it != m_cache.end()) {
    const auto& cached = it->second;
    consume(cached);
}
// 另一线程：m_cache.erase(key) 或 m_cache.clear();
```

最小触发时序：T1 查找并得到元素引用 → T2 删除该元素或清空容器 → T1 继续读取被释放的数据。`unordered_map` 的 rehash 会使迭代器失效，但本身不使元素引用/指针失效；描述风险时区分结构竞态、迭代器失效和被删除元素的引用失效。

```cpp
// 仍有风险：查找被锁保护，结果却只是借用。
const cache_type* lookup(key_type key)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_cache.find(key);
    return it == m_cache.end() ? nullptr : &it->second;
}
```

可用的修复形态是锁内复制拥有数据的快照，或锁内复制指向不可变数据的拥有指针：

```cpp
std::shared_ptr<const cache_type> lookup(key_type key)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_cache.find(key);
    return it == m_cache.end() ? nullptr : it->second;
}
// map 类型为 map<key_type, shared_ptr<const cache_type>>；发布后无其他可变别名写入。
```

快照仍含 `string_view`、裸指针、引用或共享可变子对象时，继续核对所指数据生命期和并发修改。`shared_ptr` 仅保证其所有权协议，不保证 pointee 线程安全；同一个 `shared_ptr` 实例的并发读写也需要同步。复制 variant/dict 等类型时检查其复制/写时复制实现，不能仅凭赋值语法认定完全隔离。

### 生命周期与锁边界

查找对象表、绑定回调、保存连接列表和删除对象可能来自不同入口。按真实 signal/connection 实现核对 `disconnect` 是否等待在途回调，以及析构前是否已阻止新访问。锁内 swap、锁外 disconnect 可以缩短临界区和避开回调锁顺序问题，但单独这一操作不证明捕获 `[this]` 的回调已结束。

`init`、`shutdown` 与 bind 的竞争只有在调用协议允许其重叠时才列为问题；不能仅凭它们存在就假设并发。将对象注销与属性回调交叠列为测试时，还要符合 engine 自身的对象生命期契约，避免测试制造本来禁止的裸指针访问。

缓存自身的锁覆盖正确后，继续核对业务消费所需的对象是否仍有效。`m_recovering` 这样的原子标记解决该标记的同步或流程过滤，不保护 map/vector，也不自动实现多个原子操作的事务。

## R2 共享锁下修改进程级上下文

### 基线事实

`b5e17836` 在 `libraries/mcdbus/src/signal.cpp` 将：

```cpp
static DBus::Match::Context s_ctx;
```

改成：

```cpp
// set_req 会写 Context 的内部 map；跨线程隔离临时状态。
thread_local DBus::Match::Context s_ctx;
```

旧 SHM 分支的 `send_signal` 在 `shm_global_lock_shared_exec` 回调内调用 `s_ctx.set_req(...)` 和匹配运行。共享锁允许 T1 与 T2 同时执行，进程级 `s_ctx` 的可变状态因此没有排他保护。内部 map 写入的依据是该修复提交的说明；目标环境中应进一步核对真实 `DBus::Match::Context` 依赖实现。

libmcpp 的 `include/mc/dbus/match.h` 中，`SharedLock` 使用 `acquire_read_lock`，`Lock` 使用 `acquire_write_lock`，包装器同步调用 callback。必须核对目标 revision 的定义，不能把带 lock 字样的名字都理解为互斥。

### 判定条件

- 数据属于全局变量、函数 static、单例或可被多线程访问的成员。
- 对数据的写可被多个调用同时执行，包含隐藏在方法里的缓存更新、lazy initialization、计数、scratch buffer 复用。
- 当前共享锁只序列化与相应排他持有者的冲突；多个共享持有者之间没有排他性，也未发现其他覆盖该数据的同步机制。

最小触发时序：T1、T2 均持有共享锁 → T1 为请求 A 修改 `s_ctx` → T2 为请求 B 修改同一个 `s_ctx` → 后续匹配读到另一请求的状态，或并发修改内部容器导致未定义行为。

```cpp
// 风险：保护共享树的读锁不能同时为进程内 scratch 提供排他性。
static request_context ctx;
shm_global_lock_shared_exec([&] {
    ctx.set_req(request);
    tree.run(ctx);
});
```

```cpp
// 通常安全：每次调用拥有独立的临时上下文，且同步调用期间不逃逸。
request_context ctx;
shm_global_lock_shared_exec([&] {
    ctx.set_req(request);
    tree.run(ctx);
});
```

以下命中需要排除或进一步区分：

| 形态 | 判断 |
| --- | --- |
| 共享锁内写本次调用局部的 `destinations/result` | 独占拥有、不逃逸时可排除；如 callback 异步保存引用则另查生命期 |
| `static const/constexpr` 且无隐藏可变状态 | 初始化和发布符合协议后可排除 |
| 真正的函数局部变量或已隔离的 per-call Context | 局部且不逃逸可排除 |
| `thread_local Context` | 跨线程写竞争可排除；同线程重入与协程交错另行核对 |
| 全局共享锁内另持 `shm_object_lock_exec(object_id, ...)` | 排他对象锁可能已正确保护写入；核对锁 ID、所有访问者及保护范围 |
| 非 const getter 或 `mutable` 缓存 | 按实现确认是否写共享状态，不能按函数名判定 |

`libraries/mcdbus/src/match.cpp` 的 `run_msg/test_match`，以及 `src/shm/shm_tree.cpp` 的 `test_shm_match`，在技能生成时使用局部 Context，可作为局部独占的对照，不应仅因存在 `set_req` 就报告缺陷。

### thread_local 与重入边界

`thread_local` 隔离不同 OS 线程，但同线程嵌套 `send_signal`、共享线程上的协程或延迟消费仍可能复用同一个 Context。只在调用链存在可达重入点或对象逃逸证据时报告；不能把这一边界当作该修复提交中已证实的剩余问题。

证据时序为：外层调用写入 A → callback/协程切换进入内层调用写入 B → 外层恢复后继续读 Context。请求独立的栈对象或显式保存恢复可处理此类临时状态；简单加递归锁仍无法保证外层状态不被内层覆盖。

### 条件编译与依赖

当前旧传输路径由 `MCDBUS_USE_OLD_SHM` 控制。打开时 `match.h` 引用 skynet 提供的真实 `dbus/match/matchs.h` 等头文件；关闭时引用 `mc/dbus/shm/mock_shm.h`。后者的 `Context::set_req` 只给 `req` 赋值，不能代表真实实现中的 map 修改、分配或重入行为。

将“该构建关闭旧 SHM，因此当前运行不可达”与“源码所有配置均安全”区分开。真实依赖源码不可得时，记录限制；报告引用提交说明时明确依据，避免声称已检查外部实现。当前修复分支的 `thread_local s_ctx` 也不再是历史 static 全局竞争。

## 验证 R1/R2

用基线提交的父版本与修复版本进行人工对照：R1 应能追踪到旧缓存的查询与插入/删除冲突，修复后应识别统一锁和拥有快照；R2 应区分进程级 static 与线程隔离的 Context。候选脚本在修复前后均可能命中，这是其设计行为。

补充安全对照：读锁内写局部容器、初始化后不可变配置、同锁保护的所有访问、不可变拥有快照、带对象排他锁的共享锁写入。补充危险对照：只给写路径加锁、锁内返回裸引用、getter 隐藏写全局缓存。检查报告是否提供真正的冲突访问和线程入口，是否将待验证风险误写成已确认。
