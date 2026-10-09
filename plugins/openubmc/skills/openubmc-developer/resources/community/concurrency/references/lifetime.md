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

# 生命周期与借用数据检测依据

## 历史来源

在目标 libmcpp 仓库中用 `git show <完整提交号> -- <文件>` 核对父版本与修复；保持当前 checkout。下表的证据来自补丁，仍需按目标 revision 检查调用契约。

| 提交 | 文件与事实 | 范围 |
| --- | --- | --- |
| `9c33b2e1ad8a22db759de029a45fa4ba1fd8b960` | `libraries/mcengine/src/service.cpp`：公共/私有对象注销前取得 `shared_from_this()`；表释放最后一个引用后，后续清理和 emit 仍需对象存活 | 明确标注对象卸载 coredump |
| `fb678fd61b892e79059984ac80cf98f75efc9906` | `libraries/mcengine/include/mc/engine/property.h`：property 析构中调用 `clear_connection_slots()`，interface observer 访问增加空指针检查 | 属性监听野指针修复 |
| `8112b5340d0b6f542338afed87f1e6c74c62504e` | `libraries/mcexpr/src/property/processors/ref_object_processor.cpp`、`sync_property_processor.cpp`：cleanup 捕获裸 service；调用 `remove_match` 前检查 `engine::is_service_registered` | service 析构后悬空访问修复 |
| `d053df66ba054b371548f087d771fb8bafc8e961` | `libraries/mcapp/src/discovery/service_object_group_source.cpp`：在途计数覆盖异步续延/dispatch，完成后才递减；停止后清除 host 指针 | ASAN 提交中的宿主提前销毁 UAF 修复；同提交还含泄漏及环境调整，分项判断 |
| `638183a50535140ef57f68c541684fa980833be3` | `libraries/mcengine/include/mc/engine/context.h`、`src/context.cpp`：call_info 的 interface/method/sender/path 从 `mc::string_view` 改为 `mc::string` | 悬空字符串修复；同提交另有 stop 锁序死锁，不能混为字符串 coredump |
| `a977b03681353bc4182417821d2ca3e52a0abe6d` | `libraries/mcapp/src/task/task_mgmt.cpp` 及测试：新增 `reset_for_test()`，TearDown 在停止/销毁 service 前清空任务并解除单例的 service 关联；重命名同命名空间重复 fixture | 测试 teardown 与 ODR 对照；不能据此要求生产调用测试 API |
| `0ec38a2126333e23754a9422eb7bfac903a18477` | `tests/test_json_wrapper.cpp`：`JsonValue(wrapper.get_raw())` 改为 `JsonValue(wrapper)`，保留包装器的正确引用计数语义 | 测试专用双重释放对照；借鉴所有权误用模式，不算已确认生产 coredump |

## R3 对象与异步回调生命周期

### 最后引用释放后的继续使用

从容器取 `auto& obj = *it` 后执行 `erase/remove/unregister/reset`，再调用成员、清理 owner/service 或 emit，是重点入口。区分借用引用与拥有者：移除操作或同步回调可能释放最后引用，单线程也会发生 UAF。

```cpp
// 风险：表可能是 obj 的唯一拥有者。
auto& obj = *table.find(key);
table.remove(key);
obj.emit_removed();
```

```cpp
// 对照：必须在潜在释放点之前取得拥有者，覆盖最后一次访问。
auto keep_alive = obj.shared_from_this();
table.remove(key);
obj.emit_removed();
```

`shared_from_this` 的可用性由实际类型和构造/析构阶段决定；从已经失效的裸指针重新构造 `shared_ptr` 不能补救生命期，并可能造成另一套释放协议。检查对象和属性派生析构时调用的成员、virtual 分派及清理顺序。

### 监听、cleanup 和长寿命持有者

枚举 property_changed、match cleanup、timer、单例/注册表中的裸指针及 `[this]`/裸 host 捕获。完成条件是生产者不再提交新访问，在途使用完成，随后才销毁被访问对象。检查 `disconnect` 是否等待在途回调，以及回调是否可能已经复制到队列。

基线 `8112b534` 使用服务注册表检查作为其架构中的保护。**注册表存在检查只在调用协议保证检查到使用之间不会销毁时可排除 UAF**；否则存在检查后销毁的间隙，需要拥有句柄、生命周期锁或 drain 协议。非空指针、`running()` 或把指针置空也不是通用的保活机制，跨线程读写该指针还需同步证据。

长寿命单例持有短寿命 service 时，核对解除关联时机、二次初始化和静态析构顺序。TaskMgmt 基线的实际措施是测试重置；生产修复应匹配服务归属与停止契约。ODR 重复 fixture 作为测试命名问题记录，不扩大为本规则的通用生产检测。

### 整条异步链的完成屏障

典型风险：外层回调计数/RAII guard 在发起 future/dispatch 后退出 → `wait_callbacks` 看到零 → 宿主销毁 → `then/catch_error/post` 再访问宿主。保活了 source 的 `self` 不等于保活了它所借用的 host/executor。

核对计数从接受任务开始，跨越实际排队、续延和嵌套派发，并在所有终态中恰好释放一次：成功、失败、取消、排队失败、异常和 early return。先排队后增加计数可能让任务先完成或停止方先看到零；仅统计当前同步 lambda 无法覆盖未来执行。

```cpp
// 风险示意：guard 结束时 future 仍未完成。
auto guard = begin_callback_guard();
fetch().then([host](result_type result) { host->apply(result); });
```

修复应使任务完成 token 覆盖整条链，或由拥有宿主的任务句柄、取消与 drain 协议提供保证。检查 token 是否真的被整条链持有及成功/异常/取消是否互斥；不要机械地在每个 `then` 和 `catch_error` 中追加递减。停止方与回调并发时还需核对状态转换和禁止新任务的同步。

`shared_ptr` 强捕获可以延命，也可能形成引用环；weak 捕获需在实际消费前 lock 并保持拥有者到消费完成。宿主若不可被共享管理，使用其已有生命周期协议，不凭空引入双重所有权。

### 所有权包装器与测试范围

检查 `JsonValue(get_raw())`、以 `.get()` 包装拥有型对象等线索时，阅读构造器的 adopt/borrow/ref 语义。既有拥有者还活着时，如果第二个包装器错误接管同一裸资源而未增加引用，就可能双重释放；正规的共享控制块复制或匹配的 ref/unref 不应误报。

安全对照包括注销前保活、weak lock 覆盖消费、停止阻止提交且完整 drain、监听结束早于宿主销毁，以及正确共享所有权。测试专用命中在报告中标明测试范围，不能推断已有生产事故。

## R4 非拥有字符串与借用视图

### 核对拥有者到最后消费的区间

优先检查 `std::string_view/mc::string_view`、`.c_str()/.data()/get_raw()` 和非拥有返回值进入 call_info、成员、缓存、future/dispatch 捕获或消息队列的路径。`.data()` 也可来自长期对象或非字符串容器，只是线索。

逐项记录拥有者是临时字符串、局部对象、D-Bus 消息、variant、Lua 栈上的字符串，还是可淘汰的 LRU 元素；追踪销毁、重分配、替换/写入、淘汰、Lua 弹栈后失去 GC root 等失效事件。视图按值复制仍然借用原缓冲区。

```cpp
// 风险：临时字符串在分号处销毁，消费发生在之后。
call_info info;
info.path = make_path_string();  // info.path 是 string_view
queue.post([info] { consume(info.path); });
```

```cpp
// 安全对照：排队之前在拥有型字段中保存数据。
call_info info;
info.path = mc::string(make_path_string());  // info.path 是 mc::string
queue.post([info] { consume(info.path); });
```

获取时加锁而解锁后保留内部视图，按 R1 的引用保护继续查；释放与消费的生命期问题按 R4 表述，同一根因只报告一次。复制持有 view 的外层 struct 或将其包进 shared_ptr 不自动延长源缓冲区生命期。

### 排除与修复边界

字符串字面量、长期不可变所有者，以及在调用返回前同步完成且未逃逸的参数视图可以排除。证明期间无重分配/修改，不能仅凭所有者没有析构。容器节点地址稳定也不保证其字符串内部缓冲区稳定。

修复优先在存储或延迟消费边界取得拥有字符串；也可显式持有真实 buffer owner 至最后使用。`const mc::string&` 仍是借用返回值，字段改为拥有型并不使从中返回的引用永久有效。核对接口兼容、二进制布局和复制成本；不要把所有同步 `string_view` 参数机械替换掉。

### 验证

用创建后释放唯一外部引用再注销的用例覆盖 R3；让异步完成晚于 stop，观测 drain 与宿主析构顺序，避免在途工作只存在于伪造测试中。R4 用源字符串/消息结束后消费、缓存淘汰和重分配场景，核对结果仍正确。可用 ASan 补充 UAF 证据；单线程释放顺序问题无需人为添加并发。
