---
name: openubmc-dt-testing
description: 为 openUBMC 组件设计、编写和执行 UT/IT 测试，包括 LuaUnit、Mock、测试数据、bingo test、集成测试配置与覆盖率分析。Use when the user asks to add or run unit tests, integration tests, coverage checks, assertions, mocks, or test fixtures for an openUBMC component. Do not use for OpenBMC test frameworks or unrelated third-party runners.
---

# OpenUBMC DT 测试

openUBMC DT 测试框架基于 LuaUnit，通过 `bingo test` 命令驱动。UT 验证组件内函数可靠性，IT 验证组件间 D-Bus 接口可靠性。本 Skill 覆盖从用例编写到执行验证的完整流程。

## Step 1: 收集需求

在编写测试之前，向用户收集以下信息：

- **必须**：被测组件名和被测模块
- **必须**：测试类型（UT 还是 IT）
- **按需**：当前 `test/` 目录结构（判断是新增还是补充）
- **按需**：`service.json` 内容（IT 需要确认依赖声明）
- **按需**：失败日志或 `dt_result.json`（如排查问题）

## Step 2: 编写单元测试（UT）

### 2.1 确定测试范围

UT 测试对象是模块通过 `return` 导出的函数。CRITICAL: 禁止把未导出的 `local` 函数当成 UT 主测试对象——通过测试其调用方间接覆盖。

### 2.2 编写测试用例文件

在 `test/unit/test_<module>.lua` 中编写用例。命名规则：文件名以 `test_` 开头，测试 table 以 `Test` 开头，测试函数以 `test_` 开头。

```lua
local calculator = require 'operation'
local lu = require 'luaunit'

test_calculator = {}

function test_calculator:test_multiply()
    local re = calculator:multiply(0, 1)
    lu.assertEquals(re, 0)
end

function test_calculator:test_divide()
    local re = calculator:divide(6, 3)
    lu.assertEquals(re, 2)
    local ok = pcall(calculator.divide, calculator, 1, 0)
    lu.assertFalse(ok)
end

function test_calculator:test_divide_by_zero()
    local ok, err = pcall(calculator.divide, calculator, 1, 0)
    lu.assertFalse(ok)
    lu.assertStrContains(err, "Division by zero")
end
```

### 2.3 配置入口文件

`test/unit/test.lua` 是 UT 入口，`bingo test -ut` 自动执行此文件。大部分代码固定，只需用 `require` 导入测试模块：

```lua
loadfile(os.getenv('CONFIG_FILE'), 't', {package = package, os = os})()

local lu = require('luaunit')
local utils = require 'utils.core'
local logging = require 'mc.logging'

local current_file_dir = debug.getinfo(1).source:match('@?(.*)/')

utils.chdir(current_file_dir)
logging:setPrint(nil)
logging:setLevel(logging.INFO)

require 'test_operation'
-- 新增测试模块在此添加 require

os.exit(lu.LuaUnit.run())
```

### 2.4 Mock 打桩

对依赖 skynet 或外部模块的函数，通过替换函数实现 mock。在 `setUp` 中替换，`tearDown` 中恢复：

```lua
local kmc = require 'mc.kmc'
local KmcEnc = kmc.encrypt_data
local KmcDec = kmc.decrypt_data

function TestMyModule:setUp()
    kmc.encrypt_data = function(domain_id, cipher_alg_id, hmac_alg_id, plaintext)
        return plaintext
    end
    kmc.decrypt_data = function(domain_id, ciphertext)
        return ciphertext
    end
end

function TestMyModule:tearDown()
    kmc.encrypt_data = KmcEnc
    kmc.decrypt_data = KmcDec
end
```

也可以在模块层面整体 mock：

```lua
function TestMyModule:setupClass()
    self.mock_client = MockClient.new()
    self.mock_client.some_method = function(cls, arg)
        return arg
    end
end
```

### 2.5 数据准备与清理

测试不依赖外部环境。初始化和清理必须充分完成：

- 建立临时目录，拷贝外部依赖文件
- 对需要外部输入的配置统一设定参数入口
- 数据清理可在测试开始前先做一次，防止残留数据干扰

### 2.6 运行

```bash
bingo test -ut
```

带过滤器运行特定用例：

```bash
bingo test -ut -f "test_calculator"
```

## Step 3: 编写集成测试（IT）

IT 验证组件通过 D-Bus 对外暴露的接口。UT 无法与 D-Bus 联动，涉及资源树的功能必须在 IT 中测试。

### 3.1 创建配置文件

在 `test/integration/test_<app>.conf` 中定义 skynet 环境和依赖组件：

```lua
include("$CONFIG_FILE")

config:init_integration_test_dirs()

config:set_start("test_<app>")

-- 依赖组件必须在 service.json 中声明 test 依赖
config:include_app('<app>')
config:done()

TEST_DATA_DIR = 'test/integration/.test_temp_data/'
test_apps_root = 'test/integration/apps/'
```

### 3.2 创建测试入口文件

在 `test/integration/test_<app>.lua` 中编写测试逻辑：

```lua
local skynet = require 'skynet'
require 'skynet.manager'
local log = require 'mc.logging'
local utils = require 'mc.utils'
local test_common = require 'test_common.utils'

local function prepare_test_data()
    local test_data_dir = skynet.getenv('TEST_DATA_DIR')
    os.execute('mkdir -p ' .. test_data_dir)
    os.execute('mkdir -p ' .. '/tmp/test_dump')
end

local function clear_test_data(exit_test)
    log:info('clear test data')
    local test_data_dir = skynet.getenv('TEST_DATA_DIR')
    if not exit_test then
        return utils.remove_file(test_data_dir)
    end
    skynet.timeout(0, function()
        skynet.sleep(20)
        skynet.abort()
        utils.remove_file(test_data_dir)
        utils.remove_file('/tmp/test_dump')
    end)
end

local function test_my_app()
    log:info('================ test start ================')
    -- 在此编写集成测试逻辑
    log:info('================ test complete ================')
end

skynet.start(function()
    clear_test_data(false)
    prepare_test_data()
    test_common.dbus_launch()
    skynet.uniqueservice('main')
    skynet.fork(function()
        local ok, err = pcall(test_my_app)
        clear_test_data(true)
        if not ok then
            error(err)
        end
    end)
end)
```

### 3.3 IT 中的 RPC 调用

IT 启动了相关服务，可直接通过 D-Bus 调用，无需 mock：

```lua
local function get_property(bus, prop_name)
    return bus:call('<bus_name>', '<object_path>',
        'org.freedesktop.DBus.Properties', 'Get', 'ss',
        '<interface_name>', prop_name):value()
end

local function set_property(bus, prop_name, value)
    return bus:call('<bus_name>', '<object_path>',
        'org.freedesktop.DBus.Properties', 'Set', 'ssv',
        '<interface_name>', prop_name, gvariant.new_uint32(value))
end
```

### 3.4 检查 service.json 依赖

IT 依赖的组件必须在 `service.json` 中声明。缺少声明会导致 `bingo test -it` 超时或卡住。

### 3.5 运行

```bash
bingo test -it
```

## Step 4: 测试覆盖率

```bash
bingo test -ut -cov
```

覆盖率范围是组件 `src/` 目录下所有 Lua 代码。结果输出：

- `temp/coverage/luacov.report.html`：可视化覆盖率报告
- `temp/coverage/dt_result.json`：结构化结果（含增量覆盖率）

应尽可能提高覆盖率，充分考虑正常流、异常逻辑和边界值。

## Step 5: 设计测试用例

测试用例最低包含以下要素：

| 字段 | 说明 |
|------|------|
| 用例名称 | 简要描述测试点，动宾结构，≤20 字 |
| 用例编号 | `特性_子特性_测试类型_编号`，如 `Fan_Speed_Function_0001` |
| 用例级别 | L0（门槛）/ L1（基本）/ L2（重要）/ L3（生僻） |
| 测试类型 | Function test / Reliability test / Performance test 等 |
| 预置条件 | 环境配置、硬件要求、组网信息 |
| 测试步骤 | 主谓宾结构，命令参数明确，≤7 步 |
| 预期结果 | 可观察、可量化，编号用 A/B/C |

保持一个用例一个主要验证点。步骤和结果必须可执行、可观察、可回归。

## 关键规则

- CRITICAL: 严格按 openUBMC 官方 DT 体系工作，禁止套用 OpenBMC 或 generic Lua 测试套路
- CRITICAL: 官方命令为 `bingo test -ut` 和 `bingo test -it`，禁止写成 `bingo test --unit`、`bingo test --integration`、`bingo test --e2e`
- CRITICAL: 禁止默认引入第三方 runner 替代官方 UT 框架
- CRITICAL: 禁止只给运行命令，不说明测试对象、目录和入口文件
- UT 文件结构：`test/unit/test.lua`（入口）+ `test/unit/test_xxx.lua`（用例）
- IT 文件结构：`test/integration/test_<app>.conf`（配置）+ `test/integration/test_<app>.lua`（入口）
- UT 中对外部依赖使用 mock 打桩，IT 中直接通过 D-Bus 调用
- 禁止把组件测试、方案测试和版本测试混成一类
- 用例耦合度低：单个用例调用方法数量不超过 5-10 个

## Examples

### 示例 1：为 operation.lua 模块编写 UT

被测文件 `src/lualib/operation.lua`：

```lua
local calculator = {}

function calculator:multiply(v1, v2)
    return v1 * v2
end

function calculator:divide(v1, v2)
    if v2 == 0 then
        error("Division by zero")
    end
    return v1 / v2
end

return calculator
```

测试文件 `test/unit/test_operation.lua`：

```lua
local calculator = require 'operation'
local lu = require 'luaunit'

test_calculator = {}

function test_calculator:test_multiply()
    lu.assertEquals(calculator:multiply(2, 3), 6)
    lu.assertEquals(calculator:multiply(0, 100), 0)
    lu.assertEquals(calculator:multiply(-1, 5), -5)
end

function test_calculator:test_divide()
    lu.assertEquals(calculator:divide(6, 3), 2)
    lu.assertEquals(calculator:divide(0, 1), 0)
end

function test_calculator:test_divide_by_zero()
    local ok = pcall(calculator.divide, calculator, 1, 0)
    lu.assertFalse(ok)
end
```

入口文件 `test/unit/test.lua` 中添加：

```lua
require 'test_operation'
```

运行：`bingo test -ut`

### 示例 2：为 new_app 组件编写 IT

配置文件 `test/integration/test_new_app.conf`：

```lua
include("$CONFIG_FILE")
config:init_integration_test_dirs()
config:set_start("test_new_app")
config:include_app('new_app')
config:done()
TEST_DATA_DIR = 'test/integration/.test_temp_data/'
```

入口文件 `test/integration/test_new_app.lua`：

```lua
local skynet = require 'skynet'
require 'skynet.manager'
local log = require 'mc.logging'
local utils = require 'mc.utils'
local test_common = require 'test_common.utils'

local function test_new_app()
    log:info('================ test start ================')
    -- 验证对象创建和属性设置
    log:info('================ test complete ================')
end

skynet.start(function()
    local test_data_dir = skynet.getenv('TEST_DATA_DIR')
    os.execute('mkdir -p ' .. test_data_dir)
    test_common.dbus_launch()
    skynet.uniqueservice('main')
    skynet.fork(function()
        local ok, err = pcall(test_new_app)
        utils.remove_file(test_data_dir)
        skynet.timeout(0, function()
            skynet.sleep(20)
            skynet.abort()
        end)
        if not ok then error(err) end
    end)
end)
```

确认 `service.json` 中声明了 test 依赖后运行：`bingo test -it`

### 示例 3：带 Mock 的 UT

```lua
local my_module = require 'my_module'
local external_api = require 'mc.kmc'
local lu = require 'luaunit'

local orig_encrypt = external_api.encrypt_data

TestMyModule = {}

function TestMyModule:setUp()
    external_api.encrypt_data = function(_, _, _, plaintext)
        return plaintext
    end
end

function TestMyModule:tearDown()
    external_api.encrypt_data = orig_encrypt
end

function TestMyModule:test_process_with_mock()
    local result = my_module:process("test_data")
    lu.assertNotNil(result)
end
```

## Troubleshooting

### bingo test -ut 找不到测试文件

1. 确认 `test/unit/test.lua` 存在
2. 确认 `test/unit/test.lua` 中 `require` 了目标测试模块
3. 确认测试文件命名以 `test_` 开头

### bingo test -it 超时或卡住

1. 检查 `service.json` 中的测试依赖声明
2. 确认 `test_<app>.conf` 中包含 `config:set_start(...)`
3. 确认 `test_<app>.lua` 中调用了 `test_common.dbus_launch()` 和 `skynet.uniqueservice('main')`

### 覆盖率报告为空或显示 0%

1. 确认使用 `bingo test -ut -cov` 运行
2. 检查 `temp/coverage/` 目录是否生成
3. 确认测试用例覆盖了目标模块的导出函数

### 断言失败但看不到详细信息

1. 检查 `dt_result.json` 中的详细错误信息
2. 在断言中添加描述信息：`assertEquals(actual, expected, "描述说明")`

### UT 中调用外部组件接口失败

UT 直接执行 Lua 脚本，无法调用 D-Bus 外部接口。使用 mock 打桩模拟接口调用（参考 Step 2.4），或将该测试移至 IT。

## Related Skills

- **openubmc-developer** — 当测试暴露出源码归属、生成链或跨层实现问题时，交给统一 Developer 工作流处理
- **openubmc-qemu-testing** — 需要仓库 launcher、镜像、串口、端口和 guest readiness 证据时，转入 QEMU 分层验证

## References

- 组件的独立测试: <https://www.openubmc.cn/docs/zh/development/develop_guide/app_development/testing.html>
- DT 用例编写指南: <https://www.openubmc.cn/docs/zh/development/develop_guide/app_development/DT_code_guide.html>
- 测试用例设计指导: <https://www.openubmc.cn/docs/zh/development/test_guide/case_guide.html>
