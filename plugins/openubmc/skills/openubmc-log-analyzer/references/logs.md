# openUBMC 日志参考

Last updated: 2026-04-07
Source:
- NotebookLM: openUBMC 架构设计与特性参考指南
- Local bundle inventory: openUBMC_20260204-0112.tar
- Log bundle replay with a sanitized fixture

## 目录含义

- `LogDump`
  - BMC 运行期主日志。
  - 大多数功能异常、登录失败、组件报错，先从这里入手。
- `AppDump`
  - 各组件私有日志和 MDB 资源树快照。
  - 适合查“对象没上树”“属性不同步”“某个组件内部逻辑异常”。
- `RTOSDump`
  - OS、systemd、kernel、网络和系统信息。
  - 适合查服务拉起失败、驱动/内核异常、磁盘满、系统资源问题。
- `OSDump`
  - 串口或控制台录屏类日志。
  - 适合查主机 OS 或启动阶段异常。
- `SpLogDump`
  - 平台特定或版本类日志。
  - 含义可能因平台而异。
- `BMALogDump`
  - 带内代理/主机侧相关日志。
  - 适合主机侧数据不上来、带内通信异常。
- `DeviceDump`
  - 设备级低层日志或寄存器快照。
  - 适合硬件厂商定界或二进制故障分析。

## 常用日志

### LogDump

- `app.log`
  - 作用：业务组件运行日志。
  - 常见内容：业务流程、接口调用、Lua/C++ 代码级报错、异常栈。
  - 适合：功能异常、某个组件接口报错、具体逻辑失败。
- `framework.log`
  - 作用：框架层日志，重点看 `maca`、`hwdiscovery`、`hwproxy`。
  - 常见内容：服务拉起、健康检查、对象上树、进程重启、框架级拦截。
  - 适合：启动失败、进程反复重启、对象上树失败、框架未拉起组件。
- `operation.log`
  - 作用：操作审计与防抵赖轨迹。
  - 常见内容：登录/登出、配置变更、命令下发、谁在何时做了什么操作。
  - 适合：追操作来源、登录失败审计、定位“是谁改了配置导致后续异常”。
- `security.log`
  - 作用：安全与认证事件。
  - 常见内容：登录成功/失败、账号锁定/解锁、密码校验失败、证书/签名校验失败。
  - 适合：Web/SSH/BMC 登录失败、权限异常、账号策略问题。
- `maintenance.log`
  - 作用：维护类事件和故障码。
  - 适合：维护历史、故障码关联。
- `running.log`
  - 作用：运行期状态与关键进程事件。
  - 适合：系统稳定性、长期异常、资源波动时的辅助判断。
- `sensor.log`
  - 作用：传感器与 SEL 相关事件。
  - 适合：传感器读值失败、SEL 排查、健康告警。
- `alarm.log`
  - 作用：告警 assert/deassert 生命周期。
  - 适合：告警生成、清除、对象和阈值是否匹配。
- `cooling_control.log`
  - 作用：风扇控制策略与目标占空比计算。
  - 适合：风扇异常、控温策略异常。
- `Thermal.log`
  - 作用：温控调试日志。
  - 适合：温控策略、过温保护、温度采样异常。
- `bmc_health.log`
  - 作用：CPU/内存等资源使用统计。
  - 适合：高 CPU、高内存、性能波动。
- `ps_black_box.log`
  - 作用：PSU 黑匣子快照。
  - 适合：电源异常、PSU 故障定界。
- `net_stream.log`
  - 作用：网络侧交互摘要。
  - 适合：网络协议、链路、NCSI 类问题辅助判断。
- `hw_stream.log`
  - 作用：I2C/PCIe 等底层总线交互摘要。
  - 适合：总线超时、底层数据交互异常。
- `mc_stream.log`
  - 作用：组件间 RPC 交互摘要。
  - 适合：跨组件调用链排查。

### AppDump 常见文件

路径通常位于 `dump_info/AppDump/<component>/`。

- `mdb_info.log`
  - 作用：一键拉包瞬间的 MDB 资源树快照。
  - 适合：确认对象是否真的存在、接口是否挂上、属性当前值是什么。
- `sync_property_trace.log`
  - 作用：同步属性轨迹。
  - 常见内容：`fetch`、`sig_properties_changed` 等同步来源和触发路径。
  - 适合：属性不更新、同步关系异常、信号是否到达。
- `rpc_records.log`
  - 作用：RPC 调用统计。
  - 适合：高频调用、调用风暴、组件阻塞或超时的旁证。
- `raid_controller_lib.log`
  - 作用：RAID 库和控制器交互。
  - 适合：阵列卡识别、配置和底层硬件交互问题。

### RTOSDump 重点文件

- `sysinfo/journalctl.log*`
  - 作用：systemd/journal 总日志，轮转文件也常有关键证据。
  - 适合：服务拉起失败、底层崩溃、驱动/内核报错、框架没来得及打印前的异常。
- `other_info/login`
  - 作用：本地控制台/串口登录相关记录。
  - 适合：串口或本地 TTY 登录失败、登录策略或记录辅助判断。
- `other_info/sshd`
  - 作用：OpenSSH 守护进程侧配置或状态。
  - 适合：SSH 协议、加密套件、PAM 或底层服务导致的 SSH 登录失败。
- `networkinfo/netstat_info`
  - 作用：监听端口和连接状态。
  - 适合：确认 `ssh`、`https`、`ipmi` 是否监听，异常连接数是否过高。
- `networkinfo/route_info`
  - 作用：路由表。
  - 适合：跨网段访问失败、默认路由异常。
- `networkinfo/ifconfig_info`
  - 作用：网卡配置与收发统计。
  - 适合：链路 up/down、丢包、RX/TX 异常。
- `sysinfo/df_info`
  - 作用：磁盘使用率。
  - 适合：`/var/log`、`/data` 满导致组件异常。
- `driver_info/dmesg_info`
  - 作用：内核 ring buffer。
  - 适合：驱动、硬件、文件系统底层异常。

## 常见问题到日志

### 1. BMC 登录失败

推荐顺序：

1. `security.log`
2. `operation.log`
3. `RTOSDump/other_info/sshd`
4. `RTOSDump/other_info/login`

直接失败证据：

- `security.log` 中明确的 `login failed`、账号锁定、密码校验失败。
- `operation.log` 中带用户名、来源 IP、接口类型的登录失败审计记录。
- `sshd` 中 PAM、认证模式、协议或加密套件错误。

辅助证据：

- `operation.log` 里是否有人修改过密码、权限、接口开关。
- `security.log` 中连续失败次数，能解释为什么触发锁定。
- `other_info/login` 主要用于串口/本地控制台登录失败，不是 Web/SSH 首选。

区分：

- `security.log` 更偏“安全事件与直接拦截原因”。
- `operation.log` 更偏“谁在什么时候做了什么”，是审计和时间线证据。
- `sshd`/`login` 更偏 OS 底层服务，不是 BMC 业务层日志。

### 2. 对象不同步 / 对象缺失 / 上树异常

推荐顺序：

1. `framework.log`
2. `mdb_info.log`
3. `sync_property_trace.log`
4. `app.log`
5. `rpc_records.log`

直接失败证据：

- `framework.log` 里 `hwdiscovery` / `hwproxy` / `maca` 打出对象解析失败、上树失败、忽略对象、类型错误。
- `mdb_info.log` 里直接搜不到目标对象路径或接口。
- `sync_property_trace.log` 里没有对应 `fetch` 或 `sig_properties_changed` 轨迹。

辅助证据：

- `app.log` 里组件自己打印的取值失败、转换失败、脚本异常。
- `rpc_records.log` 里异常高频调用，说明组件可能在重试或卡死。

### 3. 启动失败 / 进程重启 / 组件 crash

推荐顺序：

1. `framework.log`
2. `app.log`
3. `journalctl.log*`
4. `rpc_records.log`
5. `operation.log`

直接失败证据：

- `framework.log` 里的 `StartupCheck failed`、频繁退出、反复拉起。
- `app.log` 里的 `FATAL SIGNAL CAUGHT`、崩溃报告、脚本级 stacktrace。
- `journalctl.log*` 里的 systemd 启动失败、底层进程退出、kill、服务不存在。

辅助证据：

- `rpc_records.log` 的高频调用或调用堆积。
- `operation.log` 可判断崩溃前是否有用户执行升级、重置或大规模配置。
- 如果 bundle 中存在 CoreDump，属于更硬的崩溃证据。

### 4. 性能 / 高 CPU / 高内存

推荐顺序：

1. `bmc_health.log`
2. `running.log`
3. `journalctl.log*`
4. `RTOSDump/sysinfo/top_info`
5. `RTOSDump/sysinfo/free_info`
6. `RTOSDump/sysinfo/vmstat`

### 5. 网络异常 / SSH 连不上 / HTTPS 不通

推荐顺序：

1. `other_info/sshd`
2. `journalctl.log*`
3. `networkinfo/netstat_info`
4. `networkinfo/ifconfig_info`
5. `networkinfo/route_info`
6. `net_stream.log`

## 组件目录提示

- `AppDump/account` / `AppDump/iam`
  - 登录、权限、账户相关。
- `AppDump/hwdiscovery`
  - 对象发现、上树、CSR/SR 装载。
- `AppDump/hwproxy`
  - 底层硬件访问、I2C/SMBus/GPIO。
- `AppDump/maca`
  - 组件拉起、健康检查、进程重启。
- `AppDump/network_adapter`
  - 网卡、光模块、NCSI。
- `AppDump/storage`
  - RAID、硬盘、卷管理。
- `AppDump/thermal_mgmt`
  - 温控、风扇策略。
- `AppDump/bmc_upgrade`
  - 升级流程、校验、应用阶段。

## 使用建议

- 大多数文本日志都可能带轮转文件，实际分析时不要只看主文件。
- 登录类问题优先看 `security.log` 和 `operation.log`，不要先跳到底层 `sshd`。
- 对象类问题优先看 `framework.log` + `AppDump/*`，不要只看 `app.log`。
- 启动类问题如果框架日志没打出来，立刻看 `journalctl.log*`。
- 遇到 bundle 中新增且含义不明确的文件，先查 NotebookLM，再补回 `logs.md` 和 `logs.json`。
