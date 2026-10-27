# openUBMC 日志参考

Last updated: 2026-09-02

本参考维护一键日志包中的已知目录、文件用途和问题路由。它是分析启发式，不是产品协议；具体平台未提供的文件不能据此推断为异常。

字段词表、语义等级、来源要求和安全不变量见 [catalog-schema.md](catalog-schema.md)。本文件说明常见工件和维护判断，不复制完整的可执行目录。

只有当 `source_reference` 使用小写 `https://`、公共 DNS 主机和规范端口，不含 userinfo 或查询字符串，可独立访问且能定位到具体文档或源文件，并同时提供非空 `source_revision` 时，才将文件用途标记为已有公开依据；URL 可带简单的章节或行号锚点。当前目录已为一组可公开核验的社区定义记录精确来源，其余条目仍保持仓库启发式或仅观察路径。单独的文件名、讨论导出名、仓库首页或某个日志包中观察到的路径，都不足以建立跨产品语义。

## 目录

- [目录含义](#目录含义)
- [公开社区来源](#公开社区来源)
- [常用日志](#常用日志)
  - [LogDump](#logdump)
  - [AppDump 常见文件](#appdump-常见文件)
  - [Event 组件候选文件](#event-组件候选文件)
  - [Thermal 管理候选文件](#thermal-管理候选文件)
  - [Network Adapter 候选文件](#network-adapter-候选文件)
  - [RTOSDump 重点文件](#rtosdump-重点文件)
  - [3rdDump 中的 Web 文本日志](#3rddump-中的-web-文本日志)
- [目录覆盖审计](#目录覆盖审计)
- [常见问题到日志](#常见问题到日志)
  - [BMC 登录失败](#1-bmc-登录失败)
  - [对象不同步、对象缺失或上树异常](#2-对象不同步--对象缺失--上树异常)
  - [启动失败、进程重启或组件 crash](#3-启动失败--进程重启--组件-crash)
  - [性能、高 CPU 或高内存](#4-性能--高-cpu--高内存)
  - [网络异常、SSH 连不上或 HTTPS 不通](#5-网络异常--ssh-连不上--https-不通)
  - [综合故障概览](#6-综合故障概览)
- [组件目录提示](#组件目录提示)
- [使用建议](#使用建议)

分析结果会同时给出定义状态和可靠等级：

- `maintained_heuristic` / `repository_maintained` / `heuristic`：仓库维护的通用分析启发式，不声称有可独立核验的公开条目支持；
- `bundle_local_routing` / `bundle_local` / `local_only`：只使用当前包内的组件目录名称限定扫描范围；
- `observed_path` / `validated_bundle_structure` / `observed_only`：只确认该路径或文件族出现在已校验日志包中，不确认字段语义；
- `documented`、`community_supported`：仅在有精确、稳定且可公开核验的来源时使用。

这些等级描述文件定义依据，不替代对具体证据行的新鲜度、完整性和一致性判断。

## 公开社区来源

| 范围 | 来源 | 可支持的定义边界 |
| --- | --- | --- |
| `app.log`、`framework.log`、`bmc_health.log`、`linux_kernel_log`、`operation.log`、`security.log`、`cooling_control.log`、`mdb_info.log`、`sel.txt` | [openUBMC 一键收集介绍](https://discuss.openubmc.cn/t/topic/290) | 支持文件用途和主要内容类别，不构成字段级协议。 |
| 一键日志目录结构、`SpLogDump`、`RTOSDump`、`OSDump`、`LogDump`、`DeviceDump`、`AppDump`、`3rdDump` | [openUBMC 全量日志解读](https://discuss.openubmc.cn/t/topic/3374) | 支持目录级用途；该帖未给出 `OptBMC`、`BMALogDump` 的定义。 |
| `AppDump/network_adapter/net_card_info`、同组件 `mdb_info.log` | [网卡、网口和光模块信息路径答复](https://discuss.openubmc.cn/t/topic/2597/6) | 开启 BMA 时前者可含光模块信息；未开启时从资源树快照查询带外对象。 |
| `AppDump/network_adapter/netcard/netcard_info.txt*`、`LogDump/netcard/netcard_info.txt*` | [网卡问题讨论中的补充路径](https://discuss.openubmc.cn/t/topic/2597/2) | 支持将该文件族作为网卡、网口或光模块问题的辅助快照，不构成字段级协议。 |
| `sync_property_trace.log` | [同步属性轨迹字段答复](https://discuss.openubmc.cn/t/topic/2870/2) | `fetch`、`sig_properties_changed`、`sig_interfaces_added` 表示不同同步来源。 |
| 一键收集文件说明 | [openUBMC 在线帮助](https://gitcode.com/openUBMC/web_online_help/blob/760dc2b615aa3b4679f367ce19081f9dff9a82a6/src/openUBMC/openUBMC_cn/bmc_help_0055.html) | 支持 BIOS、网络、计算、硬件、传感器、OSDump 等文件或文件族的用途；不自动授予正文扫描权限。 |
| BIOS、devmon、sensor、general_hardware、network_adapter、power_mgmt、chassis、mctpd、rootfs_user | `logs.json` 中固定到具体文件与提交的公开源码链接 | 支持源码直接生成的文件用途或结构；数据库、配置和二进制工件仍保持元数据处理。 |

社区讨论提供可核验的用途依据，因此可靠等级仍为 `heuristic`；分析器不会据此把字段值、状态码或缺失文件解释为稳定产品协议。

`references/logs.json` 是唯一可执行的目录来源。文件定义未重复填写来源字段时，加载器使用顶层
`definition_metadata.default`，并输出中性的 `repository-maintained heuristic`；这不代表某个产品协议。
`keywords` 只负责问题到文件的路由；当这些词也常见于正常初始化或注册日志时，可用更窄的
`evidence_keywords` 定义内容证据词，避免把普通生命周期记录提升为问题证据。
目录路径只能是包内 POSIX 相对路径，禁止反斜杠、空组件、`.`、`..`、NUL 和递归 `**` 通配符。
日志包自身的文件名若含反斜杠或 ASCII 控制字符也会在结构校验阶段拒绝，避免输出不可移植的相对路径。
规则关键词及其 `include`/`primary` 引用会在分析前严格校验；无效目录会 fail closed，不会回退到内置目录。

## 目录含义

- `LogDump`
  - BMC 运行期主日志。
  - 大多数功能异常、登录失败、组件报错，先从这里入手。
- `AppDump`
  - 各组件日志和 MDB 资源树快照。
  - 适合查“对象没上树”“属性不同步”“某个组件自身逻辑异常”。
- `RTOSDump`
  - OS、systemd、kernel、网络和系统信息。
  - 适合查服务拉起失败、驱动/内核异常、磁盘满、系统资源问题。
- `OSDump`
  - 系统快照以及最近一次 OS/BIOS 启动、串口或控制台日志。
  - 适合查主机 OS、BIOS 枚举或启动阶段异常。
- `SpLogDump`
  - 版本类元数据。
  - 具体文件和字段仍可能因平台而异。
- `BMALogDump`
  - 已观察到该目录名称，但公开资料未给出可靠的跨产品定义。
  - 默认只记录路径、数量和大小，不读取或解释内容。
- `DeviceDump`
  - 设备级低层日志或寄存器快照。
  - 适合硬件厂商定界或二进制故障分析。
- `3rdDump`
  - 第三方服务工件；已观察到的包可能包含 Nginx 文本日志和配置，但目录内容随产品变化。
  - Web/HTTPS 问题可优先读取 `access_log*` 与 `error_log*`，不要默认读取或展示配置正文。
- `CoreDump`
  - 崩溃工件或 core 归档。
  - 默认只记录存在性、路径和大小，不递归解开归档；是否深入分析需结合问题和用户授权。
- `OptBMC`
  - 产品特定的配置或状态工件，可能含 `pram/`、恢复数据或备份归档。
  - 当前没有可靠的跨产品语义约定，应按不透明且潜在敏感的证据处理。

### 文件覆盖与未知语义

每个物理文件都必须有安全处置契约，但不要求每个文件都有字段级业务语义。目录覆盖的兼容分类仍按三类统计：

- `semantic`：存在文件级用途定义，可以按问题路由并在安全边界内扫描正文；
- `explicit_opaque`：已确认数据库、归档、二进制或编码不稳定的文件族，只记录路径、数量和大小；
- `generic_fallback`：只有目录层级兜底，没有文件级用途定义。

这保证结构审计不会把真实文件误报成“没有定义”，同时不把处理覆盖率误当成语义确认。`semantic_level` 独立表示只知道路径、已知用途、已知结构或具备诊断解释；`artifact_format`、`route_mode` 和 `sensitivity` 分别控制格式、安全路由和敏感边界。用户明确给出日志包中实际存在的文件名或相对路径时，分析器先绑定该物理文件，再继承最具体的文件定义或目录兜底定义。此时不会继续追加同目录的组件伴随日志。若多个目录存在同名文件，输出名称使用相对路径消歧。`CoreDump`、`OptBMC`、二进制、图片和嵌套归档仍按不透明边界处理。

工件定义使用 `scan_mode: metadata_only`。即使用户按名称询问这类工件，分析器也只确认匹配路径和数量，不读取正文；有稳定文本契约的日志继续使用默认的 `scan_mode: text`。

`dump_info/dump_log` 和 `dump_info/dump_app_log` 分别是收集结果清单和组件日志清单。分析器可以有界读取这两个文本索引，但不会据清单中的名称为其他未知工件创造语义。

对于 `AppDump` 中尚未维护语义的组件目录，分析器可以把目录名作为包内路由提示：当问题明确提到该组件名或其下划线/连字符变体时，只选择该目录中语义已维护的 `mdb_info.log`、`sync_property_trace.log`、`rpc_records.log`。目录名本身不会赋予其他未知文件含义。组件提示发现最多检查 4,096 个目录条目并保留 64 个匹配提示；含通配符、反斜杠、控制字符、首尾空白或过长名称的目录会被跳过并记录诊断。

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
  - 作用：BMC CPU 使用率历史，常见字段包括 `user`、`sys`、`idle` 和 `uptime`。
  - 适合：高 CPU 和 CPU 波动；不能单独作为内存使用证据。
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
- `pciecard/*/error_log_*.bin`、`pciecard/*/operate_log_*.bin`
  - 已观察到设备特定的二进制或带填充内容，但没有稳定解码契约。
  - 默认只记录路径和大小，不按普通文本日志扫描。
- `storage/phy/*/*_PHY_Error_Count*.csv`
  - 作为 SAS PHY 错误计数快照使用；带设备前缀和数字轮转后缀的文件属于同一文件族。
  - 字段含义仍按仓库启发式处理，不提升为公开字段协议。

### AppDump 常见文件

路径通常位于 `dump_info/AppDump/<component>/`。

- `mdb_info.log`
  - 作用：一键拉包瞬间的 MDB 资源树快照。
  - 适合：确认对象是否真的存在、接口是否挂上、属性当前值是什么。
- `sync_property_trace.log`
  - 作用：同步属性轨迹。
  - 常见内容：同步源服务、资源树路径、接口、属性、历史值，以及 `fetch`、`sig_properties_changed`、`sig_interfaces_added` 等同步来源。
  - 适合：属性不更新、同步关系异常、信号是否到达。
- `rpc_records.log`
  - 作用：RPC 调用统计。
  - 适合：高频调用、调用风暴、组件阻塞或超时的旁证。
- `skynet_info.json`
  - 在部分已验证日志包的组件目录中观察到，但当前公开资料没有提供可靠的字段和用途定义。
  - 普通问题不会自动选择或解释；用户明确点名该物理文件时只按 `metadata_only` 确认路径和大小。只有源码、精确公开 URL 或用户提供的可信说明确认含义后，才更新其语义定义。
- `raid_controller_lib.log`
  - 作用：RAID 库和控制器交互。
  - 适合：阵列卡识别、配置和底层硬件交互问题。

### Event 组件候选文件

路径通常位于 `dump_info/AppDump/event/`。下列用途为仓库维护的分析启发式，仅在文件实际存在时用于选择证据；缺失不代表产品异常。

- `current_event.txt`：当前告警。
- `sel.txt`、`eo_sel.csv`：历史事件。
- `mask_event.txt`：已屏蔽事件。
- `event.db`、`event_reset.db`：持久化数据库；默认不作为通用文本日志扫描。

这两个数据库具有显式不透明定义。分析器可以确认其存在性和大小，但在没有公开 schema 和明确需求时不读取表、记录或字段。

用户明确询问 `event.db` 时只选择实际存在的 `event.db`，不会因为 `event` 目录名再附加 `mdb_info.log`、`rpc_records.log` 或 `sync_property_trace.log`。

排查“告警未产生”时，同时区分：当前告警是否存在、历史事件是否出现、事件是否被屏蔽。不能只因 `alarm.log` 没有匹配行就判定事件机制正常。

### Thermal 管理候选文件

路径通常位于 `dump_info/AppDump/thermal_mgmt/`。下列用途为仓库维护的分析启发式，不视为产品协议。

- `fan_info.txt`、`thermal_info.txt`
  - 可查看风扇槽位号、名称、型号、转速、速率比和部件编码等信息。
  - 适合验证风扇识别、型号、实际转速和硬件信息，再与 `cooling_control.log`、`Thermal.log` 的调速决策对照。

### Network Adapter 候选文件

- `dump_info/AppDump/network_adapter/net_card_info`
  - 查看网卡和网口快照；开启 BMA 收集时可包含光模块信息。已验证样本还观察到在位、厂商、序列号、MAC 和链路状态等字段。
  - 适合“网卡/网口未显示”“链路状态异常”“光模块信息缺失”等问题。
  - 未开启 BMA 时，带外光模块对象应从同组件 `mdb_info.log` 的网卡、网口、光模块层级查询；该用途仍不是稳定字段协议。
- `dump_info/AppDump/network_adapter/netcard/netcard_info.txt*`、`dump_info/LogDump/netcard/netcard_info.txt*`
  - 作为网卡、网口或光模块排查的辅助快照。
  - 社区资料只支持该用途边界，不能据此假定跨产品字段格式一致。

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
- `versioninfo/server_config.txt`
  - 已观察到服务器型号和配置快照，但样本可能含字段内 NUL 或产品特定编码。
  - 默认只报告元数据；在没有受限解析器前不全局删除 NUL，也不按普通文本扫描。

### 3rdDump 中的 Web 文本日志

- `access_log*`
  - 作用：在产品确实由 Nginx 生成该文件时，记录 HTTP/HTTPS 请求、状态码和访问时间线。
  - 适合：请求是否到达、返回状态码、失败是否集中在特定 URI。
- `error_log*`
  - 作用：在产品确实由 Nginx 生成该文件时，记录 TLS、upstream、gateway 和请求处理错误。
  - 适合：HTTPS 不通、反向代理失败、TLS 握手或后端服务异常。

这两个文件用途属于仓库维护的分析启发式；仅在路径实际存在时读取，不据此断言所有产品都采用相同目录或日志语义。

## 目录覆盖审计

需要回答“所有文件是否都有解释”或维护 `logs.json` 时，运行：

```bash
python3 scripts/audit_catalog_coverage.py \
  --bundle /path/to/openubmc-log-bundle.tar.gz \
  --json
```

也可使用 `--bundle-dir` 审计已解压目录。结果分别给出：

- `coverage_counts.semantic`：有文件级语义定义的物理文件数；
- `coverage_counts.explicit_opaque`：有明确不透明处置定义的文件数；
- `coverage_counts.generic_fallback`：仍只有目录级兜底的文件数；
- `uncovered_path_count`：没有任何处理定义的路径；
- `ambiguous_path_count`：同时命中多个同优先级定义、需要消歧的路径；
- `generic_fallback_by_section`：通用兜底集中在哪些目录。
- `conflicting_coverage_class_count`：同一路径同时命中互斥的语义扫描和不透明处置定义的数量。
- `semantic_level_counts`：按 `path_only`、`purpose`、`structure`、`diagnostic` 统计知识深度；
- `artifact_format_counts`、`route_mode_counts`、`sensitivity_counts`、`scan_mode_counts`：分别统计格式、路由、安全等级和检查方式；
- `purpose_definition_coverage_percent`、`structure_definition_coverage_percent`、`diagnostic_definition_coverage_percent`：分层语义覆盖率。

多个文件级定义与一个目录兜底同时命中是预期行为；同一优先级存在多个定义记入 `ambiguous_path_count`，语义扫描与不透明处置同时命中则独立记入 `conflicting_coverage_class_count`。两类冲突都必须消除。覆盖审计不得用 `657/657` 一类处理覆盖数字替代语义覆盖说明。

`SMARTAttribute` 基础文件按已维护的文本定义扫描；`SMARTAttribute.<数字>` 轮转工件使用单独的不透明定义，只记录元数据。两个定义均关闭自动轮转扩展，避免同一物理文件同时获得互斥处置契约。

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

缺失或待验证证据：

- 只有在目标名称明确、相关 `mdb_info.log` 路径发现和扫描均完整、且快照与故障时点适用时，未观察到目标对象路径或接口才支持“快照中缺失”的判断；否则它只是证据缺口。
- `sync_property_trace.log` 中未观察到对应 `fetch` 或 `sig_properties_changed` 不能单独证明同步没有发生，必须结合扫描完整性、时间窗及其他组件证据。

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
- CoreDump 的存在仅说明包内有崩溃相关工件候选；应先核对时间、对象和来源，且其存在本身不能证明与当前故障存在因果关系。

### 4. 性能 / 高 CPU / 高内存

高 CPU 推荐顺序：

1. `bmc_health.log`
2. `LogDump/cpumem_usage_info_dump.csv`
3. `RTOSDump/sysinfo/top_info`
4. `running.log`
5. `journalctl.log*`

高内存或内存泄漏推荐顺序：

1. `LogDump/cpumem_usage_info_dump.csv`
2. `LogDump/mem_info_*.csv`
3. `RTOSDump/sysinfo/top_info`
4. `RTOSDump/sysinfo/free_info`
5. `RTOSDump/sysinfo/vmstat`
6. `journalctl.log*`

`bmc_health.log` 当前确认的是 CPU 使用率历史，不应作为高内存的主证据。

### 5. 网络异常 / SSH 连不上 / HTTPS 不通

推荐顺序：

1. Web/HTTPS：`3rdDump/error_log*`、`3rdDump/access_log*`
2. SSH：`other_info/sshd`
3. `journalctl.log*`
4. `networkinfo/netstat_info`
5. `networkinfo/ifconfig_info`
6. `networkinfo/route_info`
7. `net_stream.log`

网卡、网口或光模块问题优先增加：

1. `AppDump/network_adapter/net_card_info`
2. `LogDump/netcard/netcard_info.txt*`
3. `AppDump/network_adapter/mdb_info.log`

### 6. 综合故障概览

“主要故障”“主要异常”“故障概览”“整体分析”或“综合诊断”这类宽问题使用固定的八类候选，不扩展为全包扫描：

1. `AppDump/event/current_event.txt`
2. `AppDump/event/sel.txt`
3. `LogDump/app.log`
4. `LogDump/framework.log`
5. `RTOSDump/sysinfo/journalctl.log*`
6. `LogDump/maintenance.log`
7. `LogDump/running.log`
8. `LogDump/alarm.log`

当前告警和历史事件是首选入口；运行日志用于补充故障表现、服务状态和生命周期上下文。文件缺失、没有匹配行或扫描不完整都应作为证据边界报告，不能据此认定系统无故障。

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
- `AppDump/pcie_device/cable_info`
  - 可提取端口、配置槽位、状态码和记录位置。
  - 状态码在缺少公开产品定义时保持不透明，不据此直接判断缺卡、错插或正常；设备 UID 不进入结构化摘要。
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
- 不默认递归展开 `CoreDump`、`OptBMC` 备份、配置归档或其他嵌套压缩包；先把它们作为路径与大小可见的不透明工件。
- Nginx 配置、备份和 core 可能包含敏感内容，不纳入通用文本扫描路径。
- 遇到含义不明确的新文件，将其记录为证据缺口。只有从精确公开 URL、源码或用户提供的可信说明确认含义后，才更新 `logs.md` 和 `logs.json`。
- `operation.log` 可作为失败操作的时间锚点；附近组件日志和共享模块名只用于缩小排查范围，不直接证明因果关系。
