# Redfish 接口变化语义级方法论

## Goal

基于两个代码状态生成中文 Redfish 接口变化报告。报告面向发布、评审和测试，不展示 JSON 叶子噪声，而是按 `interface_mapping.md` 的映射语义展示请求体、响应体、请求头、响应头和执行引用影响。

## Inputs

支持：

1. 本地 git 仓库 + 两个 refs；
2. 本地或远端 git 仓库路径 + 两个 refs；
3. 两个源码目录；
4. 两个 zip 源码包。

始终明确方向为 `old -> new`。

## Interface Key

接口唯一键为：

```text
(HTTP method, URI)
```

历史接口变化只统计 old/new 同时存在且 `(method, URI)` 完全一致的接口。没有确证依据时，不推断 URI 迁移、路径修改或属性改名。

## Categories

报告和 CSV 可使用以下类别：

- `接口新增`
- `接口删除`
- `HTTP方法变更`
- `属性新增`
- `属性删除`
- `属性类型变更`
- `响应体内容变化`
- `返回数据类型变更`
- `请求体内容变化`
- `请求数据类型变更`
- `POST/PATCH请求体内容变化`
- `请求头内容变化`
- `响应头内容变化`
- `接口行为变化`
- `Schema/Metadata变化`

统一使用“接口变化”。只有历史原因明显的 `HTTP方法变更` 等技术分类可保留“变更”。

## ReqBody Semantics

请求体从 `ReqBody.Properties` 构建语义 surface。每个请求参数以 schema 对象展示，例如：

```text
ReqBody/Password
类型：Object
定义：请求体属性对象；类型 string；必选；敏感信息；校验规则 Length[0, 512]
```

不要输出这些 schema 叶子碎片：

```text
ReqBody/Properties/Password/Type
ReqBody/Properties/Password/Required
ReqBody/Properties/Password/Validator[0]/Formula[0]
```

必须解释：

- `Type`：字符串或多类型数组；
- `Required`：必选或可选；
- `Sensitive`：敏感信息，错误消息中打码为 `******`；
- `Validator`：`Enum`、`Length`、`Nonempty`、`Range`、`Regex`、`IPFormat`、`Script`；
- `Items`：列表验证或元组验证；
- `minItems/maxItems/uniqueItems`；
- `LockdownAllow`；
- `Description`；
- nested `Properties`。

## RspBody Semantics

响应体按最底层可读对象聚合：

- primitive 字段单行展示；
- Action、ActionInfo `Parameters[]`、Links、Oem 嵌套对象、数组元素对象按对象行展示；
- 新增/删除完整接口保留 `@odata.*`、`Id`、`Name`；
- 历史接口普通 diff 可跳过 `@odata.context`、`@odata.id`、`@odata.type`、`Id`、`Name`、`Description` 这些样板字段。

## Headers

`ReqHeader`、文档中写作数据来源的 `ReaHeader`、`RspHeader` 必须纳入接口 surface。

- 请求头变化输出 `请求头内容变化`。
- 响应头变化输出 `响应头内容变化`。
- 没变化时不输出 header 行。

## Statements And ProcessingFlow

`Statements` 与 `ProcessingFlow` 不作为独立表格范围展示。必须把它们的变化回溯到请求体、响应体、请求头、响应头或资源存在性条件上。

必须识别：

- `${Statements/Foo()}`、`${Statements/Foo()[#INDEX]}`；
- `${ProcessingFlow[n]/Destination/X}`；
- `${ReqBody/X}`、`${ReqBodyOriginal/X}`；
- `${ReqHeader/X}`、`${ReaHeader/X}`、`${RspHeader/X}`；
- `${Uri/X}`、`${Query/X}`、`${Context/X}`；
- Plugin/Script Formula 中的 `ReqBody.X`、`ProcessingFlow[n].Destination.X`。

处理规则：

- 对每个新增、删除、修改的 statement 函数单独追溯调用点。
- 如果多个 statement 函数同时变化，必须分别分析，不能只报第一个。
- statement 的 `Input` 和 `Steps[].Formula` 中的嵌套引用也要加入调用图。
- ProcessingFlow 的 `Destination` 产物被响应体/header/statement 引用时，在对应字段的 `关联调用变化` 中说明。
- ProcessingFlow 的 `Source`、`Params`、`ContextParams`、`CallIf`、`Foreach`、`Path` 使用请求体或 header 字段时，在对应请求字段或 header 行说明。
- 无法回溯到字段时，输出一条 `接口执行逻辑`，不要展开 raw Statements/ProcessingFlow JSON。

## Output Contract

`redfish_interface_change_list.csv` 保留接口级列：

```text
change_type,categories,method,uri,source_file,summary,detail,mr_links,authors,issue_links
```

`redfish_interface_change_details.csv` 包含：

```text
category,method,uri,path,old_type,new_type,old_value,new_value,note,reference_note,source_file
```

Markdown 报告的完整明细表必须包含 `关联调用变化` 列。

Markdown 中必须把 `$` 转义为 `&#36;`；CSV 保留原始 `$`，便于追溯。

## Acceptance Checks

以 `f2859d7e -> 3136bb47` 的 `!1218` 为回归样例：

- Password 以 `ReqBody/Password` 对象行展示；
- 不存在 `ReqBody/Properties/Password/Type` 或 `Validator[0]/Formula[0]`；
- 不存在独立 `语句` 或 `处理流程` 范围；
- `RspBody/MessageId` 关联新增 `Statements/GetMessageId()`；
- `ReqBody/Password` 关联新增 ProcessingFlow 方法 `VerifyPassword`；
- header 变化能展示，未变化不展示。
