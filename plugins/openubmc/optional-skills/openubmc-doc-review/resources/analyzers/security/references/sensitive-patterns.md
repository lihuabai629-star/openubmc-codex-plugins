# 敏感信息模式库

完整的正则表达式模式与检测规则，供 `doc-security-sensitive-tester` 技能参考使用。

***

## 一、个人身份信息（PII）模式

### 1.1 中国大陆身份证号

| 名称 | 正则表达式 | 说明 |
|------|-----------|------|
| 18位身份证号 | `[1-9]\d{5}(19\|20)\d{2}(0[1-9]\|1[0-2])(0[1-9]\|[12]\d\|3[01])\d{3}[\dXx]` | 含校验位，X可为大小写 |
| 15位身份证号（旧） | `[1-9]\d{5}\d{2}(0[1-9]\|1[0-2])(0[1-9]\|[12]\d\|3[01])\d{3}` | 2000年前签发 |

### 1.2 手机号码

| 名称 | 正则表达式 | 说明 |
|------|-----------|------|
| 中国大陆手机号 | `1[3-9]\d{9}` | 11位，1开头 |
| 国际手机号 | `\+\d{1,3}\s?\d{4,14}` | 含国际区号 |

### 1.3 电子邮箱

| 名称 | 正则表达式 | 说明 |
|------|-----------|------|
| 通用邮箱 | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` | 基本格式匹配 |

### 1.4 银行卡号

| 名称 | 正则表达式 | 说明 |
|------|-----------|------|
| 通用银行卡号 | `\b\d{13,19}\b` | 须结合上下文（变量名含card/bank/account等）判断 |
| 银联卡号 | `\b62\d{14,17}\b` | 以62开头 |

### 1.5 护照号码

| 名称 | 正则表达式 | 说明 |
|------|-----------|------|
| 中国护照号 | `[EGD]\d{8}` | E/G/D开头+8位数字 |
| 外国护照号 | `[A-Z]{1,2}\d{6,9}` | 须结合上下文判断 |

### 1.6 其他个人数据

| 名称 | 正则表达式 | 说明 |
|------|-----------|------|
| 中国车牌号 | `[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁][A-Z][A-HJ-NP-Z0-9]{4,5}[A-HJ-NP-Z0-9挂学警港澳]` | |
| 社保号码 | `\d{6}(19\|20)\d{2}(0[1-9]\|1[0-2])\d{4}` | 地区码+年月+序号 |
| 邮政编码 | `[1-9]\d{5}(?!\d)` | 6位数字 |

***

## 二、密钥与凭证模式

### 2.1 云服务密钥

| 平台 | 密钥类型 | 正则表达式 | 说明 |
|------|---------|-----------|------|
| AWS | Access Key ID | `AKIA[0-9A-Z]{16}` | 20位，AKIA开头 |
| AWS | Secret Access Key | `[A-Za-z0-9/+=]{40}` | 40位Base64，须结合上下文 |
| 阿里云 | AccessKey ID | `LTAI[A-Za-z0-9]{12,20}` | LTAI开头 |
| 阿里云 | AccessKey Secret | `[A-Za-z0-9]{30}` | 30位，须结合上下文 |
| 华为云 | AK | `[A-Z0-9]{20}` | 须结合上下文 |
| 腾讯云 | SecretId | `AKID[A-Za-z0-9]{32}` | AKID开头 |

### 2.2 开发平台Token

| 平台 | Token类型 | 正则表达式 | 说明 |
|------|----------|-----------|------|
| GitHub | Personal Access Token | `gh[pous]_[A-Za-z0-9]{36}` | ghp_/gho_/ghu_/ghs_ |
| GitHub | Fine-grained PAT | `github_pat_[A-Za-z0-9_]{82}` | |
| GitLab | Personal Access Token | `glpat-[A-Za-z0-9\-]{20}` | glpat-开头 |
| GitLab | Deploy Token | `gldt-[A-Za-z0-9\-]{20}` | gldt-开头 |
| Slack | Bot Token | `xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}` | |
| Slack | User Token | `xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}` | |
| Slack | App Token | `xapp-[0-9]{10,13}-[A-Za-z0-9]{24}` | |
| Stripe | Live Secret Key | `sk_live_[0-9a-zA-Z]{24,}` | |
| Stripe | Test Secret Key | `sk_test_[0-9a-zA-Z]{24,}` | |
| Stripe | Restricted Key | `rk_live_[0-9a-zA-Z]{24,}` | |

### 2.3 通用凭证格式

| 类型 | 正则表达式 | 说明 |
|------|-----------|------|
| JWT Token | `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` | 三段Base64URL编码 |
| SSH RSA公钥指纹 | `SHA256:[A-Za-z0-9+/=]{43}` | |
| PEM私钥 | `-----BEGIN (?:RSA \|EC \|DSA )?PRIVATE KEY-----` | 各类PEM格式 |
| 通用API Key | `[A-Za-z0-9]{32,64}` | 须结合上下文（变量名含key/secret/token） |

### 2.4 凭证变量名模式

以下变量名后跟非占位符值时须标记为违规：

```
api_key|apikey|api-key|API_KEY
secret_key|secretkey|secret-key|SECRET_KEY
access_key|accesskey|access-key|ACCESS_KEY
password|passwd|pwd|PASSWORD|PASSWD
token|TOKEN|Bearer
private_key|PRIVATE_KEY|privatekey
client_secret|CLIENT_SECRET
encryption_key|ENCRYPTION_KEY
auth_token|AUTH_TOKEN
refresh_token|REFRESH_TOKEN
database_url|DATABASE_URL|DB_PASSWORD
```

### 2.5 安全占位符白名单

以下占位符模式不会触发违规：

```
<YOUR_API_KEY>|<YOUR_PASSWORD>|<YOUR_TOKEN>|<YOUR_SECRET_KEY>|<YOUR_ACCESS_KEY>
${API_KEY}|${PASSWORD}|${TOKEN}|${SECRET_KEY}|${ACCESS_KEY}
your_api_key|your_password|your_token|your_secret_key
REPLACE_ME|PLACEHOLDER|INSERT_HERE|<REPLACE>
<API_KEY>|<PASSWORD>|<TOKEN>|<SECRET>
changeme|default_password|sample_key|test_key
```

***

## 三、网络信息模式

### 3.1 IP地址

| 类别 | 正则表达式 | 风险级别 |
|------|-----------|----------|
| 私有IP（A类） | `10\.\d{1,3}\.\d{1,3}\.\d{1,3}` | required |
| 私有IP（B类） | `172\.(1[6-9]\|2\d\|3[01])\.\d{1,3}\.\d{1,3}` | required |
| 私有IP（C类） | `192\.168\.\d{1,3}\.\d{1,3}` | required |
| 回环地址 | `127\.\d{1,3}\.\d{1,3}\.\d{1,3}` | 豁免 |
| 链路本地 | `169\.254\.\d{1,3}\.\d{1,3}` | suggestion |
| 示例IP（RFC 5737） | `192\.0\.2\.\d{1,3}\|198\.51\.100\.\d{1,3}\|203\.0\.113\.\d{1,3}` | 豁免 |
| IPv6私有 | `f[cd][0-9a-f]{2}:` | required |
| IPv6链路本地 | `fe[89ab][0-9a-f]:` | suggestion |
| IPv6回环 | `::1` | 豁免 |

### 3.2 内部域名后缀

| 后缀 | 说明 |
|------|------|
| `.internal` | 内部服务域名 |
| `.local` | 本地域名（mDNS） |
| `.intranet` | 内网域名 |
| `.corp` | 企业内网域名 |
| `.lan` | 局域网域名 |
| `.home` | 家庭网络域名 |
| `.private` | 私有域名 |
| `.test` | 测试域名 |
| `.localhost` | 本地域名 |

### 3.3 数据库连接串

| 类型 | 模式 | 说明 |
|------|------|------|
| MySQL | `mysql://[^:]+:[^@]+@[^\s]+` | 含用户名密码的连接串 |
| PostgreSQL | `postgres(ql)?://[^:]+:[^@]+@[^\s]+` | |
| MongoDB | `mongodb(\+srv)?://[^:]+:[^@]+@[^\s]+` | |
| Redis | `redis://:[^@]+@[^\s]+` | 含密码的Redis连接 |
| JDBC | `jdbc:\w+://[^:]+:[^@]+@[^\s]+` | 通用JDBC格式 |

***

## 四、局点与客户信息模式

### 4.1 常见局点关键词

| 关键词模式 | 说明 |
|-----------|------|
| `XX省XX市XX机房` | 具体机房地址 |
| `数据中心` + 具体地名 | 数据中心物理位置 |
| `IDC` + 具体名称 | 互联网数据中心 |
| `机房` + 具体名称 | 物理机房 |
| `局点` + 具体名称 | 部署局点 |
| `站点` + 具体名称 | 部署站点 |

### 4.2 项目代号模式

| 模式 | 说明 |
|------|------|
| `Project [A-Z][a-z]+` | 英文项目代号 |
| `项目代号：` | 中文项目代号标识 |
| `PRJ-[A-Z]+-\d+` | 内部项目编号 |

### 4.3 合同/订单模式

| 模式 | 说明 |
|------|------|
| `合同编号` | 合同标识 |
| `订单号` | 订单标识 |
| `PO-[A-Z0-9]+` | 采购订单编号 |
| `SO-[A-Z0-9]+` | 销售订单编号 |

***

## 五、敏感词与合规模式

### 5.1 商业机密标记

| 模式 | 说明 |
|------|------|
| `绝密\|TOP SECRET` | 最高密级 |
| `机密\|CONFIDENTIAL` | 较高密级 |
| `秘密\|SECRET` | 一般密级 |
| `内部\|INTERNAL` | 内部文档 |
| `仅供内部参考` | 内部参考 |
| `DRAFT\|草稿\|未定稿` | 未定稿 |

### 5.2 绝对化声明

| 模式 | 替换建议 |
|------|----------|
| `100%安全\|100%可靠\|绝对安全` | "具备多层安全防护机制" |
| `完全不可破解\|无法破解` | "具有较强安全防护能力" |
| `唯一选择\|唯一方案` | "推荐方案之一" |
| `保证\|承诺`（安全相关） | "致力于""力求" |

### 5.3 包容性语言替换

| 原词 | 替换建议 | 原因 |
|------|----------|------|
| 黑名单 / blacklist | 阻止列表 / blocklist | 中性表述 |
| 白名单 / whitelist | 允许列表 / allowlist | 中性表述 |
| 主从 / master-slave | 主备 / leader-follower | 减少等级/奴役暗示 |
| 主节点 / master | 主节点 / primary / leader | 中性表述 |
| 从节点 / slave | 备节点 / replica / follower | 中性表述 |
| 杀进程 / kill | 终止进程 / terminate | 减少暴力色彩 |
| 黑客攻击 / hack | 恶意攻击 / 未授权访问 | 防御视角 |
| 暴力破解 / brute force | 密码猜测攻击 / password guessing | 防御视角 |

***

## 六、元数据与隐藏信息模式

### 6.1 HTML注释

| 模式 | 说明 |
|------|------|
| `<!--[\s\S]*?-->` | HTML注释内容 |
| `<!-- TODO:.*-->` | TODO标记 |
| `<!-- FIXME:.*-->` | FIXME标记 |
| `<!-- HACK:.*-->` | HACK标记 |
| `<!-- XXX:.*-->` | XXX标记 |

### 6.2 内部追踪系统链接

| 模式 | 说明 |
|------|------|
| `https?://jira\..+/browse/[A-Z]+-\d+` | Jira工单链接 |
| `https?://.+/browse/[A-Z]+-\d+` | 通用工单链接 |
| `https?://.+/issues/\d+` | GitHub/GitLab Issue链接 |
| `https?://confluence\..+` | Confluence链接 |
| `https?://wiki\.(internal\|intranet)` | 内部Wiki链接 |
| `https?://.+/projects/[A-Z]+/issues/\d+` | Redmine链接 |

### 6.3 调试与日志模式

| 模式 | 说明 |
|------|------|
| `\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}` | 时间戳格式（可能为真实日志） |
| `\[INFO\]\|\[ERROR\]\|\[DEBUG\]\|\[WARN\]` | 日志级别标记 |
| `Traceback \(most recent call last\)` | Python异常追踪 |
| `Exception in thread` | Java异常信息 |
| `stack traceback` | Lua栈追踪 |

***

## 七、综合检查策略

### 7.1 优先级排序

1. **P0 — 立即处理**：明文密钥、私钥、JWT Token、SSH密钥
2. **P1 — 必须修复**：身份证号、银行卡号、密码明文、数据库连接串
3. **P2 — 应当修复**：手机号、邮箱、内网IP、客户名称、局点地址
4. **P3 — 建议修复**：HTML注释、TODO标记、追踪链接、端口暴露、绝对化声明

### 7.2 误报排除策略

| 场景 | 排除方式 |
|------|----------|
| 示例数据 | 检查上下文中是否有"示例""样例""Sample"等标记 |
| 占位符 | 匹配安全占位符白名单（见2.5节） |
| RFC示例IP | 匹配RFC 5737示例IP范围 |
| 示例域名 | 匹配 `example.com`、`example.org`、`example.net` |
| 代码块中的配置示例 | 检查是否在代码块（\`\`\`）内且使用占位符 |
| 公开信息 | 检查是否为法规要求公开的信息 |
