# 链接模式检测参考

## 域名拼写错误

| 错误模式 | 正确写法 | 说明 |
|----------|---------|------|
| `githb.com` | `github.com` | 缺少 `u` |
| `github.org` | `github.com` | 错误顶级域名（.org 非 GitHub 官网） |
| `ggitee.com` | `gitee.com` | 重复首字母 `g` |
| `hhiascend.com` | `hiascend.com` | 重复首字母 `h` |
| `ssupport.huawei.com` | `support.huawei.com` | 重复首字母 `s` |
| `ddownload.` | `download.` | 重复首字母 `d` |
| `modelss` | `models` | 重复尾字母 `s` |
| `eenterprise` | `enterprise` | 重复首字母 `e` |
| `hhuawei` | `huawei` | 重复首字母 `h` |

## 协议拼写错误

| 错误模式 | 正确写法 | 说明 |
|----------|---------|------|
| `htp://` | `http://` | 缺少 `t` |
| `hhttps://` | `https://` | 多出首字母 `h` |
| `htps://` | `https://` | 缺少 `t` |

## URL 路径格式错误

| 错误模式 | 说明 | 严重级别 |
|----------|------|---------|
| `https://example.com//path` | path 中包含连续双斜杠 `//`，排除 `://` 协议分隔符 | Warning |
| `https://example.com/path/` | 路径末尾多余斜杠，可能与无尾斜杠版本指向不同资源 | Warning |

## 静态模式匹配表

| 错误 URL 片段 | 正确写法 | 检测正则 |
|--------------|---------|---------|
| `githb.com` | `github.com` | `githb\.com` |
| `github.org`（非官方） | `github.com` | `github\.org` |
| `ggitee.com` | `gitee.com` | `ggitee\.com` |
| `hhiascend.com` | `hiascend.com` | `hhiascend\.com` |
| `ssupport.huawei.com` | `support.huawei.com` | `ssupport\.huawei\.com` |
| `support.hhuawei.com` | `support.huawei.com` | `support\.hhuawei\.com` |
| `ddownload.` | `download.` | `ddownload\.` |
| `htp://` | `http://` | `\bhtp://` |
| `hhttps://` | `https://` | `\bhhttps://` |
| `htps://` | `https://` | `\bhtps://` |
