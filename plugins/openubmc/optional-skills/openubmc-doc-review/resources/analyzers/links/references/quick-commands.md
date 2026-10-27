# 快速检查命令

## 断链检查

```bash
# 查找所有 Markdown 链接
grep -rn '\[.*\](.*)' --include='*.md' .

# 查找所有图片引用
grep -rn '!\[.*\](.*)' --include='*.md' .

# 查找内部锚点链接
grep -rn '\[.*\](#.*)' --include='*.md' .

# 查找 HTML 媒体标签
grep -rn '<\(img\|video\|audio\|source\)[^>]*src=' --include='*.md' .

# 查找 HTML <a> 标签链接
grep -rn '<a[^>]*href=' --include='*.md' .

# 查找代码片段导入
grep -rn '^<<<' --include='*.md' .

# 查找跨文件锚点
grep -rn '\[.*\](\.\/.*#.*)' --include='*.md' .
```

## 链接文本质量

```bash
grep -rni '点击此处\|点击这里\|参见这里\|\[这里\]\|\[link\]\|\[\]\|click here\|read more\|learn more' --include='*.md' .
```

## 裸 URL 检查

```bash
grep -rn 'https\?://' --include='*.md' . | grep -v '\[.*\](.*https\?://\|!\[' | grep -v '^<!--'
```

## 版本一致性

```bash
# 查找链接中可能硬编码的版本号
grep -rn '/[0-9]\.[0-9]/' --include='*.md' .

# 查找 /latest/ 链接
grep -rn '/latest/' --include='*.md' .

# 查找代码托管平台的 HTTP 链接（强制 HTTPS）
grep -rn 'http://\(github\.com\|gitee\.com\|gitcode\.com\|atomgit\.com\)' --include='*.md' .

# 查找所有 HTTP 链接
grep -rn 'http://' --include='*.md' . | grep -v 'http://\(localhost\|127\.0\.0\.1\|192\.168\|10\.\|172\.\(1[6-9]\|2[0-9]\|3[01]\)\)' | grep -v 'http://\(github\.com\|gitee\.com\|gitcode\.com\|atomgit\.com\)'
```

## 重复标题/锚点

```bash
# 查找同一文件中的重复标题
for f in $(find . -name '*.md'); do grep '^#' "$f" | sed 's/^#* //' | sort | uniq -d | while read line; do echo "$f: $line"; done; done
```

## 应加链接内容

```bash
# 查找书名号内容
grep -rn '《[^《》]*》' --include='*.md' .

# 查找引导关键词
grep -rni '参照\|参见\|参考\|详见\|点击查看' --include='*.md' .
```
