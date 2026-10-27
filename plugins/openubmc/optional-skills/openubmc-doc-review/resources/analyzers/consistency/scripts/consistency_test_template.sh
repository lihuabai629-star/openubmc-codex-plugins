#!/bin/bash
# consistency_test_template.sh — 文档与产品一致性验证脚本模板
# 用法：source consistency_test_template.sh
#       然后调用各 check_* 函数执行验证

PASS=0; FAIL=0; SKIP=0; WARN=0
RESULTS=()

# === 参数名验证 ===

extract_help_params() {
    local cmd="$1"
    $cmd --help 2>&1 | grep -oE '\-\-[a-zA-Z0-9_-]+' | sort -u
}

extract_doc_params() {
    local doc_file="$1"
    grep -oE '\-\-[a-zA-Z0-9_-]+' "$doc_file" | sort -u
}

diff_params() {
    local cmd="$1" doc_file="$2"
    diff <(extract_help_params "$cmd") <(extract_doc_params "$doc_file")
}

check_param() {
    local id="$1" doc_param="$2" cmd="$3"
    echo "--- [CHECK $id] 参数名一致性: $doc_param"
    local actual_params
    actual_params=$($cmd --help 2>&1 | grep -oE '\-\-[a-zA-Z0-9_-]+' | sort -u)
    if echo "$actual_params" | grep -qF "$doc_param"; then
        echo "PASS: 参数 $doc_param 存在"
        PASS=$((PASS+1)); RESULTS+=("PASS|$id|参数名|$doc_param|")
    else
        echo "FAIL: 参数 $doc_param 不存在于 $cmd --help"
        FAIL=$((FAIL+1)); RESULTS+=("FAIL|$id|参数名|$doc_param|not found in --help")
    fi
}

# === 缺省值验证 ===

check_default_port() {
    local expected="$1" cmd="$2"
    local actual
    actual=$($cmd --help 2>&1 | grep -i 'port' | grep -oE '[0-9]+' | head -1)
    if [ "$actual" != "$expected" ]; then
        echo "MISMATCH: doc says port=$expected, actual=$actual"
    fi
}

check_default_config() {
    local config_file="$1" key="$2" expected="$3"
    local actual
    actual=$(grep "^$key" "$config_file" | awk -F'= ' '{print $2}' | tr -d ' ')
    if [ "$actual" != "$expected" ]; then
        echo "MISMATCH: doc says $key=$expected, actual=$actual"
    fi
}

check_default() {
    local id="$1" key="$2" expected="$3" actual="$4"
    echo "--- [CHECK $id] 缺省值一致性: $key"
    if [ "$actual" = "$expected" ]; then
        echo "PASS: $key 缺省值一致 (=$expected)"
        PASS=$((PASS+1)); RESULTS+=("PASS|$id|缺省值|$key|$expected=$actual")
    else
        echo "FAIL: $key 缺省值不一致 (文档=$expected, 实际=$actual)"
        FAIL=$((FAIL+1)); RESULTS+=("FAIL|$id|缺省值|$key|doc=$expected actual=$actual")
    fi
}

# === 回显输出验证 ===

capture_and_compare() {
    local cmd="$1" doc_output_file="$2" section="$3"
    local actual_output
    actual_output=$(eval "$cmd" 2>&1)
    echo "$actual_output" > "/tmp/actual_${section}.txt"
    echo "--- 实际输出 ---"
    echo "$actual_output"
    echo "--- 文档描述 ---"
    cat "$doc_output_file"
    echo "--- 差异 ---"
    diff "/tmp/actual_${section}.txt" "$doc_output_file" || true
}

check_output() {
    local id="$1" desc="$2" cmd="$3" expected_pattern="$4"
    echo "--- [CHECK $id] 回显输出一致性: $desc"
    local actual_output
    actual_output=$(eval "$cmd" 2>&1)
    if echo "$actual_output" | grep -qE "$expected_pattern"; then
        echo "PASS: 输出匹配期望模式"
        PASS=$((PASS+1)); RESULTS+=("PASS|$id|回显输出|$desc|")
    else
        echo "FAIL: 输出不匹配期望模式"
        echo "  期望模式: $expected_pattern"
        echo "  实际输出: $actual_output"
        FAIL=$((FAIL+1)); RESULTS+=("FAIL|$id|回显输出|$desc|output mismatch")
    fi
}

# === 操作结果验证 ===

check_result() {
    local id="$1" desc="$2" cmd="$3" expect_exit="$4" expect_keyword="$5"
    echo "--- [CHECK $id] 操作结果一致性: $desc"
    local output exit_code
    output=$(eval "$cmd" 2>&1)
    exit_code=$?
    if [ "$exit_code" -ne "$expect_exit" ]; then
        echo "FAIL: 退出码不一致 (期望=$expect_exit, 实际=$exit_code)"
        FAIL=$((FAIL+1)); RESULTS+=("FAIL|$id|操作结果|$desc|exit=$exit_code expected=$expect_exit")
    elif [ -n "$expect_keyword" ] && ! echo "$output" | grep -qF "$expect_keyword"; then
        echo "FAIL: 结果缺少期望关键字 '$expect_keyword'"
        FAIL=$((FAIL+1)); RESULTS+=("FAIL|$id|操作结果|$desc|missing keyword")
    else
        echo "PASS"
        PASS=$((PASS+1)); RESULTS+=("PASS|$id|操作结果|$desc|")
    fi
}

# === 状态标记 ===

skip_check() {
    echo "--- [SKIP $1] $2 — $3"
    SKIP=$((SKIP+1)); RESULTS+=("SKIP|$1|$2|$3")
}

warn_check() {
    echo "--- [WARN $1] $2 — $3"
    WARN=$((WARN+1)); RESULTS+=("WARN|$1|$2|$3")
}

# === 汇总 ===

print_summary() {
    echo ""
    echo "============================================================"
    echo "PASS: $PASS  FAIL: $FAIL  SKIP: $SKIP  WARN: $WARN  总计: $((PASS+FAIL+SKIP+WARN))"
    echo "============================================================"
}

# === 验证用例（由一致性验证器自动生成）===
# ... 此处填充具体验证

# === 执行汇总 ===
print_summary
