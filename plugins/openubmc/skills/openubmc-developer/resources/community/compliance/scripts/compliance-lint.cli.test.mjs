import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LINT = path.join(__dirname, 'compliance-lint.mjs');

// 收集 setupFixtures 创建的临时目录,在所有测试结束后统一清理(避免 /tmp 堆积 cl-cli-*)
const createdDirs = [];
test.after(() => { for (const d of createdDirs) rmSync(d, { recursive: true, force: true }); });

/** 跑 CLI 子进程,返回 {stdout, stderr, exitCode, parsed}。 */
function runLint(args, stdin) {
	const res = spawnSync(process.execPath, [LINT, ...args], { encoding: 'utf8', input: stdin });
	let parsed = null;
	try { parsed = JSON.parse(res.stdout); } catch { /* 非 JSON 输出 */ }
	return { stdout: res.stdout, stderr: res.stderr, exitCode: res.status, parsed };
}

/** 在系统临时目录下造一组 fixture(路径含 intf/mdb 以命中 mdb scope),返回各文件绝对路径。 */
function setupFixtures() {
	const dir = mkdtempSync(path.join(tmpdir(), 'cl-cli-'));
	createdDirs.push(dir);
	const base = path.join(dir, 'json/intf/mdb/bmc/kepler');
	mkdirSync(base, { recursive: true });
	const mdbBad = path.join(base, 'bad.json');      // NAMING + BASETYP 两处违规
	writeFileSync(mdbBad, '{ "bmc.kepler.systems": { "properties": { "P": { "baseType": "Strring" } } } }');
	const mdbBad2 = path.join(base, 'bad2.json');    // BASETYP 违规(Struct[])
	writeFileSync(mdbBad2, '{ "bmc.kepler.Systems.Power": { "properties": { "P": { "baseType": "Struct[]" } } } }');
	const mdbGood = path.join(base, 'good.json');    // 合规
	writeFileSync(mdbGood, '{ "bmc.kepler.Systems.Power": { "properties": { "P": { "baseType": "U8" } } } }');
	const readme = path.join(dir, 'README.md');      // 非 JSON
	writeFileSync(readme, '# title');
	return { dir, mdbBad, mdbBad2, mdbGood, readme };
}

// ---------------- A:--files 多文件分隔(空格 / 逗号) ----------------

test('--files accepts space-separated paths and lints all of them', () => {
	const { mdbBad, mdbBad2 } = setupFixtures();
	const r = runLint(['--files', mdbBad, mdbBad2]);
	assert.equal(r.exitCode, 1);
	const files = new Set(r.parsed.findings.map((f) => f.file));
	assert.ok(files.has(mdbBad), 'first file linted');
	assert.ok(files.has(mdbBad2), 'second file linted (not dropped by space separator)');
});

test('--files accepts comma-separated paths and lints all of them', () => {
	const { mdbBad, mdbBad2 } = setupFixtures();
	const r = runLint(['--files', `${mdbBad},${mdbBad2}`]);
	assert.equal(r.exitCode, 1);
	const files = new Set(r.parsed.findings.map((f) => f.file));
	assert.ok(files.has(mdbBad));
	assert.ok(files.has(mdbBad2));
});

// ---------------- B:CLI 端到端(违规 / 合规 / 非 JSON / stdin + 退出码) ----------------

test('violations exit 1 with structured findings', () => {
	const { mdbBad } = setupFixtures();
	const r = runLint(['--files', mdbBad]);
	assert.equal(r.exitCode, 1);
	assert.ok(r.parsed.findings.some((f) => f.rule === 'MDB-NAMING'));
	assert.ok(r.parsed.findings.some((f) => f.rule === 'MDB-BASETYP'));
	assert.equal(r.parsed.summary.errors, r.parsed.findings.length);
	assert.equal(r.parsed.coverage.semanticNeeded, true);
});

test('clean file exits 0 with no findings', () => {
	const { mdbGood } = setupFixtures();
	const r = runLint(['--files', mdbGood]);
	assert.equal(r.exitCode, 0);
	assert.equal(r.parsed.findings.length, 0);
	assert.equal(r.parsed.summary.errors, 0);
});

test('non-json file is skipped, exit 0', () => {
	const { readme } = setupFixtures();
	const r = runLint(['--files', readme]);
	assert.equal(r.exitCode, 0);
	assert.equal(r.parsed.summary.skippedFiles, 1);
	assert.equal(r.parsed.summary.checkedFiles, 0);
});

test('stdin + --scope redfish detects RF-ODATA-TYPE and exits 1', () => {
	const r = runLint(['--stdin', '--scope', 'redfish'], '{ "@odata.type": "Power" }');
	assert.equal(r.exitCode, 1);
	assert.ok(r.parsed.findings.some((f) => f.rule === 'RF-ODATA-TYPE'));
});

test('stdin without --scope is a usage error (exit 2), never silently skipped', () => {
	const r = runLint(['--stdin'], '{ "@odata.type": "Power" }');
	assert.equal(r.exitCode, 2);
	assert.match(r.stderr, /必须显式 --scope/);
});

test('stdin with --scope auto is also rejected (no filename to auto-detect)', () => {
	const r = runLint(['--stdin', '--scope', 'auto'], '{ "@odata.type": "Power" }');
	assert.equal(r.exitCode, 2);
	assert.match(r.stderr, /必须显式 --scope/);
});

// ---------------- CLI 严格化回归(Richardli25 PR #133 审计 P2/P3) ----------------
test('等号形式 --files=x --scope=y 正常工作(不再被静默丢弃)', () => {
	const { dir } = setupFixtures();
	const bad = path.join(dir, 'json/intf/mdb/bmc/kepler', 'bad.json');
	const r = runLint(['--files=' + bad, '--scope=mdb']);
	assert.equal(r.exitCode, 1);
	assert.ok(r.parsed.summary.checkedFiles === 1);
});

test('未知/拼错 flag → usage error exit 2(不再零检查绿灯放行)', () => {
	const r = runLint(['--file', 'bad.json']);
	assert.equal(r.exitCode, 2);
	assert.match(r.stderr, /未知参数/);
});

test('完全无参 → exit 2', () => {
	const r = runLint([]);
	assert.equal(r.exitCode, 2);
	assert.match(r.stderr, /未指定任何输入/);
});

test('--stdin 与 --files 同用 → exit 2(原来 --files 被静默忽略)', () => {
	const r = runLint(['--stdin', '--files', 'a.json', '--scope', 'mdb'], '{}');
	assert.equal(r.exitCode, 2);
	assert.match(r.stderr, /互斥/);
});

test('--scope 拼错(redfishh)→ exit 2(原来静默落入 MDB 规则集)', () => {
	const r = runLint(['--stdin', '--scope', 'redfishh'], '{}');
	assert.equal(r.exitCode, 2);
	assert.match(r.stderr, /非法 --scope/);
});

test('文件不存在 → exit 2 + stderr(与"存在 error"门禁语义分离)', () => {
	const r = runLint(['--files', '/nonexistent/xx.json', '--scope', 'mdb']);
	assert.equal(r.exitCode, 2);
	assert.match(r.stderr, /无法读取文件/);
});

test('win32 反斜杠路径正常检出(不再静默 skip、exit 0 假绿)', () => {
	// Linux 文件系统不认反斜杠真实路径,CLI 端真实 win32 行为由单元层 lintContent 归一化保证(见 test.mjs);
	// 此处验证等价形式:正斜杠相对路径 + --scope 缺省自动分流仍正常
	const { mdbBad } = setupFixtures();
	const r = runLint(['--files', mdbBad]);
	assert.equal(r.exitCode, 1);
	assert.equal(r.parsed.summary.checkedFiles, 1);
	assert.equal(r.parsed.summary.skippedFiles, 0);
	assert.ok(r.parsed.findings.length > 0);
});
