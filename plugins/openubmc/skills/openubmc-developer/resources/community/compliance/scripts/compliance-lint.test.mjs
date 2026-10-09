import test from 'node:test';
import assert from 'node:assert/strict';
import { lintContent, lintFiles, lintWithRules } from './compliance-lint.mjs';

// 代表性路径(决定 scope 分流)
const MDB = 'json/intf/mdb/bmc/kepler/Systems/Power.json';
const MDB_MSG = 'messages/custom.json';
const MDB_PATH = 'json/path/mdb/bmc/kepler/Chassis/Power.json';
const RF = 'interface_config/redfish/Chassis/Power/Power.json';

const rulesOf = (r) => new Set(r.findings.map((f) => f.rule));

// ---------------- MDB 规则 ----------------

test('MDB-SYNTAX flags malformed JSON as error', () => {
  const r = lintContent(MDB, '{ "a": 1 "b": 2 }');
  assert.ok(r.findings.some((f) => f.rule === 'MDB-SYNTAX' && f.severity === 'error'));
});

test('MDB-NAMING flags non-PascalCase segment', () => {
  const r = lintContent(MDB, '{ "bmc.kepler.systems": { "properties": {} } }');
  assert.ok(r.findings.some((f) => f.rule === 'MDB-NAMING'));
});

test('MDB-NAMING accepts valid interface name', () => {
  const r = lintContent(MDB, '{ "bmc.kepler.Systems.Power": { "properties": {} } }');
  assert.ok(!rulesOf(r).has('MDB-NAMING'));
});

test('MDB-BASETYP flags misspelled type', () => {
  const r = lintContent(MDB, '{ "bmc.kepler.Systems.Power": { "properties": { "P": { "baseType": "Strring" } } } }');
  assert.ok(r.findings.some((f) => f.rule === 'MDB-BASETYP' && /Strring/.test(f.message)));
});

test('MDB-BASETYP rejects Struct[] array suffix on non-scalar', () => {
  const r = lintContent(MDB, '{ "bmc.kepler.Systems.Power": { "properties": { "P": { "baseType": "Struct[]" } } } }');
  assert.ok(r.findings.some((f) => f.rule === 'MDB-BASETYP'));
});

test('MDB-BASETYP accepts U8 and String[]', () => {
  const r = lintContent(MDB, '{ "bmc.kepler.Systems.Power": { "properties": { "P": { "baseType": "U8" }, "Q": { "baseType": "String[]" } } } }');
  assert.ok(!rulesOf(r).has('MDB-BASETYP'));
});

test('MDB-IPMI-CC flags decimal completion code', () => {
  const r = lintContent(MDB_MSG, '{ "MsgX": { "IpmiCompletionCode": "255" } }');
  assert.ok(r.findings.some((f) => f.rule === 'MDB-IPMI-CC'));
});

test('MDB-IPMI-CC accepts 0xFF and N/A', () => {
  const r = lintContent(MDB_MSG, '{ "A": { "IpmiCompletionCode": "0xFF" }, "B": { "IpmiCompletionCode": "N/A" } }');
  assert.ok(!rulesOf(r).has('MDB-IPMI-CC'));
});

test('MDB-EMITS warns on invalid emitsChangedSignal', () => {
  const r = lintContent(MDB, '{ "bmc.kepler.Systems.Power": { "properties": { "P": { "baseType": "U8", "options": { "emitsChangedSignal": "yes" } } } } }');
  const f = r.findings.find((x) => x.rule === 'MDB-EMITS');
  assert.ok(f && f.severity === 'warning');
});

test('MDB-PATH flags non /bmc/ path', () => {
  const r = lintContent(MDB_PATH, '{ "Obj": { "path": "/redfish/v1/Chassis" } }');
  assert.ok(r.findings.some((f) => f.rule === 'MDB-PATH'));
});

// ---------------- Redfish 规则 ----------------

test('RF-ODATA-TYPE flags missing # and version', () => {
  const r = lintContent(RF, '{ "@odata.type": "Power", "Id": "1", "Name": "n", "@odata.id": "/redfish/v1/x" }');
  assert.ok(r.findings.some((f) => f.rule === 'RF-ODATA-TYPE'));
});

test('RF-ODATA-TYPE locates the line number', () => {
  const content = '{\n  "@odata.type": "Power",\n  "Id": "1"\n}';
  const r = lintContent(RF, content);
  const f = r.findings.find((x) => x.rule === 'RF-ODATA-TYPE');
  assert.ok(f);
  assert.equal(f.line, 2);
});

test('RF-META flags missing @odata.id on resource', () => {
  const r = lintContent(RF, '{ "@odata.type": "#Power.v1_0_0", "Id": "1", "Name": "n" }');
  assert.ok(r.findings.some((f) => f.rule === 'RF-META'));
});

test('RF-URI flags non /redfish/v1/ uri', () => {
  const r = lintContent(RF, '{ "@odata.type": "#Power.v1_0_0", "Id": "1", "Name": "n", "@odata.id": "/redfish/v1/x", "URI": "/api/power" }');
  assert.ok(r.findings.some((f) => f.rule === 'RF-URI'));
});

test('RF-ENUM warns on invalid Health value', () => {
  const r = lintContent(RF, '{ "@odata.type": "#Power.v1_0_0", "Id": "1", "Name": "n", "@odata.id": "/redfish/v1/x", "Health": "Bad" }');
  const f = r.findings.find((x) => x.rule === 'RF-ENUM');
  assert.ok(f && f.severity === 'warning');
});

// ---------------- 分流 / 聚合 ----------------

test('mdb file is scoped to mdb and skips redfish rules', () => {
  const r = lintContent(MDB, '{ "bmc.kepler.Systems.Power": { "properties": { "P": { "baseType": "U8" } } } }');
  assert.equal(r.scope, 'mdb');
  assert.equal(r.findings.length, 0);
});

test('redfish file is scoped to redfish', () => {
  const r = lintContent(RF, '{ "@odata.type": "#Power.v1_0_0", "Id": "1", "Name": "n", "@odata.id": "/redfish/v1/x" }');
  assert.equal(r.scope, 'redfish');
  assert.equal(r.findings.length, 0);
});

test('non-json file is skipped without findings', () => {
  const r = lintContent('README.md', '# title');
  assert.equal(r.skipped, true);
  assert.equal(r.findings.length, 0);
});

test('uncovered path has null scope and is skipped', () => {
  const r = lintContent('some/other/file.json', '{}');
  assert.equal(r.scope, null);
  assert.equal(r.skipped, true);
});

test('lintFiles aggregates summary and marks semanticNeeded', () => {
  const result = lintFiles([
    { filename: MDB, content: '{ "bmc.kepler.systems": { "properties": {} } }' },        // MDB-NAMING error
    { filename: 'README.md', content: 'x' },                           // skipped
    { filename: RF, content: '{ "@odata.type": "Power" }' },           // RF-ODATA-TYPE + RF-META
  ]);
  assert.ok(result.findings.length >= 3);
  assert.equal(result.summary.checkedFiles, 2);
  assert.equal(result.summary.skippedFiles, 1);
  assert.equal(result.coverage.semanticNeeded, true);
});

test('clean files produce no findings (regression)', () => {
  const result = lintFiles([
    { filename: MDB, content: '{ "bmc.kepler.Systems.Power": { "properties": { "P": { "baseType": "U8" } } } }' },
    { filename: RF, content: '{ "@odata.type": "#Power.v1_0_0", "Id": "1", "Name": "n", "@odata.id": "/redfish/v1/x" }' },
  ]);
  assert.equal(result.findings.length, 0);
});

// ---------------- scope 覆盖(对应详设 lint_pr 的 scope 参数,CI 门禁/stdin 场景) ----------------

test('scope override forces mdb linting regardless of path', () => {
  const r = lintContent('anywhere/file.json', '{ "bmc.kepler.systems": { "properties": {} } }', 'mdb');
  assert.equal(r.scope, 'mdb');
  assert.ok(r.findings.some((f) => f.rule === 'MDB-NAMING'));
});

test('lintFiles honors options.scope for paths that would otherwise be skipped', () => {
  const result = lintFiles(
    [{ filename: 'stdin.json', content: '{ "@odata.type": "Power" }' }],
    { scope: 'redfish' }
  );
  assert.ok(result.findings.some((f) => f.rule === 'RF-ODATA-TYPE'));
});

// ---------------- 规则容错(对应详设 FM-09/10:单规则抛错不中断其余,入 skippedRules) ----------------

test('lintWithRules records a throwing rule in skippedRules without breaking others', () => {
  const throwing = { id: 'X-THROW', run: () => { throw new Error('boom'); } };
  const ok = { id: 'X-OK', run: () => [{ rule: 'X-OK', severity: 'error', file: 'f', message: 'm' }] };
  const { findings, skippedRules } = lintWithRules({}, [throwing, ok], { file: 'f' });
  assert.ok(skippedRules.includes('X-THROW'));
  assert.ok(findings.some((f) => f.rule === 'X-OK'));
});

// ---------------- 真实语料修复回归(Richardli25 PR #133 审计) ----------------
// @odata.type 三种合法形态(DMTF DSP0266 §9.6.3 + rackmount main 真实值)
test('RF-ODATA-TYPE 接受 #Type.vX_Y_Z / #Type.vX_Y_Z.Entity / #XCollection.XCollection', () => {
	for (const t of ['#Power.v1_0_0', '#ManagerAccount.v1_11_0.ManagerAccount', '#ManagerAccountCollection.ManagerAccountCollection', '#CertificateLocations.CertificateLocations']) {
		const r = lintContent(RF, JSON.stringify({ '@odata.type': t }));
		assert.ok(!rulesOf(r).has('RF-ODATA-TYPE'), `${t} 应合法`);
	}
});

test('RF-ODATA-TYPE 仍拒绝裸 #Type / 无 # 前缀', () => {
	for (const t of ['#Power', 'Power.v1_0_0']) {
		const r = lintContent(RF, JSON.stringify({ '@odata.type': t }));
		assert.ok(r.findings.some((f) => f.rule === 'RF-ODATA-TYPE'), `${t} 应报错`);
	}
});

test('RF-META 豁免 Message 系模板(规范字段 MessageId/Message/Severity/Resolution)', () => {
	const r = lintContent(RF, JSON.stringify({ error: { '@odata.type': '#Message.v1_0_0.Message', 'MessageId': 'x', 'Message': 'y', 'Severity': 'Warning', 'Resolution': 'z' } }));
	assert.ok(!rulesOf(r).has('RF-META'));
});

test('RF-META Collection 只要求 @odata.id+Name(DSP0266 集合 shall not 含 Id)', () => {
	const ok = lintContent(RF, JSON.stringify({ '@odata.type': '#AccountCollection.AccountCollection', '@odata.id': '/redfish/v1/Accounts', 'Name': 'Accounts' }));
	assert.ok(!rulesOf(ok).has('RF-META'));
	const miss = lintContent(RF, JSON.stringify({ '@odata.type': '#AccountCollection.AccountCollection', 'Name': 'Accounts' }));
	assert.ok(miss.findings.some((f) => f.rule === 'RF-META' && /Collection/.test(f.message)));
});

test('RF-META 非 Collection 资源缺字段仍报', () => {
	const r = lintContent(RF, JSON.stringify({ '@odata.type': '#Power.v1_0_0.Power', 'Id': '1' }));
	assert.ok(r.findings.some((f) => f.rule === 'RF-META'));
});

test('MDB-NAMING/PATH 域段允许大小写厂商名(mdb_interface main 真实形态 bmc.CMCC.UpdateService)', () => {
	const r = lintContent(MDB, '{ "bmc.CMCC.UpdateService": { "properties": {} } }');
	assert.ok(!rulesOf(r).has('MDB-NAMING'));
	const p = lintContent(MDB_PATH, JSON.stringify({ path: '/bmc/CMCC/UpdateService' }));
	assert.ok(!rulesOf(p).has('MDB-PATH'));
});

test('MDB-NAMING 两段域级接口形态合法(bmc.dev 带 methods),三段小写尾仍报', () => {
	const ok = lintContent(MDB, '{ "bmc.dev": { "properties": {}, "methods": { "AddBoard": { "req": {}, "rsp": {} } } } }');
	assert.ok(!rulesOf(ok).has('MDB-NAMING'), 'bmc.dev 域级接口应合法');
	const bad = lintContent(MDB, '{ "bmc.kepler.systems": { "properties": {} } }');
	assert.ok(bad.findings.some((f) => f.rule === 'MDB-NAMING'), '三段小写尾仍应报');
});

test('RF-URI 收集驼峰 Uri 键,豁免 /bmc/ /Expand/ 模板值(rackmount main 普查 Uri×59)', () => {
	const bad = lintContent(RF, JSON.stringify({ Resources: [{ Uri: '/web/entities' }] }));
	assert.ok(bad.findings.some((f) => f.rule === 'RF-URI' && /\/web\/entities/.test(f.message)));
	for (const v of ['/bmc/kepler/Systems', '/Expand/1', '/redfish/v1/Systems/${Id}', '/redfish/v1/Chassis/{{cid}}']) {
		const r = lintContent(RF, JSON.stringify({ Uri: v }));
		assert.ok(!rulesOf(r).has('RF-URI'), `${v} 应豁免`);
	}
});

test('findLine 消耗式:同值多次出现行号按文档序配对(不再全报到首次出现)', () => {
	const content = [
		'{ "a": { "@odata.type": "#Power.v1_0_0" },',
		'  "b": { "@odata.type": "#Power.v1_0_0" },',
		'  "c": { "@odata.type": "#Power.v1_0_0" } }',
	].join('\n');
	// 三处同值全合法不产 finding——用同值重复的 Uri 违规验证行号
	const content2 = [
		'{ "x": { "Uri": "/web/1" },',
		'  "y": { "Uri": "/web/1" } }',
	].join('\n');
	const r = lintContent(RF, content2);
	const lines = r.findings.filter((f) => f.rule === 'RF-URI').map((f) => f.line).sort((a, b) => a - b);
	assert.deepEqual(lines, [1, 2]);
});

test('非字符串标量值报错(不再静默跳过):baseType/State 数字、emitsChangedSignal 数字', () => {
	const r = lintContent(MDB, '{ "bmc.kepler.S": { "properties": { "P": { "baseType": 8 } } } }');
	assert.ok(r.findings.some((f) => f.rule === 'MDB-BASETYP' && /应为字符串/.test(f.message)));
	const rf = lintContent(RF, JSON.stringify({ State: 3 }));
	assert.ok(rf.findings.some((f) => f.rule === 'RF-ENUM' && /应为字符串/.test(f.message)));
});

test('emitsChangedSignal 布尔 true 不报(真实 DSL 形态),数字报', () => {
	const ok = lintContent(MDB, '{ "bmc.kepler.S": { "properties": { "P": { "emitsChangedSignal": true } } } }');
	assert.ok(!rulesOf(ok).has('MDB-EMITS'));
	const bad = lintContent(MDB, '{ "bmc.kepler.S": { "properties": { "P": { "emitsChangedSignal": 1 } } } }');
	assert.ok(bad.findings.some((f) => f.rule === 'MDB-EMITS'));
});

test('State=Degraded/Qualified 合法(DMTF 现行枚举)', () => {
	for (const s of ['Degraded', 'Qualified']) {
		const r = lintContent(RF, JSON.stringify({ State: s }));
		assert.ok(!rulesOf(r).has('RF-ENUM'), `${s} 应合法`);
	}
});

test('UTF-8 BOM 输入不误报 SYNTAX', () => {
	const r = lintContent(RF, '﻿{ "@odata.type": "#Power.v1_0_0" }');
	assert.ok(!rulesOf(r).has('RF-SYNTAX'));
});

test('显式 scope 不再绕过 guard 等价类外规则(--scope messages 只放行 MDB-IPMI-CC)', () => {
	// path 非法 + IpmiCompletionCode 非法混在一个 stdin 内容里,messages scope 只该报 IPMI-CC
	const content = JSON.stringify({ path: 'not-a-bmc-path', IpmiCompletionCode: '0x1' });
	const r = lintContent('stdin.json', content, 'messages');
	assert.ok(r.findings.some((f) => f.rule === 'MDB-IPMI-CC'));
	assert.ok(!rulesOf(r).has('MDB-PATH'));
});

test('win32 反斜杠路径归一化:反斜杠 filename 照常分流检出(不再静默 skip)', () => {
	// lintContent 直接接收反斜杠路径字符串,验证 normPath 分流(Linux 下文件系统不认反斜杠,故走单元层)
	const win = 'C:\\repo\\json\\intf\\mdb\\bmc\\kepler\\Power.json';
	const r = lintContent(win, '{ "bmc.kepler.systems": { "properties": {} } }');
	assert.equal(r.skipped, false);
	assert.equal(r.scope, 'mdb');
	assert.ok(r.findings.some((f) => f.rule === 'MDB-NAMING'));
});

// ---------------- 第二轮真实语料收敛回归(rackmount main 189 文件残余形态) ----------------

// 造带 Resources/Interfaces 结构的映射文件形态;type 缺省视为 GET
const wrapIfaces = (rspBody, type = 'GET') => ({ Resources: [{ Interfaces: [{ Type: type, RspBody: rspBody }] }] });

test('RF-URI 接受服务根精确形态与中段混拼/无头 Expand(rackmount 残余形态)', () => {
	for (const v of [
		'/redfish', '/redfish/v1',                                                    // v1.json 服务根 Uri
		'/Chassis/:chassisid/Power/bmc/kepler/Systems/:systemid',                     // 资源段+DBus 中段混拼
		'/PerformanceCollection/Expand/Thermal/OnlyType/bmc/kepler/Systems/1',        // 中段 Expand
		'/StorageId/Expand/:name',                                                    // 中段 Expand(无模板)
		'Expand/redfish/v1/Systems/:systemid/Memory/:memoryid/Oem/OemIdentifier',     // 无头斜杠 Expand
	]) {
		const r = lintContent(RF, JSON.stringify({ Resources: [{ Uri: v }] }));
		assert.ok(!rulesOf(r).has('RF-URI'), `${v} 应豁免`);
	}
	const bad = lintContent(RF, JSON.stringify({ Uri: '/redfishh/v1/Systems' }));
	assert.ok(bad.findings.some((f) => f.rule === 'RF-URI'), '/redfishh 拼错应仍报');
});

test('RF-META 只查 GET 接口 RspBody 顶层:POST 响应体/数组 member/嵌套 fragment 不要求 triple', () => {
	// POST RspBody(HwSystemErase 形态:仅 @odata.id+Components)不报
	const post = lintContent(RF, JSON.stringify(wrapIfaces(
		{ '@odata.type': '#HwSystemErase.v1_0_0.HwSystemErase', '@odata.id': '/redfish/v1/Managers/1/SPService/SystemErase/1', Components: '${ReqBody/Components}' }, 'POST')));
	assert.ok(!rulesOf(post).has('RF-META'), 'POST RspBody 不应要求 triple');
	// GET RspBody 内嵌套对象不查:数组 member(StorageController 带 MemberId 无 Id)与 @Redfish.Settings fragment
	const nested = lintContent(RF, JSON.stringify(wrapIfaces({
		'@odata.type': '#Storage.v1_10_0.Storage', Id: '1', Name: 'S', '@odata.id': '/redfish/v1/Systems/1/Storage/1',
		StorageControllers: [{ MemberId: '${Statements/MemberId()}', '@odata.type': '#Storage.v1_10_0.StorageController', '@odata.id': '/x#/c/1', Name: 'c' }],
		'@Redfish.Settings': { '@odata.type': '#Settings.v1_0_2.Settings', ETag: '${Statements/GetETag()}' },
	})));
	assert.ok(!rulesOf(nested).has('RF-META'), '嵌套 member/fragment 不应要求 triple');
	// GET RspBody 顶层版本化资源缺 Id 仍报
	const missId = lintContent(RF, JSON.stringify(wrapIfaces(
		{ '@odata.type': '#Power.v1_0_0.Power', Name: 'n', '@odata.id': '/redfish/v1/x' })));
	assert.ok(missId.findings.some((f) => f.rule === 'RF-META'), 'GET 顶层版本化资源缺 Id 应报');
});

test('RF-META 豁免 Registry 族(v1.json 服务根的注册表 RspBody 合法无 @odata.id)', () => {
	for (const t of ['#MessageRegistry.v1_0_0.MessageRegistry', '#EventRegistry.v1_0_0.EventRegistry']) {
		const r = lintContent(RF, JSON.stringify(wrapIfaces({ '@odata.type': t, Id: 'Base.1.0.0', Name: 'Base', Language: 'en' })));
		assert.ok(!rulesOf(r).has('RF-META'), `${t} 应豁免`);
	}
});

test('RF-META 无版本 OEM 形态与版本化 Collection 均按两字段口径(Hw 传感器/Transceivers 形态)', () => {
	// #HwThresholdSensor.HwThresholdSensor:有 @odata.id+Name 无 Id → 合规
	const ok = lintContent(RF, JSON.stringify(wrapIfaces(
		{ '@odata.type': '#HwThresholdSensor.HwThresholdSensor', '@odata.id': '/redfish/v1/Chassis/${Uri/chassisid}/ThresholdSensors', Name: 'ThresholdSensors', Sensors: '${Statements/GetSensors()}' })));
	assert.ok(!rulesOf(ok).has('RF-META'), '无版本 OEM 形态两字段即合规');
	// #HwTransceiverLaneMappingCollection.v1_0_0.*(版本化 Collection)缺 Id 也合规
	const ok2 = lintContent(RF, JSON.stringify(wrapIfaces(
		{ '@odata.type': '#HwTransceiverLaneMappingCollection.v1_0_0.HwTransceiverLaneMappingCollection', '@odata.id': '/redfish/v1/Chassis/1/T', Name: 'T' })));
	assert.ok(!rulesOf(ok2).has('RF-META'), '版本化 Collection 两字段即合规');
	// 无版本形态缺 @odata.id 仍报
	const miss = lintContent(RF, JSON.stringify(wrapIfaces(
		{ '@odata.type': '#HwThresholdSensor.HwThresholdSensor', Name: 'ThresholdSensors' })));
	assert.ok(miss.findings.some((f) => f.rule === 'RF-META'), '无版本形态缺 @odata.id 应报');
});

test('RF-ENUM 豁免模板值与直通映射块内的源属性名引用(152 条 warning 残余形态)', () => {
	// 模板计算值
	const tpl = lintContent(RF, JSON.stringify({ Status: { State: '${Statements/GetState()}', Health: '${ProcessingFlow[1]/Destination/Health}' } }));
	assert.ok(!rulesOf(tpl).has('RF-ENUM'), '模板值应豁免');
	// Destination 直通块:同对象存在 "k":"k" 同名对,State 值为源属性名引用(可为异名 DetectorState)
	const pass = lintContent(RF, JSON.stringify({ Destination: { Id: 'Id', Name: 'Name', Enabled: 'Enabled', State: 'DetectorState', Health: 'Health' } }));
	assert.ok(!rulesOf(pass).has('RF-ENUM'), '直通块内源属性名引用应豁免');
	// 单键自身即同名对:"State": "State"
	const self = lintContent(RF, JSON.stringify({ Destination: { State: 'State' } }));
	assert.ok(!rulesOf(self).has('RF-ENUM'), '值===键名的直通引用应豁免');
	// 普通 Status 对象里的字面量拼写错误仍报
	const bad = lintContent(RF, JSON.stringify({ Status: { State: 'Enabled ', Health: 'Bad' } }));
	assert.equal(rfindings_count(bad, 'RF-ENUM'), 2, '普通 Status 字面量错误仍应报');
	// 索引变体直通块:"Health": "Health[#INDEX]"(块内 Presence/Name 同为 [#INDEX] 引用)
	const idx = lintContent(RF, JSON.stringify({ Destination: { Presence: 'Presence[#INDEX]', Health: 'Health[#INDEX]', Name: 'Name[#INDEX]' } }));
	assert.ok(!rulesOf(idx).has('RF-ENUM'), '[#INDEX] 索引引用应豁免');
});

test('RF-ODATA-TYPE 豁免模板计算类型(${Statements/GetCertOdataType()})', () => {
	const r = lintContent(RF, JSON.stringify(wrapIfaces(
		{ '@odata.type': '${Statements/GetCertOdataType()}', Id: '${Uri/id}', Name: 'Manager CA Certificate', '@odata.id': '/redfish/v1/Managers/${Uri/managerid}/Certificates/${Uri/id}' })));
	assert.ok(!r.findings.some((f) => f.rule === 'RF-ODATA-TYPE'), '动态计算类型应豁免');
});
function rfindings_count(r, rule) { return r.findings.filter((f) => f.rule === rule).length; }
