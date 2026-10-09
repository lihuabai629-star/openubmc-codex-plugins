#!/usr/bin/env node
/**
 * doc-coverage.mjs 单元测试(node:test,零依赖)
 *
 * 覆盖详设 3.3.1 用例表:触发判定 / Redfish 提取(目录+服务级 Uri)/ IPMI 提取(cmds+patch 定位)/
 * 条件一并集与链接隔离 / 条件二 netfn 后缀与 cmd 前缀匹配(含中文文件名)/ evaluate 三态结论 / CLI --stdin。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import {
	detectTriggered,
	extractRedfishResources,
	extractUrisFromPatch,
	extractIpmiCommands,
	hexToHh,
	extractDocPrLinks,
	matchRedfishDoc,
	matchIpmiDoc,
	evaluateCoverage,
} from './doc-coverage.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));

// ---------------- 触发判定 ----------------
test('detectTriggered: redfish 目录路径', () => {
	assert.deepEqual(detectTriggered(['interface_config/redfish/mapping_config/Systems/Bios/config.json']), ['redfish']);
});

test('detectTriggered: mds/ipmi.json', () => {
	assert.deepEqual(detectTriggered(['mds/ipmi.json', 'src/foo.lua']), ['ipmi']);
});

test('detectTriggered: 同一 PR 双触发', () => {
	assert.deepEqual(
		detectTriggered(['interface_config/redfish/mapping_config/Systems/Bios/config.json', 'mds/ipmi.json']),
		['redfish', 'ipmi'],
	);
});

test('detectTriggered: 无关变更不触发(范围外路径)', () => {
	assert.deepEqual(
		detectTriggered(['interface_config/redfish/config.json', 'interface_config/redfish/trim_ipmi.json', 'src/foo.lua', 'docs/x.md']),
		[],
	);
});

// ---------------- Redfish 资源提取 ----------------
test('redfish 目录形态: {Service}/{Resource} 路径段提取', () => {
	const r = extractRedfishResources(['interface_config/redfish/mapping_config/Systems/Bios/config.json']);
	assert.equal(r.resources.length, 1);
	assert.equal(r.resources[0].service, 'Systems');
	assert.equal(r.resources[0].resource, 'Bios');
	assert.deepEqual(r.unmatchedFiles, []);
});

test('redfish 服务级文件: Actions.json 真实样例——动作 URI(主语≠服务名)归待人工,不产出资源', () => {
	const content = JSON.stringify({
		Resources: [
			{ Uri: '/redfish/v1/Systems/:systemid/Actions/ComputerSystem.Reset', ReqBody: {} },
			{ Uri: '/redfish/v1/Systems/:systemid/Actions/ComputerSystem.SetDefaultBootOrder' },
		],
	});
	const r = extractRedfishResources(['interface_config/redfish/mapping_config/Systems/Actions.json'], { 'interface_config/redfish/mapping_config/Systems/Actions.json': content });
	assert.equal(r.resources.length, 0); // 动作 URI 不再产出伪资源(真实语料回归:Systems/ComputerSystem 误报)
	assert.equal(r.manualActions.length, 2);
	assert.ok(r.manualActions.every((m) => m.kind === 'redfish-action-uri'));
});

test('redfish 服务级文件: 普通资源 Uri 取最后大写段', () => {
	const content = JSON.stringify({ Resources: [{ Uri: '/redfish/v1/Chassis/1/Power' }] });
	const r = extractRedfishResources(['interface_config/redfish/mapping_config/Chassis/Power.json'], { 'interface_config/redfish/mapping_config/Chassis/Power.json': content });
	assert.equal(r.resources[0].resource, 'Power');
});

test('redfish 服务级文件: collection 根 Uri(资源名=service)归待人工确认', () => {
	const content = JSON.stringify({ Resources: [{ Uri: '/redfish/v1/Systems' }] });
	const r = extractRedfishResources(['interface_config/redfish/mapping_config/Systems/index.json'], { 'interface_config/redfish/mapping_config/Systems/index.json': content });
	assert.deepEqual(r.resources, []);
	assert.deepEqual(r.unmatchedFiles, []);
	// 动作主语与服务同名(含 collection 根/Service.X 动作)的 Uri 不再静默丢弃,转入待人工
	assert.equal(r.manualActions.length, 1);
	assert.equal(r.manualActions[0].kind, 'redfish-action-uri');
	assert.equal(r.manualActions[0].uri, '/redfish/v1/Systems');
});

test('redfish 服务级文件: 内容缺失 → 待人工确认;非法 JSON → skippedFiles', () => {
	const missing = extractRedfishResources(['interface_config/redfish/mapping_config/Systems/Actions.json']);
	assert.deepEqual(missing.unmatchedFiles, ['interface_config/redfish/mapping_config/Systems/Actions.json']);
	const broken = extractRedfishResources(['interface_config/redfish/mapping_config/Systems/Actions.json'], { 'interface_config/redfish/mapping_config/Systems/Actions.json': '{<<CONFLICT>>' });
	assert.deepEqual(broken.skippedFiles, [{ file: 'interface_config/redfish/mapping_config/Systems/Actions.json', reason: 'parse-error' }]);
});

test('redfish 映射规则外形态(mapping_config 根下文件)归待人工确认', () => {
	const r = extractRedfishResources(['interface_config/redfish/mapping_config/readme.txt']);
	assert.deepEqual(r.unmatchedFiles, ['interface_config/redfish/mapping_config/readme.txt']);
});

// ---------------- IPMI 命令提取 ----------------
const IPMI_JSON = JSON.stringify({
	cmds: {
		GetPEFCapabilities: { netfn: '0x04', cmd: '0x10' },
		SetPEFConfiguration: { netfn: '0x04', cmd: '0x11' },
		GetChassisStatus: { netfn: '0x00', cmd: '0x01' },
	},
}, null, 2);

test('ipmi: patch 缺失 → 保守全量命令', () => {
	const r = extractIpmiCommands(IPMI_JSON, undefined);
	assert.equal(r.scopedByPatch, false);
	assert.equal(r.commands.length, 3);
	assert.equal(r.commands[0].name, 'GetPEFCapabilities');
	assert.equal(r.commands[0].netfn, '0x04');
});

test('ipmi: patch 修改命令体内 netfn 值(键行不在 diff)→ hunk 行号对齐命中', () => {
	// IPMI_JSON 各行:1 {  2 "cmds": {  3 GetPEF...  4..5 体  6 SetPEF... 7..8 体  9 GetChassis...
	// 第 4 行(netfn 值)被修改,属 GetPEFCapabilities 体 [3,5]
	const patch = '@@ -1,9 +1,9 @@\n {\n   "cmds": {\n     "GetPEFCapabilities": {\n-      "netfn": "0x04",\n+      "netfn": "0x0A",\n       "cmd": "0x10"\n     },';
	const r = extractIpmiCommands(IPMI_JSON, patch);
	assert.equal(r.scopedByPatch, true);
	assert.deepEqual(r.commands.map((c) => c.name), ['GetPEFCapabilities']);
});

test('ipmi: patch 纯新增命令(count=0 hunk)→ 增删行键名命中', () => {
	const patch = '@@ -9,0 +10,4 @@\n+    "NewCmd": {\n+      "netfn": "0x06",\n+      "cmd": "0x01"\n+    }';
	const full = JSON.stringify({ cmds: { GetPEFCapabilities: { netfn: '0x04', cmd: '0x10' }, NewCmd: { netfn: '0x06', cmd: '0x01' } } }, null, 2);
	const r = extractIpmiCommands(full, patch);
	assert.deepEqual(r.commands.map((c) => c.name), ['NewCmd']);
});

test('ipmi: 非法 JSON → parse-error;缺 cmds → no-cmds', () => {
	assert.equal(extractIpmiCommands('<<<', '').error, 'parse-error');
	assert.equal(extractIpmiCommands('{"other":1}', '').error, 'no-cmds');
});

test('ipmi: 前部插入命令后,后续命令体修改按 diff 新行号正确归位(旧行号会错位归错的回归)', () => {
	// 旧文件(IPMI_JSON):GetPEF[3,6] SetPEF[7,10] GetChassis[11,14]
	// 新文件(前插 NewCmd 4 行):NewCmd[3,6] GetPEF[7,10] SetPEF[11,14] GetChassis[15,18]
	// hunk2 修改 GetChassis 的 netfn:旧行 12(旧逻辑对新区间 [11,14] 会错归 SetPEF),新行 16
	const full = JSON.stringify({
		cmds: {
			NewCmd: { netfn: '0x06', cmd: '0x02' },
			GetPEFCapabilities: { netfn: '0x04', cmd: '0x10' },
			SetPEFConfiguration: { netfn: '0x04', cmd: '0x11' },
			GetChassisStatus: { netfn: '0x0A', cmd: '0x01' },
		},
	}, null, 2);
	const patch = [
		'@@ -2,3 +2,7 @@',
		' "cmds": {',
		'+    "NewCmd": {',
		'+      "netfn": "0x06",',
		'+      "cmd": "0x02"',
		'+    },',
		'     "GetPEFCapabilities": {',
		'@@ -11,4 +15,4 @@',
		'     "GetChassisStatus": {',
		'-      "netfn": "0x00",',
		'+      "netfn": "0x0A",',
		'       "cmd": "0x01"',
		'     }',
	].join('\n');
	const r = extractIpmiCommands(full, patch);
	assert.equal(r.scopedByPatch, true);
	assert.deepEqual(r.commands.map((c) => c.name).sort(), ['GetChassisStatus', 'NewCmd']);
});

test('ipmi: 命令体行被删除(带上下文)→ 锚定前一条上下文新行号命中该命令', () => {
	// 删除 GetChassisStatus 的 netfn 行(旧行 12),上下文行 11(键行)为锚点 → 落区间 [11,14]
	const patch = [
		'@@ -11,4 +11,3 @@',
		'     "GetChassisStatus": {',
		'-      "netfn": "0x00",',
		'       "cmd": "0x01"',
		'     }',
	].join('\n');
	const r = extractIpmiCommands(IPMI_JSON, patch);
	assert.equal(r.scopedByPatch, true);
	assert.deepEqual(r.commands.map((c) => c.name), ['GetChassisStatus']);
});

test('回归 sensor_mgmt #134: cmds 末尾追加命令,补逗号的结构行不把上一条命令拖进检查对象', () => {
	// 真实形态:head 中 GetTemperatureReadings 是原最后一条命令,patch 在其后追加 GetDocSyncVerify,
	// diff 首个 + 行 `+        },`(上一条命令闭合括号补逗号)落在上一命令区间内——修复前会把
	// 已文档化的 GetTemperatureReadings 误报为"涉及 2 条命令"
	const head = [
		'{',
		'  "cmds": {',
		'    "GetTemperatureReadings": {',
		'      "netfn": "0x2C",',
		'      "cmd": "0x10",',
		'      "rsp": [',
		'                {"data": "TempDataCount", "baseType": "U8", "len": "1B"},',
		'                {"data": "TempData", "baseType":"String", "len":"*"}',
		'            ]',
		'        },',
		'        "GetDocSyncVerify": {',
		'            "netfn": "0x04",',
		'            "cmd": "0x2C",',
		'            "rsp": [',
		'                {"data": "CompletionCode", "baseType": "U8", "len": "1B"}',
		'            ]',
		'        }',
		'    }',
		'}',
	].join('\n');
	const patch = [
		'@@ -847,6 +847,17 @@',
		'                 {"data": "TempDataCount", "baseType": "U8", "len": "1B"},',
		'                 {"data": "TempData", "baseType":"String", "len":"*"}',
		'             ]',
		'+        },',
		'+        "GetDocSyncVerify": {',
		'+            "netfn": "0x04",',
		'+            "cmd": "0x2C",',
		'+            "rsp": [',
		'+                {"data": "CompletionCode", "baseType": "U8", "len": "1B"}',
		'+            ]',
		'+        }',
		'         }',
		'     }',
		' }',
	].join('\n');
	const r = extractIpmiCommands(head, patch);
	assert.equal(r.scopedByPatch, true);
	assert.deepEqual(r.commands.map((c) => c.name), ['GetDocSyncVerify']); // 仅新增命令涉及
	assert.deepEqual(r.deletedCommands, []);
});

test('ipmi: cmds 末尾整删命令,Prev 闭合括号去逗号的结构行不把 Prev 拖进检查对象', () => {
	// 删除最后一条命令 Last:Prev 的 `},` 变 `}`(diff 中 `-        },` + `+        }`),
	// 修复前 `-        },` 锚定到上一条上下文行落在 Prev 区间 → Prev 被误标涉及
	const head = [
		'{',
		'  "cmds": {',
		'    "Prev": {',
		'      "netfn": "0x06",',
		'      "cmd": "0x01",',
		'      "rsp": [',
		'                {"data": "CompletionCode", "baseType": "U8", "len": "1B"}',
		'            ]',
		'        }',
		'    }',
		'}',
	].join('\n');
	const patch = [
		'@@ -8,11 +8,6 @@',
		'             ]',
		'-        },',
		'-        "Last": {',
		'-            "netfn": "0x0A",',
		'-            "cmd": "0x02"',
		'-        }',
		'+        }',
		'     }',
		' }',
	].join('\n');
	const r = extractIpmiCommands(head, patch);
	assert.equal(r.scopedByPatch, true);
	assert.deepEqual(r.commands.map((c) => c.name), []); // Prev 不涉及
	assert.deepEqual(r.deletedCommands, ['Last']); // 被整删命令显式转待人工
});

// ---------------- hexToHh ----------------
test('hexToHh: 0x 前缀规范化为 docs 命名形态', () => {
	assert.equal(hexToHh('0x04'), '04h');
	assert.equal(hexToHh('0x4'), '04h');
	assert.equal(hexToHh('0x0A'), '0ah');
	assert.equal(hexToHh('0X10'), '10h');
	assert.equal(hexToHh('4'), null);
	assert.equal(hexToHh(''), null);
});

// ---------------- 条件一链接提取 ----------------
test('extractDocPrLinks: pull/merge_requests 多链接去重,非 docs 仓不匹配', () => {
	const body = [
		'关联文档: https://gitcode.com/openUBMC/docs/pull/135',
		'另一个 https://gitcode.com/openUBMC/docs/merge_requests/200',
		'重复 https://gitcode.com/openUBMC/docs/pull/135',
		'代码仓 https://gitcode.com/openUBMC/rackmount/pull/9',
	].join('\n');
	assert.deepEqual(extractDocPrLinks(body), ['135', '200']);
});

test('extractDocPrLinks: 其它 owner 的 */docs 链接不匹配(编号碰撞会误判覆盖)', () => {
	const body = [
		'参考: https://gitcode.com/someone/docs/pull/9',
		'fork: https://gitcode.com/gcjoke/docs/merge_requests/135',
		'官方: https://gitcode.com/openUBMC/docs/pull/135',
	].join('\n');
	assert.deepEqual(extractDocPrLinks(body), ['135']);
});

// ---------------- 覆盖匹配 ----------------
const REDFISH_TREE = ['docs/zh/development/specifications/redfish/details/Systems/Bios.md', 'docs/zh/development/specifications/redfish/details/Systems/ComputerSystem.md'];
const IPMI_TREE = ['docs/zh/development/specifications/ipmi/details/SE-04h/10h-获取PEF能力.md', 'docs/zh/development/specifications/ipmi/details/Storage-0Ch/01h-获取仓储信息.md'];

test('matchRedfishDoc: 精确命中与未命中', () => {
	assert.equal(matchRedfishDoc(REDFISH_TREE, 'Systems', 'Bios'), true);
	assert.equal(matchRedfishDoc(REDFISH_TREE, 'Systems', 'EthernetInterfaces'), false);
});

test('matchIpmiDoc: netfn 目录后缀 + cmd 文件前缀,中文文件名可匹配', () => {
	assert.equal(matchIpmiDoc(IPMI_TREE, '0x04', '0x10'), true);
	assert.equal(matchIpmiDoc(IPMI_TREE, '0x0c', '0x01'), true); // 大写 0x0C → 0ch 命中 Storage-0Ch
	assert.equal(matchIpmiDoc(IPMI_TREE, '0x04', '0x99'), false);
	assert.equal(matchIpmiDoc(IPMI_TREE, '0x4', '0x10'), true);
});

// ---------------- evaluateCoverage ----------------
test('UC-01 条件二通过: docs 主干已覆盖 → pass', () => {
	const r = evaluateCoverage({
		changedFiles: ['interface_config/redfish/mapping_config/Systems/Bios/config.json'],
		docsTree: REDFISH_TREE,
	});
	assert.equal(r.conclusion, 'pass');
	assert.equal(r.coverage[0].cond2, true);
	assert.equal(r.coverage[0].covered, true);
});

test('UC-02 条件一通过: 描述附文档 PR 链接,多 PR 取并集', () => {
	const r = evaluateCoverage({
		prBody: '文档: https://gitcode.com/openUBMC/docs/pull/135 和 https://gitcode.com/openUBMC/docs/pull/200',
		changedFiles: [
			'interface_config/redfish/mapping_config/Systems/Bios/config.json',
			'interface_config/redfish/mapping_config/Chassis/Power/config.json',
		],
		docsTree: [],
		docsPrFiles: { 135: ['docs/zh/development/specifications/redfish/details/Systems/Bios.md'], 200: ['docs/zh/development/specifications/redfish/details/Chassis/Power.md'] },
	});
	assert.equal(r.conclusion, 'pass');
	assert.ok(r.coverage.every((c) => c.cond1 && c.covered));
	assert.equal(r.coverage[0].cond1Via, 'docs#135');
	assert.equal(r.coverage[1].cond1Via, 'docs#200');
});

test('UC-03 未覆盖点名: 两条件均未命中 → uncovered', () => {
	const r = evaluateCoverage({
		changedFiles: ['interface_config/redfish/mapping_config/Systems/EthernetInterfaces/config.json'],
		docsTree: REDFISH_TREE,
	});
	assert.equal(r.conclusion, 'uncovered');
	assert.equal(r.coverage[0].covered, false);
	assert.equal(r.coverage[0].key, 'Systems/EthernetInterfaces');
});

test('UC-04 无接口变更 → skipped 且不产资源', () => {
	const r = evaluateCoverage({ changedFiles: ['src/foo.lua', 'README.md'], docsTree: REDFISH_TREE });
	assert.equal(r.conclusion, 'skipped');
	assert.deepEqual(r.triggered, []);
});

test('UC-05 链接无效隔离: docs PR 404 → invalidLinks,条件二继续', () => {
	const r = evaluateCoverage({
		prBody: '文档: https://gitcode.com/openUBMC/docs/pull/999',
		changedFiles: ['interface_config/redfish/mapping_config/Systems/Bios/config.json'],
		docsTree: REDFISH_TREE,
		docsPrFiles: { 999: null },
	});
	assert.deepEqual(r.invalidLinks, ['999']);
	assert.equal(r.coverage[0].cond1, false);
	assert.equal(r.coverage[0].cond2, true);
	assert.equal(r.conclusion, 'pass'); // 条件二兜住
});

test('UC-06 docs 不可达降级: docsTree=null → incomplete,退出语义不阻塞', () => {
	const r = evaluateCoverage({
		changedFiles: ['interface_config/redfish/mapping_config/Systems/Bios/config.json'],
		docsTree: null,
	});
	assert.equal(r.conclusion, 'incomplete');
	assert.equal(r.coverage[0].cond2, null);
});

test('UC-07 IPMI 端到端: 命令提取 + SE-04h/10h 中文文档匹配', () => {
	const r = evaluateCoverage({
		changedFiles: ['mds/ipmi.json'],
		fileContents: { 'mds/ipmi.json': IPMI_JSON },
		patchText: { 'mds/ipmi.json': '@@ -3,3 +3,4 @@\n     "GetPEFCapabilities": {\n       "netfn": "0x04",\n-      "cmd": "0x10"\n+      "cmd": "0x10",\n+      "new": 1' },
		docsTree: IPMI_TREE,
	});
	assert.deepEqual(r.triggered, ['ipmi']);
	assert.equal(r.coverage.length, 1);
	assert.equal(r.coverage[0].key, '04h/10h-GetPEFCapabilities');
	assert.equal(r.coverage[0].cond2, true);
	assert.equal(r.conclusion, 'pass');
});

test('evaluate: 条件一覆盖但 docsTree 缺失仍可为 pass(满足其一即过)', () => {
	const r = evaluateCoverage({
		prBody: 'https://gitcode.com/openUBMC/docs/pull/135',
		changedFiles: ['interface_config/redfish/mapping_config/Systems/Bios/config.json'],
		docsTree: null,
		docsPrFiles: { 135: ['docs/zh/development/specifications/redfish/details/Systems/Bios.md'] },
	});
	assert.equal(r.conclusion, 'pass');
});

test('evaluate: 资源全空且有待人工项 → incomplete', () => {
	const r = evaluateCoverage({
		changedFiles: ['interface_config/redfish/mapping_config/Systems/Actions.json'],
		docsTree: REDFISH_TREE,
	});
	assert.equal(r.conclusion, 'incomplete');
	assert.deepEqual(r.unmatchedFiles, ['interface_config/redfish/mapping_config/Systems/Actions.json']);
});

test('evaluate: headSha 透传(幂等标识)', () => {
	const r = evaluateCoverage({ changedFiles: ['src/a.lua'], headSha: 'abc123' });
	assert.equal(r.headSha, 'abc123');
});

// ---------------- CLI --stdin(集成冒烟,详设 3.3.2) ----------------
test('CLI --stdin: 端到端输出结论 JSON,退出码恒 0(含 incomplete 场景)', () => {
	const input = {
		changedFiles: ['interface_config/redfish/mapping_config/Systems/Bios/config.json'],
		docsTree: null,
		headSha: 'deadbeef',
	};
	const res = spawnSync(process.execPath, [path.join(here, 'doc-coverage.mjs'), '--stdin'], { input: JSON.stringify(input), encoding: 'utf8' });
	assert.equal(res.status, 0, `stderr: ${res.stderr}`);
	const out = JSON.parse(res.stdout);
	assert.equal(out.conclusion, 'incomplete');
	assert.equal(out.headSha, 'deadbeef');
});

test('CLI --stdin: 非法 JSON → 程序性错误退出码 1', () => {
	const res = spawnSync(process.execPath, [path.join(here, 'doc-coverage.mjs'), '--stdin'], { input: 'not-json', encoding: 'utf8' });
	assert.equal(res.status, 1);
});

// ---------------- 真实语料回归(Richardli25 深度检视 P1/P2/P3 修复固化) ----------------
// 路径/命名取自 openUBMC/docs main 真实树:OEM-30h/Cmd-XXh 三级嵌套、Role.md+RoleCollection.md
// 混合命名、AccountService 下无 *ActionInfo 文档(动作内联父文档)。

const REAL_DOCS_TREE = [
	'docs/zh/development/specifications/ipmi/details/OEM-30h/Cmd-90h/90h-获取系统SEL信息2（OEMGetSystemSel2）.md',
	'docs/zh/development/specifications/ipmi/details/OEM-30h/Cmd-90h/00h-设置MAC地址（Write-MAC-Address）.md',
	'docs/zh/development/specifications/ipmi/details/SE-04h/10h-获取PEF能力.md',
	'docs/zh/development/specifications/redfish/details/AccountService/AccountService.md',
	'docs/zh/development/specifications/redfish/details/AccountService/Accounts.md',
	'docs/zh/development/specifications/redfish/details/AccountService/Role.md',
	'docs/zh/development/specifications/redfish/details/AccountService/RoleCollection.md',
];

test('真实语料: OEM NetFn(0x30)三级嵌套路径可命中(修复前 0x30 全量误报未覆盖)', () => {
	assert.equal(matchIpmiDoc(REAL_DOCS_TREE, '0x30', '0x90'), true); // OEMGetSystemSel2
	assert.equal(matchIpmiDoc(REAL_DOCS_TREE, '0x30', '0x00'), true); // Write-MAC-Address
	assert.equal(matchIpmiDoc(REAL_DOCS_TREE, '0x30', '0xE2'), false); // OEM-30h 无 Cmd-E2h 时如实未覆盖
});

test('真实语料: Roles 混合命名经候选集回退命中 Role.md/RoleCollection.md', () => {
	assert.equal(matchRedfishDoc(REAL_DOCS_TREE, 'AccountService', 'Roles'), true); // 回退 Role.md
	assert.equal(matchRedfishDoc(REAL_DOCS_TREE, 'AccountService', 'Accounts'), true); // 复数直文精确命中
	assert.equal(matchRedfishDoc(REAL_DOCS_TREE, 'AccountService', 'Kerberos'), false); // 单数形态文档不存在
});

test('真实语料: *ActionInfo 资源不产出覆盖判定,转待人工(docs 惯例内联父资源文档)', () => {
	// 目录形态
	const r1 = extractRedfishResources(['interface_config/redfish/mapping_config/AccountService/ImportRootCertificateActionInfo/config.json']);
	assert.deepEqual(r1.resources, []);
	assert.equal(r1.manualActions.filter((m) => m.kind === 'redfish-actioninfo').length, 1);
	// 服务级文件 Uri 提取
	const content = JSON.stringify({ Resources: [{ Uri: '/redfish/v1/AccountService/Accounts/1/ImportRootCertificateActionInfo' }] });
	const r2 = extractRedfishResources(['interface_config/redfish/mapping_config/AccountService/Action.json'], { 'interface_config/redfish/mapping_config/AccountService/Action.json': content });
	assert.deepEqual(r2.resources, []); // ActionInfo 不进覆盖比对
	assert.ok(r2.manualActions.some((m) => m.kind === 'redfish-actioninfo' && m.resource === 'ImportRootCertificateActionInfo'));
});

test('真实语料: 动作主语与服务同名(Service.X)的 Uri 不再静默丢弃,转待人工', () => {
	const content = JSON.stringify({ Resources: [{ Uri: '/redfish/v1/AccountService/Actions/AccountService.ImportRootCertificate' }] });
	const r = extractRedfishResources(['interface_config/redfish/mapping_config/AccountService/Actions.json'], { 'interface_config/redfish/mapping_config/AccountService/Actions.json': content });
	assert.deepEqual(r.resources, []);
	assert.equal(r.manualActions.filter((m) => m.kind === 'redfish-action-uri').length, 1);
});

test('真实语料: 整删命令(dcmid SetAssetTag 场景)被删命令转待人工,不误归上一命令', () => {
	// head(删除后):GetAssetTag 之后直接是 SetBIOSEventData(与真实 dcmid main 结构一致)
	const head = JSON.stringify({
		cmps: { version: '1.0' },
		cmds: {
			GetAssetTag: { netfn: '0x2c', cmd: '0x06' },
			SetBIOSEventData: { netfn: '0x30', cmd: '0x92' },
		},
	}, null, 2);
	const patch = [
		'@@ -10,9 +10,6 @@',
		'   "cmds": {',
		'     "GetAssetTag": {',
		'       "netfn": "0x2c",',
		'-    "SetAssetTag": {',
		'-      "netfn": "0x2c",',
		'-      "cmd": "0x08"',
		'     },',
		'     "SetBIOSEventData": {',
	].join('\n');
	const r = extractIpmiCommands(head, patch);
	assert.deepEqual(r.commands.map((c) => c.name), []); // GetAssetTag 未被修改,不得误报
	assert.deepEqual(r.deletedCommands, ['SetAssetTag']); // 被整删命令显式可见
});

test('真实语料: netfn/cmd 非 0x 形态 → cond2 null 透传,结论 incomplete 待人工(不臆断未覆盖)', () => {
	const content = JSON.stringify({ cmds: { WeirdCmd: { netfn: '30', cmd: 16 } } }); // 十进制/数字形态
	const r = evaluateCoverage({
		changedFiles: ['mds/ipmi.json'],
		fileContents: { 'mds/ipmi.json': content },
		patchText: { 'mds/ipmi.json': '@@ -1,3 +1,3 @@\n {\n-  "cmds": {}\n+  "cmds": {\n+    "WeirdCmd": { "netfn": "30", "cmd": 16 }\n+  }\n }' },
		docsTree: ['docs/zh/development/specifications/ipmi/details/SE-04h/10h-获取PEF能力.md'],
		docsPrFiles: {},
	});
	assert.equal(r.conclusion, 'incomplete');
	assert.equal(r.coverage[0].cond2, null);
});

test('真实语料: 仅改 cmds 之外的尾部键,最后一条命令不被误点名(区间截到姊妹键/闭括号)', () => {
	const lines = [
		'{',
		'  "mds": { "version": "1.0" },',
		'  "cmds": {',
		'    "GetPEFCapabilities": {',
		'      "netfn": "0x04",',
		'      "cmd": "0x10"',
		'    },',
		'    "SetPEFConfig": {',
		'      "netfn": "0x04",',
		'      "cmd": "0x11"',
		'    }',
		'  },',
		'  "extra_meta": { "flag": true }',
		'}',
	].join('\n');
	const patch = [
		'@@ -12,4 +12,4 @@',
		'   },',
		'-  "extra_meta": { "flag": false }',
		'+  "extra_meta": { "flag": true }',
		' }',
	].join('\n');
	const r = extractIpmiCommands(lines, patch);
	assert.deepEqual(r.commands, []); // SetPEFConfig 是最后一条命令,尾部元数据变更不得误点名
});

test('真实语料: 已关闭未合入的 docs PR 置 null → invalidLinks,条件二独立判定', () => {
	const r = evaluateCoverage({
		prBody: '关联文档: https://gitcode.com/openUBMC/docs/pull/999',
		changedFiles: ['interface_config/redfish/mapping_config/Systems/Bios/config.json'],
		docsTree: ['docs/zh/development/specifications/redfish/details/Systems/Bios.md'],
		docsPrFiles: { '999': null }, // 语义层按 state!=open 置 null
	});
	assert.deepEqual(r.invalidLinks, ['999']);
	assert.equal(r.coverage[0].covered, true); // 条件二独立兜住
});

test('真实语料: 目录形态与服务级文件产出同一资源时去重(检查对象计数不虚高)', () => {
	const files = [
		'interface_config/redfish/mapping_config/AccountService/Accounts/config.json',
		'interface_config/redfish/mapping_config/AccountService/Accounts.json',
	];
	const content = JSON.stringify({ Resources: [{ Uri: '/redfish/v1/AccountService/Accounts' }] });
	const r = evaluateCoverage({
		changedFiles: files,
		fileContents: { 'interface_config/redfish/mapping_config/AccountService/Accounts.json': content },
		docsTree: ['docs/zh/development/specifications/redfish/details/AccountService/Accounts.md'],
		docsPrFiles: {},
	});
	assert.equal(r.coverage.filter((c) => c.key === 'AccountService/Accounts').length, 1);
});

test('真实语料: URI 尾段为模板参数/OData 函数 → redfish-malformed-uri 待人工,不产出伪资源', () => {
	const content = JSON.stringify({
		Resources: [
			{ Uri: '/redfish/v1/Chassis/Expansion:id' }, // 真实语料:模板参数与资源名同段(段内冒号)
			{ Uri: '/redfish/v1/$metadata/UriNode()}' },
			{ Uri: '/redfish/v1/Chassis/1/Power' },
		],
	});
	const r = extractRedfishResources(['interface_config/redfish/mapping_config/Chassis/Expansion.json'], { 'interface_config/redfish/mapping_config/Chassis/Expansion.json': content });
	assert.equal(r.resources.length, 1); // 仅 Power 是干净资源名
	assert.equal(r.resources[0].resource, 'Power');
	const kinds = r.manualActions.map((m) => m.kind).sort();
	assert.deepEqual(kinds, ['redfish-malformed-uri', 'redfish-malformed-uri']);
});

test('真实语料: 根级框架文件存量条目不产出资源——无 patch 时转 redfish-framework-file 待人工(不静默放行)', () => {
	const files = [
		'interface_config/redfish/mapping_config/v1.json',
		'interface_config/redfish/mapping_config/Metadata.json',
		'interface_config/redfish/mapping_config/Odata.json',
		'interface_config/redfish/mapping_config/Schemas.json',
	];
	// 场景一:无 patchText(如输入组装遗漏)→ 4 个框架文件各产出一条待人工,不产出资源、不静默 pass
	const r1 = extractRedfishResources(files, { 'interface_config/redfish/mapping_config/v1.json': JSON.stringify({ Resources: [{ Uri: '/redfish/v1/$metadata/GetId()}' }] }) });
	assert.equal(r1.resources.length, 0);
	assert.equal(r1.unmatchedFiles.length, 0); // 框架文件不进 unmatched,与 config.json/trim_* 同通道
	assert.equal(r1.manualActions.length, 4);
	assert.ok(r1.manualActions.every((m) => m.kind === 'redfish-framework-file'));
	// 场景二:patch 只动存量框架条目(改 RspBody 模板,未新增 Uri)→ 零清单项(存量框架 URI 本就不该判资源)
	const r2 = extractRedfishResources(['interface_config/redfish/mapping_config/v1.json'], {}, {
		'interface_config/redfish/mapping_config/v1.json': [
			'@@ -10,4 +10,4 @@',
			'     "Resources": [',
			'       {',
			'-        "RspBody": "${Statements/GetOdata()}"',
			'+        "RspBody": "${Statements/GetOdata(1)}"',
		].join('\n'),
	});
	assert.equal(r2.resources.length, 0);
	assert.equal(r2.manualActions.length, 0); // 有 patch 且新增行无 Uri → 无产出;其余 3 文件无 patch 也不该出现
	assert.deepEqual(extractUrisFromPatch('+++ b/x.json\n+  "Uri": "/redfish/v1/odata"\n+ "URI": "/redfish/v1/$metadata"'), ['/redfish/v1/odata', '/redfish/v1/$metadata']);
});

test('回归 rackmount #1456: Odata.json patch 新增资源条目 → 检出为待覆盖资源(修复静默漏报)', () => {
	// 真实形态摘录:在 Resources 数组追加 { "Uri": "/redfish/v1/Managers/1/DocSyncVerify", "Interfaces": [...] }
	const patch = [
		'diff --git a/interface_config/redfish/mapping_config/Odata.json b/interface_config/redfish/mapping_config/Odata.json',
		'--- a/interface_config/redfish/mapping_config/Odata.json',
		'+++ b/interface_config/redfish/mapping_config/Odata.json',
		'@@ -12,6 +12,25 @@',
		'     "Resources": [',
		'       {',
		'         "Uri": "/redfish/v1/odata",',
		'+      {',
		'+        "Uri": "/redfish/v1/Managers/1/DocSyncVerify",',
		'+        "Interfaces": [',
		'+          { "Type": "GET" }',
		'+        }',
		'+      }',
		'       }',
	].join('\n');
	const r = evaluateCoverage({
		prBody: '',
		changedFiles: ['interface_config/redfish/mapping_config/Odata.json'],
		fileContents: { 'interface_config/redfish/mapping_config/Odata.json': JSON.stringify({ Resources: [{ Uri: '/redfish/v1/odata' }, { Uri: '/redfish/v1/Managers/1/DocSyncVerify' }] }) },
		patchText: { 'interface_config/redfish/mapping_config/Odata.json': patch },
		docsTree: ['docs/zh/development/specifications/redfish/details/Managers/Managers.md'], // 不含 DocSyncVerify
		docsPrFiles: {},
		headSha: '02a5d5de',
	});
	assert.equal(r.conclusion, 'uncovered');
	const hit = r.coverage.find((c) => c.key === 'Odata/DocSyncVerify');
	assert.ok(hit, '应产出 Odata/DocSyncVerify 资源项');
	assert.equal(hit.covered, false);
	// 同一 Uri 若在 docs PR 条件一里覆盖 → 结论回升 pass(正例闭环)
	const r2 = evaluateCoverage({
		prBody: 'docs: gitcode.com/openUBMC/docs/pull/201',
		changedFiles: ['interface_config/redfish/mapping_config/Odata.json'],
		patchText: { 'interface_config/redfish/mapping_config/Odata.json': patch },
		docsTree: [],
		docsPrFiles: { '201': ['docs/zh/development/specifications/redfish/details/Odata/DocSyncVerify.md'] },
		headSha: '02a5d5de',
	});
	assert.equal(r2.conclusion, 'pass');
});

test('真实语料: Actions 动作目录形态 → redfish-action-dir 待人工(rackmount UpdateService/Actions 真实形态)', () => {
	const r = extractRedfishResources([
		'interface_config/redfish/mapping_config/UpdateService/Actions/FullImageUpdate.json',
		'interface_config/redfish/mapping_config/UpdateService/Actions/StartActivate.json',
	]);
	assert.equal(r.resources.length, 0);
	assert.equal(r.manualActions.length, 1); // 同服务 Actions 目录去重为一条
	assert.equal(r.manualActions[0].kind, 'redfish-action-dir');
	assert.equal(r.manualActions[0].service, 'UpdateService');
});

test('真实语料: docs 命名四种形态候选集——单数 URI 命复数文 / 不带 s 资源配 Collection', () => {
	const tree = [
		'docs/zh/development/specifications/redfish/details/Managers/Managers.md', // Manager → Managers.md
		'docs/zh/development/specifications/redfish/details/Managers/VirtualMediaCollection.md', // VirtualMedia → *Collection.md
		'docs/zh/development/specifications/redfish/details/Systems/Storages.md', // Storage → Storages.md
	];
	assert.equal(matchRedfishDoc(tree, 'Managers', 'Manager'), true);
	assert.equal(matchRedfishDoc(tree, 'Managers', 'VirtualMedia'), true);
	assert.equal(matchRedfishDoc(tree, 'Systems', 'Storage'), true);
	assert.equal(matchRedfishDoc(tree, 'Systems', 'Nonexistent'), false); // 回退不虚命中
});
