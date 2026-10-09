#!/usr/bin/env node
/**
 * compliance-lint.mjs —— IPMI/Redfish/mdb 机械合规 linter
 *
 * 纯 Node 标准库,零运行时依赖;随 skill 自包含分发,供流水线/CI/agent 直接 `node` 调用。
 *
 * 用法:
 *   node compliance-lint.mjs --files a.json b.json        # 对本地文件跑,errors>0 退出码 1(可作 CI 门禁)
 *   node compliance-lint.mjs --stdin --scope mdb < f.json  # 从 stdin 读单个文件;stdin 无路径可自动分流,必须显式 --scope(缺省报错退出 2)
 * 输出:JSON { findings, summary, coverage } 到 stdout。
 *
 * 设计边界(与同目录 gitcode_cli.py 分工):
 *   - 数据层(gitcode_cli.py):拉 PR/files/设计帖、提交评论。
 *   - 机械层(本脚本):对 JSON 文本跑确定性规则,产 findings。纯函数,可单测。
 *   - 语义层(SKILL.md):设计一致性、签名对照等由 AI 判断。
 * coverage.semanticNeeded=true 即提示:lint 仅覆盖基线,**lint 无 finding ≠ 合规**。
 */
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

// ---------------- 常量 ----------------
const SCALAR_BASE_TYPES = new Set(['Boolean', 'U8', 'U16', 'U32', 'U64', 'S16', 'S32', 'S64', 'Double', 'String']);
const ALL_BASE_TYPES = new Set([...SCALAR_BASE_TYPES, 'Struct', 'Enum', 'Array', 'Dictionary']);
const EMITS_ALLOWED = new Set(['true', 'false', 'const', 'invalidates']);
const HEALTH_SET = new Set(['OK', 'Warning', 'Critical']);
// DMTF Resource.State 现行枚举(DSP0266 / Redfish Schema),含 Degraded/Qualified
const STATE_SET = new Set(['Enabled', 'Disabled', 'StandbyOffline', 'StandbySpare', 'InTest', 'Starting', 'Absent', 'UnavailableOffline', 'Deferring', 'Quiesced', 'Updating', 'Degraded', 'Qualified']);
// @odata.type 三种合法形态(DMTF DSP0266 §9.6.3 + 真实 rackmount 语料):
//   #Type.vX_Y_Z(中间形态)/ #Type.vX_Y_Z.Entity(资源标准全形态,如 #ManagerAccount.v1_11_0.ManagerAccount)/
//   #XCollection.XCollection(Collection 无版本形态)
//   要求 '#' 前缀 + 至少一段 '.'(裸 #Type 与无 '#' 前缀不合法)
const ODATA_RE = /^#[A-Za-z][A-Za-z0-9]*(\.v\d+_\d+_\d+)?(\.[A-Za-z][A-Za-z0-9]*)?$/;
const isOdataTypeOk = (v) => ODATA_RE.test(v) && v.includes('.');
// mdb 域名段允许大小写厂商名(真实 mdb_interface: bmc/ 下 Baidu/ByteDance/CMCC/JD/Kwai/Tencent 大写、demo/dev/kepler 小写),
// 两段形态 bmc.{域} 是合法的域级接口/域根(如 bmc.dev 带 methods);三段及以上时后段须 PascalCase;
// 对齐官方 interface.schema.json 的宽松段字符集 [A-Za-z0-9_]
const MDB_NAME_RE = /^bmc\.[A-Za-z][A-Za-z0-9_]*(\.[A-Z][A-Za-z0-9_]*)*$/;
const MDB_PATH_RE = /^\/bmc\/[A-Za-z][A-Za-z0-9_]*(\/[^/]+)*$/;
const IPMI_CC_RE = /^0x[0-9A-Fa-f]{2}$/;
// RF-URI 键名:真实 DSL 为驼峰 Uri(rackmount main 普查 Uri×59 / URI×0 / uri×0),兼容另两种防其它仓形态
const RF_URI_KEYS = ['Uri', 'URI', 'uri'];
// Uri 值域豁免(rackmount main 全量普查形态):/redfish 与 /redfish/v1 服务根精确形态;/bmc/(DBus 对象
// 路径,含中段混拼如 /Chassis/:id/Power/bmc/kepler/...);Expand/expand 段(内部展开路径,含无头斜杠的
// Expand/redfish/... 与中段 /StorageId/Expand/:name);${}/{{}} 模板片段——均合法且不指向标准 Redfish 资源
const RF_URI_ROOTS = new Set(['/redfish', '/redfish/v1']);
const isUriExempt = (v) => RF_URI_ROOTS.has(v) || v.includes('/bmc/') || /(^|\/)expand\//i.test(v) || v.includes('${') || v.includes('{{');

function finding(rule, severity, file, line, message, suggestion, snippet) {
	const f = { rule, severity, file, message };
	if (line !== undefined && line !== null) f.line = line;
	if (suggestion) f.suggestion = suggestion;
	if (snippet) f.snippet = snippet;
	return f;
}

// ---------------- scope 分流 ----------------
// win32 反斜杠路径统一归一化为正斜杠后再匹配(否则反斜杠绝对路径会静默 skip、exit 0 假绿)
const normPath = (f) => String(f).replace(/\\/g, '/');

function detectScope(filename) {
	const f = normPath(filename).toLowerCase();
	if (/interface_config\/redfish/.test(f) || /\/redfish\//.test(f)) return 'redfish';
	if (/intf\/mdb/.test(f) || /path\/mdb/.test(f) || /(^|\/)messages\//.test(f) || /mdb_interface/.test(f)) return 'mdb';
	return null;
}
const isIntf = (fn) => /intf\/mdb/.test(normPath(fn).toLowerCase());
const isMsg = (fn) => /(^|\/)messages\//.test(normPath(fn).toLowerCase());
const isPath = (fn) => /path\/mdb/.test(normPath(fn).toLowerCase());
// 显式 --scope 的 guard 等价映射:stdin 等无路径形态按 scope 对应文件类放行对应规则,
// 不再无差别绕过全部 guard(原 `|| scopeOverride` 会令 --scope messages 跑到 MDB-PATH 等 intf 专属规则)
const SCOPE_GUARDS = { mdb: isIntf, messages: isMsg, path: isPath };

// ---------------- 行号索引(best-effort,逐行匹配 "key": value) ----------------
function buildLineIndex(text) {
	const entries = [];
	const re = /"((?:[^"\\]|\\.)*)"\s*:\s*("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/g;
	text.split(/\r?\n/).forEach((line, i) => {
		re.lastIndex = 0;
		let m;
		while ((m = re.exec(line)) !== null) entries.push({ key: m[1], valueRaw: m[2], line: i + 1 });
	});
	return entries;
}
// 消耗式行号查找:同键同值的多次出现按文档序依次配对(重复 @odata.type/枚举值不再全部错指到首次出现处)。
// 未命中时回退全量首查且不推进游标(值转义形态差异等场景仍给 best-effort 行号)。
function makeLineFinder(index) {
	const cursors = new Map();
	return function findLine(key, value) {
		const valueRaw = typeof value === 'string' ? JSON.stringify(value) : String(value);
		const from = cursors.get(key) ?? 0;
		for (let i = from; i < index.length; i++) {
			if (index[i].key === key && index[i].valueRaw === valueRaw) {
				cursors.set(key, i + 1);
				return index[i].line;
			}
		}
		const hit = index.find((e) => e.key === key && e.valueRaw === valueRaw);
		return hit ? hit.line : undefined;
	};
}

// ---------------- AST 遍历工具 ----------------
// 收集任意标量值(不只字符串):baseType/Health/State 等键写成数字/布尔时由规则报"应为字符串"error,
// 不再静默跳过——那恰是该 skill 声称要拦的"机械可判定"形态错误
function collectByKey(obj, keyName, acc = []) {
	if (Array.isArray(obj)) { obj.forEach((i) => collectByKey(i, keyName, acc)); return acc; }
	if (obj && typeof obj === 'object') {
		for (const [k, v] of Object.entries(obj)) {
			if (k === keyName && (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')) acc.push(v);
			if (v && typeof v === 'object') collectByKey(v, keyName, acc);
		}
	}
	return acc;
}
function collectObjectsWith(obj, keyName, acc = []) {
	if (Array.isArray(obj)) { obj.forEach((i) => collectObjectsWith(i, keyName, acc)); return acc; }
	if (obj && typeof obj === 'object') {
		if (keyName in obj) acc.push(obj);
		for (const v of Object.values(obj)) if (v && typeof v === 'object') collectObjectsWith(v, keyName, acc);
	}
	return acc;
}
// 收集"GET 接口 RspBody 顶层对象"——资源元字段(Id/Name/@odata.id)只对 GET 响应的资源体要求完整 triple:
// POST 等写接口的 RspBody(任务/回显响应,如 HwSystemErase 只有 @odata.id+Components)、深层嵌套对象
// (@Redfish.* fragment 如 Settings、数组 member 如 StorageControllers[{MemberId,...}])按真实语料均不要求。
// 文件无 Resources[].Interfaces[] 结构(简单/服务级形态)时 sawInterfaces=false,调用方回退全对象遍历。
function collectGetRspBodies(obj) {
	const bodies = [];
	let sawInterfaces = false;
	(function walk(n, seen) {
		if (!n || typeof n !== 'object' || seen.has(n)) return;
		seen.add(n);
		if (Array.isArray(n)) { n.forEach((i) => walk(i, seen)); return; }
		for (const [k, v] of Object.entries(n)) {
			if (k === 'Interfaces' && Array.isArray(v)) {
				sawInterfaces = true;
				for (const it of v) {
					if (!it || typeof it !== 'object' || !it.RspBody || typeof it.RspBody !== 'object') continue;
					if (!('Type' in it) || it.Type === 'GET') {
						if (Array.isArray(it.RspBody)) it.RspBody.forEach((m) => { if (m && typeof m === 'object' && !Array.isArray(m)) bodies.push(m); });
						else bodies.push(it.RspBody);
					}
				}
			}
			if (v && typeof v === 'object') walk(v, seen);
		}
	})(obj, new WeakSet());
	return { bodies, sawInterfaces };
}
// 收集枚举键条目(带上下文):passthroughBlock 标记同对象内存在 "k":"k" 同名直通对——
// ProcessingFlow/Destination 字段映射块的形态特征(Id:"Id"、Name:"Name"…,含索引变体
// "Name":"Name[#INDEX]"),块内 State/Health 的值是 DBus 源属性名引用(如 "State":"DetectorState"),
// 不是枚举字面量,不应按枚举集合校验
function collectEnumEntries(obj, keys, acc = []) {
	if (Array.isArray(obj)) { obj.forEach((i) => collectEnumEntries(i, keys, acc)); return acc; }
	if (obj && typeof obj === 'object') {
		const passthroughBlock = Object.entries(obj).some(([k2, v2]) => typeof v2 === 'string' && (v2 === k2 || v2.startsWith(k2 + '[')));
		for (const [k, v] of Object.entries(obj)) {
			if (keys.includes(k) && (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')) {
				acc.push({ key: k, val: v, passthroughBlock });
			}
		}
		for (const v of Object.values(obj)) if (v && typeof v === 'object') collectEnumEntries(v, keys, acc);
	}
	return acc;
}

// ---------------- MDB 规则(每条独立 try/catch,异常入 skippedRules) ----------------
const MDB_RULES = [
	{
		id: 'MDB-BASETYP', severity: 'error', guard: isIntf,
		run(ast, { file }) {
			const out = [];
			for (const val of collectByKey(ast, 'baseType')) {
				if (typeof val !== 'string') {
					out.push(finding(this.id, this.severity, file, undefined, `baseType 值应为字符串,实为 ${typeof val}`, 'baseType 须为字符串类型字面量', String(val)));
					continue;
				}
				const isArr = val.endsWith('[]');
				const base = isArr ? val.slice(0, -2) : val;
				const ok = ALL_BASE_TYPES.has(base) && (!isArr || SCALAR_BASE_TYPES.has(base));
				if (!ok) out.push(finding(this.id, this.severity, file, undefined,
					`baseType '${val}' 非法`,
					'合法:Boolean/U8/U16/U32/U64/S16/S32/S64/Double/String/Struct/Enum/Array/Dictionary(仅标量可加 [])', val));
			}
			return out;
		},
	},
	{
		id: 'MDB-NAMING', severity: 'error', guard: isIntf,
		run(ast, { file }) {
			const out = [];
			for (const [k, v] of Object.entries(ast)) {
				if (v && typeof v === 'object' && !Array.isArray(v)
					&& ('properties' in v || 'methods' in v || 'signals' in v) && !MDB_NAME_RE.test(k)) {
					out.push(finding(this.id, this.severity, file, undefined,
						`接口名 '${k}' 不符合命名规范(域段任意大小写、后段须 PascalCase)`,
						'应为 bmc.{域}.{PascalCase}+,如 bmc.kepler.Systems.Power / bmc.CMCC.UpdateService', k));
				}
			}
			return out;
		},
	},
	{
		id: 'MDB-IPMI-CC', severity: 'error', guard: isMsg,
		run(ast, { file }) {
			const out = [];
			for (const val of collectByKey(ast, 'IpmiCompletionCode')) {
				if (typeof val !== 'string') {
					out.push(finding(this.id, this.severity, file, undefined, `IpmiCompletionCode 值应为字符串,实为 ${typeof val}`, '须为 "0xNN" 字符串,数字字面量非法', String(val)));
					continue;
				}
				if (!IPMI_CC_RE.test(val) && val !== 'N/A' && val !== 'NA') {
					out.push(finding(this.id, this.severity, file, undefined,
						`IpmiCompletionCode '${val}' 非法`, '须为 0x00-0xFF(如 0xFF),或不适用时 N/A', val));
				}
			}
			return out;
		},
	},
	{
		id: 'MDB-EMITS', severity: 'warning', guard: isIntf,
		run(ast, { file }) {
			const out = [];
			for (const val of collectByKey(ast, 'emitsChangedSignal')) {
				// JSON 原生布尔 true/false 合法;字符串形态 'true'/'false'/'const'/'invalidates' 合法
				const ok = val === true || val === false || (typeof val === 'string' && EMITS_ALLOWED.has(val));
				if (!ok) out.push(finding(this.id, this.severity, file, undefined,
					`emitsChangedSignal '${val}' 非法`, '须为 true/false/const/invalidates(默认 true)', String(val)));
			}
			return out;
		},
	},
	{
		id: 'MDB-PATH', severity: 'error', guard: isPath,
		run(ast, { file }) {
			const out = [];
			for (const val of collectByKey(ast, 'path')) {
				if (typeof val !== 'string') {
					out.push(finding(this.id, this.severity, file, undefined, `path 值应为字符串,实为 ${typeof val}`, 'path 须为字符串类型字面量', String(val)));
					continue;
				}
				if (!MDB_PATH_RE.test(val)) out.push(finding(this.id, this.severity, file, undefined,
					`资源 path '${val}' 不以 /bmc/{域} 开头或格式错`,
					'如 /bmc/kepler/Chassis/${ChassisId}/Power / /bmc/CMCC/...', val));
			}
			return out;
		},
	},
];

// ---------------- Redfish 规则 ----------------
const RF_RULES = [
	{
		id: 'RF-ODATA-TYPE', severity: 'error',
		run(ast, { file, findLine }) {
			const out = [];
			for (const val of collectByKey(ast, '@odata.type')) {
				if (typeof val !== 'string') {
					out.push(finding(this.id, this.severity, file, undefined, `@odata.type 值应为字符串,实为 ${typeof val}`, '@odata.type 须为字符串类型字面量', String(val)));
					continue;
				}
				// 模板计算的类型(如 ${Statements/GetCertOdataType()})是运行期动态值,无法静态校验形态 → 豁免
				if (val.includes('${') || val.includes('{{')) continue;
				if (!isOdataTypeOk(val)) out.push(finding(this.id, this.severity, file,
					findLine('@odata.type', val),
					`@odata.type '${val}' 缺 '#' 前缀或形态非法`, '合法:#Type.vX_Y_Z / #Type.vX_Y_Z.Entity / #XCollection.XCollection,如 #Power.v1_0_0.Power', val));
			}
			return out;
		},
	},
	{
		id: 'RF-META', severity: 'error',
		run(ast, { file, findLine }) {
			const out = [];
			// 有 Resources[].Interfaces[] 结构的映射文件:只查 GET 接口 RspBody 顶层(资源体);
			// 无该结构(简单/服务级形态)回退全对象遍历
			const { bodies, sawInterfaces } = collectGetRspBodies(ast);
			const targets = sawInterfaces ? bodies : collectObjectsWith(ast, '@odata.type');
			for (const obj of targets) {
				if (!('@odata.type' in obj)) continue;
				const t = String(obj['@odata.type']);
				// Message 系模板(错误/成功响应):规范字段是 MessageId/Message/Severity/Resolution,不含 Id/Name → 豁免
				if (/^#Message(\.|$)/i.test(t)) continue;
				// Registry 族(MessageRegistry/EventRegistry/AttributeRegistry…):DSP0228 注册表载荷,
				// 非 DSP0266 资源,合法无 @odata.id → 豁免(v1.json 服务根的注册表 RspBody 形态)
				if (/registry$/i.test(t.split('.').pop())) continue;
				// Collection 后缀,或无版本 OEM 形态(#X.Y,如 #HwThresholdSensor.HwThresholdSensor):
				// 按集合口径只要求 @odata.id + Name(DSP0266:集合 shall not 含 Id)
				const versionless = !t.split('.').some((s) => /^v\d+_\d+/.test(s));
				if (/collection$/i.test(t.split('.').pop()) || versionless) {
					if (!('@odata.id' in obj) || !('Name' in obj)) {
						out.push(finding(this.id, this.severity, file, findLine('@odata.type', obj['@odata.type']),
							'Collection/无版本对象缺 @odata.id/Name 元字段', '资源集合与无版本对象须含 @odata.id 与 Name(按 DSP0266 不得含 Id)'));
					}
					continue;
				}
				if (!('Id' in obj) || !('Name' in obj) || !('@odata.id' in obj)) {
					out.push(finding(this.id, this.severity, file, findLine('@odata.type', obj['@odata.type']),
						'Redfish 资源对象缺 Id/Name/@odata.id 元字段',
						'GET 响应的版本化资源体须同时含 Id、Name、@odata.id'));
				}
			}
			return out;
		},
	},
	{
		id: 'RF-URI', severity: 'error',
		run(ast, { file, findLine }) {
			const out = [];
			for (const keyName of RF_URI_KEYS) {
				for (const val of collectByKey(ast, keyName)) {
					if (typeof val !== 'string') {
						out.push(finding(this.id, this.severity, file, undefined, `${keyName} 值应为字符串,实为 ${typeof val}`, 'Uri 须为字符串类型字面量', String(val)));
						continue;
					}
					if (!val.startsWith('/redfish/v1/') && !isUriExempt(val)) {
						out.push(finding(this.id, this.severity, file, findLine(keyName, val),
							`Uri '${val}' 不以 /redfish/v1/ 开头`, '指向 Redfish 资源的 Uri 应以 /redfish/v1/ 开头(/bmc/、/Expand/、模板值豁免)', val));
					}
				}
			}
			return out;
		},
	},
	{
		id: 'RF-ENUM', severity: 'warning',
		run(ast, { file, findLine }) {
			const out = [];
			for (const { key, val, passthroughBlock } of collectEnumEntries(ast, ['Health', 'State'])) {
				if (typeof val !== 'string') {
					out.push(finding(this.id, this.severity, file, undefined, `${key} 值应为字符串,实为 ${typeof val}`, `${key} 须为字符串枚举`, String(val)));
					continue;
				}
				// 动态/引用值豁免:${}/{{}} 模板(Statements/ProcessingFlow 计算值)、[# 索引引用(Health[#INDEX])
				// 与直通映射块内的源属性名引用(值===键名或块内有同名对,如 "State":"DetectorState")——均非枚举字面量
				if (val.includes('${') || val.includes('{{') || val.includes('[#') || passthroughBlock) continue;
				const allowed = key === 'Health' ? HEALTH_SET : STATE_SET;
				if (!allowed.has(val)) out.push(finding(this.id, this.severity, file, findLine(key, val),
					`枚举值 '${val}' 不在 ${key} 允许集合内`,
					key === 'Health' ? '允许:OK/Warning/Critical' : '允许:Enabled/Disabled/.../Degraded/Qualified(DMTF Resource.State)', val));
			}
			return out;
		},
	},
];

// ---------------- 核心纯函数 ----------------

/** 对一组规则逐条跑(run),每条独立 try/catch:抛错的入 skippedRules,不中断其余。对应详设 FM-09/10。 */
export function lintWithRules(ast, rules, ctx) {
	const findings = [];
	const skippedRules = [];
	for (const rule of rules) {
		try {
			findings.push(...rule.run(ast, ctx));
		} catch {
			skippedRules.push(rule.id);
		}
	}
	return { findings, skippedRules };
}

export function lintContent(filename, content, scopeOverride) {
	if (!normPath(filename).toLowerCase().endsWith('.json')) {
		return { file: filename, scope: null, skipped: true, findings: [], skippedRules: [] };
	}
	const scope = scopeOverride || detectScope(filename);
	if (!scope) return { file: filename, scope: null, skipped: true, findings: [], skippedRules: [] };

	const syntaxRule = scope === 'redfish' ? 'RF-SYNTAX' : 'MDB-SYNTAX';
	let ast;
	try {
		ast = JSON.parse(content.charCodeAt(0) === 0xfeff ? content.slice(1) : content); // UTF-8 BOM 剥离(BOM 误报 SYNTAX)
	} catch (e) {
		return { file: filename, scope, skipped: false, findings: [finding(syntaxRule, 'error', filename, undefined,
			`JSON 语法错误:${e.message}`, '修复 JSON 语法')], skippedRules: [] };
	}
	const index = buildLineIndex(content);
	const rules = (scope === 'redfish' ? RF_RULES : MDB_RULES)
		.filter((r) => !r.guard || r.guard(filename) || (scopeOverride && SCOPE_GUARDS[scopeOverride] === r.guard));
	const { findings, skippedRules } = lintWithRules(ast, rules, { file: filename, index, findLine: makeLineFinder(index) });
	return { file: filename, scope, skipped: false, findings, skippedRules };
}

export function lintFiles(files, options = {}) {
	const findings = [];
	const skippedRules = new Set();
	let checkedFiles = 0;
	let skippedFiles = 0;
	for (const { filename, content } of files) {
		const r = lintContent(filename, content, options.scope);
		if (r.skipped) { skippedFiles++; continue; }
		checkedFiles++;
		findings.push(...r.findings);
		r.skippedRules.forEach((x) => skippedRules.add(x));
	}
	const count = (sev) => findings.filter((f) => f.severity === sev).length;
	return {
		findings,
		summary: { errors: count('error'), warnings: count('warning'), infos: count('info'), checkedFiles, skippedFiles, skippedRules: [...skippedRules] },
		coverage: { baseline: true, semanticNeeded: true },
	};
}

// ---------------- CLI ----------------
const USAGE = `usage: compliance-lint.mjs [--files f1.json [f2.json ...] | --stdin --scope <mdb|redfish|messages|path>]
  --files   对本地文件跑(空格或逗号分隔);与 --stdin 互斥
  --stdin   从 stdin 读单个文件;必须显式 --scope(无路径可自动分流)
  --scope   显式指定规则域(默认 auto 按文件路径分流)
退出码:0 无 error / 1 存在 error(可作 CI 门禁) / 2 调用错误(参数/IO,未执行检查)`;

const VALID_SCOPES = new Set(['auto', 'mdb', 'redfish', 'messages', 'path']);

function parseArgs(argv) {
	const args = { files: [], scope: 'auto', error: null };
	// 支持 `--flag value` 与 `--flag=value` 两种形式;未知/拼错 flag 一律报错(静默吞参 = 零检查绿灯放行)
	for (let i = 0; i < argv.length; i++) {
		let t = argv[i];
		let inlineVal = null;
		const eq = t.indexOf('=');
		if (t.startsWith('--') && eq > 0) { inlineVal = t.slice(eq + 1); t = t.slice(0, eq); }
		if (t === '--files') {
			if (inlineVal !== null) { inlineVal.split(',').filter(Boolean).forEach((f) => args.files.push(f)); continue; }
			while (i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
				argv[++i].split(',').filter(Boolean).forEach((f) => args.files.push(f));
			}
		} else if (t === '--scope') {
			const v = inlineVal !== null ? inlineVal : (i + 1 < argv.length && !argv[i + 1].startsWith('--') ? argv[++i] : null);
			if (v === null) { args.error = `--scope 缺值`; break; }
			args.scope = v;
		} else if (t === '--stdin') {
			args.stdin = true;
		} else {
			args.error = `未知参数 '${t}'(检查拼写)`;
			break;
		}
	}
	if (!args.error && args.stdin && args.files.length) args.error = '--stdin 与 --files 互斥(同时给出时 --files 会被忽略,现一律报错)';
	if (!args.error && !args.stdin && !args.files.length) args.error = '未指定任何输入(--files 或 --stdin)';
	if (!args.error && !VALID_SCOPES.has(args.scope)) args.error = `非法 --scope '${args.scope}',合法值:${[...VALID_SCOPES].join('/')}`;
	if (!args.error && args.stdin && args.scope === 'auto') args.error = '--stdin 无文件路径可供自动分流,必须显式 --scope <mdb|redfish|messages|path>';
	return args;
}

async function main() {
	const args = parseArgs(process.argv.slice(2));
	if (args.error) {
		console.error(`error: ${args.error}\n${USAGE}`);
		process.exit(2);
	}
	let files;
	if (args.stdin) {
		const chunks = [];
		for await (const chunk of process.stdin) chunks.push(chunk);
		files = [{ filename: 'stdin.json', content: Buffer.concat(chunks).toString('utf8') }];
	} else {
		files = [];
		for (const f of args.files) {
			try {
				files.push({ filename: f, content: readFileSync(f, 'utf8') });
			} catch (e) {
				// IO 失败与"存在 error"门禁语义分离:调用错误退出 2,编排层可区分"代码不合规"与"调用出错"
				console.error(`error: 无法读取文件 '${f}':${e.message}`);
				process.exit(2);
			}
		}
	}
	const scope = args.scope !== 'auto' ? args.scope : undefined;
	const result = lintFiles(files, { scope });
	console.log(JSON.stringify(result, null, 2));
	process.exitCode = result.summary.errors > 0 ? 1 : 0;
}

const invokedDirectly = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
	main().catch((e) => { console.error(e.stack || String(e)); process.exit(1); });
}
