#!/usr/bin/env node
/**
 * doc-coverage.mjs —— Redfish/IPMI 代码文档同步检查(机械层)
 *
 * 纯 Node 标准库,零运行时依赖,不做任何网络请求;随 skill 自包含分发。
 *
 * 用法:
 *   node doc-coverage.mjs --stdin < input.json
 * 输入(JSON,由语义层/数据层组装):
 *   {
 *     "prBody":       "<PR 描述原文,用于条件一链接提取>",
 *     "changedFiles": ["interface_config/redfish/mapping_config/Systems/Bios/config.json", ...],
 *     "fileContents": { "mds/ipmi.json": "<完整文件内容>", "<服务级json路径>": "<完整内容>" },
 *     "patchText":    { "mds/ipmi.json": "<unified diff,用于定位涉及的命令>", "interface_config/redfish/mapping_config/<框架文件>.json": "<unified diff,用于提取新增 Uri 条目>" },
 *     "docsTree":     ["docs/zh/development/specifications/..."] | null,  // docs 主干清单(null=拉取失败)
 *     "docsPrFiles":  { "135": ["docs/...md"] | null },                   // 描述中各文档 PR 的变更文件(null=链接无效/拉取失败/PR 已关闭未合入)
 *     "headSha":      "<PR head commit,幂等标识>"
 *   }
 * 输出:JSON { triggered, resources, coverage, unmatchedFiles, skippedFiles, manualActions, invalidLinks, conclusion, headSha }
 *   manualActions:机械层无法判定、需人工确认的项(ActionInfo 资源 / 动作 URI / Actions 动作目录 / URI 尾段非资源名形态 / 无 patch 的根级框架文件 / 被整删的 IPMI 命令)
 *
 * 设计边界(与同目录 gitcode_cli.py 分工):
 *   - 数据层(gitcode_cli.py):拉 PR/变更/docs 树/docs PR 文件、提交评论。
 *   - 机械层(本脚本):资源提取 + 条件一/条件二覆盖比对。纯函数,可单测。
 *   - 语义层(SKILL.md):评论渲染与降级话术。
 *
 * 退出码:始终 0 —— 检查结论仅供参考、不作合入门禁(需求 #87/#88 约束);
 *         仅输入不可读等程序性错误为 1。
 */
import { pathToFileURL } from 'node:url';

// ---------------- 常量(映射规则表,详设 2.1.1.1) ----------------
export const DOCS_REPO = 'openUBMC/docs';
export const DOCS_TREE_PREFIX = 'docs/zh/development/specifications/';
export const REDFISH_TRIGGER = 'interface_config/redfish/mapping_config/';
export const IPMI_TRIGGER_FILE = 'mds/ipmi.json';
export const FOLD_THRESHOLD = 50; // 评论未覆盖清单折叠阈值

const REDFISH_DETAILS = `${DOCS_TREE_PREFIX}redfish/details/`;
const IPMI_DETAILS = `${DOCS_TREE_PREFIX}ipmi/details/`;
// 仅认 openUBMC/docs 的 PR 链接:其它 owner 的 */docs 链接与 openUBMC/docs PR 编号碰撞时会错误判覆盖
const DOCS_PR_LINK_RE = /gitcode\.com\/openUBMC\/docs\/(?:pull|merge_requests)\/(\d+)/g;

const normPath = (f) => String(f).replace(/\\/g, '/');

// ---------------- 触发判定(F-01) ----------------
export function detectTriggered(changedFiles) {
	const kinds = new Set();
	for (const f of changedFiles || []) {
		const p = normPath(f);
		if (p.startsWith(REDFISH_TRIGGER)) kinds.add('redfish');
		if (p === IPMI_TRIGGER_FILE || p.endsWith('/' + IPMI_TRIGGER_FILE)) kinds.add('ipmi');
	}
	return ['redfish', 'ipmi'].filter((k) => kinds.has(k));
}

// ---------------- Redfish 资源提取(F-02) ----------------
/**
 * 资源名提取规则(服务级文件,依据真实仓库侦察):
 *   取 URI 中最后一个首字母大写的段作为资源名;段含 '.' 时取 '.' 前缀
 *   (Actions URI `.../Actions/ComputerSystem.Reset` → ComputerSystem)。
 *   以下形态不产出资源名,由调用方归入待人工确认——不静默丢弃(避免动作映射变更绕过检查):
 *   - 任一段为 Actions(动作 URI):动作文档惯例内联在父资源文档,与主语是否等于服务名无关
 *     (如 Systems 服务的 `.../Actions/ComputerSystem.Reset`)→ 返回 'ACTION_SELF';
 *   - 尾段非干净资源名形态(模板参数 `Expansion:id`、OData 函数 `UriNode()}` 等
 *     非 `首字母大写纯字母数字`)→ 返回 'MALFORMED';
 *   - 尾段与 service 相同(服务根 URI)→ 返回 'ACTION_SELF'。
 *   无大写段 → null(不产出)。
 */
const URI_SEGMENT_RE = /^[A-Z][A-Za-z0-9]+$/; // 干净资源名段:首字母大写、纯字母数字

export function resourceNameFromUri(uri, service) {
	const path = String(uri).split('#')[0];
	const segs = normPath(path).split('/').filter(Boolean);
	if (segs.some((s) => s.toLowerCase() === 'actions')) return 'ACTION_SELF';
	for (let i = segs.length - 1; i >= 0; i--) {
		let seg = segs[i];
		if (seg.includes('.')) seg = seg.split('.')[0];
		if (/^[A-Z]/.test(seg)) {
			if (!URI_SEGMENT_RE.test(seg)) return 'MALFORMED';
			return seg === service ? 'ACTION_SELF' : seg;
		}
	}
	return null;
}

// ActionInfo 类资源:docs 惯例不为其单独成文(动作及参数内联在父资源文档的 POST (ACTION) 章节),
// 机械层无法映射 → 不产出覆盖判定,转入待人工确认
const isActionInfoResource = (resource) => /actioninfo$/i.test(String(resource));

function extractResourceNamesFromJson(text, service) {
	let data;
	try {
		data = JSON.parse(text);
	} catch {
		return null; // 解析失败 → skippedFiles
	}
	const names = [];
	const actionSelfUris = [];
	const malformedUris = [];
	const walk = (node) => {
		if (Array.isArray(node)) { node.forEach(walk); return; }
		if (node && typeof node === 'object') {
			if (typeof node.Uri === 'string') {
				const r = resourceNameFromUri(node.Uri, service);
				if (r === 'ACTION_SELF') {
					if (!actionSelfUris.includes(node.Uri)) actionSelfUris.push(node.Uri);
				} else if (r === 'MALFORMED') {
					if (!malformedUris.includes(node.Uri)) malformedUris.push(node.Uri);
				} else if (r && !names.includes(r)) {
					names.push(r);
				}
			}
			Object.values(node).forEach(walk);
		}
	};
	walk(data);
	return { names, actionSelfUris, malformedUris };
}

// 根级框架文件($metadata/OData 框架配置,存量条目均为框架自身 URI,不产出资源文档对象)。
// 整文件提取会把存量框架条目误判为资源(v1.json 的 Registries 系)→ 只认 PR patch 新增行里的 Uri;
// patch 缺失时不得静默放行(PR 在框架文件新增未文档化资源会整体漏报)→ 转 manualActions 待人工。
const REDFISH_FRAMEWORK_FILES = new Set(['metadata.json', 'odata.json', 'schemas.json', 'v1.json']);

/** 从 unified diff 新增行(+ 开头,排除 +++ 文件头)提取 Uri/URI/uri 键的字符串值(去重保序) */
export function extractUrisFromPatch(patchText) {
	const uris = [];
	for (const ln of String(patchText || '').split(/\r?\n/)) {
		if (!ln.startsWith('+') || ln.startsWith('+++')) continue;
		const m = ln.match(/"(?:Uri|URI|uri)"\s*:\s*"((?:[^"\\]|\\.)*)"/);
		if (!m) continue;
		const uri = m[1].replace(/\\\//g, '/'); // JSON 转义斜杠还原
		if (!uris.includes(uri)) uris.push(uri);
	}
	return uris;
}

export function extractRedfishResources(changedFiles, fileContents = {}, patchText = {}) {
	const resources = [];
	const unmatchedFiles = [];
	const skippedFiles = [];
	const manualActions = [];
	const seenActionDirs = new Set();
	for (const f of changedFiles || []) {
		const p = normPath(f);
		if (!p.startsWith(REDFISH_TRIGGER)) continue;
		const segs = p.slice(REDFISH_TRIGGER.length).split('/');
		if (segs.length === 1 && REDFISH_FRAMEWORK_FILES.has(segs[0].toLowerCase())) {
			// 根级框架文件:只认 patch 新增行中的 Uri(新增资源挂载点,如 Odata.json 挂 /redfish/v1/Managers/1/xxx)
			const service = segs[0].replace(/\.json$/, '');
			const patch = patchText?.[p] ?? patchText?.[f];
			if (patch === undefined || patch === null) {
				manualActions.push({ kind: 'redfish-framework-file', service, sourceFile: f, reason: '根级框架文件无 PR patch,无法区分新增与存量条目,需人工确认是否有未文档化新增资源' });
			} else {
				for (const uri of extractUrisFromPatch(patch)) {
					const r = resourceNameFromUri(uri, service);
					if (r === 'ACTION_SELF') {
						manualActions.push({ kind: 'redfish-action-uri', service, uri, sourceFile: f, reason: '动作 URI(Actions 段或服务根),文档惯例内联在父资源文档,机械层不判定动作文档同步' });
					} else if (r === 'MALFORMED') {
						manualActions.push({ kind: 'redfish-malformed-uri', service, uri, sourceFile: f, reason: 'URI 尾段非资源名形态(模板参数/OData 函数等),机械层无法映射 docs 文档' });
					} else if (r) {
						if (isActionInfoResource(r)) {
							manualActions.push({ kind: 'redfish-actioninfo', service, resource: r, sourceFile: f, reason: 'ActionInfo 惯例内联在父资源文档,机械层不单独判定' });
						} else {
							resources.push({ kind: 'redfish-resource', service, resource: r, sourceFile: f });
						}
					}
					// r === null(无大写段,如 /redfish/v1/odata 服务框架自引用)→ 框架自身 URI,不产出
				}
			}
			continue;
		}
		if (segs.length >= 3) {
			// 目录形态 mapping_config/{Service}/{Resource}/** → 资源 {Service}/{Resource}
			if (segs[1].toLowerCase() === 'actions') {
				// Actions 动作目录:动作文档惯例内联在父资源文档,不单独成文 → 待人工
				const key = `${segs[0]}/Actions`;
				if (!seenActionDirs.has(key)) {
					seenActionDirs.add(key);
					manualActions.push({ kind: 'redfish-action-dir', service: segs[0], resource: 'Actions', sourceFile: f, reason: 'Actions 动作目录,文档惯例内联在父资源文档,机械层不单独判定' });
				}
			} else if (isActionInfoResource(segs[1])) {
				manualActions.push({ kind: 'redfish-actioninfo', service: segs[0], resource: segs[1], sourceFile: f, reason: 'ActionInfo 惯例内联在父资源文档,机械层不单独判定' });
			} else {
				resources.push({ kind: 'redfish-resource', service: segs[0], resource: segs[1], sourceFile: f });
			}
		} else if ((segs.length === 2 && segs[1].endsWith('.json')) || (segs.length === 1 && segs[0].endsWith('.json'))) {
			// 服务级文件 mapping_config/{S}/<file>.json 或 mapping_config/{S}.json → 解析 Uri 提取资源名
			const service = segs.length === 1 ? segs[0].replace(/\.json$/, '') : segs[0];
			const content = fileContents[p] ?? fileContents[f];
			if (content === undefined) {
				unmatchedFiles.push(f);
				continue;
			}
			const extracted = extractResourceNamesFromJson(content, service);
			if (extracted === null) {
				skippedFiles.push({ file: f, reason: 'parse-error' });
			} else {
				extracted.actionSelfUris.forEach((uri) => manualActions.push({ kind: 'redfish-action-uri', service, uri, sourceFile: f, reason: '动作 URI(Actions 段或服务根),文档惯例内联在父资源文档,机械层不判定动作文档同步' }));
				extracted.malformedUris.forEach((uri) => manualActions.push({ kind: 'redfish-malformed-uri', service, uri, sourceFile: f, reason: 'URI 尾段非资源名形态(模板参数/OData 函数等),机械层无法映射 docs 文档' }));
				const names = extracted.names;
				if (names.length === 0 && extracted.actionSelfUris.length === 0 && extracted.malformedUris.length === 0) {
					unmatchedFiles.push(f);
				} else {
					names.forEach((resource) => {
						if (isActionInfoResource(resource)) {
							manualActions.push({ kind: 'redfish-actioninfo', service, resource, sourceFile: f, reason: 'ActionInfo 惯例内联在父资源文档,机械层不单独判定' });
						} else {
							resources.push({ kind: 'redfish-resource', service, resource, sourceFile: f });
						}
					});
				}
			}
		} else {
			// 不在映射规则内的形态(如根级非 json 文件)→ 待人工确认
			unmatchedFiles.push(f);
		}
	}
	return { resources, unmatchedFiles, skippedFiles, manualActions };
}

// ---------------- IPMI 命令提取(F-03) ----------------
/** '0x04'/'0x4'/'0x0A'/'0X10' → '04h'(docs 目录后缀 / 文件前缀的小写十六进制形态) */
export function hexToHh(v) {
	const m = String(v ?? '').trim().match(/^0[xX]([0-9a-fA-F]{1,2})$/);
	if (!m) return null;
	return m[1].toLowerCase().padStart(2, '0') + 'h';
}

/**
 * 完整文件内容(变更后 head 版本)中各命令键的行号区间 [start,end](1-based),供 diff hunk 新行号对齐。
 * 区间终点截到「下一个同缩进姊妹键行 / 缩进更浅的闭括号行」——最后一条命令不再吞到文件尾,
 * 避免只改 cmds 之外的尾部键(如元数据/收尾大括号)时误点名最后一条命令。
 */
function ipmiCommandLineRanges(content, commandNames) {
	const nameSet = new Set(commandNames);
	const lines = String(content).split(/\r?\n/);
	const hits = [];
	lines.forEach((ln, i) => {
		const m = ln.match(/^(\s*)"([^"]+)"\s*:\s*\{/);
		if (m && nameSet.has(m[2])) hits.push({ name: m[2], line: i + 1, indent: m[1] });
	});
	const ranges = {};
	for (const h of hits) {
		let end = lines.length;
		for (let j = h.line; j < lines.length; j++) { // j 为 0-based 索引,对应行号 j+1
			const ln = lines[j];
			const sibling = ln.match(/^(\s*)"[^"]+"\s*:/);
			if (sibling && sibling[1] === h.indent) { end = j; break; }
			const closer = ln.match(/^(\s*)\}/);
			if (closer && closer[1].length < h.indent.length) { end = j; break; }
		}
		ranges[h.name] = [h.line, end];
	}
	return ranges;
}

/**
 * 从 unified diff 中定位涉及的命令,双规则并用:
 *  1. hunk 内「+ 变更行」的新行号落在某命令体区间内 → 该命令被修改;
 *     删除行在新文件中不存在,锚定其前一条上下文行的新行号(区间基于变更后 head 文件,
 *     与 diff 新行号同基准——前部增删行时旧行号会错位归到错误命令);
 *     上下文行不算变更,避免相邻命令误报;**整条命令删除**(键行起全为 `-` 行、无上下文中断)
 *     的体行不锚定到 head 任何区间——否则会误归到上一条未修改的命令;
 *     **纯结构行**(裸 `{`/`}`/`]` 及带逗号形态)不参与区间归因——在 cmds 末尾追加命令时
 *     `+        },`(上一条命令闭合括号补逗号)会落在上一命令区间内,把它误拖进检查对象
 *     (sensor_mgmt #134:仅新增 1 条命令却报 2 条涉及);末尾整删命令的 `-        },` 同理;
 *  2. +/- 行的命令键名(`"Name": {` 增删)→ 覆盖纯新增/删除 hunk;被整删命令的键名不在
 *     head cmds 里,nameSet 并入 patch 删除键名,使 `^-"Name": {` 能兜住整删场景。
 */
const STRUCTURAL_LINE_RE = /^\s*[\{\}\[\]]\s*,?\s*$/; // 裸括号结构行(归因交给同块的内容行/键行)

function commandsTouchedByPatch(patchText, content, commandNames) {
	const touched = new Set();
	const nameSet = new Set(commandNames);
	for (const m of String(patchText).matchAll(/^-\s*"([^"]+)"\s*:\s*\{/gm)) nameSet.add(m[1]);
	const ranges = content ? ipmiCommandLineRanges(content, commandNames) : {};
	const matchRanges = (lineNo) => {
		for (const [name, [s, e]] of Object.entries(ranges)) {
			if (lineNo >= s && lineNo <= e) touched.add(name);
		}
	};
	const lines = String(patchText).split(/\r?\n/);
	let i = 0;
	while (i < lines.length) {
		const h = lines[i].match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
		if (!h) { i++; continue; }
		i++;
		let newLine = parseInt(h[3], 10);
		let prevNewLine = newLine - 1; // 最近一条上下文行的新行号,作为删除行的锚点
		let deletedBlock = null; // 当前正在整删的命令键名:其体行不锚定(避免误归上一命令)
		while (i < lines.length && !lines[i].startsWith('@@')) {
			const ln = lines[i];
			const payload = ln.slice(1); // 去掉 +/- 前缀后的行体
			if (ln.startsWith('-')) {
				const km = ln.match(/^-\s*"([^"]+)"\s*:\s*\{/);
				if (km) {
					deletedBlock = km[1];
					if (nameSet.has(km[1])) touched.add(km[1]);
				} else if (deletedBlock === null && !STRUCTURAL_LINE_RE.test(payload)) {
					// 删除行:锚定到其前一条上下文行(hunk 开头时锚点为 0,交给规则 2);纯结构行不锚定
					if (prevNewLine >= 1) matchRanges(prevNewLine);
				}
			} else {
				if (ln.startsWith('+')) {
					if (!STRUCTURAL_LINE_RE.test(payload)) matchRanges(newLine);
					newLine++;
				} else {
					prevNewLine = newLine;
					newLine++;
				}
				// 上下文行/新增行结束「纯删除块」,此后删除行恢复锚定(部分修改场景命令仍存在)
				deletedBlock = null;
			}
			i++;
		}
	}
	for (const m of String(patchText).matchAll(/^[+-]\s*"([^"]+)"\s*:\s*\{/gm)) {
		if (nameSet.has(m[1])) touched.add(m[1]);
	}
	return touched;
}

export function extractIpmiCommands(content, patchText) {
	let cmds;
	try {
		cmds = JSON.parse(content).cmds;
	} catch {
		return { error: 'parse-error' };
	}
	if (!cmds || typeof cmds !== 'object') return { error: 'no-cmds' };
	const all = Object.entries(cmds).map(([name, def]) => ({
		kind: 'ipmi-command',
		name,
		netfn: String(def?.netfn ?? ''),
		cmd: String(def?.cmd ?? ''),
	}));
	if (patchText === undefined || patchText === null || String(patchText).trim() === '') {
		return { commands: all, deletedCommands: [], scopedByPatch: false }; // patch 缺失 → 保守全量
	}
	const headNames = all.map((c) => c.name);
	const touched = commandsTouchedByPatch(patchText, content, headNames);
	// touched 中 head 已不存在的键 = 本次被整条删除的命令:head 无 netfn/cmd 定义,无法机械比对文档
	const deletedCommands = [...touched].filter((n) => !headNames.includes(n));
	return { commands: all.filter((c) => touched.has(c.name)), deletedCommands, scopedByPatch: true };
}

// ---------------- 条件一:PR 描述文档 PR 链接(F-04) ----------------
export function extractDocPrLinks(prBody) {
	const out = [];
	DOCS_PR_LINK_RE.lastIndex = 0;
	let m;
	while ((m = DOCS_PR_LINK_RE.exec(String(prBody ?? ''))) !== null) {
		if (!out.includes(m[1])) out.push(m[1]);
	}
	return out;
}

function docsPrUnion(docsPrFiles) {
	const set = new Set();
	for (const v of Object.values(docsPrFiles || {})) {
		if (Array.isArray(v)) v.forEach((p) => set.add(normPath(p)));
	}
	return [...set];
}

// ---------------- 覆盖匹配(条件一/条件二共用映射规则) ----------------

/**
 * docs 命名是混合惯例:部分资源复数直文(Accounts.md),部分单数+Collection(Role.md/RoleCollection.md)。
 * 候选集回退:精确 `{R}.md` → `{R去s}.md` → `{R去s}Collection.md`,任一命中即视为该资源有文档。
 */
// docs 混合命名候选集(真实树四种形态全兜住,任一命中即覆盖):
//   Accounts.md 复数直文 / Role.md+RoleCollection.md 单数+Collection / Managers.md 单数 URI 命复数文 /
//   VirtualMediaCollection.md 不带 s 的资源配 Collection
export function redfishDocCandidates(service, resource) {
	const names = [resource, `${resource}Collection`];
	if (/[^s]s$/.test(resource)) {
		const singular = resource.replace(/s$/, '');
		names.push(singular, `${singular}Collection`);
	} else {
		names.push(`${resource}s`, `${resource}sCollection`);
	}
	return names.map((r) => `/redfish/details/${service}/${r}.md`.toLowerCase());
}

export function matchRedfishDoc(paths, service, resource) {
	const wanted = redfishDocCandidates(service, resource);
	return (paths || []).some((p) => wanted.some((w) => normPath(p).toLowerCase().endsWith(w)));
}

export function matchIpmiDoc(paths, netfn, cmd) {
	const nf = hexToHh(netfn);
	const cf = hexToHh(cmd);
	if (!nf || !cf) return null; // netfn/cmd 非法 → 无法判定
	// docs 树两种目录形态都认:标准 NetFn 两级 `*-{nf}/{cf}-*.md`;
	// OEM NetFn(0x30/0x32/0x3A/0x3E)为三级 `*-{nf}/Cmd-{XX}h/{cf}-*.md`——真实树中 Cmd-{XX}h 只是
	// 分组目录编号,与其下文件前缀解耦(如 OEM-30h/Cmd-90h/ 下有 00h/01h/90h-* 等文件),
	// 故中间段编号不参与匹配,锚定 NetFn 目录后缀与文件名 {cf}- 前缀
	const re = new RegExp(`/ipmi/details/[^/]*-${nf}/(?:cmd-[^/]+/)?${cf}-[^/]+\\.md$`);
	return (paths || []).some((p) => re.test(normPath(p).toLowerCase()));
}

// ---------------- 汇总判定(F-05/F-06) ----------------
/**
 * conclusion:
 *   skipped     未命中触发路径(不发检查评论)
 *   pass        全部资源已被条件一或条件二覆盖,且无待人工项
 *   uncovered   存在两条件均可判且均未覆盖的资源(明确行动信号,优先级高于待人工)
 *   incomplete  存在不可判定项(docs 树缺失 / netfn 非法 / 待人工确认 / 资源提取失败)
 */
export function evaluateCoverage(input) {
	const changedFiles = input.changedFiles || [];
	const triggered = detectTriggered(changedFiles);
	const headSha = input.headSha ?? null;
	if (triggered.length === 0) {
		return { triggered: [], resources: [], coverage: [], unmatchedFiles: [], skippedFiles: [], manualActions: [], invalidLinks: [], conclusion: 'skipped', headSha };
	}

	const resources = [];
	const unmatchedFiles = [];
	const skippedFiles = [];
	const manualActions = [];

	if (triggered.includes('redfish')) {
		const r = extractRedfishResources(changedFiles, input.fileContents || {}, input.patchText || {});
		resources.push(...r.resources);
		unmatchedFiles.push(...r.unmatchedFiles);
		skippedFiles.push(...r.skippedFiles);
		manualActions.push(...r.manualActions);
	}
	if (triggered.includes('ipmi')) {
		const ipmiFile = changedFiles.map(normPath).find((p) => p === IPMI_TRIGGER_FILE || p.endsWith('/' + IPMI_TRIGGER_FILE));
		const content = ipmiFile ? (input.fileContents?.[ipmiFile] ?? input.fileContents?.[ipmiFile.split('/').pop()]) : undefined;
		if (ipmiFile === undefined || content === undefined) {
			skippedFiles.push({ file: ipmiFile || IPMI_TRIGGER_FILE, reason: 'content-missing' });
		} else {
			const patch = input.patchText?.[ipmiFile] ?? input.patchText?.[IPMI_TRIGGER_FILE];
			const r = extractIpmiCommands(content, patch);
			if (r.error) skippedFiles.push({ file: ipmiFile, reason: r.error });
			else {
				resources.push(...r.commands);
				// 整删命令:head 已无定义(netfn/cmd 未知),无法机械比对文档同步 → 待人工确认
				for (const name of r.deletedCommands || []) {
					manualActions.push({ kind: 'ipmi-command-deleted', name, sourceFile: ipmiFile, reason: '命令被整条删除,删除后文档是否需同步无法机械判定' });
				}
			}
		}
	}

	// 资源去重:目录形态与服务级文件可能产出同一 {service, resource}(如 Accounts.json + Accounts/ 目录)
	const seen = new Set();
	const dedupedResources = [];
	for (const res of resources) {
		const key = res.kind === 'redfish-resource' ? `${res.service}/${res.resource}` : `ipmi:${res.name}`;
		if (seen.has(key)) continue;
		seen.add(key);
		dedupedResources.push(res);
	}

	// 条件一:描述链接的文档 PR 变更文件并集
	const docPrLinks = extractDocPrLinks(input.prBody);
	const docsPrFiles = input.docsPrFiles || {};
	// 数据层明确标记 null 的链接 = 404/拉取失败/已关闭未合入 → invalidLinks;条件二继续独立判定
	const invalidLinks = docPrLinks.filter((n) => docsPrFiles[n] === null);
	const union1 = docsPrUnion(docsPrFiles);

	// 条件二:docs 主干清单(docsTree === null 表示拉取失败 → 不可判)
	const docsTreeNull = input.docsTree === null || input.docsTree === undefined;

	const coverage = [];
	for (const res of dedupedResources) {
		let cond1 = false;
		let cond1Via = null;
		let cond2 = docsTreeNull ? null : false;
		if (res.kind === 'redfish-resource') {
			if (matchRedfishDoc(union1, res.service, res.resource)) {
				cond1 = true;
				cond1Via = firstPrCovering(docsPrFiles, (paths) => matchRedfishDoc(paths, res.service, res.resource));
			}
			if (!docsTreeNull) cond2 = matchRedfishDoc(input.docsTree, res.service, res.resource);
		} else if (res.kind === 'ipmi-command') {
			const c1 = matchIpmiDoc(union1, res.netfn, res.cmd);
			if (c1 === true) {
				cond1 = true;
				cond1Via = firstPrCovering(docsPrFiles, (paths) => matchIpmiDoc(paths, res.netfn, res.cmd) === true);
			}
			// null(netfn/cmd 非法)透传 → cond2 为 null,整体归 incomplete 待人工,不臆断未覆盖
			if (!docsTreeNull) cond2 = matchIpmiDoc(input.docsTree, res.netfn, res.cmd);
		}
		coverage.push({
			key: res.kind === 'redfish-resource' ? `${res.service}/${res.resource}` : `${hexToHh(res.netfn) || res.netfn}/${hexToHh(res.cmd) || res.cmd}-${res.name}`,
			kind: res.kind,
			cond1,
			cond1Via,
			cond2,
			covered: cond1 || cond2 === true,
		});
	}

	let conclusion;
	if (coverage.length === 0) {
		conclusion = unmatchedFiles.length || skippedFiles.length || manualActions.length ? 'incomplete' : 'pass';
	} else if (coverage.some((r) => !r.covered && r.cond2 === null)) {
		// 判定条件本身不可用(docs 树拉不到/netfn 非法)→ uncovered 结论不可信,归 incomplete
		conclusion = 'incomplete';
	} else if (coverage.some((r) => !r.covered)) {
		conclusion = 'uncovered';
	} else if (manualActions.length || unmatchedFiles.length || skippedFiles.length) {
		conclusion = 'incomplete';
	} else {
		conclusion = 'pass';
	}

	return { triggered, resources: dedupedResources, coverage, unmatchedFiles, skippedFiles, manualActions, invalidLinks, conclusion, headSha };
}

function firstPrCovering(docsPrFiles, predicate) {
	for (const [n, paths] of Object.entries(docsPrFiles || {})) {
		if (Array.isArray(paths) && predicate(paths)) return `docs#${n}`;
	}
	return null;
}

// ---------------- CLI ----------------
async function main() {
	const chunks = [];
	for await (const chunk of process.stdin) chunks.push(chunk);
	const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
	console.log(JSON.stringify(evaluateCoverage(input), null, 2));
	// 退出码始终 0:结论仅供参考,不作门禁
}

const invokedDirectly = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly && process.argv.includes('--stdin')) {
	main().catch((e) => { console.error(String(e && e.message ? e.message : e)); process.exit(1); });
}
