"use strict";
const incomingSession = location.hash.slice(1);
if (incomingSession)
  sessionStorage.setItem("openubmc-configuration-session", incomingSession);
const session =
  incomingSession ||
  sessionStorage.getItem("openubmc-configuration-session") ||
  "";
history.replaceState(null, "", location.pathname);
let state,
  kind = "targets",
  busy = false,
  closed = false,
  id = 0;
const $ = (id) => document.getElementById(id);
const reasons = {
  remote_missing: "本机未找到该 Conan remote，请选择当前构建环境中的已有仓库。",
  configuration_changed: "检查期间配置发生变化，请重新检查。",
  connected: "连接成功",
  credentials_missing: "凭据不完整，请填写后保存并生效。",
  authentication_failed: "认证失败，请检查账号或密码。",
  network_error: "网络连接失败，请检查地址和网络。",
  host_identity_failed: "SSH 主机身份未确认，请在本机完成主机身份校验。",
  tls_error: "TLS 证书校验失败，请配置可信证书。",
  interaction_required: "认证需要验证码或其他人工操作，请在身份服务中完成。",
  permission_denied: "账号没有访问权限。",
  timeout: "检查超时，请检查网络和服务状态。",
  check_unavailable: "本机检查工具或依赖未就绪。",
  connection_failed: "连接未通过，请检查本机配置与服务状态。",
  activation_required: "请先保存并生效。",
  target_required: "请填写要检查的目标 IP。",
  confirmation_required: "请选择目标后点击检查连接。",
};
function node(tag, text, parent) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (parent) parent.append(e);
  return e;
}
function notice(text, error = false) {
  $("notice").textContent = text;
  $("notice").className = error ? "error" : "";
}
async function api(path, data) {
  const response = await fetch(path, {
    method: data ? "POST" : "GET",
    headers: {
      "X-OpenUBMC-Session": session,
      ...(data ? { "Content-Type": "application/json" } : {}),
    },
    ...(data ? { body: JSON.stringify(data) } : {}),
  });
  const result = await response.json();
  if (!response.ok)
    throw new Error(
      result.message ||
        (response.status === 403
          ? "页面会话已失效，请重新打开本机配置页面。"
          : "本地配置操作失败。"),
    );
  return result;
}
async function action(fn) {
  if (busy) return;
  busy = true;
  document.querySelectorAll("button").forEach((b) => (b.disabled = true));
  try {
    await fn();
  } catch (error) {
    notice(error.message, true);
  } finally {
    busy = false;
    document.querySelectorAll("button").forEach((b) => (b.disabled = closed));
  }
}
function input(parent, label, value = "", type = "text") {
  const wrap = node("div", undefined, parent);
  wrap.className = "field";
  const key = "field-" + ++id;
  const l = node("label", label, wrap);
  l.htmlFor = key;
  const e = node("input", undefined, wrap);
  e.id = key;
  e.type = type;
  e.value = value;
  e.autocomplete = type === "password" ? "new-password" : "off";
  return e;
}
function select(parent, label, options, value = "") {
  const wrap = node("div", undefined, parent);
  wrap.className = "field";
  const key = "field-" + ++id;
  const l = node("label", label, wrap);
  l.htmlFor = key;
  const e = node("select", undefined, wrap);
  e.id = key;
  for (const [v, t] of options) {
    const o = node("option", t, e);
    o.value = v;
  }
  e.value = value;
  return e;
}
function secret(parent, label, isSet, source) {
  const wrap = node("div", undefined, parent);
  wrap.className = "secret";
  const mode = select(
    wrap,
    label,
    [
      ["keep", "保留"],
      ["replace", "替换"],
      ["remove", "移除"],
    ],
    isSet ? "keep" : "replace",
  );
  const value = input(wrap, "新" + label, "", "password");
  value.placeholder = isSet ? "已保存的秘密不会显示" : "输入后保存在本机";
  value.disabled = mode.value !== "replace";
  mode.onchange = () => {
    value.disabled = mode.value !== "replace";
    if (mode.value !== "replace") value.value = "";
  };
  node("small", isSet ? "已保存" : "未填写", wrap);
  return () =>
    mode.value === "replace"
      ? { action: "replace", value: value.value }
      : {
          action: mode.value,
          ...(mode.value === "keep" && source ? { source } : {}),
        };
}
function table(parent, headers) {
  const wrap = node("div", undefined, parent);
  wrap.className = "table-wrap";
  const t = node("table", undefined, wrap);
  const row = node("tr", undefined, node("thead", undefined, t));
  headers.forEach((h) => node("th", h, row));
  return node("tbody", undefined, t);
}
let collect;
function records(parent, config, conan = false) {
  node("h3", conan ? "仓库账号" : "凭据记录", parent);
  node(
    "p",
    conan
      ? "填写已存在的 Conan remote 名称。检查成功后，Conan 会更新当前用户的认证缓存。"
      : "多个用途可以选择同一条凭据记录。IP 覆盖使用完整记录。",
    parent,
  );
  const body = table(
    parent,
    conan
      ? ["Remote 名称", "用户名", "密码", ""]
      : ["记录名称", "用户名", "密码", "SSH 密钥路径", ""],
  );
  const rows = [];
  function add(name = "", record = {}) {
    const row = node("tr", undefined, body);
    const cells = Array.from({ length: conan ? 4 : 5 }, () =>
      node("td", undefined, row),
    );
    const n = input(cells[0], conan ? "Remote" : "名称", name);
    const user = input(cells[1], "用户名", record.user || "");
    const password = secret(cells[2], "密码", record.password_set, name);
    const key = conan
      ? null
      : input(cells[3], "密钥文件", record.identity_file || "");
    const remove = node("button", "删除", cells.at(-1));
    remove.type = "button";
    remove.className = "delete";
    const entry = { row, n, user, password, key };
    rows.push(entry);
    remove.onclick = () => {
      rows.splice(rows.indexOf(entry), 1);
      row.remove();
    };
  }
  Object.entries(config.credentials || {}).forEach(([name, r]) => add(name, r));
  const button = node(
    "button",
    conan ? "添加仓库账号" : "添加凭据记录",
    parent,
  );
  button.type = "button";
  button.className = "add";
  button.onclick = () => add();
  const read = () => {
    const value = Object.create(null);
    for (const r of rows) {
      const name = r.n.value.trim();
      if (!name || Object.hasOwn(value, name))
        throw new Error("凭据记录名称不能为空或重复。");
      value[name] = {
        user: r.user.value,
        password: r.password(),
        ...(r.key ? { identity_file: r.key.value } : {}),
      };
    }
    return value;
  };
  read.options = () => rows.map((r) => [r.n.id, r.n.value.trim()]);
  read.reference = (name) =>
    rows.find((r) => r.n.value.trim() === name)?.n.id || "";
  read.recordName = (reference) =>
    rows.find((r) => r.n.id === reference)?.n.value.trim() || "";
  return read;
}
function renderTargets(config) {
  const parent = $("fields");
  const getRecords = records(parent, config);
  node("h3", "全局默认", parent);
  const grid = node("div", undefined, parent);
  grid.className = "form-grid";
  const references = [];
  const options = [["", "未配置"], ...getRecords.options()];
  const bmcSsh = select(
    grid,
    "BMC SSH",
    options,
    getRecords.reference(config.defaults?.bmc?.ssh),
  );
  const redfish = select(
    grid,
    "BMC Redfish",
    options,
    getRecords.reference(config.defaults?.bmc?.redfish),
  );
  const osSsh = select(
    grid,
    "OS SSH",
    options,
    getRecords.reference(config.defaults?.os?.ssh),
  );
  references.push([bmcSsh, "未配置"], [redfish, "未配置"], [osSsh, "未配置"]);
  node("h3", "按 IP 覆盖", parent);
  const body = table(parent, [
    "目标 IP",
    "BMC SSH",
    "BMC Redfish",
    "OS SSH",
    "",
  ]);
  const rows = [];
  function add(ip = "", value = {}) {
    const row = node("tr", undefined, body);
    const cells = Array.from({ length: 5 }, () => node("td", undefined, row));
    const address = input(cells[0], "IP 地址", ip);
    const opts = [["", "继承全局默认"], ...getRecords.options()];
    const ssh = select(
      cells[1],
      "SSH 记录",
      opts,
      getRecords.reference(value.bmc?.ssh),
    );
    const rf = select(
      cells[2],
      "Redfish 记录",
      opts,
      getRecords.reference(value.bmc?.redfish),
    );
    const os = select(
      cells[3],
      "OS 记录",
      opts,
      getRecords.reference(value.os?.ssh),
    );
    references.push(
      [ssh, "继承全局默认"],
      [rf, "继承全局默认"],
      [os, "继承全局默认"],
    );
    const entry = { row, address, ssh, rf, os };
    rows.push(entry);
    const del = node("button", "删除", cells[4]);
    del.type = "button";
    del.className = "delete";
    del.onclick = () => {
      rows.splice(rows.indexOf(entry), 1);
      row.remove();
    };
  }
  Object.entries(config.targets || {}).forEach(([ip, value]) => add(ip, value));
  const addButton = node("button", "添加 IP 覆盖", parent);
  addButton.type = "button";
  addButton.className = "add";
  addButton.onclick = () => add();
  function refs(sshReference, rfReference, osReference) {
    const ssh = getRecords.recordName(sshReference);
    const rf = getRecords.recordName(rfReference);
    const os = getRecords.recordName(osReference);
    return {
      ...(ssh || rf
        ? { bmc: { ...(ssh ? { ssh } : {}), ...(rf ? { redfish: rf } : {}) } }
        : {}),
      ...(os ? { os: { ssh: os } } : {}),
    };
  }
  parent.oninput = () => {
    for (const [ref, empty] of references) {
      const old = ref.value;
      ref.replaceChildren();
      for (const [v, t] of [["", empty], ...getRecords.options()]) {
        const option = node("option", t, ref);
        option.value = v;
      }
      ref.value = old;
    }
  };
  collect = () => {
    const targets = Object.create(null);
    for (const row of rows) {
      const ip = row.address.value.trim();
      if (!ip || Object.hasOwn(targets, ip))
        throw new Error("覆盖 IP 不能为空或重复。");
      targets[ip] = refs(row.ssh.value, row.rf.value, row.os.value);
    }
    return {
      schema_version: 1,
      credentials: getRecords(),
      defaults: refs(bmcSsh.value, redfish.value, osSsh.value),
      targets,
    };
  };
}
function renderKb(config) {
  const parent = $("fields");
  const grid = node("div", undefined, parent);
  grid.className = "form-grid";
  const user = input(grid, "openUBMC 账号", config.username || "");
  const password = secret(grid, "密码", config.password_set);
  const clientSecret = secret(grid, "OAuth 应用密钥", config.clientSecret_set);
  node(
    "p",
    "应用密钥由你的授权应用提供。需要验证码时，连接检查会提示你完成身份验证。",
    parent,
  );
  const advanced = node("details", undefined, parent);
  node("summary", "服务与应用设置", advanced);
  const fields = {};
  for (const [key, label] of Object.entries({
    lightragUrl: "知识库服务 URL",
    userCenterUrl: "用户中心 URL",
    oauthBaseUrl: "OAuth 服务 URL",
    clientId: "OAuth Client ID",
    redirectUri: "回调 URI",
    tokenCachePath: "Token 缓存路径",
  }))
    fields[key] = input(advanced, label, config[key] || "");
  const scopes = input(
    advanced,
    "Scopes（空格分隔）",
    (config.scopes || []).join(" "),
  );
  const timeout = input(
    advanced,
    "请求时限（毫秒）",
    config.requestTimeoutMs || "",
    "number",
  );
  collect = () => {
    const value = {
      username: user.value,
      password: password(),
      clientSecret: clientSecret(),
    };
    for (const [k, e] of Object.entries(fields))
      if (e.value.trim()) value[k] = e.value.trim();
    if (scopes.value.trim()) value.scopes = scopes.value.trim().split(/\s+/);
    if (timeout.value) value.requestTimeoutMs = Number(timeout.value);
    return value;
  };
}
function checks() {
  const parent = $("check-fields");
  parent.replaceChildren();
  parent.className = "form-grid";
  let target = () => null;
  if (kind === "targets") {
    const ip = input(parent, "目标 IP");
    const purpose = select(
      parent,
      "用途",
      [
        ["bmc", "BMC"],
        ["os", "OS"],
      ],
      "bmc",
    );
    const transport = select(
      parent,
      "协议",
      [
        ["ssh", "SSH"],
        ["redfish", "Redfish"],
      ],
      "ssh",
    );
    purpose.onchange = () => {
      transport.querySelector("option[value=redfish]").disabled =
        purpose.value === "os";
      if (purpose.value === "os") transport.value = "ssh";
    };
    target = () =>
      ip.value.trim()
        ? {
            ip: ip.value.trim(),
            purpose: purpose.value,
            transport: transport.value,
          }
        : null;
  } else if (kind === "conan") {
    const remote = select(
      parent,
      "Conan remote",
      Object.keys(state.conan.config.credentials || {}).map((n) => [n, n]),
    );
    target = () => ({ remote: remote.value });
  }
  const desc = {
    targets: "只检查指定目标的 SSH 或 Redfish 连接。未填写 IP 时不会连接设备。",
    kb: "访问已配置的知识库服务，检查账号是否可用。",
    conan: "对选定的已有 remote 执行认证。成功后构建可复用 Conan 的本地缓存。",
  };
  $("check-description").textContent = desc[kind];
  $("check").onclick = () =>
    action(async () => {
      const result = await api("/api/check", {
        kind,
        target: target(),
        confirm: true,
      });
      notice(reasons[result.code] || "检查未完成。", !result.verified);
      state = await api("/api/state");
      renderChecks();
    });
  renderChecks();
}
function renderChecks() {
  const parent = $("check-results");
  parent.replaceChildren();
  for (const ready of state[kind].readiness || []) {
    const scope = ready.scope === "default" ? "全局默认" : ready.scope;
    node(
      "p",
      `${scope}${ready.purpose ? " / " + ready.purpose.toUpperCase() + " " + ready.transport : ""}：${ready.configured ? "已配置" : "凭据不完整"}`,
      parent,
    );
  }
  const entries = state[kind].checks || [];
  if (!entries.length) {
    node("p", "尚未验证连接。保存与生效不代表账号已通过认证。", parent);
    return;
  }
  for (const entry of entries) {
    const t = entry.target;
    const label = t?.ip
      ? `${t.ip} / ${t.purpose.toUpperCase()} / ${t.transport}`
      : t?.remote || "知识库";
    const row = node(
      "div",
      `${label}：${reasons[entry.code] || "检查未完成"}`,
      parent,
    );
    row.className = "check-row" + (entry.verified ? " ok" : "");
  }
}
function render() {
  const current = state[kind];
  $("fields").replaceChildren();
  $("fields").oninput = null;
  const names = {
    targets: ["BMC 与 OS", "先填写常用账号，再为不同设备设置 IP 覆盖。"],
    kb: ["知识库", "配置独立的 openUBMC 知识库账号与授权应用。"],
    conan: ["Conan", "为已有的构建仓库保存账号并检查认证。"],
  };
  $("title").textContent = names[kind][0];
  $("subtitle").textContent = names[kind][1];
  $("saved-state").textContent = !current.saved
    ? "未保存"
    : current.revision === current.active_revision
      ? "已保存并生效"
      : "有尚未生效的更改";
  $("source-path").textContent = current.source;
  $("import").hidden = !current.legacy_available;
  if (kind === "targets") renderTargets(current.config);
  else if (kind === "kb") renderKb(current.config);
  else
    collect = (() => {
      const read = records($("fields"), current.config, true);
      return () => ({ credentials: read() });
    })();
  checks();
  document
    .querySelectorAll("[data-tab]")
    .forEach((button) =>
      button.setAttribute(
        "aria-current",
        button.dataset.tab === kind ? "page" : "false",
      ),
    );
}
async function save(activate) {
  const saved = await api("/api/save", {
    kind,
    expected_revision: state[kind].revision,
    config: collect(),
  });
  state[kind] = saved;
  if (activate)
    state[kind] = await api("/api/activate", {
      kind,
      revision: saved.revision,
      expected_active_revision: saved.active_revision,
    });
  render();
  notice(
    activate
      ? "配置已生效，后续请求会使用当前配置。"
      : "已保存。点击“保存并生效”后用于后续请求。",
  );
}
$("save").onclick = () => action(() => save(false));
$("activate").onclick = () => action(() => save(true));
$("import").onclick = () =>
  action(async () => {
    state[kind] = await api("/api/import", {
      kind,
      expected_revision: state[kind].revision,
    });
    render();
    notice("已有配置已导入为待生效更改，原文件保留。");
  });
$("editor").onsubmit = (e) => e.preventDefault();
document.querySelectorAll("[data-tab]").forEach(
  (button) =>
    (button.onclick = () => {
      kind = button.dataset.tab;
      render();
      notice("");
    }),
);
action(async () => {
  state = await api("/api/state");
  $("environment").textContent =
    `${state.environment.platform} / ${state.environment.hostname}`;
  $("location").textContent = state.environment.config_home;
  render();
});

$("finish").onclick = () =>
  action(async () => {
    await api("/api/close", {});
    closed = true;
    sessionStorage.removeItem("openubmc-configuration-session");
    notice("本机配置服务已关闭，可以关闭此页面。");
    document
      .querySelectorAll("input,select")
      .forEach((e) => (e.disabled = true));
  });

let pluginPreview, pluginTransaction;
async function pluginStatus() {
  const result = await api("/api/plugin", { action: "status" });
  const status = $("plugin-status");
  status.replaceChildren();
  if (result.available === false) {
    node("p", "请从已安装的插件打开本机配置页面。", status);
    return;
  }
  for (const [label, value] of [
    ["版本", result.version || "无法验证"],
    ["安装文件", result.integrity ? "完整" : "校验未通过，请重新安装市场版本"],
    ["Runtime", result.runtime ? "可启动" : "未就绪，可尝试修复依赖"],
    ["知识库", result.kb ? "可启动" : "未就绪，可尝试修复依赖"],
    ["启动配置", result.configuration.ready ? "未发现覆盖冲突" : result.configuration.conflict
      ? "存在自定义或冲突配置，请保留原配置并联系维护者处理"
      : "发现旧启动覆盖，可预览修复"],
  ]) node("p", `${label}：${value}`, status);
}
$("plugin-check").onclick = () => action(pluginStatus);
$("plugin-preview").onclick = () => action(async () => {
  const result = await api("/api/plugin", { action: "preview" });
  if (result.available === false) throw new Error("请从已安装的插件打开页面。");
  pluginPreview = result.preview_id;
  $("plugin-apply").hidden = !result.would_change;
  $("plugin-result").textContent = result.would_change
    ? `将备份当前配置，并移除以下手工启动覆盖：${result.servers.join("、")}。插件将管理启动入口。`
    : "没有需要清理的标准启动覆盖。";
});
$("plugin-apply").onclick = () => action(async () => {
  const result = await api("/api/plugin", { action: "apply", preview_id: pluginPreview });
  pluginTransaction = result.transaction;
  $("plugin-apply").hidden = true;
  $("plugin-undo").hidden = !pluginTransaction;
  $("plugin-result").textContent = "配置已备份并修复。请重新打开受影响的任务，确认能够恢复。";
  await pluginStatus();
});
$("plugin-undo").onclick = () => action(async () => {
  await api("/api/plugin", { action: "undo", transaction: pluginTransaction });
  $("plugin-undo").hidden = true;
  $("plugin-result").textContent = "已恢复修复前的配置。";
  await pluginStatus();
});
for (const capability of ["runtime", "kb"]) {
  $("plugin-" + capability).onclick = () => action(async () => {
    $("plugin-result").textContent = "正在修复依赖，请保持页面打开。";
    const result = await api("/api/plugin", { action: "dependencies", capability });
    $("plugin-result").textContent = result.repaired ? "依赖修复完成。" : "修复未完成，请检查本机网络或联系维护者。";
    await pluginStatus();
  });
}
