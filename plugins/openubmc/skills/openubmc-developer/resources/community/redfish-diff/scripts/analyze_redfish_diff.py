#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""中文 Redfish 接口差异分析器：支持 zip/目录/本地 git refs/远端 git refs。

增强版：除细分类外，为每个接口输出具体变更明细，包括新增/删除字段的类型和定义、
同名字段的类型和值变化、请求体变化、响应体变化以及接口行为变化。
"""
from __future__ import annotations

import argparse
import csv
import difflib
import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from zipfile import ZipFile

REDFISH_SCOPES = ("interface_config/redfish/", "oem/huawei/redfish/")
MAPPING_TOKEN = "/mapping_config/"
EXTERNAL_PREFIX = "/redfish/v1"
INTERNAL_REPORT_PREFIXES = ("/Expand/", "/Chassis/")
RSP_NOISE = {"@odata.context", "@odata.id", "@odata.type", "Id", "Name", "Description"}
REQ_META = {
    "Name",
    "Type",
    "Required",
    "Validator",
    "Formula",
    "Format",
    "Nullable",
    "Pattern",
    "MaxLength",
    "MinLength",
    "Minimum",
    "Maximum",
    "Default",
    "AllowableValues",
    "PropertyInfo",
    "CustomError",
    "ArrayItem",
    "Sensitive",
    "Items",
    "maxItems",
    "minItems",
    "uniqueItems",
    "LockdownAllow",
    "Description",
}
EntryKey = Tuple[str, str]

CATEGORY_ORDER = [
    "接口新增",
    "接口删除",
    "接口URI变化",
    "URI路径变化",
    "HTTP方法变更",
    "属性新增",
    "属性删除",
    "属性名称变更",
    "属性类型变更",
    "响应体内容变化",
    "返回数据类型变更",
    "请求体内容变化",
    "请求数据类型变更",
    "POST/PATCH请求体内容变化",
    "请求头内容变化",
    "响应头内容变化",
    "接口行为变化",
    "Schema/Metadata变化",
]

CHANGE_TYPE_CN = {"ADDED": "新增", "REMOVED": "删除", "MODIFIED": "修改"}
FILE_STATUS_CN = {"ADDED": "新增", "REMOVED": "删除", "MODIFIED": "修改", "A": "新增", "D": "删除", "M": "修改"}
DETAIL_REPORT_LIMIT = 10
VALUE_LIMIT = 180
CSV_VALUE_LIMIT = 500


# ---------------------------- input preparation ----------------------------
def run(cmd: List[str], cwd: Optional[Path] = None) -> None:
    p = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="utf-8",
        errors="replace",
    )
    if p.returncode:
        raise RuntimeError("命令执行失败: {}\n{}".format(" ".join(cmd), p.stdout))


def run_capture(cmd: List[str], cwd: Optional[Path] = None) -> str:
    p = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="utf-8",
        errors="replace",
    )
    if p.returncode:
        raise RuntimeError("命令执行失败: {}\n{}".format(" ".join(cmd), p.stdout))
    return p.stdout


def is_git_repo(path: Path) -> bool:
    return (
        subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )


def repo_top(path: Path) -> Path:
    p = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if p.returncode:
        raise RuntimeError("不是 git 仓库: {}\n{}".format(path, p.stderr))
    return Path(p.stdout.strip()).resolve()


def prepare_git(repo: str, old_ref: str, new_ref: str, work: Path) -> Tuple[Path, Path, Path]:
    cand = Path(repo).expanduser()
    if cand.exists() and is_git_repo(cand):
        r = repo_top(cand)
    else:
        r = work / "repo"
        run(["git", "clone", "--no-checkout", repo, str(r)])
        run(["git", "fetch", "origin", old_ref, new_ref], cwd=r)

    def rev(ref: str) -> str:
        for c in (ref, "origin/" + ref):
            p = subprocess.run(
                ["git", "rev-parse", "--verify", c + "^{commit}"],
                cwd=str(r),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            if p.returncode == 0:
                return p.stdout.strip()
        raise RuntimeError("无法在 {} 中解析 git ref '{}'".format(r, ref))

    def export_ref(commit: str, label: str) -> Path:
        archive = work / (label + ".zip")
        out = work / (label + "-archive-tree")
        out.mkdir(parents=True, exist_ok=True)
        run(["git", "archive", "--format=zip", "-o", str(archive), commit], cwd=r)
        with ZipFile(archive) as z:
            z.extractall(out)
        return unwrap(out)

    old_commit = rev(old_ref)
    new_commit = rev(new_ref)
    old = work / "old-tree"
    new = work / "new-tree"
    try:
        run(["git", "worktree", "add", "--detach", str(old), old_commit], cwd=r)
        run(["git", "worktree", "add", "--detach", str(new), new_commit], cwd=r)
    except RuntimeError as exc:
        print("Tip: git worktree 不可用，改用 git archive 导出 ref；原因: {}".format(str(exc).splitlines()[-1]))
        old = export_ref(old_commit, "old")
        new = export_ref(new_commit, "new")
    return old, new, r


def unwrap(p: Path) -> Path:
    kids = [x for x in p.iterdir() if not x.name.startswith("__MACOSX")]
    dirs = [x for x in kids if x.is_dir()]
    files = [x for x in kids if x.is_file()]
    return dirs[0] if len(dirs) == 1 and not files else p


def prepare_input(path: str, work: Path, label: str) -> Path:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(str(p))
    if p.is_file() and p.suffix.lower() == ".zip":
        out = work / label
        out.mkdir(parents=True, exist_ok=True)
        with ZipFile(p) as z:
            z.extractall(out)
        return unwrap(out)
    if p.is_dir():
        return p
    raise ValueError("输入必须是源码目录或 .zip 源码包: {}".format(p))


# ---------------------------- basic utilities ----------------------------
def rel(p: Path, root: Path) -> str:
    return p.relative_to(root).as_posix()


def reportable_uri(uri: str) -> bool:
    return uri.startswith(EXTERNAL_PREFIX) or uri.startswith(INTERNAL_REPORT_PREFIXES)


def is_redfish_rel(r: str) -> bool:
    return r.startswith(REDFISH_SCOPES)


def is_mapping_json(r: str) -> bool:
    return r.endswith(".json") and MAPPING_TOKEN in "/" + r


def fh(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def collect_files(root: Path) -> Dict[str, str]:
    d = {}
    for p in root.rglob("*"):
        if p.is_file():
            r = rel(p, root)
            if is_redfish_rel(r):
                d[r] = fh(p)
    return d


def load_json(p: Path) -> Optional[Any]:
    for enc in ("utf-8", "utf-8-sig"):
        try:
            return json.loads(p.read_text(encoding=enc))
        except UnicodeDecodeError:
            continue
        except Exception:
            return None
    return None


def canon(o: Any) -> str:
    return json.dumps(o, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def kind(v: Any) -> str:
    if isinstance(v, dict):
        t = v.get("Type")
        if isinstance(t, str):
            return t
        if "Properties" in v:
            return "Object"
        return "Object"
    if isinstance(v, list):
        return "Array"
    if isinstance(v, bool):
        return "Boolean"
    if isinstance(v, int) and not isinstance(v, bool):
        return "Integer"
    if isinstance(v, float):
        return "Number"
    if isinstance(v, str):
        return "String"
    if v is None:
        return "Null"
    return type(v).__name__


def brief_value(v: Any, limit: int = VALUE_LIMIT) -> str:
    """Return a compact, deterministic preview of a mapping value."""
    if isinstance(v, dict):
        # Preserve important mapping/schema hints before falling back to JSON.
        hints = []
        for k in (
            "Type",
            "Required",
            "Sensitive",
            "Validator",
            "Formula",
            "Format",
            "Pattern",
            "MaxLength",
            "MinLength",
            "Minimum",
            "Maximum",
            "Default",
            "AllowableValues",
        ):
            if k in v:
                hints.append(f"{k}={brief_value(v[k], 60)}")
        if "Statements" in v:
            hints.append("Statements=" + brief_value(v["Statements"], 80))
        if "ProcessingFlow" in v:
            hints.append("ProcessingFlow=" + brief_value(v["ProcessingFlow"], 80))
        if "Properties" in v and isinstance(v["Properties"], dict):
            hints.append(
                "Properties=["
                + ", ".join(list(v["Properties"].keys())[:12])
                + ("..." if len(v["Properties"]) > 12 else "")
                + "]"
            )
        if hints:
            s = "; ".join(hints)
        else:
            s = canon(v)
    elif isinstance(v, list):
        if len(v) == 0:
            s = "[]"
        else:
            s = "Array(len={}, first={})".format(len(v), brief_value(v[0], 80))
    else:
        s = repr(v)
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= limit else s[: limit - 3] + "..."


def sl(vals: Iterable[str], n: int = 12) -> str:
    v = sorted({str(x) for x in vals if str(x)})
    return ", ".join(v) if len(v) <= n else ", ".join(v[:n]) + f" ...（另 {len(v)-n} 项）"


def md_escape(s: Any) -> str:
    """Escape text for markdown table cells and ChatGPT markdown rendering.

    Values from mapping_config often contain ${...}. ChatGPT/Web markdown renderers may
    treat $...$ as KaTeX math. If the content later contains #, e.g. Actions/#Foo,
    the renderer can raise "KaTeX parse error".  For markdown reports, convert dollar
    signs to the HTML entity &#36;. CSV outputs keep the original raw values.
    """
    text = str(s)
    text = text.replace("$", "&#36;")
    text = text.replace("|", "\\|")
    text = text.replace("\n", "<br>")
    return text


def esc(s):
    return md_escape(s)


def cat_list(value: str) -> List[str]:
    return [x for x in re.split("[;；]", str(value or "")) if x]


def parent(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else ""


def leaf(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def similar(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio()


# ---------------------------- semantic mapping surfaces ----------------------------
REF_IN_BRACES_RE = re.compile(r"\$\{([^}]+)\}")
BARE_DATA_RE = re.compile(
    r"\b(ReqBodyOriginal|ReqBody|ReqHeader|ReaHeader|RspHeader|Uri|Query|Context|Input)"
    r"\.([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)"
)
BARE_PROCESSING_RE = re.compile(
    r"\bProcessingFlow\[(\d+)\]\.Destination\.([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)"
)
STATEMENT_NAME_RE = re.compile(r"^Statements/([^()/\[\]]+)\(\)(?:\[.*\])?$")
PROCESSING_DEST_RE = re.compile(r"^ProcessingFlow\[(\d+)\]/Destination(?:/(.+))?$")


def normalize_ref(ref: str) -> str:
    text = str(ref or "").strip()
    if text.startswith("${") and text.endswith("}"):
        text = text[2:-1].strip()
    text = text.replace(".", "/")
    m = STATEMENT_NAME_RE.match(text)
    if m:
        return "Statements/" + m.group(1)
    return text


def extract_refs(obj: Any) -> List[str]:
    refs = set()

    def walk(v: Any) -> None:
        if isinstance(v, str):
            for m in REF_IN_BRACES_RE.finditer(v):
                refs.add(normalize_ref(m.group(1)))
            for m in BARE_DATA_RE.finditer(v):
                refs.add(normalize_ref(m.group(1) + "/" + m.group(2).replace(".", "/")))
            for m in BARE_PROCESSING_RE.finditer(v):
                refs.add(f"ProcessingFlow[{m.group(1)}]/Destination/{m.group(2).replace('.', '/')}")
        elif isinstance(v, dict):
            for k, val in v.items():
                walk(k)
                walk(val)
        elif isinstance(v, list):
            for item in v:
                walk(item)

    walk(obj)
    return sorted(refs)


def surface(
    type_: str, value: str, raw: Any = None, refs: Optional[Iterable[str]] = None, note: str = ""
) -> Dict[str, Any]:
    return {
        "type": type_,
        "value": value,
        "raw": raw,
        "refs": sorted(set(refs or extract_refs(raw))),
        "reference_note": note,
    }


def format_type_value(v: Any) -> str:
    if isinstance(v, list):
        return "[" + ", ".join(str(x) for x in v) + "]"
    return str(v)


def summarize_validator_rule(rule: Any) -> str:
    if not isinstance(rule, dict):
        return brief_value(rule, 120)
    typ = str(rule.get("Type", "")).strip()
    formula = rule.get("Formula", "")
    if typ == "Length":
        return "Length{}".format(format_type_value(formula))
    if typ == "Range":
        return "Range{}".format(format_type_value(formula))
    if typ == "Enum":
        return "Enum{}".format(format_type_value(formula))
    if typ == "Regex":
        return "Regex({})".format(brief_value(formula, 120))
    if typ == "Nonempty":
        return "Nonempty"
    if typ == "IPFormat":
        return "IPFormat"
    if typ == "Script":
        return "Script({})".format(brief_value(formula, 120))
    if typ:
        return "{}({})".format(typ, brief_value(formula, 120)) if formula != "" else typ
    return brief_value(rule, 120)


def summarize_items(items: Any) -> str:
    if isinstance(items, dict):
        parts = []
        if "Type" in items:
            parts.append("元素类型 {}".format(format_type_value(items.get("Type"))))
        if isinstance(items.get("Properties"), dict):
            parts.append("元素子属性 {}".format(", ".join(items["Properties"].keys())))
        return "Items(" + ("；".join(parts) if parts else brief_value(items, 120)) + ")"
    if isinstance(items, list):
        vals = []
        for idx, item in enumerate(items):
            vals.append(
                "[{}]:{}".format(
                    idx,
                    (
                        format_type_value(item.get("Type"))
                        if isinstance(item, dict) and "Type" in item
                        else brief_value(item, 60)
                    ),
                )
            )
        return "Items(tuple: {})".format(", ".join(vals))
    return "Items({})".format(brief_value(items, 120))


def summarize_req_schema(schema: Any, *, root: bool = False) -> str:
    if not isinstance(schema, dict):
        return brief_value(schema, CSV_VALUE_LIMIT)
    parts = ["请求体根对象" if root else "请求体属性对象"]
    if "Type" in schema:
        parts.append("类型 {}".format(format_type_value(schema.get("Type"))))
    if schema.get("Required") is True:
        parts.append("必选")
    elif schema.get("Required") is False:
        parts.append("可选")
    if schema.get("Sensitive") is True:
        parts.append("敏感信息，错误消息中应打码为 ******")
    if "LockdownAllow" in schema:
        parts.append("系统锁定允许={}".format(schema.get("LockdownAllow")))
    if "Description" in schema:
        parts.append("描述={}".format(brief_value(schema.get("Description"), 120)))
    if "Items" in schema:
        parts.append(summarize_items(schema.get("Items")))
    for key, label in (("minItems", "最少元素"), ("maxItems", "最多元素"), ("uniqueItems", "元素唯一")):
        if key in schema:
            parts.append("{}={}".format(label, schema.get(key)))
    validators = schema.get("Validator")
    if isinstance(validators, list) and validators:
        parts.append("校验规则 " + "；".join(summarize_validator_rule(v) for v in validators))
    elif validators is not None:
        parts.append("校验规则 " + brief_value(validators, 120))
    props = schema.get("Properties")
    if isinstance(props, dict) and props:
        parts.append("子属性 " + ", ".join(props.keys()))
    return "；".join(parts)


def _req_schema_walk(schema: Any, path: str, out: Dict[str, Dict[str, Any]]) -> None:
    out[path] = surface("Object", summarize_req_schema(schema), raw=schema)
    if not isinstance(schema, dict):
        return
    props = schema.get("Properties")
    if isinstance(props, dict):
        for name, child in props.items():
            _req_schema_walk(child, path + "/" + str(name), out)
    items = schema.get("Items")
    if isinstance(items, dict) and isinstance(items.get("Properties"), dict):
        for name, child in items["Properties"].items():
            _req_schema_walk(child, path + "[]/" + str(name), out)
    elif isinstance(items, list):
        for idx, item in enumerate(items):
            if isinstance(item, dict):
                _req_schema_walk(item, path + f"[{idx}]", out)


def build_req_surface(req: Any, *, include_root: bool = False) -> Dict[str, Dict[str, Any]]:
    out = {}
    if isinstance(req, dict):
        if include_root:
            out["ReqBody"] = surface("Object", summarize_req_schema(req, root=True), raw=req)
        props = req.get("Properties")
        if isinstance(props, dict):
            for name, schema in props.items():
                _req_schema_walk(schema, "ReqBody/" + str(name), out)
        elif include_root:
            # Some mapping files use ReqBody itself as a schema-like object.
            for key, val in req.items():
                if key not in REQ_META and isinstance(val, (dict, list)):
                    _req_schema_walk(val, "ReqBody/" + str(key), out)
    elif isinstance(req, list):
        for idx, schema in enumerate(req):
            name = str(schema.get("Name", idx)) if isinstance(schema, dict) else str(idx)
            _req_schema_walk(schema, "ReqBody/" + name, out)
    elif req is not None and include_root:
        out["ReqBody"] = surface(kind(req), brief_value(req, CSV_VALUE_LIMIT), raw=req)
    return out


def _is_lowest_rsp_object(obj: Dict[str, Any]) -> bool:
    return not any(isinstance(v, (dict, list)) for v in obj.values())


def summarize_rsp_object(obj: Any) -> str:
    if isinstance(obj, dict):
        parts = ["响应对象"]
        vals = []
        for k, v in obj.items():
            vals.append("{}={}".format(k, brief_value(v, 80)))
        if vals:
            parts.append("字段 " + "；".join(vals[:12]) + (" ..." if len(vals) > 12 else ""))
        return "；".join(parts)
    if isinstance(obj, list):
        return "响应数组；{}".format(brief_value(obj, CSV_VALUE_LIMIT))
    return brief_value(obj, CSV_VALUE_LIMIT)


def _rsp_walk(obj: Any, path: str, out: Dict[str, Dict[str, Any]], *, include_noise: bool, root: bool = False) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if root and not include_noise and k in RSP_NOISE:
                continue
            p = path + "/" + str(k) if path else str(k)
            if isinstance(v, dict):
                if _is_lowest_rsp_object(v):
                    out[p] = surface("Object", summarize_rsp_object(v), raw=v)
                else:
                    _rsp_walk(v, p, out, include_noise=include_noise)
            elif isinstance(v, list):
                if not v or all(not isinstance(x, dict) for x in v):
                    out[p] = surface("Array", summarize_rsp_object(v), raw=v)
                else:
                    for idx, item in enumerate(v):
                        ip = f"{p}[{idx}]"
                        if isinstance(item, dict):
                            if _is_lowest_rsp_object(item):
                                out[ip] = surface("Object", summarize_rsp_object(item), raw=item)
                            else:
                                _rsp_walk(item, ip, out, include_noise=include_noise)
                        else:
                            out[ip] = surface(kind(item), brief_value(item, CSV_VALUE_LIMIT), raw=item)
            else:
                out[p] = surface(kind(v), brief_value(v, CSV_VALUE_LIMIT), raw=v)
    elif isinstance(obj, list):
        out[path or "RspBody"] = surface("Array", summarize_rsp_object(obj), raw=obj)
    elif obj is not None:
        out[path or "RspBody"] = surface(kind(obj), brief_value(obj, CSV_VALUE_LIMIT), raw=obj)


def build_rsp_surface(rsp: Any, *, include_noise: bool = False) -> Dict[str, Dict[str, Any]]:
    out = {}
    _rsp_walk(rsp, "RspBody", out, include_noise=include_noise, root=True)
    return out


def build_header_surface(header: Any, prefix: str) -> Dict[str, Dict[str, Any]]:
    out = {}
    if isinstance(header, dict):
        for k, v in header.items():
            p = prefix + "/" + str(k)
            if isinstance(v, dict):
                out[p] = surface("Object", summarize_rsp_object(v), raw=v)
            elif isinstance(v, list):
                out[p] = surface("Array", summarize_rsp_object(v), raw=v)
            else:
                out[p] = surface(kind(v), brief_value(v, CSV_VALUE_LIMIT), raw=v)
    elif header is not None:
        out[prefix] = surface(kind(header), brief_value(header, CSV_VALUE_LIMIT), raw=header)
    return out


def build_resource_surface(resource: Any) -> Dict[str, Dict[str, Any]]:
    out = {}
    if isinstance(resource, dict):
        for k, v in resource.items():
            path = "ResourceExist/" + str(k)
            refs = extract_refs(k) + extract_refs(v)
            out[path] = surface(
                kind(v), "资源存在性条件；期望 {}".format(brief_value(v, 120)), raw={"key": k, "value": v}, refs=refs
            )
    elif resource is not None:
        out["ResourceExist"] = surface(kind(resource), brief_value(resource, CSV_VALUE_LIMIT), raw=resource)
    return out


def flatten_body(
    obj: Any, prefix: str = "", out: Optional[Dict[str, Dict[str, str]]] = None, *, mode: str
) -> Dict[str, Dict[str, str]]:
    """Compatibility wrapper returning semantic body surfaces."""
    built = build_req_surface(obj) if mode == "req" else build_rsp_surface(obj)
    if prefix:
        built = {prefix + "/" + k: v for k, v in built.items()}
    if out is not None:
        out.update(built)
        return out
    return built


def statement_names_changed(old_statements: Any, new_statements: Any) -> Dict[str, str]:
    if not isinstance(old_statements, dict):
        old_statements = {}
    if not isinstance(new_statements, dict):
        new_statements = {}
    result = {}
    for name in sorted(set(old_statements) | set(new_statements)):
        if name not in old_statements:
            result[name] = "新增"
        elif name not in new_statements:
            result[name] = "删除"
        elif canon(old_statements[name]) != canon(new_statements[name]):
            result[name] = "变更"
    return result


def processing_flows_changed(old_flow: Any, new_flow: Any) -> Dict[int, str]:
    old_flow = old_flow if isinstance(old_flow, list) else []
    new_flow = new_flow if isinstance(new_flow, list) else []
    result = {}
    for idx in range(max(len(old_flow), len(new_flow))):
        if idx >= len(old_flow):
            result[idx] = "新增"
        elif idx >= len(new_flow):
            result[idx] = "删除"
        elif canon(old_flow[idx]) != canon(new_flow[idx]):
            result[idx] = "变更"
    return result


def build_statement_graph(interface: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    statements = interface.get("Statements") if isinstance(interface, dict) else {}
    graph = {}
    if not isinstance(statements, dict):
        return graph
    for name, stmt in statements.items():
        graph[str(name)] = {"refs": extract_refs(stmt), "raw": stmt}
    return graph


def build_processing_flow_graph(interface: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    flow = interface.get("ProcessingFlow") if isinstance(interface, dict) else []
    graph = {}
    if not isinstance(flow, list):
        return graph
    for idx, item in enumerate(flow):
        refs = extract_refs(item)
        dests = []
        if isinstance(item, dict) and isinstance(item.get("Destination"), dict):
            dests = [str(v) for v in item["Destination"].values()]
        graph[idx] = {"refs": refs, "destinations": dests, "raw": item}
    return graph


def top_rsp(body: Any) -> List[str]:
    return sorted(k for k in body.keys() if k not in RSP_NOISE) if isinstance(body, dict) else []


def top_req(body: Any) -> List[str]:
    return (
        sorted(body.get("Properties", {}).keys())
        if isinstance(body, dict) and isinstance(body.get("Properties"), dict)
        else []
    )


def strip_body_fields(interface: Dict[str, Any]) -> Dict[str, Any]:
    return {
        k: v
        for k, v in interface.items()
        if k not in ("ReqBody", "RspBody", "ReqHeader", "ReaHeader", "RspHeader", "Statements", "ProcessingFlow")
    }


def merge_entry(prev: Dict[str, Any], item: Dict[str, Any]) -> None:
    prev["source_files"].extend(item["source_files"])
    prev["source_file"] = ";".join(sorted(set(prev["source_files"])))
    for key in ("rsp_map", "req_map", "req_header_map", "rsp_header_map", "resource_map"):
        prev[key].update(item[key])
    prev["top_rsp"] = sorted(set(prev["top_rsp"]) | set(item["top_rsp"]))
    prev["top_req"] = sorted(set(prev["top_req"]) | set(item["top_req"]))
    prev["signature"] += "\n" + item["signature"]


def collect_entries_from_mapping(data: Any, source_file: str) -> Dict[EntryKey, Dict[str, Any]]:
    out = {}
    if not isinstance(data, dict):
        return out
    for ri, res in enumerate(data.get("Resources", []) or []):
        if not isinstance(res, dict):
            continue
        uri = res.get("Uri")
        if not isinstance(uri, str) or not uri:
            continue
        for ii, it in enumerate(res.get("Interfaces", []) or []):
            if not isinstance(it, dict):
                continue
            m = str(it.get("Type") or "").upper()
            if not m:
                continue
            key = (m, uri)
            req_header = it.get("ReqHeader", it.get("ReaHeader"))
            item = {
                "method": m,
                "uri": uri,
                "source_file": source_file,
                "source_files": [source_file],
                "rsp_map": build_rsp_surface(it.get("RspBody"), include_noise=False),
                "req_map": build_req_surface(it.get("ReqBody")),
                "req_header_map": build_header_surface(req_header, "ReqHeader"),
                "rsp_header_map": build_header_surface(it.get("RspHeader"), "RspHeader"),
                "resource_map": build_resource_surface(it.get("ResourceExist")),
                "top_rsp": top_rsp(it.get("RspBody")),
                "top_req": top_req(it.get("ReqBody")),
                "interface": it,
                "behavior": strip_body_fields(it),
                "statement_graph": build_statement_graph(it),
                "processing_graph": build_processing_flow_graph(it),
                "signature": canon({"uri": uri, "interface": it}),
                "resource_index": ri,
                "interface_index": ii,
            }
            if key in out:
                merge_entry(out[key], item)
            else:
                out[key] = item
    return out


def collect_entries(root: Path) -> Dict[EntryKey, Dict[str, Any]]:
    out = {}
    for p in root.rglob("*.json"):
        r = rel(p, root)
        if not is_mapping_json(r):
            continue
        for key, item in collect_entries_from_mapping(load_json(p), r).items():
            if key in out:
                merge_entry(out[key], item)
            else:
                out[key] = item
    return out


# ---------------------------- diff and classification ----------------------------
def file_diff(old: Dict[str, str], new: Dict[str, str]) -> List[Dict[str, str]]:
    rows = []
    for f in sorted(set(old) | set(new)):
        st = "A" if f not in old else "D" if f not in new else "M" if old[f] != new[f] else ""
        if st:
            rows.append({"status": st, "file": f})
    return rows


def maybe_renames(removed: List[str], added: List[str]) -> List[str]:
    pairs = []
    used = set()
    for r in removed:
        best = None
        score = 0.0
        for a in added:
            if a in used or parent(a) != parent(r):
                continue
            sc = similar(leaf(r), leaf(a))
            if sc > score:
                score = sc
                best = a
        if best and score >= 0.55:
            used.add(best)
            pairs.append(f"{r} -> {best}")
    return pairs


def uri_shape(uri: str) -> str:
    x = re.sub(r":[A-Za-z0-9_]+", "{}", uri)
    x = re.sub(r"\{[^/]+\}", "{}", x)
    return x


def uri_pairs(removed: List[Dict[str, Any]], added: List[Dict[str, Any]]) -> Dict[Tuple[str, str], str]:
    pairs = {}
    used = set()
    for r in removed:
        best = None
        score = 0.0
        for a in added:
            if id(a) in used or a["method"] != r["method"]:
                continue
            sc = similar(uri_shape(r["uri"]), uri_shape(a["uri"]))
            if sc > score:
                score = sc
                best = a
        if best and score >= 0.62:
            used.add(id(best))
            pairs[(r["method"], r["uri"])] = best["uri"]
            pairs[(best["method"], best["uri"])] = r["uri"]
    return pairs


def method_change_pairs(removed: List[Dict[str, Any]], added: List[Dict[str, Any]]) -> Dict[Tuple[str, str], str]:
    pairs = {}
    removed_by_uri = defaultdict(list)
    added_by_uri = defaultdict(list)
    for r in removed:
        removed_by_uri[r["uri"]].append(r["method"])
    for a in added:
        added_by_uri[a["uri"]].append(a["method"])
    for u in set(removed_by_uri) & set(added_by_uri):
        pairs[("*", u)] = f"{','.join(removed_by_uri[u])} -> {','.join(added_by_uri[u])}"
    return pairs


def add_detail(
    details: List[Dict[str, Any]],
    *,
    category: str,
    method: str,
    uri: str,
    path: str = "",
    old_type: str = "",
    new_type: str = "",
    old_value: str = "",
    new_value: str = "",
    note: str = "",
    source_file: str = "",
    reference_note: str = "",
):
    details.append(
        {
            "category": category,
            "method": method,
            "uri": uri,
            "path": path,
            "old_type": old_type,
            "new_type": new_type,
            "old_value": old_value,
            "new_value": new_value,
            "note": note,
            "source_file": source_file,
            "reference_note": reference_note,
        }
    )


def _has_descendant(path: str, paths: Iterable[str]) -> bool:
    if not path:
        return False
    prefix = path.rstrip("/") + "/"
    return any(p.startswith(prefix) for p in paths if p and p != path)


def minimize_details(details: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Keep only minimal meaningful changed nodes.

    Drop noisy parent container rows such as Oem, Location, Actions, or an object/array
    whose only visible difference is caused by changed children.  Preserve true type
    changes and leaf/schema changes.
    """
    if not details:
        return details
    paths = [d.get("path", "") for d in details if d.get("path")]
    result = []
    for d in details:
        p = d.get("path", "")
        cat = d.get("category", "")
        ot = d.get("old_type", "")
        nt = d.get("new_type", "")
        has_child = _has_descendant(p, paths)
        drop = False
        if has_child:
            # Container property added/removed: children carry the useful, minimal fields.
            if cat in ("属性新增", "属性删除") and (nt in ("Object", "Array") or ot in ("Object", "Array")):
                drop = True
            # Container content changed without type change: keep only changed descendants.
            if cat in ("响应体内容变化", "请求体内容变化") and ot == nt and ot in ("Object", "Array"):
                drop = True
        # Very broad container rows are rarely useful in the main report when descendants exist.
        if has_child and p in ("Oem", "Links", "Actions", "Location"):
            drop = True
        if not drop:
            result.append(d)
    return result


def categories_from_details(
    base_cats: Iterable[str], details: List[Dict[str, Any]], change_type: str, method: str
) -> List[str]:
    cats = set(base_cats)
    detail_cats = {d.get("category", "") for d in details}
    cats.update(c for c in detail_cats if c)
    if any(c in detail_cats for c in ("属性新增", "属性删除", "属性类型变更", "响应体内容变化")):
        # Attribute rows can come from response or request. Keep existing body tags from base;
        # if absent, retain the attribute class only and avoid guessing body direction.
        pass
    if any(d.get("category") == "请求体内容变化" for d in details) and method in ("POST", "PATCH", "PUT"):
        cats.add("POST/PATCH请求体内容变化")
    if change_type == "ADDED":
        cats.add("接口新增")
    if change_type == "REMOVED":
        cats.add("接口删除")
    return categories_sorted(cats)


def finalize_categories_and_details(
    cats: List[str], details: List[Dict[str, Any]], change_type: str, method: str
) -> Tuple[List[str], List[Dict[str, Any]]]:
    details = minimize_details(details)
    return categories_from_details(cats, details, change_type, method), details


def detail_text(details: List[Dict[str, Any]], limit: int = DETAIL_REPORT_LIMIT) -> str:
    parts = []
    for d in details[:limit]:
        cat = d["category"]
        p = d.get("path") or d.get("note") or "-"
        if cat in ("属性新增", "请求体内容变化", "响应体内容变化", "请求头内容变化", "响应头内容变化") and not d.get(
            "old_type"
        ):
            parts.append(f"{cat}: {p}（新增类型={d.get('new_type', '')}，新定义={d.get('new_value', '')}）")
        elif cat in ("属性删除", "请求体内容变化", "响应体内容变化", "请求头内容变化", "响应头内容变化") and not d.get(
            "new_type"
        ):
            parts.append(f"{cat}: {p}（原类型={d.get('old_type', '')}，原定义={d.get('old_value', '')}）")
        elif cat in ("属性类型变更", "返回数据类型变更", "请求数据类型变更"):
            parts.append(
                f"{cat}: {p}（{d.get('old_type', '')} -> {d.get('new_type', '')}；"
                f"{d.get('old_value', '')} -> {d.get('new_value', '')}）"
            )
        elif cat in ("响应体内容变化", "请求体内容变化", "请求头内容变化", "响应头内容变化"):
            parts.append(f"{cat}: {p}（旧={d.get('old_value', '')}；新={d.get('new_value', '')}）")
        elif cat == "接口行为变化":
            parts.append(f"接口行为变化: {p}（旧={d.get('old_value', '')}；新={d.get('new_value', '')}）")
        elif cat in ("接口URI变化", "URI路径变化", "HTTP方法变更"):
            parts.append(d.get("note") or f"{cat}: {p}")
        else:
            parts.append(d.get("note") or f"{cat}: {p}")
        if d.get("reference_note"):
            parts[-1] += "；关联调用变化：" + d.get("reference_note", "")
    if len(details) > limit:
        parts.append(f"另有 {len(details)-limit} 条明细，见 redfish_interface_change_details.csv")
    return "；".join(parts)


def field_changes(
    old_map: Dict[str, Dict[str, Any]],
    new_map: Dict[str, Dict[str, Any]],
    *,
    body_label: str,
    method: str,
    uri: str,
    source_file: str,
) -> Tuple[List[str], List[Dict[str, Any]]]:
    cats = []
    details = []
    old_paths = set(old_map)
    new_paths = set(new_map)
    added = sorted(new_paths - old_paths)
    removed = sorted(old_paths - new_paths)
    common = sorted(old_paths & new_paths)
    content_cat = "接口行为变化" if body_label == "接口行为" else f"{body_label}内容变化"
    add_cat = "属性新增" if body_label == "响应体" else content_cat
    remove_cat = "属性删除" if body_label == "响应体" else content_cat
    if added:
        cats += [add_cat, content_cat] if add_cat != content_cat else [content_cat]
        for p in added:
            add_detail(
                details,
                category=add_cat,
                method=method,
                uri=uri,
                path=p,
                new_type=new_map[p]["type"],
                new_value=new_map[p]["value"],
                source_file=source_file,
                reference_note=new_map[p].get("reference_note", ""),
            )
    if removed:
        cats += [remove_cat, content_cat] if remove_cat != content_cat else [content_cat]
        for p in removed:
            add_detail(
                details,
                category=remove_cat,
                method=method,
                uri=uri,
                path=p,
                old_type=old_map[p]["type"],
                old_value=old_map[p]["value"],
                source_file=source_file,
                reference_note=old_map[p].get("reference_note", ""),
            )
    for p in common:
        o = old_map[p]
        n = new_map[p]
        if o["type"] != n["type"]:
            cats += ["属性类型变更", content_cat]
            if body_label == "响应体":
                cats.append("返回数据类型变更")
            elif body_label == "请求体":
                cats.append("请求数据类型变更")
            add_detail(
                details,
                category="属性类型变更",
                method=method,
                uri=uri,
                path=p,
                old_type=o["type"],
                new_type=n["type"],
                old_value=o["value"],
                new_value=n["value"],
                source_file=source_file,
                reference_note="；".join(x for x in (o.get("reference_note", ""), n.get("reference_note", "")) if x),
            )
        elif o["value"] != n["value"]:
            cats.append(content_cat)
            add_detail(
                details,
                category=content_cat,
                method=method,
                uri=uri,
                path=p,
                old_type=o["type"],
                new_type=n["type"],
                old_value=o["value"],
                new_value=n["value"],
                source_file=source_file,
                reference_note="；".join(x for x in (o.get("reference_note", ""), n.get("reference_note", "")) if x),
            )
    return cats, details


def _short_keys(keys: Iterable[str], limit: int = 20) -> str:
    vals = sorted(str(x) for x in keys)
    if not vals:
        return "-"
    return ", ".join(vals[:limit]) + (f" ...（另 {len(vals)-limit} 项）" if len(vals) > limit else "")


def summarize_behavior_value(key: str, value: Any) -> str:
    if value == "<不存在>":
        return "<不存在>"
    if key == "Statements" and isinstance(value, dict):
        return "Statements项=" + _short_keys(value.keys())
    if key == "ProcessingFlow" and isinstance(value, list):
        types = []
        for item in value:
            if isinstance(item, dict):
                types.append(str(item.get("Type", "?")))
            else:
                types.append(type(item).__name__)
        return "数组长度={}；步骤类型={}".format(len(value), _short_keys(types, 12))
    if key == "ResourceExist" and isinstance(value, dict):
        return "资源存在性条件=" + _short_keys(value.keys())
    if key == "Privilege":
        return brief_value(value, 160)
    return brief_value(value, 180)


def summarize_behavior_diff(key: str, old_value: Any, new_value: Any) -> Tuple[str, str]:
    if key == "Statements" and isinstance(old_value, dict) and isinstance(new_value, dict):
        ok = set(old_value.keys())
        nk = set(new_value.keys())
        added = sorted(nk - ok)
        removed = sorted(ok - nk)
        changed = sorted(k for k in ok & nk if canon(old_value[k]) != canon(new_value[k]))
        old_summary = "旧Statements项=" + _short_keys(ok)
        pieces = []
        if added:
            pieces.append("新增=" + _short_keys(added))
        if removed:
            pieces.append("删除=" + _short_keys(removed))
        if changed:
            pieces.append("修改=" + _short_keys(changed))
        return old_summary, "；".join(pieces) if pieces else "Statements内部顺序或格式变化"
    if key == "ProcessingFlow" and isinstance(old_value, list) and isinstance(new_value, list):
        return summarize_behavior_value(key, old_value), summarize_behavior_value(key, new_value)
    if key == "ResourceExist" and isinstance(old_value, dict) and isinstance(new_value, dict):
        ok = set(old_value.keys())
        nk = set(new_value.keys())
        pieces = []
        if nk - ok:
            pieces.append("新增条件=" + _short_keys(nk - ok))
        if ok - nk:
            pieces.append("删除条件=" + _short_keys(ok - nk))
        if ok & nk:
            pieces.append("保留条件=" + _short_keys(ok & nk))
        return summarize_behavior_value(key, old_value), "；".join(pieces)
    return summarize_behavior_value(key, old_value), summarize_behavior_value(key, new_value)


def behavior_changes(
    old: Dict[str, Any], new: Dict[str, Any], *, method: str, uri: str, source_file: str
) -> Tuple[List[str], List[Dict[str, Any]]]:
    details = []
    cats = []
    oldb = old.get("behavior", {})
    newb = new.get("behavior", {})
    for k in sorted(set(oldb) | set(newb)):
        ov = oldb.get(k, "<不存在>")
        nv = newb.get(k, "<不存在>")
        if canon(ov) != canon(nv):
            cats.append("接口行为变化")
            old_summary, new_summary = summarize_behavior_diff(k, ov, nv)
            add_detail(
                details,
                category="接口行为变化",
                method=method,
                uri=uri,
                path=k,
                old_type=kind(ov),
                new_type=kind(nv),
                old_value=old_summary,
                new_value=new_summary,
                source_file=source_file,
            )
    return cats, details


def all_surface_maps(item: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    merged = {}
    for key in ("req_map", "rsp_map", "req_header_map", "rsp_header_map", "resource_map"):
        merged.update(item.get(key, {}) or {})
    return merged


def empty_entry(method: str = "", uri: str = "", source_file: str = "") -> Dict[str, Any]:
    return {
        "method": method,
        "uri": uri,
        "source_file": source_file,
        "interface": {},
        "req_map": {},
        "rsp_map": {},
        "req_header_map": {},
        "rsp_header_map": {},
        "resource_map": {},
        "statement_graph": {},
        "processing_graph": {},
    }


def normalize_surface_path(path: str) -> str:
    text = str(path or "").replace("[#INDEX]", "[]")
    text = re.sub(r"\[\d+\]", "[]", text)
    return text


def find_surface_for_ref(item: Dict[str, Any], ref: str) -> List[str]:
    ref_norm = normalize_surface_path(ref)
    exact = []
    ancestors = []
    descendants = []
    for path in all_surface_maps(item):
        p_norm = normalize_surface_path(path)
        if p_norm == ref_norm:
            exact.append(path)
        elif ref_norm.startswith(p_norm + "/"):
            ancestors.append(path)
        elif p_norm.startswith(ref_norm + "/"):
            descendants.append(path)
    if exact:
        return sorted(exact)
    if ancestors:
        # Use the most specific containing object, not every parent up to ReqBody.
        max_len = max(len(normalize_surface_path(p)) for p in ancestors)
        return sorted(p for p in ancestors if len(normalize_surface_path(p)) == max_len)
    if descendants:
        return sorted(descendants, key=lambda x: (len(x), x))
    # For ReqBodyOriginal and the historical ReaHeader spelling, map to the reported surface names.
    if ref.startswith("ReqBodyOriginal/"):
        return find_surface_for_ref(item, "ReqBody/" + ref.split("/", 1)[1])
    if ref.startswith("ReaHeader/"):
        return find_surface_for_ref(item, "ReqHeader/" + ref.split("/", 1)[1])
    return []


def category_for_surface_path(path: str) -> str:
    if path.startswith("ReqBody"):
        return "请求体内容变化"
    if path.startswith("RspBody"):
        return "响应体内容变化"
    if path.startswith("ReqHeader"):
        return "请求头内容变化"
    if path.startswith("RspHeader"):
        return "响应头内容变化"
    return "接口行为变化"


def surface_from_items(path: str, old: Dict[str, Any], new: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    return all_surface_maps(old).get(path, {}) or {}, all_surface_maps(new).get(path, {}) or {}


def append_ref_note(existing: str, note: str) -> str:
    if not note:
        return existing or ""
    parts = [p for p in str(existing or "").split("；") if p]
    if note not in parts:
        parts.append(note)
    return "；".join(parts)


def upsert_reference_detail(
    details: List[Dict[str, Any]],
    *,
    old: Dict[str, Any],
    new: Dict[str, Any],
    method: str,
    uri: str,
    path: str,
    note: str,
    source_file: str,
) -> None:
    if not path:
        return
    category = category_for_surface_path(path)
    for d in details:
        if d.get("path") == path and d.get("category") == category:
            d["reference_note"] = append_ref_note(d.get("reference_note", ""), note)
            return
    old_s, new_s = surface_from_items(path, old, new)
    add_detail(
        details,
        category=category,
        method=method,
        uri=uri,
        path=path,
        old_type=old_s.get("type", ""),
        new_type=new_s.get("type", ""),
        old_value=old_s.get("value", ""),
        new_value=new_s.get("value", ""),
        source_file=source_file,
        reference_note=note,
    )


def statement_call_sites(item: Dict[str, Any], statement_name: str) -> List[str]:
    ref = "Statements/" + statement_name
    sites = []
    for path, data in all_surface_maps(item).items():
        if ref in data.get("refs", []):
            sites.append(path)
    return sorted(set(sites))


def statements_using_ref(item: Dict[str, Any], ref: str) -> List[str]:
    result = []
    ref_norm = normalize_surface_path(ref)
    for name, data in item.get("statement_graph", {}).items():
        refs = [normalize_surface_path(r) for r in data.get("refs", [])]
        if ref_norm in refs:
            result.append(name)
    return result


def processing_flow_label(flow: Any, idx: int) -> str:
    if isinstance(flow, dict):
        typ = flow.get("Type", "?")
        name = flow.get("Name") or flow.get("Interface") or flow.get("Path") or "?"
        return f"ProcessingFlow[{idx}]({typ}/{name})"
    return f"ProcessingFlow[{idx}]"


def processing_flow_input_refs(flow: Any) -> List[str]:
    refs = extract_refs(flow)
    return [r for r in refs if r.startswith(("ReqBody/", "ReqBodyOriginal/", "ReqHeader/", "ReaHeader/"))]


def add_unresolved_logic_detail(
    details: List[Dict[str, Any]], *, method: str, uri: str, source_file: str, note: str
) -> None:
    for d in details:
        if d.get("path") == "接口执行逻辑" and d.get("category") == "接口行为变化":
            d["reference_note"] = append_ref_note(d.get("reference_note", ""), note)
            return
    add_detail(
        details,
        category="接口行为变化",
        method=method,
        uri=uri,
        path="接口执行逻辑",
        old_type="Object",
        new_type="Object",
        old_value="-",
        new_value="-",
        source_file=source_file,
        reference_note=note,
    )


def add_reference_impacts(
    old: Dict[str, Any], new: Dict[str, Any], details: List[Dict[str, Any]], *, method: str, uri: str, source_file: str
) -> Tuple[List[str], List[Dict[str, Any]]]:
    cats = []
    old_itf = old.get("interface", {}) or {}
    new_itf = new.get("interface", {}) or {}
    changed_statements = statement_names_changed(old_itf.get("Statements"), new_itf.get("Statements"))
    for name, change in changed_statements.items():
        sites = statement_call_sites(new, name) or statement_call_sites(old, name)
        note = f"{change} Statements/{name}()"
        if sites:
            for path in sites:
                upsert_reference_detail(
                    details,
                    old=old,
                    new=new,
                    method=method,
                    uri=uri,
                    path=path,
                    note=f"{path} 引用了{note}",
                    source_file=source_file,
                )
                cats.append(category_for_surface_path(path))
        else:
            # If another changed or unchanged statement calls it, surface the transitive callers.
            transitive = []
            for caller, data in {**old.get("statement_graph", {}), **new.get("statement_graph", {})}.items():
                if "Statements/" + name in data.get("refs", []):
                    transitive.extend(statement_call_sites(new, caller) or statement_call_sites(old, caller))
            if transitive:
                for path in sorted(set(transitive)):
                    upsert_reference_detail(
                        details,
                        old=old,
                        new=new,
                        method=method,
                        uri=uri,
                        path=path,
                        note=f"{path} 通过 Statements 调用链关联{note}",
                        source_file=source_file,
                    )
                    cats.append(category_for_surface_path(path))
            else:
                add_unresolved_logic_detail(
                    details,
                    method=method,
                    uri=uri,
                    source_file=source_file,
                    note=note + "，未定位到请求体/响应体/header 调用点",
                )
                cats.append("接口行为变化")

    changed_flows = processing_flows_changed(old_itf.get("ProcessingFlow"), new_itf.get("ProcessingFlow"))
    old_flow = old_itf.get("ProcessingFlow") if isinstance(old_itf.get("ProcessingFlow"), list) else []
    new_flow = new_itf.get("ProcessingFlow") if isinstance(new_itf.get("ProcessingFlow"), list) else []
    for idx, change in changed_flows.items():
        flow = new_flow[idx] if idx < len(new_flow) else old_flow[idx] if idx < len(old_flow) else {}
        label = processing_flow_label(flow, idx)
        touched = False
        for ref in processing_flow_input_refs(flow):
            for path in find_surface_for_ref(new, ref) or find_surface_for_ref(old, ref):
                upsert_reference_detail(
                    details,
                    old=old,
                    new=new,
                    method=method,
                    uri=uri,
                    path=path,
                    note=f"{path} 被{change}{label}使用",
                    source_file=source_file,
                )
                cats.append(category_for_surface_path(path))
                touched = True
        dests = []
        if isinstance(flow, dict) and isinstance(flow.get("Destination"), dict):
            dests = [str(v) for v in flow["Destination"].values()]
        for dest in dests:
            ref = f"ProcessingFlow[{idx}]/Destination/{dest}"
            sites = []
            for item in (new, old):
                for path, data in all_surface_maps(item).items():
                    if ref in data.get("refs", []):
                        sites.append(path)
                for stmt in statements_using_ref(item, ref):
                    sites.extend(statement_call_sites(new, stmt) or statement_call_sites(old, stmt))
            for path in sorted(set(sites)):
                upsert_reference_detail(
                    details,
                    old=old,
                    new=new,
                    method=method,
                    uri=uri,
                    path=path,
                    note=f"{path} 引用了{change}{label}的 Destination/{dest}",
                    source_file=source_file,
                )
                cats.append(category_for_surface_path(path))
                touched = True
        if not touched and change:
            add_unresolved_logic_detail(
                details,
                method=method,
                uri=uri,
                source_file=source_file,
                note=f"{change}{label}，未定位到请求体/响应体/header 调用点",
            )
            cats.append("接口行为变化")
    return cats, details


def semantic_interface_definition(interface: Dict[str, Any], *, change_word: str = "新增") -> List[Dict[str, Any]]:
    rows = []
    if not isinstance(interface, dict):
        return rows
    for key in ("Type", "Privilege", "LockdownAllow", "Usage", "Brief", "Description"):
        if key in interface:
            rows.append(
                {
                    "path": key,
                    "type": kind(interface[key]),
                    "value": brief_value(interface[key], CSV_VALUE_LIMIT),
                    "reference_note": "",
                }
            )
    for path, data in build_resource_surface(interface.get("ResourceExist")).items():
        rows.append({"path": path, "type": data["type"], "value": data["value"], "reference_note": ""})
    for path, data in build_header_surface(interface.get("ReqHeader", interface.get("ReaHeader")), "ReqHeader").items():
        rows.append({"path": path, "type": data["type"], "value": data["value"], "reference_note": ""})
    for path, data in build_header_surface(interface.get("RspHeader"), "RspHeader").items():
        rows.append({"path": path, "type": data["type"], "value": data["value"], "reference_note": ""})
    for path, data in build_req_surface(interface.get("ReqBody"), include_root=True).items():
        rows.append({"path": path, "type": data["type"], "value": data["value"], "reference_note": ""})
    for path, data in build_rsp_surface(interface.get("RspBody"), include_noise=True).items():
        rows.append({"path": path, "type": data["type"], "value": data["value"], "reference_note": ""})
    pseudo = {
        "interface": interface,
        "req_map": build_req_surface(interface.get("ReqBody"), include_root=True),
        "rsp_map": build_rsp_surface(interface.get("RspBody"), include_noise=True),
        "req_header_map": build_header_surface(interface.get("ReqHeader", interface.get("ReaHeader")), "ReqHeader"),
        "rsp_header_map": build_header_surface(interface.get("RspHeader"), "RspHeader"),
        "resource_map": build_resource_surface(interface.get("ResourceExist")),
        "statement_graph": build_statement_graph(interface),
        "processing_graph": build_processing_flow_graph(interface),
    }
    row_by_path = {r["path"]: r for r in rows}
    statement_names = (
        sorted((interface.get("Statements") or {}).keys()) if isinstance(interface.get("Statements"), dict) else []
    )
    for name in statement_names:
        for path in statement_call_sites(pseudo, name):
            if path in row_by_path:
                row_by_path[path]["reference_note"] = append_ref_note(
                    row_by_path[path].get("reference_note", ""), f"{path} 引用了{change_word} Statements/{name}()"
                )
    flow = interface.get("ProcessingFlow") if isinstance(interface.get("ProcessingFlow"), list) else []
    for idx, item in enumerate(flow):
        label = processing_flow_label(item, idx)
        for ref in processing_flow_input_refs(item):
            for path in find_surface_for_ref(pseudo, ref):
                if path in row_by_path:
                    row_by_path[path]["reference_note"] = append_ref_note(
                        row_by_path[path].get("reference_note", ""), f"{path} 被{change_word}{label}使用"
                    )
        dests = (
            [str(v) for v in item.get("Destination", {}).values()]
            if isinstance(item, dict) and isinstance(item.get("Destination"), dict)
            else []
        )
        for dest in dests:
            ref = f"ProcessingFlow[{idx}]/Destination/{dest}"
            for path, data in all_surface_maps(pseudo).items():
                if ref in data.get("refs", []) and path in row_by_path:
                    row_by_path[path]["reference_note"] = append_ref_note(
                        row_by_path[path].get("reference_note", ""),
                        f"{path} 引用了{change_word}{label}的 Destination/{dest}",
                    )
            for stmt in statements_using_ref(pseudo, ref):
                for path in statement_call_sites(pseudo, stmt):
                    if path in row_by_path:
                        row_by_path[path]["reference_note"] = append_ref_note(
                            row_by_path[path].get("reference_note", ""),
                            f"{path} 通过 Statements/{stmt}() 引用了{change_word}{label}的 Destination/{dest}",
                        )
    return rows


def flatten_added_definition(
    obj: Any, prefix: str = "", out: Optional[List[Dict[str, str]]] = None
) -> List[Dict[str, str]]:
    """Compatibility wrapper for semantic full-interface definition rows."""
    if isinstance(obj, dict) and not prefix:
        return semantic_interface_definition(obj, change_word="新增")
    rows = out if out is not None else []
    rows.append(
        {
            "path": prefix or "<value>",
            "type": kind(obj),
            "value": brief_value(obj, CSV_VALUE_LIMIT),
            "reference_note": "",
        }
    )
    return rows


def categories_sorted(cats: Iterable[str]) -> List[str]:
    return sorted(set(cats), key=lambda x: CATEGORY_ORDER.index(x) if x in CATEGORY_ORDER else 99)


def summary_from_details(change_type: str, details: List[Dict[str, Any]], uri_related: str = "") -> str:
    parts = []
    if uri_related:
        parts.append(uri_related)
    # Concise rollup by category.
    for cat in (
        "属性新增",
        "属性删除",
        "属性名称变更",
        "属性类型变更",
        "响应体内容变化",
        "请求体内容变化",
        "请求头内容变化",
        "响应头内容变化",
        "接口行为变化",
    ):
        ds = [d for d in details if d["category"] == cat]
        if not ds:
            continue
        if cat == "属性新增":
            parts.append("属性新增: " + sl([d["path"] for d in ds if d.get("path")], 12))
        elif cat == "属性删除":
            parts.append("属性删除: " + sl([d["path"] for d in ds if d.get("path")], 12))
        elif cat == "属性名称变更":
            parts.append(sl([d.get("note", "") for d in ds], 4))
        elif cat == "属性类型变更":
            parts.append("属性类型变化: " + sl([f"{d['path']}:{d['old_type']}->{d['new_type']}" for d in ds], 8))
        elif cat == "响应体内容变化":
            parts.append("响应定义变化: " + sl([d["path"] for d in ds if d.get("path")], 8))
        elif cat == "请求体内容变化":
            parts.append("请求定义变化: " + sl([d["path"] for d in ds if d.get("path")], 8))
        elif cat == "接口行为变化":
            parts.append("行为变化: " + sl([d["path"] for d in ds if d.get("path")], 8))
    if not parts:
        parts.append(
            "新增接口"
            if change_type == "ADDED"
            else "删除接口" if change_type == "REMOVED" else "接口 mapping 逻辑、校验、脚本或后端调用变化"
        )
    return "；".join(parts)


def diff_entries(
    old: Dict[EntryKey, Dict[str, Any]], new: Dict[EntryKey, Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    raw_added = [new[k] for k in set(new) - set(old) if reportable_uri(new[k]["uri"])]
    raw_removed = [old[k] for k in set(old) - set(new) if reportable_uri(old[k]["uri"])]
    mpairs = method_change_pairs(raw_removed, raw_added)
    rows = []
    all_details = []

    for e in raw_added:
        cats = ["接口新增"]
        details = []
        if ("*", e["uri"]) in mpairs:
            cats.append("HTTP方法变更")
            add_detail(
                details,
                category="HTTP方法变更",
                method=e["method"],
                uri=e["uri"],
                note="HTTP 方法变化: " + mpairs[("*", e["uri"])],
                source_file=e["source_file"],
            )
        if e["rsp_map"]:
            cats += ["响应体内容变化", "属性新增"]
            for p, n in sorted(e["rsp_map"].items()):
                add_detail(
                    details,
                    category="属性新增",
                    method=e["method"],
                    uri=e["uri"],
                    path=p,
                    new_type=n["type"],
                    new_value=n["value"],
                    source_file=e["source_file"],
                    reference_note=n.get("reference_note", ""),
                )
        if e["req_map"]:
            cats += ["请求体内容变化"]
            if e["method"] in ("POST", "PATCH", "PUT"):
                cats.append("POST/PATCH请求体内容变化")
            for p, n in sorted(e["req_map"].items()):
                add_detail(
                    details,
                    category="请求体内容变化",
                    method=e["method"],
                    uri=e["uri"],
                    path=p,
                    new_type=n["type"],
                    new_value=n["value"],
                    source_file=e["source_file"],
                    reference_note=n.get("reference_note", ""),
                )
        if e.get("req_header_map"):
            cats += ["请求头内容变化"]
            for p, n in sorted(e["req_header_map"].items()):
                add_detail(
                    details,
                    category="请求头内容变化",
                    method=e["method"],
                    uri=e["uri"],
                    path=p,
                    new_type=n["type"],
                    new_value=n["value"],
                    source_file=e["source_file"],
                    reference_note=n.get("reference_note", ""),
                )
        if e.get("rsp_header_map"):
            cats += ["响应头内容变化"]
            for p, n in sorted(e["rsp_header_map"].items()):
                add_detail(
                    details,
                    category="响应头内容变化",
                    method=e["method"],
                    uri=e["uri"],
                    path=p,
                    new_type=n["type"],
                    new_value=n["value"],
                    source_file=e["source_file"],
                    reference_note=n.get("reference_note", ""),
                )
        c, details = add_reference_impacts(
            empty_entry(e["method"], e["uri"], e["source_file"]),
            e,
            details,
            method=e["method"],
            uri=e["uri"],
            source_file=e["source_file"],
        )
        cats += c
        cats, details = finalize_categories_and_details(cats, details, "ADDED", e["method"])
        detail = detail_text(details, limit=max(DETAIL_REPORT_LIMIT, len(details)))
        row = {
            "change_type": "ADDED",
            "categories": "；".join(categories_sorted(cats)),
            "method": e["method"],
            "uri": e["uri"],
            "source_file": e["source_file"],
            "summary": summary_from_details("ADDED", details),
            "detail": detail,
            "_added_definition": flatten_added_definition(e.get("interface", {})),
        }
        rows.append(row)
        all_details.extend(details)

    for e in raw_removed:
        cats = ["接口删除"]
        details = []
        if ("*", e["uri"]) in mpairs:
            cats.append("HTTP方法变更")
            add_detail(
                details,
                category="HTTP方法变更",
                method=e["method"],
                uri=e["uri"],
                note="HTTP 方法变化: " + mpairs[("*", e["uri"])],
                source_file=e["source_file"],
            )
        if e["rsp_map"]:
            cats += ["响应体内容变化", "属性删除"]
            for p, o in sorted(e["rsp_map"].items()):
                add_detail(
                    details,
                    category="属性删除",
                    method=e["method"],
                    uri=e["uri"],
                    path=p,
                    old_type=o["type"],
                    old_value=o["value"],
                    source_file=e["source_file"],
                    reference_note=o.get("reference_note", ""),
                )
        if e["req_map"]:
            cats += ["请求体内容变化"]
            if e["method"] in ("POST", "PATCH", "PUT"):
                cats.append("POST/PATCH请求体内容变化")
            for p, o in sorted(e["req_map"].items()):
                add_detail(
                    details,
                    category="请求体内容变化",
                    method=e["method"],
                    uri=e["uri"],
                    path=p,
                    old_type=o["type"],
                    old_value=o["value"],
                    source_file=e["source_file"],
                    reference_note=o.get("reference_note", ""),
                )
        if e.get("req_header_map"):
            cats += ["请求头内容变化"]
            for p, o in sorted(e["req_header_map"].items()):
                add_detail(
                    details,
                    category="请求头内容变化",
                    method=e["method"],
                    uri=e["uri"],
                    path=p,
                    old_type=o["type"],
                    old_value=o["value"],
                    source_file=e["source_file"],
                    reference_note=o.get("reference_note", ""),
                )
        if e.get("rsp_header_map"):
            cats += ["响应头内容变化"]
            for p, o in sorted(e["rsp_header_map"].items()):
                add_detail(
                    details,
                    category="响应头内容变化",
                    method=e["method"],
                    uri=e["uri"],
                    path=p,
                    old_type=o["type"],
                    old_value=o["value"],
                    source_file=e["source_file"],
                    reference_note=o.get("reference_note", ""),
                )
        c, details = add_reference_impacts(
            e,
            empty_entry(e["method"], e["uri"], e["source_file"]),
            details,
            method=e["method"],
            uri=e["uri"],
            source_file=e["source_file"],
        )
        cats += c
        cats, details = finalize_categories_and_details(cats, details, "REMOVED", e["method"])
        detail = detail_text(details)
        row = {
            "change_type": "REMOVED",
            "categories": "；".join(categories_sorted(cats)),
            "method": e["method"],
            "uri": e["uri"],
            "source_file": e["source_file"],
            "summary": summary_from_details("REMOVED", details),
            "detail": detail,
            "_removed_definition": semantic_interface_definition(e.get("interface", {}), change_word="删除"),
        }
        rows.append(row)
        all_details.extend(details)

    for k in sorted(set(old) & set(new), key=lambda x: (x[1], x[0])):
        o = old[k]
        n = new[k]
        if not reportable_uri(n["uri"]):
            continue
        if o["signature"] == n["signature"] and o["source_file"] == n["source_file"]:
            continue
        cats = []
        details = []
        c, d = field_changes(
            o["rsp_map"],
            n["rsp_map"],
            body_label="响应体",
            method=n["method"],
            uri=n["uri"],
            source_file=n["source_file"],
        )
        cats += c
        details += d
        c, d = field_changes(
            o["req_map"],
            n["req_map"],
            body_label="请求体",
            method=n["method"],
            uri=n["uri"],
            source_file=n["source_file"],
        )
        cats += c
        details += d
        c, d = field_changes(
            o.get("req_header_map", {}),
            n.get("req_header_map", {}),
            body_label="请求头",
            method=n["method"],
            uri=n["uri"],
            source_file=n["source_file"],
        )
        cats += c
        details += d
        c, d = field_changes(
            o.get("rsp_header_map", {}),
            n.get("rsp_header_map", {}),
            body_label="响应头",
            method=n["method"],
            uri=n["uri"],
            source_file=n["source_file"],
        )
        cats += c
        details += d
        c, d = field_changes(
            o.get("resource_map", {}),
            n.get("resource_map", {}),
            body_label="接口行为",
            method=n["method"],
            uri=n["uri"],
            source_file=n["source_file"],
        )
        cats += c
        details += d
        if n["method"] in ("POST", "PATCH", "PUT") and any(x in cats for x in ("请求体内容变化", "请求数据类型变更")):
            cats.append("POST/PATCH请求体内容变化")
        c, d = behavior_changes(o, n, method=n["method"], uri=n["uri"], source_file=n["source_file"])
        cats += c
        details += d
        c, details = add_reference_impacts(
            o, n, details, method=n["method"], uri=n["uri"], source_file=n["source_file"]
        )
        cats += c
        if not cats and o["signature"] != n["signature"]:
            cats = ["接口行为变化"]
            add_detail(
                details,
                category="接口行为变化",
                method=n["method"],
                uri=n["uri"],
                note="interface JSON 发生变化，但未定位到 ReqBody/RspBody/Header 字段级差异",
                source_file=n["source_file"],
            )
        cats, details = finalize_categories_and_details(cats, details, "MODIFIED", n["method"])
        detail = detail_text(details)
        row = {
            "change_type": "MODIFIED",
            "categories": "；".join(categories_sorted(cats)),
            "method": n["method"],
            "uri": n["uri"],
            "source_file": n["source_file"],
            "summary": summary_from_details("MODIFIED", details),
            "detail": detail,
        }
        rows.append(row)
        all_details.extend(details)

    order = {"ADDED": 0, "REMOVED": 1, "MODIFIED": 2}
    rows = sorted(
        rows,
        key=lambda r: (order.get(r["change_type"], 9), not r["uri"].startswith(EXTERNAL_PREFIX), r["uri"], r["method"]),
    )
    return rows, all_details


# ---------------------------- output ----------------------------
def write_csv(rows, path: Path) -> None:
    cols = [
        "change_type",
        "categories",
        "method",
        "uri",
        "source_file",
        "summary",
        "detail",
        "mr_links",
        "authors",
        "issue_links",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows([{c: r.get(c, "") for c in cols} for r in rows])


def write_detail_csv(details: List[Dict[str, Any]], path: Path) -> None:
    cols = [
        "category",
        "method",
        "uri",
        "path",
        "old_type",
        "new_type",
        "old_value",
        "new_value",
        "note",
        "reference_note",
        "source_file",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows([{c: d.get(c, "") for c in cols} for d in details])


def write_category_csv(rows, path: Path):
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["category", "count"])
        cnt = Counter(c for r in rows for c in r["categories"].split("；") if c)
        for c in CATEGORY_ORDER:
            if cnt.get(c):
                w.writerow([c, cnt[c]])


def table(rows, cols, limit=None):
    shown = rows if limit is None else rows[:limit]
    lines = ["| " + " | ".join(t for t, k in cols) + " |", "|" + "|".join(["---"] * len(cols)) + "|"]
    for i, r in enumerate(shown, 1):
        vals = []
        for _t, k in cols:
            if k == "#":
                anchor = r.get("_anchor")
                vals.append((f'<a id="{anchor}"></a>' if anchor else "") + str(i))
            else:
                vals.append(esc(r.get(k, "")))
        lines.append("| " + " | ".join(vals) + " |")
    if limit and len(rows) > limit:
        lines.append("| " + " | ".join(["..."] * len(cols)) + " |")
    return "\n".join(lines)


def uri_group(uri):
    ps = [p for p in uri.strip("/").split("/") if p]
    if len(ps) >= 5 and ps[0] == "redfish" and ps[1] == "v1":
        return "/" + "/".join(ps[:5])
    if len(ps) >= 3:
        return "/" + "/".join(ps[:3])
    return uri


def detail_scope(detail: Dict[str, Any], row: Optional[Dict[str, Any]] = None) -> str:
    cat = detail.get("category", "")
    path = detail.get("path", "") or detail.get("note", "")
    uri = (row or {}).get("uri", "")
    if cat == "接口新增":
        return "接口"
    if path.startswith("ReqBody") or cat == "请求体内容变化":
        return "请求体"
    if path.startswith("RspBody"):
        return "响应体"
    if path.startswith("ReqHeader") or cat == "请求头内容变化":
        return "请求头"
    if path.startswith("RspHeader") or cat == "响应头内容变化":
        return "响应头"
    if path.startswith("ResourceExist"):
        return "资源存在性"
    if cat == "接口行为变化":
        return "接口执行逻辑"
    action_hint = (
        "/Actions/" in uri
        or uri.endswith("ActionInfo")
        or "Actions/" in path
        or "ActionInfo" in path
        or "/target" in path
    )
    if action_hint:
        return "Action/ActionInfo"
    if cat in ("属性新增", "属性删除", "属性类型变更", "响应体内容变化", "返回数据类型变更"):
        return "响应体"
    return "其他"


def detail_description(detail: Dict[str, Any]) -> str:
    note = detail.get("note", "")
    if note:
        return note
    old_type = detail.get("old_type", "")
    new_type = detail.get("new_type", "")
    old_value = detail.get("old_value", "")
    new_value = detail.get("new_value", "")
    parts = []
    if old_type or new_type:
        if old_type and new_type and old_type != new_type:
            parts.append(f"类型：{old_type} -> {new_type}")
        elif new_type and not old_type:
            parts.append(f"新增类型：{new_type}")
        elif old_type and not new_type:
            parts.append(f"原类型：{old_type}")
        elif new_type:
            parts.append(f"类型：{new_type}")
    if old_value or new_value:
        if old_value and new_value:
            parts.append(f"定义：{old_value} -> {new_value}")
        elif new_value:
            parts.append(f"新定义：{new_value}")
        elif old_value:
            parts.append(f"原定义：{old_value}")
    return "；".join(parts) if parts else "-"


def added_definition_scope(path: str) -> str:
    if path in ("Type", "Privilege"):
        return "接口"
    if path.startswith("ResourceExist"):
        return "资源存在性"
    if path.startswith("ReqBody"):
        return "请求体"
    if path.startswith("RspBody"):
        return "响应体"
    if path.startswith("ReqHeader"):
        return "请求头"
    if path.startswith("RspHeader"):
        return "响应头"
    if path.startswith("OperationMap") or path.startswith("Targets"):
        return "权限映射"
    return "接口定义"


def detail_table_for_added(row: Dict[str, Any], detail_rows: List[Dict[str, Any]]) -> str:
    lines = ["| 序号 | 变动范围 | 变动类型 | 对象路径 | 说明 | 关联调用变化 |", "|---:|---|---|---|---|---|"]
    lines.append(
        "| 1 | 接口 | 接口新增 | `{}` `{}` | 新版本新增完整接口。 | - |".format(
            esc(row.get("method", "")), esc(row.get("uri", ""))
        )
    )
    full_definition = row.get("_added_definition") or []
    if full_definition:
        for idx, d in enumerate(full_definition, 2):
            path = d.get("path", "-")
            desc = "新增类型：{}；新定义：{}".format(d.get("type", ""), d.get("value", ""))
            lines.append(
                "| {} | {} | 定义新增 | {} | {} | {} |".format(
                    idx,
                    esc(added_definition_scope(path)),
                    esc(path),
                    esc(desc),
                    esc(d.get("reference_note", "") or "-"),
                )
            )
    else:
        idx = 2
        for d in detail_rows:
            target = d.get("path") or d.get("note") or "-"
            lines.append(
                "| {} | {} | {} | {} | {} | {} |".format(
                    idx,
                    esc(detail_scope(d, row)),
                    esc(d.get("category", "")),
                    esc(target),
                    esc(detail_description(d)),
                    esc(d.get("reference_note", "") or "-"),
                )
            )
            idx += 1
    return "\n".join(lines)


def detail_table_for_removed(row: Dict[str, Any], detail_rows: List[Dict[str, Any]]) -> str:
    lines = ["| 序号 | 变动范围 | 变动类型 | 对象路径 | 说明 | 关联调用变化 |", "|---:|---|---|---|---|---|"]
    lines.append(
        "| 1 | 接口 | 接口删除 | `{}` `{}` | 旧版本完整接口在新版本中删除。 | - |".format(
            esc(row.get("method", "")), esc(row.get("uri", ""))
        )
    )
    full_definition = row.get("_removed_definition") or []
    if full_definition:
        for idx, d in enumerate(full_definition, 2):
            path = d.get("path", "-")
            desc = "原类型：{}；原定义：{}".format(d.get("type", ""), d.get("value", ""))
            lines.append(
                "| {} | {} | 定义删除 | {} | {} | {} |".format(
                    idx,
                    esc(added_definition_scope(path)),
                    esc(path),
                    esc(desc),
                    esc(d.get("reference_note", "") or "-"),
                )
            )
    else:
        idx = 2
        for d in detail_rows:
            target = d.get("path") or d.get("note") or "-"
            lines.append(
                "| {} | {} | {} | {} | {} | {} |".format(
                    idx,
                    esc(detail_scope(d, row)),
                    esc(d.get("category", "")),
                    esc(target),
                    esc(detail_description(d)),
                    esc(d.get("reference_note", "") or "-"),
                )
            )
            idx += 1
    return "\n".join(lines)


def detail_change_kind(detail: Dict[str, Any]) -> str:
    cat = detail.get("category", "")
    if detail.get("old_type") and not detail.get("new_type"):
        return "删除"
    if detail.get("new_type") and not detail.get("old_type"):
        return "新增"
    if cat in ("属性新增",):
        return "新增"
    if cat in ("属性删除",):
        return "删除"
    return "变更"


def detail_old_desc(detail: Dict[str, Any]) -> str:
    old_type = detail.get("old_type", "")
    old_value = detail.get("old_value", "")
    if not old_type and not old_value:
        return "-"
    parts = []
    if old_type:
        parts.append("类型：" + old_type)
    if old_value:
        parts.append("定义：" + old_value)
    return "；".join(parts)


def detail_new_desc(detail: Dict[str, Any]) -> str:
    new_type = detail.get("new_type", "")
    new_value = detail.get("new_value", "")
    note = detail.get("note", "")
    if not new_type and not new_value and note:
        return note
    if not new_type and not new_value:
        return "-"
    parts = []
    if new_type:
        parts.append("类型：" + new_type)
    if new_value:
        parts.append("定义：" + new_value)
    return "；".join(parts)


def detail_table_for_modified(row: Dict[str, Any], detail_rows: List[Dict[str, Any]]) -> str:
    lines = [
        "| 序号 | 变动范围 | 变动性质 | 对象路径 | 旧定义 | 新定义 | 关联调用变化 |",
        "|---:|---|---|---|---|---|---|",
    ]
    lines.append(
        "| 1 | 接口路径 | 未修改 | `{}` `{}` | `{}` | `{}` | - |".format(
            esc(row.get("method", "")),
            esc(row.get("uri", "")),
            esc(row.get("uri", "")),
            esc(row.get("uri", "")),
        )
    )
    if not detail_rows:
        lines.append("| 2 | 接口定义 | 变更 | - | - | 旧版本和新版本接口定义不同，但未定位到字段级差异。 | - |")
        return "\n".join(lines)
    for idx, d in enumerate(detail_rows, 2):
        target = d.get("path") or d.get("note") or "-"
        lines.append(
            "| {} | {} | {} | {} | {} | {} | {} |".format(
                idx,
                esc(detail_scope(d, row)),
                esc(detail_change_kind(d)),
                esc(target),
                esc(detail_old_desc(d)),
                esc(detail_new_desc(d)),
                esc(d.get("reference_note", "") or "-"),
            )
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# GitCode MR / Issue / 提交人 信息收集
# ---------------------------------------------------------------------------


def collect_commit_info(repo_dir: Path, old_ref: str, new_ref: str) -> List[Dict[str, Any]]:
    sep = "---COMMIT_SEP---"
    body_end = "---BODY_END---"
    fmt = sep + "%n%H%n%P%n%an%n%s%n%b%n" + body_end
    cmd = [
        "git",
        "log",
        "--first-parent",
        "--format=" + fmt,
        "--name-only",
        "{}..{}".format(old_ref, new_ref),
        "--",
    ] + list(REDFISH_SCOPES)
    raw = run_capture(cmd, cwd=repo_dir)
    results = []
    for block in raw.split(sep):
        block = block.strip()
        if not block:
            continue
        end_idx = block.find(body_end)
        if end_idx == -1:
            continue
        header_body = block[:end_idx].strip()
        files_start = end_idx + len(body_end)
        files_part = block[files_start:].strip()
        lines_list = header_body.split("\n")
        if len(lines_list) < 4:
            continue
        commit_hash, parents, git_author, subject = (
            lines_list[0].strip(),
            lines_list[1].strip(),
            lines_list[2].strip(),
            lines_list[3].strip(),
        )
        body = "\n".join(lines_list[4:])
        mr_match = re.match(r"!(\d+)", subject)
        mr = "!{}".format(mr_match.group(1)) if mr_match else ""
        mr_num = mr_match.group(1) if mr_match else ""
        if not mr_num:
            m2 = re.search(r"See merge request:\s*\S+!(\d+)", body)
            if m2:
                mr_num = m2.group(1)
                mr = "!{}".format(mr_num)
        mr_ref = re.search(r"See merge request:\s*(\S+?)(?:\.git)?!(\d+)", body)
        if mr_ref:
            mr_url = "https://gitcode.com/{}/merge_requests/{}".format(mr_ref.group(1), mr_ref.group(2))
        elif mr_num:
            mr_url = "https://gitcode.com/openUBMC/rackmount/merge_requests/{}".format(mr_num)
        else:
            mr_url = ""
        author = ""
        from_m = re.search(r"From:\s*@?(\S+)", body)
        if from_m:
            author = from_m.group(1)
        if not author:
            cb = re.search(r"Commit-by:\s*(.+)", body)
            if cb:
                author = cb.group(1).strip()
        if not author:
            cb2 = re.search(r"Created-by:\s*(.+)", body)
            if cb2:
                author = cb2.group(1).strip()
        if not author:
            author = git_author
        issues = list(dict.fromkeys(re.findall(r"https?://gitcode\.com/\S+?/issues/\d+\S*", body)))
        files = [f.strip() for f in files_part.split("\n") if f.strip() and is_redfish_rel(f.strip())]
        if not files:
            continue
        results.append(
            {
                "hash": commit_hash,
                "parents": parents,
                "mr": mr,
                "mr_url": mr_url,
                "author": author,
                "issues": issues,
                "title": subject,
                "files": files,
            }
        )
    return results


def build_file_to_commits_map(commit_infos: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    mapping = defaultdict(list)
    for ci in commit_infos:
        for f in ci["files"]:
            mapping[f].append(ci)
    return dict(mapping)


def load_mapping_from_git(repo_dir: Path, ref: str, file_path: str) -> Any:
    try:
        raw = run_capture(["git", "show", "{}:{}".format(ref, file_path)], cwd=repo_dir)
    except Exception:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def build_entry_to_commits_map(
    repo_dir: Path, commit_infos: List[Dict[str, Any]]
) -> Dict[Tuple[str, str, str], List[Dict[str, Any]]]:
    """Map exact interface entries to commits that changed those entries.

    File-level attribution is useful for changed-files tables, but interface rows
    must not inherit every PR that touched the same JSON file.  This function
    compares each merge commit with its first parent and records only entries whose
    interface JSON was added, removed or modified in that commit.
    """
    mapping = defaultdict(list)
    for ci in commit_infos:
        commit_hash = ci.get("hash", "")
        parents = ci.get("parents", "").split()
        if not commit_hash or not parents:
            continue
        parent = parents[0]
        for f in ci.get("files", []):
            if not is_mapping_json(f):
                continue
            old_entries = collect_entries_from_mapping(load_mapping_from_git(repo_dir, parent, f), f)
            new_entries = collect_entries_from_mapping(load_mapping_from_git(repo_dir, commit_hash, f), f)
            for key in sorted(set(old_entries) | set(new_entries)):
                old_sig = (old_entries.get(key) or {}).get("signature")
                new_sig = (new_entries.get(key) or {}).get("signature")
                if old_sig == new_sig:
                    continue
                method, uri = key
                mapping[(method, uri, f)].append(ci)
    return dict(mapping)


def format_mr_link(mr: str, mr_url: str) -> str:
    return "[{}]({})".format(mr, mr_url) if mr and mr_url else mr


def format_issue_links(issue_urls: List[str]) -> str:
    links = []
    for url in issue_urls:
        m = re.search(r"gitcode\.com/[^/]+/([^/]+)/issues/(\d+)", url)
        if m:
            links.append("[{}#{}]({})".format(m.group(1), m.group(2), url.split("?")[0].split("#")[0]))
        else:
            links.append(url)
    return ", ".join(links)


def enrich_file_rows(file_rows: List[Dict[str, str]], file_map: Dict[str, List[Dict[str, Any]]]) -> None:
    for row in file_rows:
        commits = file_map.get(row["file"], [])
        authors = sorted({ci["author"] for ci in commits if ci["author"]})
        mr_links = sorted({format_mr_link(ci["mr"], ci["mr_url"]) for ci in commits if ci["mr"]})
        all_issues = []
        for ci in commits:
            all_issues.extend(ci["issues"])
        row["authors"] = ", ".join(authors)
        row["mr_links"] = ", ".join(mr_links)
        row["issue_links"] = format_issue_links(list(dict.fromkeys(all_issues)))


def enrich_interface_rows(
    rows: List[Dict[str, Any]],
    file_map: Dict[str, List[Dict[str, Any]]],
    entry_map: Optional[Dict[Tuple[str, str, str], List[Dict[str, Any]]]] = None,
) -> None:
    for row in rows:
        source_files = row.get("source_file", "").split(";")
        all_commits = []
        seen_mr = set()
        for sf in source_files:
            sf = sf.strip()
            if not sf:
                continue
            commits = (entry_map or {}).get((row.get("method", ""), row.get("uri", ""), sf))
            if commits is None:
                commits = file_map.get(sf, [])
            for ci in commits:
                if ci["mr"] not in seen_mr:
                    all_commits.append(ci)
                    seen_mr.add(ci["mr"])
        authors = sorted({ci["author"] for ci in all_commits if ci["author"]})
        mr_links = sorted({format_mr_link(ci["mr"], ci["mr_url"]) for ci in all_commits if ci["mr"]})
        all_issues = []
        for ci in all_commits:
            all_issues.extend(ci["issues"])
        row["authors"] = ", ".join(authors)
        row["mr_links"] = ", ".join(mr_links)
        row["issue_links"] = format_issue_links(list(dict.fromkeys(all_issues)))


def get_gitcode_token() -> Optional[str]:
    token = os.environ.get("GITCODE_TOKEN", "").strip()
    if token:
        return token
    creds = Path.home() / ".git-credentials"
    if creds.exists():
        for line in creds.read_text(encoding="utf-8", errors="replace").strip().split("\n"):
            if "gitcode.com" in line:
                m = re.search(r"://(?:[^:]*:)?([^@]+)@gitcode\.com", line)
                if m:
                    return m.group(1).strip()
    return None


def fetch_pr_issues_from_api(token: str, owner: str, repo: str, mr_numbers: List[str]) -> Dict[str, Dict[str, Any]]:
    import urllib.request

    result = {}
    base = "https://api.gitcode.com/api/v5"
    for mr_num in mr_numbers:
        if not mr_num:
            continue
        info = {"author": "", "title": "", "issues": []}
        try:
            pr_url = "{}/repos/{}/{}/pulls/{}?access_token={}".format(base, owner, repo, mr_num, token)
            with urllib.request.urlopen(pr_url, timeout=15) as resp:
                pr_data = json.loads(resp.read().decode("utf-8"))
            info["author"] = (pr_data.get("user") or {}).get("login", "")
            info["title"] = pr_data.get("title", "")
        except Exception:
            pass
        try:
            issues_url = "{}/repos/{}/{}/pulls/{}/issues?access_token={}".format(base, owner, repo, mr_num, token)
            with urllib.request.urlopen(issues_url, timeout=15) as resp:
                issues_data = json.loads(resp.read().decode("utf-8"))
            if isinstance(issues_data, list):
                for iss in issues_data:
                    html_url = iss.get("html_url", "")
                    if html_url:
                        info["issues"].append(
                            {"url": html_url, "title": iss.get("title", ""), "number": iss.get("number", "")}
                        )
        except Exception:
            pass
        result[mr_num] = info
    return result


def enrich_commit_info_from_api(
    commit_infos: List[Dict[str, Any]], token: str, owner: str = "openUBMC", repo: str = "rackmount"
) -> None:
    mr_numbers = sorted({ci["mr"].lstrip("!") for ci in commit_infos if ci["mr"]})
    if not mr_numbers:
        return
    print("通过 GitCode API 获取 {} 个 MR 的关联信息...".format(len(mr_numbers)))
    api_data = fetch_pr_issues_from_api(token, owner, repo, mr_numbers)
    for ci in commit_infos:
        mr_num = ci["mr"].lstrip("!")
        if not mr_num or mr_num not in api_data:
            continue
        ad = api_data[mr_num]
        if ad["author"]:
            ci["author"] = ad["author"]
        if ad["title"]:
            ci["title"] = ad["title"]
        existing_urls = set(ci["issues"])
        for iss in ad["issues"]:
            clean = iss["url"].split("?")[0].split("#")[0]
            if clean not in existing_urls:
                ci["issues"].append(iss["url"])
                existing_urls.add(clean)


def write_report(
    rows, file_rows, details, report: Path, old_name, new_name, commit_infos: Optional[List[Dict[str, Any]]] = None
):
    cnt = Counter(r["change_type"] for r in rows)
    catcnt = Counter(c for r in rows for c in cat_list(r["categories"]))
    groups = Counter(uri_group(r["uri"]) for r in rows)
    schema = [
        f
        for f in file_rows
        if any(x in f["file"].lower() for x in ("static_resource", "schema", "metadata", "registries"))
    ]
    has_mr = bool(commit_infos)
    details_by_entry = defaultdict(list)
    for d in details:
        details_by_entry[(d.get("method", ""), d.get("uri", ""), d.get("source_file", ""))].append(d)
    for idx, r in enumerate(rows, 1):
        r["_anchor"] = f"iface-{idx}"
        r["change_type_label"] = CHANGE_TYPE_CN.get(r.get("change_type", ""), r.get("change_type", ""))
    for f in file_rows:
        f["status_label"] = FILE_STATUS_CN.get(f.get("status", ""), f.get("status", ""))
    first_row_by_category = {}
    for r in rows:
        for c in cat_list(r["categories"]):
            first_row_by_category.setdefault(c, r)
    first_row_by_group = {}
    for r in rows:
        first_row_by_group.setdefault(uri_group(r["uri"]), r)

    def link(label: str, target: str) -> str:
        return f"[{label}](#{target})"

    def row_link(label: str, row: Optional[Dict[str, Any]], fallback: str) -> str:
        return link(label, row["_anchor"] if row else fallback)

    added_rows = [r for r in rows if r["change_type"] == "ADDED"]
    for idx, r in enumerate(added_rows, 1):
        r["_added_detail_anchor"] = f"added-detail-{idx}"
        r["added_detail_link"] = link("查看完整明细", r["_added_detail_anchor"])
    removed_rows = [r for r in rows if r["change_type"] == "REMOVED"]
    for idx, r in enumerate(removed_rows, 1):
        r["_removed_detail_anchor"] = f"removed-detail-{idx}"
        r["removed_detail_link"] = link("查看完整明细", r["_removed_detail_anchor"])
    modified_rows = [r for r in rows if r["change_type"] == "MODIFIED"]
    for idx, r in enumerate(modified_rows, 1):
        r["_modified_detail_anchor"] = f"modified-detail-{idx}"
        r["modified_detail_link"] = link("查看完整明细", r["_modified_detail_anchor"])
        r["path_change_status"] = "未修改"
    iface_cols = [
        ("序号", "#"),
        ("变更类型", "change_type_label"),
        ("细分类别", "categories"),
        ("方法", "method"),
        ("接口路径", "uri"),
        ("摘要", "summary"),
        ("具体变更", "detail"),
        ("文件", "source_file"),
    ]
    if has_mr:
        iface_cols += [("合并请求", "mr_links"), ("作者", "authors"), ("关联问题", "issue_links")]
    added_cols = [
        ("序号", "#"),
        ("细分类别", "categories"),
        ("方法", "method"),
        ("接口路径", "uri"),
        ("摘要", "summary"),
        ("完整明细", "added_detail_link"),
        ("文件", "source_file"),
    ]
    if has_mr:
        added_cols += [("合并请求", "mr_links"), ("作者", "authors"), ("关联问题", "issue_links")]
    removed_cols = [
        ("序号", "#"),
        ("细分类别", "categories"),
        ("方法", "method"),
        ("接口路径", "uri"),
        ("摘要", "summary"),
        ("完整明细", "removed_detail_link"),
        ("文件", "source_file"),
    ]
    if has_mr:
        removed_cols += [("合并请求", "mr_links"), ("作者", "authors"), ("关联问题", "issue_links")]
    modified_cols = [
        ("序号", "#"),
        ("细分类别", "categories"),
        ("方法", "method"),
        ("接口路径", "uri"),
        ("历史路径是否修改", "path_change_status"),
        ("摘要", "summary"),
        ("完整明细", "modified_detail_link"),
        ("文件", "source_file"),
    ]
    if has_mr:
        modified_cols += [("合并请求", "mr_links"), ("作者", "authors"), ("关联问题", "issue_links")]
    file_cols = [("状态", "status_label"), ("文件", "file")]
    if has_mr:
        file_cols += [("合并请求", "mr_links"), ("作者", "authors"), ("关联问题", "issue_links")]
    lines = [
        "# Redfish 接口变化报告",
        "",
        f"- 对比方向：`{old_name}` -> `{new_name}`。",
        "- 分析范围：`interface_config/redfish/**` 和 `oem/huawei/redfish/**`。",
        "",
    ]
    lines += [
        "**目录**",
        "",
        "- [1. 汇总](#section-summary)",
        "- [2. 细分类统计](#section-category-stats)",
        "- [3. 变更最多的接口路径分组](#section-top-groups)",
        "- [4. 新增接口](#section-added)",
        "- [5. 删除接口](#section-removed)",
        "- [6. 历史接口变化](#section-modified)",
        "- [7. 模式、元数据与静态资源变化](#section-schema)",
        "- [8. 涉及 Redfish 范围的合并请求](#section-mrs)",
        "- [9. 复核清单](#section-review)",
        "",
    ]
    lines += [
        '## 1. <a id="section-summary"></a>汇总',
        "",
        "| 指标 | 数量 | 跳转 |",
        "|---|---:|---|",
        f'| Redfish 范围变更文件 | {len(file_rows)} | {link("查看模式、元数据与静态资源变化", "section-schema")} |',
        f'| 接口新增 | {cnt.get("ADDED", 0)} | {link("查看新增接口", "section-added")} |',
        f'| 接口删除 | {cnt.get("REMOVED", 0)} | {link("查看删除接口", "section-removed")} |',
        f'| 接口修改 | {cnt.get("MODIFIED", 0)} | {link("查看历史接口变化", "section-modified")} |',
    ]
    lines.append("")
    lines += ['## 2. <a id="section-category-stats"></a>细分类统计', "", "| 细分类别 | 数量 | 跳转 |", "|---|---:|---|"]
    hidden_category_stats = {"POST/PATCH请求体内容变化", "接口行为变化"}
    for c in CATEGORY_ORDER:
        if c in hidden_category_stats:
            continue
        if catcnt.get(c):
            lines.append(
                f'| {c} | {catcnt[c]} | {row_link("查看首条明细", first_row_by_category.get(c), "section-modified")} |'
            )
    lines.append("")
    lines += [
        '## 3. <a id="section-top-groups"></a>变更最多的接口路径分组',
        "",
        "| 接口路径分组 | 变更数量 | 跳转 |",
        "|---|---:|---|",
    ]
    for g, n in groups.most_common(20):
        lines.append(f'| `{esc(g)}` | {n} | {row_link("查看首条明细", first_row_by_group.get(g), "section-added")} |')
    lines.append("")

    def sec(title, rows2, intro="", cols=None):
        lines.extend([title, ""])
        if intro:
            lines.extend([intro, ""])
        if rows2:
            lines.append(table(rows2, cols or iface_cols))
        else:
            lines.append("未发现相关变更。")
        lines.append("")

    sec(
        '## 4. <a id="section-added"></a>新增接口',
        added_rows,
        "本节先给出新增接口清单；每个接口的完整变动在清单后的独立明细表中逐项列出，避免把大量字段挤在同一个单元格里。",
        cols=added_cols,
    )
    if added_rows:
        lines += ["### 4.1 新增接口完整变动明细", ""]
        for idx, r in enumerate(added_rows, 1):
            detail_rows = details_by_entry.get((r.get("method", ""), r.get("uri", ""), r.get("source_file", "")), [])
            lines += [
                '#### 4.1.{} <a id="{}"></a>新增接口：`{}` `{}`'.format(
                    idx, r["_added_detail_anchor"], esc(r.get("method", "")), esc(r.get("uri", ""))
                ),
                "",
            ]
            lines.append("- 细分类别：{}".format(esc(r.get("categories", ""))))
            lines.append("- 文件：`{}`".format(esc(r.get("source_file", ""))))
            if has_mr:
                lines.append("- 合并请求：{}".format(esc(r.get("mr_links", "")) or "无"))
                lines.append("- 作者：{}".format(esc(r.get("authors", "")) or "无"))
                lines.append("- 关联问题：{}".format(esc(r.get("issue_links", "")) or "无"))
            lines.append("")
            lines.append(detail_table_for_added(r, detail_rows))
            lines.append("")
    sec(
        '## 5. <a id="section-removed"></a>删除接口',
        removed_rows,
        "本节先给出删除接口清单；每个被删除接口在旧版本中的完整定义会在清单后的独立明细表中逐项列出，便于确认删除影响面。",
        cols=removed_cols,
    )
    if removed_rows:
        lines += ["### 5.1 删除接口完整变动明细", ""]
        for idx, r in enumerate(removed_rows, 1):
            detail_rows = details_by_entry.get((r.get("method", ""), r.get("uri", ""), r.get("source_file", "")), [])
            lines += [
                '#### 5.1.{} <a id="{}"></a>删除接口：`{}` `{}`'.format(
                    idx, r["_removed_detail_anchor"], esc(r.get("method", "")), esc(r.get("uri", ""))
                ),
                "",
            ]
            lines.append("- 细分类别：{}".format(esc(r.get("categories", ""))))
            lines.append("- 文件：`{}`".format(esc(r.get("source_file", ""))))
            if has_mr:
                lines.append("- 合并请求：{}".format(esc(r.get("mr_links", "")) or "无"))
                lines.append("- 作者：{}".format(esc(r.get("authors", "")) or "无"))
                lines.append("- 关联问题：{}".format(esc(r.get("issue_links", "")) or "无"))
            lines.append("")
            lines.append(detail_table_for_removed(r, detail_rows))
            lines.append("")
    sec(
        '## 6. <a id="section-modified"></a>历史接口变化',
        modified_rows,
        "本节只包含旧版本和新版本同时存在、且 `(方法, 接口路径)` 精确一致的历史接口。"
        "清单中显式标明历史路径是否修改；每个接口的完整变动在清单后的独立明细表中逐项列出，并区分新增、删除和变更。"
        "没有显式映射证据的 URI 调整不会作为路径修改推断，只会分别进入新增接口或删除接口章节。",
        cols=modified_cols,
    )
    if modified_rows:
        lines += ["### 6.1 历史接口完整变动明细", ""]
        for idx, r in enumerate(modified_rows, 1):
            detail_rows = details_by_entry.get((r.get("method", ""), r.get("uri", ""), r.get("source_file", "")), [])
            lines += [
                '#### 6.1.{} <a id="{}"></a>历史接口：`{}` `{}`'.format(
                    idx, r["_modified_detail_anchor"], esc(r.get("method", "")), esc(r.get("uri", ""))
                ),
                "",
            ]
            lines.append("- 历史路径是否修改：未修改（旧版本和新版本的 `(方法, 接口路径)` 完全一致）。")
            lines.append("- 路径判定依据：本节仅采用精确同键匹配；没有 100% 事实依据时不输出 URI 路径迁移或改名推断。")
            lines.append("- 细分类别：{}".format(esc(r.get("categories", ""))))
            lines.append("- 文件：`{}`".format(esc(r.get("source_file", ""))))
            if has_mr:
                lines.append("- 合并请求：{}".format(esc(r.get("mr_links", "")) or "无"))
                lines.append("- 作者：{}".format(esc(r.get("authors", "")) or "无"))
                lines.append("- 关联问题：{}".format(esc(r.get("issue_links", "")) or "无"))
            lines.append("")
            lines.append(detail_table_for_modified(r, detail_rows))
            lines.append("")
    lines += ['## 7. <a id="section-schema"></a>模式、元数据与静态资源变化', "", ""]
    if schema:
        lines.append(table(schema, file_cols, limit=120))
    else:
        lines.append("未发现相关变更。")
    lines += ["", '## 8. <a id="section-mrs"></a>涉及 Redfish 范围的合并请求', "", ""]
    if commit_infos:
        lines.append("| 合并请求 | 标题 | 作者 | 关联问题 |")
        lines.append("|---|---|---|---|")
        for ci in commit_infos:
            mr_link = format_mr_link(ci["mr"], ci["mr_url"]) if ci["mr"] else ""
            issue_text = format_issue_links(ci["issues"])
            lines.append("| {} | {} | {} | {} |".format(mr_link, esc(ci["title"])[:100], ci["author"], issue_text))
    else:
        lines.append("未获取到 git 提交信息。")
    lines += [
        "",
        '## 9. <a id="section-review"></a>复核清单',
        "",
        "1. 确认类型变化与运行时 JSON 类型变化一致。",
        "2. 对 POST/PATCH/PUT 请求体变化做兼容性测试。",
        "3. 检查 Statements、ProcessingFlow、脚本和后端调用是否引入行为变化。",
        "4. 对新增完整接口路径按“具体变更”逐项复核请求体、响应体、Action 方法与 ActionInfo 参数。",
        "",
    ]
    report.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------- main ----------------------------
def main():
    ap = argparse.ArgumentParser(
        description="分析两个分支或源码树之间的 Redfish 接口变化，并按细分类别输出中文精准报告（v4.0）。"
    )
    g = ap.add_mutually_exclusive_group(required=False)
    g.add_argument("--repo", help="git 仓库 URL 或本地路径；已在 rackmount 仓库内时可省略，默认使用 '.'")
    g.add_argument("--old", help="旧/基线源码目录或 zip 源码包")
    ap.add_argument("--new", help="新/目标源码目录或 zip 源码包")
    ap.add_argument("--old-ref", help="旧/基线 git ref")
    ap.add_argument("--new-ref", help="新/目标 git ref")
    ap.add_argument("--old-name", default="old", help="基线显示名称")
    ap.add_argument("--new-name", default="new", help="目标显示名称")
    ap.add_argument("--out-dir", default="redfish_diff_out", help="输出目录")
    args = ap.parse_args()
    out = Path(args.out_dir).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="redfish-diff-") as td:
        work = Path(td)
        use_git = bool(args.repo) or (args.old_ref and args.new_ref and not args.old and not args.new)
        repo_dir = None
        commit_infos = []
        if use_git:
            if not args.old_ref or not args.new_ref:
                ap.error("git 模式需要 --old-ref 和 --new-ref")
            old_root, new_root, repo_dir = prepare_git(args.repo or ".", args.old_ref, args.new_ref, work)
            old_name = args.old_ref
            new_name = args.new_ref
        else:
            if not args.old or not args.new:
                ap.error("目录/zip 模式需要 --old 和 --new；或使用 --old-ref/--new-ref 进入 git 模式")
            old_root = prepare_input(args.old, work, "old")
            new_root = prepare_input(args.new, work, "new")
            old_name = args.old_name
            new_name = args.new_name
        old_files, new_files = collect_files(old_root), collect_files(new_root)
        files = file_diff(old_files, new_files)
        rows, details = diff_entries(collect_entries(old_root), collect_entries(new_root))
        # Collect and enrich MR / Issue / author info
        if repo_dir is not None:
            commit_infos = collect_commit_info(repo_dir, args.old_ref, args.new_ref)
            gc_token = get_gitcode_token()
            if gc_token:
                enrich_commit_info_from_api(commit_infos, gc_token)
            else:
                print("Tip: GITCODE_TOKEN not set, skipping API enrichment")
            file_map = build_file_to_commits_map(commit_infos)
            entry_map = build_entry_to_commits_map(repo_dir, commit_infos)
            enrich_file_rows(files, file_map)
            enrich_interface_rows(rows, file_map, entry_map)
        write_csv(rows, out / "redfish_interface_change_list.csv")
        write_detail_csv(details, out / "redfish_interface_change_details.csv")
        write_category_csv(rows, out / "redfish_change_category_stats.csv")
        with (out / "redfish_changed_files.csv").open("w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["status", "file", "authors", "mr_links", "issue_links"])
            w.writeheader()
            for row in files:
                w.writerow({k: row.get(k, "") for k in ["status", "file", "authors", "mr_links", "issue_links"]})
        write_report(rows, files, details, out / "redfish_interface_change_report.md", old_name, new_name, commit_infos)
        c = Counter(r["change_type"] for r in rows)
        print("Redfish 范围变更文件:", len(files))
        print("接口新增:", c.get("ADDED", 0))
        print("接口删除:", c.get("REMOVED", 0))
        print("接口修改:", c.get("MODIFIED", 0))
        print("字段/行为明细:", len(details))
        print("已写入", out / "redfish_interface_change_report.md")
        print("已写入", out / "redfish_interface_change_list.csv")
        print("已写入", out / "redfish_interface_change_details.csv")
        print("已写入", out / "redfish_change_category_stats.csv")
        print("已写入", out / "redfish_changed_files.csv")


if __name__ == "__main__":
    main()
