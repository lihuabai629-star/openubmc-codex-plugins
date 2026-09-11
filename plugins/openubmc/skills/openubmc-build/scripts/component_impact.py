"""Read-only task impact facts; no execution or workflow state is owned here."""

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


from collections import deque
import hashlib
import json
from pathlib import Path
import os
import stat
import subprocess

INPUT_LIMIT = 1024 * 1024


def read_bounded(path, limit=INPUT_LIMIT):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("input must be a regular file within the byte limit")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(limit + 1)
        if len(content) > limit:
            raise ValueError("input byte limit exceeded")
        return content
    finally:
        os.close(descriptor)


def source_identity(root):
    # ls-files reads the index/list only: status/diff can invoke clean filters.
    def git(*arguments):
        return subprocess.check_output(
            [
                "git",
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(root),
                *arguments,
            ],
            stderr=subprocess.DEVNULL,
            timeout=10,
        )

    head = git("rev-parse", "HEAD").decode().strip()
    names = sorted(
        set(
            git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split(
                b"\0"
            )
        )
        - {b""}
    )
    if len(names) > 50000:
        raise ValueError("component source file count limit exceeded")
    hasher, total = hashlib.sha256(), 0
    for raw_name in names:
        path = root / os.fsdecode(raw_name)
        if not path.parent.resolve().is_relative_to(root):
            raise ValueError("component source escapes its root")
        hasher.update(raw_name + b"\0")
        if path.is_symlink():
            content = b"symlink\0" + os.fsencode(os.readlink(path))
        elif not path.exists():
            content = b"absent"
        else:
            content = (
                b"file\0"
                + str(stat.S_IMODE(path.stat().st_mode)).encode()
                + b"\0"
                + read_bounded(path, 16 * INPUT_LIMIT)
            )
        total += len(content)
        if total > 256 * INPUT_LIMIT:
            raise ValueError("component source total byte limit exceeded")
        hasher.update(len(content).to_bytes(8, "big") + content)
    return {"root": str(root), "git_head": head, "content_sha256": hasher.hexdigest()}


def analyze(root, paths, graph_path, *, component_for_path, needs_generation):
    graph_path = graph_path.resolve(strict=True)
    raw = read_bounded(graph_path)
    graph = json.loads(raw)
    if (
        not isinstance(graph, dict)
        or graph.get("schema") != "openubmc.component-dependencies.v1"
    ):
        raise ValueError("unsupported dependency graph schema")
    required = {"schema", "components", "edges", "complete", "dynamic_dependencies"}
    if set(graph) != required or not isinstance(graph["components"], dict):
        raise ValueError("dependency graph fields are incomplete or invalid")
    if type(graph["complete"]) is not bool:
        raise ValueError("dependency graph complete must be a boolean")
    if any(
        not isinstance(name, str)
        or not name.strip()
        or not isinstance(path, str)
        or not path
        for name, path in graph["components"].items()
    ):
        raise ValueError("component names and roots must be nonempty strings")
    if (
        not isinstance(graph["dynamic_dependencies"], list)
        or len(graph["dynamic_dependencies"]) > 128
        or any(
            not isinstance(name, str) or not name
            for name in graph["dynamic_dependencies"]
        )
    ):
        raise ValueError("dynamic dependencies must be a bounded string array")
    if len(paths) > 4096:
        raise ValueError("task path count limit exceeded")
    roots = {
        name: (root / path).resolve() for name, path in graph["components"].items()
    }
    if len(set(roots.values())) != len(roots):
        raise ValueError("component roots must be distinct")
    if (
        not roots
        or len(roots) > 128
        or any(not path.is_relative_to(root) for path in roots.values())
    ):
        raise ValueError("dependency graph requires at most 128 local component roots")
    if (
        not isinstance(graph.get("edges", []), list)
        or len(graph.get("edges", [])) > 1024
    ):
        raise ValueError("dependency graph edge limit exceeded")
    gaps = []
    if graph.get("complete") is not True:
        gaps.append("dependency_graph_incomplete")
    for name in graph.get("dynamic_dependencies", []):
        gaps.append("dynamic_dependency:" + str(name))
    selected, changed, generation = set(), [], set()
    for raw_path in paths:
        path = (root / raw_path).resolve()
        if not path.is_relative_to(root):
            gaps.append("path_outside_workspace:" + raw_path)
            continue
        changed.append(path.relative_to(root).as_posix())
        owner = component_for_path(root, raw_path)
        names = [name for name, directory in roots.items() if directory == owner]
        if len(names) != 1:
            gaps.append("unmapped_path:" + raw_path)
            continue
        name = names[0]
        selected.add(name)
        if needs_generation([path.relative_to(roots[name]).as_posix()]):
            generation.add(name)
        elif path.is_dir() or raw_path.endswith("/"):
            gaps.append("directory_scope_unresolved:" + path.relative_to(root).as_posix())
    edges, consumers = [], {name: [] for name in roots}
    evidence_cache, total_bytes, seen_edges = {}, 0, set()
    for edge in graph.get("edges", []):
        if (
            not isinstance(edge, dict)
            or set(edge) != {"provider", "consumer", "evidence_path"}
            or any(not isinstance(item, str) or not item for item in edge.values())
        ):
            raise ValueError("dependency edge fields must be nonempty strings")
        provider, consumer = edge["provider"], edge["consumer"]
        if (provider, consumer) in seen_edges:
            raise ValueError("duplicate dependency edge")
        seen_edges.add((provider, consumer))
        if provider not in roots or consumer not in roots:
            raise ValueError("dependency edge references an unknown component")
        evidence = (graph_path.parent / edge["evidence_path"]).resolve(strict=True)
        if not evidence.is_relative_to(root) or not evidence.is_file():
            raise ValueError("dependency evidence must be a local workspace file")
        if evidence not in evidence_cache:
            content = read_bounded(evidence)
            total_bytes += len(content)
            if total_bytes > 16 * INPUT_LIMIT:
                raise ValueError("dependency evidence total byte limit exceeded")
            evidence_cache[evidence] = hashlib.sha256(content).hexdigest()
        edges.append(
            {
                "provider": provider,
                "consumer": consumer,
                "evidence": {"path": str(evidence), "sha256": evidence_cache[evidence]},
            }
        )
        consumers[provider].append(consumer)
    indegree = {name: 0 for name in roots}
    for children in consumers.values():
        for child in children:
            indegree[child] += 1
    queue = deque(name for name, count in indegree.items() if count == 0)
    visited = 0
    while queue:
        visited += 1
        for child in consumers[queue.popleft()]:
            indegree[child] -= 1
            if indegree[child] == 0:
                queue.append(child)
    if visited != len(roots):
        gaps.append("dependency_cycle")
    direct = set(selected)
    pending = deque(sorted(generation))
    while pending:
        provider = pending.popleft()
        for consumer in consumers[provider]:
            selected.add(consumer)
            if consumer not in generation:
                generation.add(consumer)
                pending.append(consumer)
    bindings = {}
    required_sources = selected | {
        edge["provider"] for edge in edges if edge["consumer"] in selected
    }
    for name in sorted(required_sources):
        bindings[name] = source_identity(roots[name])
    components = []
    for name in sorted(selected):
        source = bindings[name]
        components.append(
            {
                "component": name,
                "source": source,
                "reason": "direct" if name in direct else "interface_consumer",
                "needs_generation": name in generation,
                "required_checks": ["official_ut", "build"],
                "dependencies": {
                    edge["provider"]: bindings[edge["provider"]]
                    for edge in edges
                    if edge["consumer"] == name
                },
            }
        )
    report = {
        "schema": "openubmc.change-impact.v1",
        "changed_files": sorted(set(changed)),
        "components": components,
        "dependency_edges": [edge for edge in edges if edge["consumer"] in selected],
        "graph": {"path": str(graph_path), "sha256": hashlib.sha256(raw).hexdigest()},
        "gaps": gaps,
    }
    unsigned = json.dumps(
        report, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    report["digest"] = "sha256:" + hashlib.sha256(unsigned).hexdigest()
    return report
