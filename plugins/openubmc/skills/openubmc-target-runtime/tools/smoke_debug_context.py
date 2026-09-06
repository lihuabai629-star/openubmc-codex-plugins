#!/usr/bin/env python3
"""Run a small read-only target switch, restart recovery, and comparison smoke."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEBUG_SCRIPTS = REPOSITORY_ROOT / "openubmc-debug" / "scripts"
sys.path.insert(0, str(DEBUG_SCRIPTS))

import target_runtime_mcp  # noqa: E402


def compact_outcome(value) -> dict[str, object]:
    envelope = getattr(value, "envelope", {})
    return {
        "ok": value.get("ok"),
        "code": value.get("normalized_code", value.get("code", "")),
        "revision": envelope.get("revision", 0),
        "status": envelope.get("status", ""),
        "evidence_count": len(envelope.get("evidence_refs", [])),
    }


def run(targets: list[str], deadline: int, state_dir: Path) -> dict[str, object]:
    os.environ["OPENUBMC_TARGET_RUNTIME_STATE_DIR"] = str(state_dir)
    task_id = "context-smoke-switch"
    common = {
        "profile": "mdb",
        "mdb_only": True,
        "skip_telnet": True,
        "no_source_correlation": True,
        "mdb_queries": ["lsclass"],
        "compact_json": True,
        "deadline": deadline,
    }
    service = target_runtime_mcp.create_service()
    switch: list[dict[str, object]] = []
    case_id = ""
    try:
        order = [targets[0], targets[1], targets[0]]
        for index, target in enumerate(order, start=1):
            arguments = {
                **common,
                "ip": target,
                "target_id": f"target-{targets.index(target) + 1}",
            }
            if case_id:
                arguments["case_id"] = case_id
            result = service.call_tool(
                "debug_collect",
                arguments,
                task_id=task_id,
                operation_id=f"switch-{index}",
            )
            case_id = str(result.envelope["case_id"])
            switch.append({"target": target, **compact_outcome(result)})
    finally:
        service.close()

    recovered_service = target_runtime_mcp.create_service()
    try:
        recovered = recovered_service.call_tool(
            "case_read",
            {"case_id": case_id},
            task_id="context-smoke-recovery",
            operation_id="recover-case",
        )
        compared = recovered_service.call_tool(
            "debug_run",
            {
                **common,
                "case_id": case_id,
                "targets": [
                    {
                        "target_id": f"target-{index}",
                        "ip": target,
                        "role": "symmetric",
                    }
                    for index, target in enumerate(targets, start=1)
                ],
            },
            task_id="context-smoke-recovery",
            operation_id="compare-targets",
        )
        comparison = compared.get("comparison", {})
        if not isinstance(comparison, dict):
            comparison = {}
        diff_card = getattr(compared, "envelope", {}).get(
            "diff_card", comparison.get("diff_card", {})
        )
        if not isinstance(diff_card, dict):
            diff_card = {}
        runtime_status = recovered_service.call_tool(
            "runtime_status",
            {},
            task_id="context-smoke-recovery",
            operation_id="runtime-status",
        )
        context_status = runtime_status.get("context_runtime", {})
    finally:
        recovered_service.close()
    return {
        "schema": "openubmc.context-runtime-smoke.v1",
        "read_only": True,
        "targets": targets,
        "case_id": case_id,
        "switch": switch,
        "recovered_revision": recovered.get("revision", 0),
        "recovered_operations": len(recovered.get("operations", [])),
        "comparison": {
            "ok": compared.get("ok"),
            "partial": compared.get("partial"),
            "status": diff_card.get("status", ""),
            "conclusion": diff_card.get("conclusion", ""),
            "quality_flags": diff_card.get("quality_flags", {}),
            "incomparable_paths": diff_card.get("incomparable_paths", []),
            "mode": comparison.get("mode", ""),
            "target_count": len(
                compared.get("targets", compared.get("result", {}).get("targets", []))
            ),
        },
        "context_metrics": context_status.get("metrics", {}),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append", required=True)
    parser.add_argument("--deadline", type=int, default=45)
    parser.add_argument("--state-dir", type=Path)
    args = parser.parse_args()
    targets = list(dict.fromkeys(args.target))
    if len(targets) < 2:
        parser.error("repeat --target for at least two distinct BMCs")
    if args.state_dir is not None:
        args.state_dir.mkdir(parents=True, exist_ok=True)
        report = run(targets, args.deadline, args.state_dir.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix="openubmc-context-smoke-") as raw:
            report = run(targets, args.deadline, Path(raw))
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
