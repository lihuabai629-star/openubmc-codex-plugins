#!/usr/bin/env python3
"""Measure compact Context Runtime responses against a legacy raw result."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
import tracemalloc


RUNTIME_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RUNTIME_ROOT))

from openubmc_target_runtime import JsonRpcMcpEndpoint, RuntimeMcpService  # noqa: E402


class _Task:
    def __init__(self, task_id: str) -> None:
        self.task_id = task_id
        self.operation_count = 0


class _Backend:
    def __init__(self, raw_bytes: int) -> None:
        self.raw_bytes = raw_bytes
        self.calls = 0
        self.task_opens = 0

    @staticmethod
    def close_task(_task: _Task) -> None:
        return None

    @staticmethod
    def maintain_task(_task: _Task) -> int:
        return 0

    @staticmethod
    def task_status(task: _Task) -> dict[str, object]:
        return {"task_id": task.task_id}

    def open_task(self, task_id: str) -> _Task:
        self.task_opens += 1
        return _Task(task_id)

    def debug_run(self, task: _Task, arguments, context) -> dict[str, object]:
        context.raise_if_stopped()
        self.calls += 1
        task.operation_count += 1
        return {
            "ok": True,
            "schema": "benchmark/debug-run",
            "task": task.task_id,
            "task_operation_count": task.operation_count,
            "ip": arguments.get("ip"),
            "raw": "x" * self.raw_bytes,
        }


def encoded_bytes(value: object) -> int:
    return len(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def run(raw_bytes: int) -> dict[str, object]:
    backend = _Backend(raw_bytes)
    service = RuntimeMcpService(backend)
    endpoint = JsonRpcMcpEndpoint(service, session_task_id="benchmark-task")
    cold_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "debug_run",
            "arguments": {
                "ip": "192.0.2.50",
                "deadline": 10,
                "idempotency_key": "benchmark-cold",
            },
        },
    }
    warm_request = {
        **cold_request,
        "id": 2,
        "params": {
            **cold_request["params"],
            "arguments": {
                **cold_request["params"]["arguments"],
                "idempotency_key": "benchmark-warm",
            },
        },
    }
    tracemalloc.start()
    started = time.perf_counter()
    cold = endpoint.handle(cold_request)
    cold_seconds = time.perf_counter() - started
    started = time.perf_counter()
    warm = endpoint.handle(warm_request)
    warm_seconds = time.perf_counter() - started
    started = time.perf_counter()
    replay = endpoint.handle({**warm_request, "id": 3})
    replay_seconds = time.perf_counter() - started
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    status = service._test.context_runtime.status()
    service.close()
    cold_envelope = cold["result"]["structuredContent"]
    warm_envelope = warm["result"]["structuredContent"]
    legacy = {
        "ok": True,
        "schema": "benchmark/debug-run",
        "task": "benchmark-task",
        "task_operation_count": 1,
        "ip": "192.0.2.50",
        "raw": "x" * raw_bytes,
    }
    legacy_bytes = encoded_bytes(legacy)
    cold_bytes = encoded_bytes(cold_envelope)
    return {
        "schema": "openubmc.context-runtime-benchmark.v1",
        "raw_fixture_bytes": raw_bytes,
        "legacy_structured_bytes": legacy_bytes,
        "cold_envelope_bytes": cold_bytes,
        "warm_envelope_bytes": encoded_bytes(warm_envelope),
        "replay_envelope_bytes": encoded_bytes(
            replay["result"]["structuredContent"]
        ),
        "response_reduction_percent": round(
            (1 - cold_bytes / legacy_bytes) * 100,
            3,
        ),
        "cold_seconds": round(cold_seconds, 6),
        "warm_seconds": round(warm_seconds, 6),
        "replay_seconds": round(replay_seconds, 6),
        "domain_calls": backend.calls,
        "task_opens": backend.task_opens,
        "task_reused": backend.task_opens == 1 and backend.calls == 2,
        "duplicate_suppressed": backend.calls == 2,
        "blob_bytes": status["blob_bytes"],
        "peak_traced_memory_bytes": peak_bytes,
        "metrics": status["metrics"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-bytes", type=int, default=1024 * 1024)
    args = parser.parse_args()
    if args.raw_bytes < 1:
        parser.error("--raw-bytes must be positive")
    print(json.dumps(run(args.raw_bytes), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
