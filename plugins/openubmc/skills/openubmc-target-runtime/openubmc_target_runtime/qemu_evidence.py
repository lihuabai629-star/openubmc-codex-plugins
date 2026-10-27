"""Read one bounded QEMU receipt through the packaged QEMU contract."""
from functools import lru_cache
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat


@lru_cache(maxsize=1)
def _contract():
    path = Path(__file__).resolve().parents[2] / "qemu-testing/scripts/qemu_workflow_contract.py"
    spec = importlib.util.spec_from_file_location("openubmc_qemu_contract", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_qemu_evidence(command):
    descriptor = os.open(command.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("QEMU evidence must be a regular file")
        body = stream.read(1024 * 1024 + 1)
    if len(body) > 1024 * 1024:
        raise ValueError("QEMU evidence exceeds 1 MiB")
    if hashlib.sha256(body).hexdigest() != command.sha256:
        raise ValueError("QEMU evidence digest mismatch")
    packet = json.loads(body)
    if not isinstance(packet, dict) or packet.get("schema") != "openubmc-qemu-evidence/v1":
        raise ValueError("expected openubmc-qemu-evidence/v1")
    if set(packet) != {"schema", "run_id", "target", "plan", "result"}:
        raise ValueError("QEMU evidence contains unexpected or missing fields")
    if packet["run_id"] != command.run_id or packet["target"] != command.target:
        raise ValueError("QEMU evidence Run/target binding mismatch")
    if not isinstance(packet["plan"], dict) or not isinstance(packet["result"], dict):
        raise ValueError("QEMU plan and result must be objects")
    summary = _contract().validate_result(packet["plan"], packet["result"], verify_files=True)
    return body, {key: summary[key] for key in ("schema", "plan_digest", "status", "freshness_verified")}
