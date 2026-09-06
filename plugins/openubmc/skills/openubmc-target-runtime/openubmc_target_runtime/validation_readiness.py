"""Trustworthy validation-readiness and hardware-coverage classifications."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass


OFFICIAL_UT_STATUSES = frozenset(
    {
        "passed",
        "failed_after_start",
        "dependency_blocked_before_start",
    }
)
BUILD_STATUSES = frozenset(
    {
        "compiled",
        "compile_failed",
        "dependency_graph_blocked",
    }
)
SUPPLEMENTARY_STATUSES = frozenset({"passed", "failed", "not_run"})
DEPENDENCY_STATUSES = frozenset({"ready", "blocked"})
DEPENDENCY_RESOLUTIONS = frozenset({"available", "blocked_external"})
HARDWARE_COVERAGE_STATUSES = frozenset(
    {"covered", "blocked", "not_required", "not_reported"}
)


class ValidationReadinessError(ValueError):
    """Raised when validation evidence makes a contradictory success claim."""


def _text(value: object) -> str:
    return str(value).strip() if value is not None else ""


def _strings(value: object, *, field: str, required: bool = False) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(
        value, (str, bytes, bytearray)
    ):
        raise ValidationReadinessError(f"{field} must be an array")
    selected = [_text(item) for item in value]
    if any(not item for item in selected):
        raise ValidationReadinessError(f"{field} must contain non-empty strings")
    if required and not selected:
        raise ValidationReadinessError(f"{field} must not be empty")
    return list(dict.fromkeys(selected))


def normalize_hardware_protocol(value: object) -> str:
    """Return the canonical spelling used by validation and Evidence checks."""
    selected = _text(value).lower().replace("-", "").replace("/", "")
    aliases = {
        "nvme": "NVMe",
        "nvmeof": "NVMe-oF",
        "sata": "SATA",
        "sas": "SAS",
    }
    return aliases.get(selected, _text(value).upper())


def _dependency_readiness(value: object) -> dict[str, object]:
    if value in (None, {}):
        return {}
    if not isinstance(value, Mapping):
        raise ValidationReadinessError("dependency_readiness must be an object")
    readiness_id = _text(value.get("readiness_id"))
    status = _text(value.get("status")).lower()
    resolution = _text(value.get("resolution")).lower()
    summary = _text(value.get("summary"))
    attempt_count = value.get("attempt_count")
    if not readiness_id:
        raise ValidationReadinessError(
            "dependency_readiness.readiness_id is required"
        )
    if status not in DEPENDENCY_STATUSES:
        raise ValidationReadinessError(
            "dependency_readiness.status must be ready or blocked"
        )
    if resolution not in DEPENDENCY_RESOLUTIONS:
        raise ValidationReadinessError(
            "dependency readiness cannot fabricate or vendor an external dependency"
        )
    expected_resolution = "available" if status == "ready" else "blocked_external"
    if resolution != expected_resolution:
        raise ValidationReadinessError(
            "dependency readiness status and resolution contradict each other"
        )
    if not summary:
        raise ValidationReadinessError("dependency_readiness.summary is required")
    if (
        isinstance(attempt_count, bool)
        or not isinstance(attempt_count, int)
        or attempt_count != 1
    ):
        raise ValidationReadinessError(
            "dependency readiness must be checked once and reused"
        )
    return {
        "readiness_id": readiness_id,
        "status": status,
        "resolution": resolution,
        "summary": summary,
        "check_commands": _strings(
            value.get("check_commands", []),
            field="dependency_readiness.check_commands",
            required=True,
        ),
        "evidence_ids": _strings(
            value.get("evidence_ids", []),
            field="dependency_readiness.evidence_ids",
            required=True,
        ),
        "attempt_count": 1,
        "reused_by": _strings(
            value.get("reused_by", []),
            field="dependency_readiness.reused_by",
            required=True,
        ),
    }


def _validation_results(
    value: object,
    *,
    readiness: Mapping[str, object],
) -> tuple[list[dict[str, object]], dict[str, object], list[str]]:
    if value in (None, []):
        raw_results: Sequence[object] = ()
    elif isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        raw_results = value
    else:
        raise ValidationReadinessError("validation_results must be an array")
    normalized: list[dict[str, object]] = []
    by_kind: dict[str, list[dict[str, object]]] = {
        "official_ut": [],
        "build": [],
        "supplementary": [],
    }
    for index, raw in enumerate(raw_results):
        if not isinstance(raw, Mapping):
            raise ValidationReadinessError(
                f"validation_results[{index}] must be an object"
            )
        kind = _text(raw.get("kind")).lower()
        status = _text(raw.get("status")).lower()
        allowed = {
            "official_ut": OFFICIAL_UT_STATUSES,
            "build": BUILD_STATUSES,
            "supplementary": SUPPLEMENTARY_STATUSES,
        }.get(kind)
        if allowed is None or status not in allowed:
            raise ValidationReadinessError(
                f"validation_results[{index}] has an unsupported kind/status"
            )
        summary = _text(raw.get("summary"))
        if not summary:
            raise ValidationReadinessError(
                f"validation_results[{index}].summary is required"
            )
        item = {
            "kind": kind,
            "status": status,
            "summary": summary,
            "commands": _strings(
                raw.get("commands", []),
                field=f"validation_results[{index}].commands",
                required=True,
            ),
            "evidence_ids": _strings(
                raw.get("evidence_ids", []),
                field=f"validation_results[{index}].evidence_ids",
                required=True,
            ),
        }
        readiness_id = _text(raw.get("dependency_readiness_id"))
        if readiness_id:
            item["dependency_readiness_id"] = readiness_id
        by_kind[kind].append(item)
        normalized.append(item)
    for kind in ("official_ut", "build"):
        if len(by_kind[kind]) > 1:
            raise ValidationReadinessError(
                f"validation_results may contain only one {kind} classification"
            )
    readiness_id = _text(readiness.get("readiness_id"))
    readiness_status = _text(readiness.get("status"))
    readiness_consumers = set(readiness.get("reused_by", []))
    result_consumers = {
        _text(item.get("kind"))
        for item in normalized
        if _text(item.get("kind")) in {"official_ut", "build"}
    }
    if readiness and readiness_consumers != result_consumers:
        raise ValidationReadinessError(
            "dependency readiness reused_by must match official UT and build results"
        )
    for item in normalized:
        kind = _text(item.get("kind"))
        status = _text(item.get("status"))
        blocked = status in {
            "dependency_blocked_before_start",
            "dependency_graph_blocked",
        }
        item_readiness_id = _text(item.get("dependency_readiness_id"))
        if kind in {"official_ut", "build"} and (
            not readiness_id or item_readiness_id != readiness_id
        ):
            raise ValidationReadinessError(
                "official UT and build validation must bind dependency readiness"
            )
        if blocked and (
            readiness_status != "blocked"
        ):
            raise ValidationReadinessError(
                "dependency-blocked validation must reuse the blocked readiness result"
            )
        if (
            status in {"passed", "failed_after_start", "compiled", "compile_failed"}
            and item_readiness_id
            and (
                item_readiness_id != readiness_id
                or readiness_status != "ready"
            )
        ):
            raise ValidationReadinessError(
                "started validation cannot reference a blocked dependency result"
            )

    official = by_kind["official_ut"][0] if by_kind["official_ut"] else None
    build = by_kind["build"][0] if by_kind["build"] else None
    supplementary = by_kind["supplementary"]
    official_status = _text(official.get("status")) if official else "not_run"
    build_status = _text(build.get("status")) if build else "not_run"
    supplementary_status = (
        "not_run"
        if not supplementary
        else "failed"
        if any(item["status"] == "failed" for item in supplementary)
        else "passed"
        if all(item["status"] == "passed" for item in supplementary)
        else "not_run"
    )
    acceptance = {
        "passed": "passed",
        "failed_after_start": "failed",
        "dependency_blocked_before_start": "blocked",
        "compiled": "passed",
        "compile_failed": "failed",
        "dependency_graph_blocked": "blocked",
        "not_run": "not_run",
    }
    summary = {
        "official_ut": {
            "status": official_status,
            "acceptance": acceptance[official_status],
        },
        "build": {
            "status": build_status,
            "acceptance": acceptance[build_status],
        },
        "supplementary": {
            "status": supplementary_status,
            "count": len(supplementary),
            "counts_as_official_ut": False,
        },
    }
    gaps: list[str] = []
    if official_status != "passed":
        gaps.append(f"official_ut={official_status}")
    if build_status != "compiled":
        gaps.append(f"build={build_status}")
    if supplementary and official_status != "passed":
        gaps.append("supplementary tests do not satisfy official UT acceptance")
    return normalized, summary, gaps


def _hardware_coverage(
    value: object,
    *,
    allowed_evidence_ids: frozenset[str],
) -> tuple[dict[str, object], list[str]]:
    if value in (None, {}):
        coverage = {
            "status": "not_reported",
            "required_protocols": [],
            "observed_protocols": [],
            "devices": [],
            "evidence_ids": [],
            "gaps": ["hardware_coverage=not_reported"],
            "proves_required_protocols": False,
        }
        return coverage, list(coverage["gaps"])
    if not isinstance(value, Mapping):
        raise ValidationReadinessError("hardware_coverage must be an object")
    required = sorted(
        {normalize_hardware_protocol(item) for item in _strings(
            value.get("required_protocols", []),
            field="hardware_coverage.required_protocols",
        )}
    )
    raw_devices = value.get("devices", [])
    if not isinstance(raw_devices, Sequence) or isinstance(
        raw_devices, (str, bytes, bytearray)
    ):
        raise ValidationReadinessError("hardware_coverage.devices must be an array")
    devices: list[dict[str, str]] = []
    for index, raw in enumerate(raw_devices):
        if not isinstance(raw, Mapping):
            raise ValidationReadinessError(
                f"hardware_coverage.devices[{index}] must be an object"
            )
        device_id = _text(raw.get("device_id"))
        protocol = normalize_hardware_protocol(raw.get("protocol"))
        if not device_id or not protocol:
            raise ValidationReadinessError(
                f"hardware_coverage.devices[{index}] requires device_id and protocol"
            )
        devices.append({"device_id": device_id, "protocol": protocol})
    observed = sorted({item["protocol"] for item in devices})
    proves_required = bool(required) and set(required).issubset(observed)
    expected_status = (
        "not_required" if not required else "covered" if proves_required else "blocked"
    )
    supplied_status = _text(value.get("status")).lower()
    if supplied_status not in HARDWARE_COVERAGE_STATUSES:
        raise ValidationReadinessError(
            "hardware_coverage.status must be covered, blocked, or not_required"
        )
    if supplied_status != expected_status:
        raise ValidationReadinessError(
            "hardware coverage status contradicts the observed protocol coverage"
        )
    gaps = _strings(value.get("gaps", []), field="hardware_coverage.gaps")
    evidence_ids = _strings(
        value.get("evidence_ids", []),
        field="hardware_coverage.evidence_ids",
        required=expected_status == "covered" or bool(devices),
    )
    unknown_evidence = sorted(set(evidence_ids) - set(allowed_evidence_ids))
    if unknown_evidence:
        raise ValidationReadinessError(
            "hardware coverage evidence_ids are not bound to current target Evidence: "
            + ", ".join(unknown_evidence)
        )
    if expected_status == "blocked" and not gaps:
        missing = sorted(set(required) - set(observed))
        gaps = ["missing representative hardware protocols: " + ", ".join(missing)]
    coverage = {
        "status": expected_status,
        "required_protocols": required,
        "observed_protocols": observed,
        "devices": devices,
        "evidence_ids": evidence_ids,
        "gaps": gaps,
        "proves_required_protocols": proves_required,
    }
    return coverage, gaps


@dataclass(frozen=True)
class ValidationAssessment:
    dependency_readiness: Mapping[str, object]
    validation_results: tuple[Mapping[str, object], ...]
    validation_summary: Mapping[str, object]
    hardware_coverage: Mapping[str, object]
    gaps: tuple[str, ...]

    def payload_fields(
        self,
        *,
        phase_type: str,
        phase_status: str,
        has_artifact: bool,
    ) -> dict[str, object]:
        build_summary = self.validation_summary.get("build")
        build_acceptance = (
            _text(build_summary.get("acceptance"))
            if isinstance(build_summary, Mapping)
            else ""
        )
        artifact_claim = (
            phase_type == "build.artifact"
            and phase_status == "completed"
            and has_artifact
            and build_acceptance == "passed"
        )
        claims = {
            "package": artifact_claim,
            "firmware": artifact_claim,
            "upgrade": False,
            "hardware_repair_validated": False,
        }
        summary = {
            **dict(self.validation_summary),
            "dependency_readiness": dict(self.dependency_readiness),
            "claims": claims,
        }
        return {
            "dependency_readiness": dict(self.dependency_readiness),
            "validation_results": [dict(item) for item in self.validation_results],
            "validation_summary": summary,
            "hardware_coverage": dict(self.hardware_coverage),
            "validation_gaps": list(self.gaps),
        }


def assess_validation_payload(
    payload: Mapping[str, object],
    *,
    allowed_hardware_evidence_ids: Sequence[str] = (),
) -> ValidationAssessment:
    """Normalize one phase payload without promoting source work to runtime success."""

    readiness = _dependency_readiness(payload.get("dependency_readiness"))
    results, summary, validation_gaps = _validation_results(
        payload.get("validation_results"),
        readiness=readiness,
    )
    coverage, coverage_gaps = _hardware_coverage(
        payload.get("hardware_coverage"),
        allowed_evidence_ids=frozenset(
            _text(item)
            for item in allowed_hardware_evidence_ids
            if _text(item)
        ),
    )
    return ValidationAssessment(
        dependency_readiness=readiness,
        validation_results=tuple(results),
        validation_summary=summary,
        hardware_coverage=coverage,
        gaps=tuple(dict.fromkeys((*validation_gaps, *coverage_gaps))),
    )
