"""Pure component acceptance rules; RunEngine alone commits their results."""

from collections.abc import Mapping
import hashlib
import json
import re

from .validation_readiness import assess_validation_payload, ValidationReadinessError


class ComponentValidationError(ValueError):
    pass


def _object(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ComponentValidationError(f"{label} has an invalid field set")
    return value


def _strings(value, label):
    if not isinstance(value, list) or any(
        not isinstance(x, str) or not x.strip() for x in value
    ):
        raise ComponentValidationError(f"{label} must contain nonempty strings")
    return value


def _source(value):
    _object(value, ("root", "git_head", "content_sha256"), "component source")
    if not isinstance(value["root"], str) or not value["root"].startswith("/"):
        raise ComponentValidationError("component source root must be absolute")
    for key, size in (("git_head", 40), ("content_sha256", 64)):
        if (
            not isinstance(value[key], str)
            or re.fullmatch("[0-9a-f]{" + str(size) + "}", value[key]) is None
        ):
            raise ComponentValidationError("component source identity is invalid")


def _evidence(value):
    _object(value, ("path", "sha256"), "dependency evidence")
    if (
        not isinstance(value["path"], str)
        or not value["path"]
        or not isinstance(value["sha256"], str)
        or re.fullmatch("[0-9a-f]{64}", value["sha256"]) is None
    ):
        raise ComponentValidationError("dependency evidence identity is invalid")


def normalize_impact(value):
    _object(
        value,
        (
            "schema",
            "changed_files",
            "components",
            "dependency_edges",
            "graph",
            "gaps",
            "digest",
        ),
        "change impact",
    )
    if value["schema"] != "openubmc.change-impact.v1":
        raise ComponentValidationError("unsupported change impact schema")
    unsigned = {key: item for key, item in value.items() if key != "digest"}
    actual = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
        ).hexdigest()
    )
    if value["digest"] != actual:
        raise ComponentValidationError("change impact digest mismatch")
    _strings(value["changed_files"], "changed files")
    _strings(value["gaps"], "impact gaps")
    _evidence(value["graph"])
    components = value["components"]
    if not isinstance(components, list) or not 1 <= len(components) <= 128:
        raise ComponentValidationError("change impact requires 1 to 128 components")
    index = {}
    for component in components:
        _object(
            component,
            (
                "component",
                "source",
                "reason",
                "needs_generation",
                "required_checks",
                "dependencies",
            ),
            "affected component",
        )
        name = component["component"]
        if not isinstance(name, str) or not name.strip() or name in index:
            raise ComponentValidationError("duplicate or invalid component identity")
        _source(component["source"])
        if (
            component["reason"] not in ("direct", "interface_consumer")
            or type(component["needs_generation"]) is not bool
        ):
            raise ComponentValidationError("invalid component impact reason")
        if set(_strings(component["required_checks"], "component required checks")) != {
            "official_ut",
            "build",
        }:
            raise ComponentValidationError(
                "component requires official UT and build validation"
            )
        dependencies = component["dependencies"]
        if not isinstance(dependencies, dict) or len(dependencies) > 128:
            raise ComponentValidationError("invalid component dependencies")
        for provider, source in dependencies.items():
            if not isinstance(provider, str) or not provider.strip():
                raise ComponentValidationError("invalid dependency component")
            _source(source)
        index[name] = component
    edges = value["dependency_edges"]
    if not isinstance(edges, list) or len(edges) > 1024:
        raise ComponentValidationError("invalid component dependency edges")
    selected_edges = set()
    for edge in edges:
        _object(edge, ("provider", "consumer", "evidence"), "dependency edge")
        provider, consumer = edge["provider"], edge["consumer"]
        if (
            not isinstance(provider, str)
            or not isinstance(consumer, str)
            or consumer not in index
        ):
            raise ComponentValidationError("dependency edge has an unknown consumer")
        if (provider, consumer) in selected_edges or provider not in index[consumer][
            "dependencies"
        ]:
            raise ComponentValidationError("duplicate or unbound dependency edge")
        selected_edges.add((provider, consumer))
        _evidence(edge["evidence"])
        if (
            provider in index
            and index[consumer]["dependencies"][provider] != index[provider]["source"]
        ):
            raise ComponentValidationError("stale component dependency source")
    expected_edges = {
        (provider, name)
        for name, component in index.items()
        for provider in component["dependencies"]
    }
    if selected_edges != expected_edges:
        raise ComponentValidationError("component dependency evidence is incomplete")
    return index


def assess_components(payload, *, prior_impact=None, prior_rows=(), completed=False):
    """Validate only supplied evidence; no source reads, effects or state writes."""
    impact = payload.get("change_impact", prior_impact)
    if impact is None:
        if "component_validation" in payload:
            raise ComponentValidationError(
                "component validation requires change impact"
            )
        return {}
    index = normalize_impact(impact)
    if prior_impact is not None and impact != prior_impact:
        raise ComponentValidationError(
            "accepted component impact cannot change during handoff"
        )
    rows = payload.get("component_validation", [])
    if not isinstance(rows, list) or len(rows) > 128:
        raise ComponentValidationError("invalid component validation collection")
    # Prior rows are Runtime-owned normalized facts from the preceding partial
    # submission of this same phase. Incoming rows replace their own component.
    incoming_names = [row.get("component") for row in rows if isinstance(row, dict)]
    rows = [row for row in prior_rows if row["component"] not in incoming_names] + rows
    seen, normalized, gaps = set(), [], list(impact["gaps"])
    for row in rows:
        _object(
            row,
            (
                "component",
                "source",
                "dependencies",
                "dependency_readiness",
                "validation_results",
            ),
            "component validation",
        )
        name = row["component"]
        if not isinstance(name, str) or name not in index or name in seen:
            raise ComponentValidationError(
                "missing, duplicate or unexpected component validation identity"
            )
        seen.add(name)
        component = index[name]
        if (
            row["source"] != component["source"]
            or row["dependencies"] != component["dependencies"]
        ):
            raise ComponentValidationError(
                "component source or dependency binding mismatch"
            )
        try:
            assessment = assess_validation_payload(row)
        except ValidationReadinessError as error:
            raise ComponentValidationError(f"component {name}: {error}") from error
        for kind in component["required_checks"]:
            if assessment.validation_summary[kind]["acceptance"] != "passed":
                gaps.append(f"component {name}: {kind} has not passed")
        normalized.append(
            {
                **row,
                "dependency_readiness": dict(assessment.dependency_readiness),
                "validation_results": [
                    dict(item) for item in assessment.validation_results
                ],
            }
        )
    gaps += [
        "component " + name + ": validation missing"
        for name in sorted(set(index) - seen)
    ]
    if completed and gaps:
        raise ComponentValidationError("component scope incomplete: " + "; ".join(gaps))
    return {"change_impact": impact, "component_validation": normalized}
