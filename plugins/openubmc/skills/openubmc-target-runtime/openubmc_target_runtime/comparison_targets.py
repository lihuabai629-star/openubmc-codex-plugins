"""Canonical Runtime-owned identities for multi-target diagnosis."""

from __future__ import annotations

from collections.abc import Mapping, Sequence


def comparison_target_identities(
    targets: Sequence[Mapping[str, object]],
) -> tuple[tuple[str, str], ...]:
    """Return the canonical (role, target_id) pair for each requested target."""

    if len(targets) < 2:
        raise ValueError("multi-target comparison requires at least two targets")
    raw_roles = [str(target.get("role") or "").strip().lower() for target in targets]
    if len(targets) == 2:
        if all(role == "" for role in raw_roles) or all(
            role == "symmetric" for role in raw_roles
        ):
            roles = ["target-a", "target-b"]
        elif set(raw_roles) == {"reference", "candidate"}:
            roles = raw_roles
        else:
            raise ValueError(
                "target roles must both be omitted, both be symmetric, or be "
                "reference and candidate"
            )
    else:
        reference_indexes = [
            index for index, role in enumerate(raw_roles) if role == "reference"
        ]
        if len(reference_indexes) > 1:
            raise ValueError("only one reference target is allowed")
        if reference_indexes:
            if any(role not in {"", "reference", "candidate"} for role in raw_roles):
                raise ValueError(
                    "reference mode accepts only reference/candidate roles"
                )
            roles = [
                "reference" if index == reference_indexes[0] else "candidate"
                for index in range(len(targets))
            ]
        else:
            if any(raw_roles):
                raise ValueError(
                    "symmetric multi-target mode requires omitted roles"
                )
            roles = [f"target-{index}" for index in range(1, len(targets) + 1)]

    candidate_index = 0
    identities: list[tuple[str, str]] = []
    for target, role in zip(targets, roles, strict=True):
        explicit = str(target.get("target_id") or "").strip()
        if explicit:
            target_id = explicit
        elif role == "candidate" and len(targets) > 2:
            candidate_index += 1
            target_id = f"candidate-{candidate_index}"
        else:
            target_id = role
        identities.append((role, target_id))
    target_ids = [target_id for _role, target_id in identities]
    if len(target_ids) != len(set(target_ids)):
        raise ValueError("multi-target target_id values must be unique")
    return tuple(identities)
