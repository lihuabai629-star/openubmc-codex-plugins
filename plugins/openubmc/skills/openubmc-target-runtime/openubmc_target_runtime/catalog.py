"""Single-source operation descriptors for MCP, CLI, and domain dispatch."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import math
import re


class OperationCatalogError(ValueError):
    """Raised when operation declarations cannot form a valid catalog."""


_JSON_TYPES = {
    "array",
    "boolean",
    "integer",
    "null",
    "number",
    "object",
    "string",
}


def _validate_schema(schema: Mapping[str, object], *, path: str = "$") -> None:
    raw_type = schema.get("type")
    if raw_type is not None:
        declared = [raw_type] if isinstance(raw_type, str) else raw_type
        if not isinstance(declared, (list, tuple)) or not declared:
            raise OperationCatalogError(f"schema {path}.type must name JSON types")
        if not all(isinstance(item, str) and item in _JSON_TYPES for item in declared):
            raise OperationCatalogError(f"schema {path}.type contains an invalid JSON type")

    properties = schema.get("properties")
    if properties is not None:
        if not isinstance(properties, Mapping):
            raise OperationCatalogError(f"schema {path}.properties must be an object")
        for name, child in properties.items():
            if not isinstance(name, str) or not isinstance(child, Mapping):
                raise OperationCatalogError(
                    f"schema {path}.properties entries must be named schemas"
                )
            _validate_schema(child, path=f"{path}.properties.{name}")

    required = schema.get("required")
    if required is not None and (
        not isinstance(required, (list, tuple))
        or not all(isinstance(item, str) and item for item in required)
    ):
        raise OperationCatalogError(f"schema {path}.required must be string names")

    items = schema.get("items")
    if items is not None:
        if not isinstance(items, Mapping):
            raise OperationCatalogError(f"schema {path}.items must be a schema")
        _validate_schema(items, path=f"{path}.items")

    additional = schema.get("additionalProperties")
    if additional is not None and not isinstance(additional, (bool, Mapping)):
        raise OperationCatalogError(
            f"schema {path}.additionalProperties must be boolean or a schema"
        )
    if isinstance(additional, Mapping):
        _validate_schema(additional, path=f"{path}.additionalProperties")

    for keyword in ("oneOf", "allOf"):
        branches = schema.get(keyword)
        if branches is None:
            continue
        if not isinstance(branches, (list, tuple)) or not branches:
            raise OperationCatalogError(f"schema {path}.{keyword} must not be empty")
        for index, branch in enumerate(branches):
            if not isinstance(branch, Mapping):
                raise OperationCatalogError(
                    f"schema {path}.{keyword}[{index}] must be a schema"
                )
            _validate_schema(branch, path=f"{path}.{keyword}[{index}]")

    for keyword in ("if", "then", "else"):
        branch = schema.get(keyword)
        if branch is not None:
            if not isinstance(branch, Mapping):
                raise OperationCatalogError(f"schema {path}.{keyword} must be a schema")
            _validate_schema(branch, path=f"{path}.{keyword}")

    pattern = schema.get("pattern")
    if pattern is not None:
        if not isinstance(pattern, str):
            raise OperationCatalogError(f"schema {path}.pattern must be a string")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise OperationCatalogError(f"schema {path}.pattern is invalid: {exc}") from exc
    for keyword in ("minLength", "maxLength"):
        length = schema.get(keyword)
        if length is not None and (
            not isinstance(length, int) or isinstance(length, bool) or length < 0
        ):
            raise OperationCatalogError(
                f"schema {path}.{keyword} must be a non-negative integer"
            )


def validate_json_schema(schema: Mapping[str, object], *, path: str = "$") -> None:
    """Validate the supported JSON Schema subset used by Runtime contracts."""

    if not isinstance(schema, Mapping) or not schema:
        raise OperationCatalogError(f"schema {path} must be a non-empty object")
    _validate_schema(schema, path=path)

def _matches_type(value: object, expected: str) -> bool:
    if expected == "null":
        return value is None
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "string":
        return isinstance(value, str)
    if expected == "array":
        return isinstance(value, (list, tuple))
    if expected == "object":
        return isinstance(value, Mapping)
    return False


def _instance_errors(
    value: object,
    schema: Mapping[str, object],
    *,
    path: str,
) -> list[str]:
    errors: list[str] = []
    raw_type = schema.get("type")
    if raw_type is not None:
        declared = [raw_type] if isinstance(raw_type, str) else list(raw_type)
        if not any(_matches_type(value, item) for item in declared):
            return [f"{path} must be {' or '.join(str(item) for item in declared)}"]

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path} must equal {schema['const']!r}")
    enum = schema.get("enum")
    if isinstance(enum, (list, tuple)) and value not in enum:
        errors.append(f"{path} must be one of {list(enum)!r}")

    if isinstance(value, str):
        minimum = schema.get("minLength")
        if isinstance(minimum, int) and len(value) < minimum:
            errors.append(f"{path} must contain at least {minimum} characters")
        maximum = schema.get("maxLength")
        if isinstance(maximum, int) and len(value) > maximum:
            errors.append(f"{path} must contain at most {maximum} characters")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            errors.append(f"{path} does not match the required pattern")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            return [f"{path} must be finite"]
        minimum = schema.get("minimum")
        if isinstance(minimum, (int, float)) and value < minimum:
            errors.append(f"{path} must be at least {minimum}")
        exclusive = schema.get("exclusiveMinimum")
        if isinstance(exclusive, (int, float)) and value <= exclusive:
            errors.append(f"{path} must be greater than {exclusive}")
        maximum = schema.get("maximum")
        if isinstance(maximum, (int, float)) and value > maximum:
            errors.append(f"{path} must be at most {maximum}")

    if isinstance(value, (list, tuple)):
        minimum = schema.get("minItems")
        if isinstance(minimum, int) and len(value) < minimum:
            errors.append(f"{path} must contain at least {minimum} items")
        maximum = schema.get("maxItems")
        if isinstance(maximum, int) and len(value) > maximum:
            errors.append(f"{path} must contain at most {maximum} items")
        items = schema.get("items")
        if isinstance(items, Mapping):
            for index, item in enumerate(value):
                errors.extend(_instance_errors(item, items, path=f"{path}[{index}]"))

    if isinstance(value, Mapping):
        required = schema.get("required")
        if isinstance(required, (list, tuple)):
            for name in required:
                if name not in value:
                    errors.append(f"{path}.{name} is required")
        properties = schema.get("properties")
        known = properties if isinstance(properties, Mapping) else {}
        for name, item in value.items():
            child = known.get(name)
            if isinstance(child, Mapping):
                errors.extend(_instance_errors(item, child, path=f"{path}.{name}"))
                continue
            additional = schema.get("additionalProperties", True)
            if additional is False:
                errors.append(f"{path}.{name} is unexpected")
            elif isinstance(additional, Mapping):
                errors.extend(
                    _instance_errors(item, additional, path=f"{path}.{name}")
                )

    one_of = schema.get("oneOf")
    if isinstance(one_of, (list, tuple)):
        matches = sum(
            not _instance_errors(value, branch, path=path)
            for branch in one_of
            if isinstance(branch, Mapping)
        )
        if matches != 1:
            errors.append(f"{path} must match exactly one allowed schema")

    all_of = schema.get("allOf")
    if isinstance(all_of, (list, tuple)):
        for branch in all_of:
            if isinstance(branch, Mapping):
                errors.extend(_instance_errors(value, branch, path=path))

    condition = schema.get("if")
    if isinstance(condition, Mapping):
        branch_name = "then" if not _instance_errors(value, condition, path=path) else "else"
        branch = schema.get(branch_name)
        if isinstance(branch, Mapping):
            errors.extend(_instance_errors(value, branch, path=path))
    return errors


@dataclass(frozen=True)
class OperationDescriptor:
    """One versioned operation declaration and its dispatch binding."""

    name: str
    description: str
    input_schema: Mapping[str, object]
    handler_name: str | None = None
    lifecycle: str = "invoke"
    mutation: bool = False
    exposure: str = "internal"
    audience: str = "internal"
    cost_hint: str = "unbounded"
    scope_contract: str = ""
    result_projector: str = ""

    def __post_init__(self) -> None:
        name = self.name.strip()
        if not name:
            raise OperationCatalogError("operation name must not be empty")
        if not self.description.strip():
            raise OperationCatalogError(f"operation {name} requires a description")
        if self.input_schema.get("type") != "object":
            raise OperationCatalogError(
                f"operation {name} input schema must describe an object"
            )
        _validate_schema(self.input_schema)
        if self.lifecycle not in {"invoke", "read", "close", "status"}:
            raise OperationCatalogError(
                f"operation {name} has unsupported lifecycle {self.lifecycle}"
            )
        if self.exposure not in {"agent", "operator", "internal"}:
            raise OperationCatalogError(
                f"operation {name} has unsupported exposure {self.exposure}"
            )
        if self.audience not in {"agent", "operator", "internal"}:
            raise OperationCatalogError(
                f"operation {name} has unsupported audience {self.audience}"
            )
        if self.cost_hint not in {"small", "medium", "large", "unbounded"}:
            raise OperationCatalogError(
                f"operation {name} has unsupported cost hint {self.cost_hint}"
            )
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "description", self.description.strip())
        object.__setattr__(self, "input_schema", dict(self.input_schema))
        if self.handler_name is not None:
            handler_name = self.handler_name.strip()
            if not handler_name:
                raise OperationCatalogError(
                    f"operation {name} handler name must not be empty"
                )
            object.__setattr__(self, "handler_name", handler_name)

    @classmethod
    def from_tool_definition(
        cls,
        definition: Mapping[str, object],
        *,
        lifecycle: str = "invoke",
        handler_name: str | None = None,
        mutation: bool = False,
        exposure: str = "internal",
        audience: str = "internal",
        cost_hint: str = "unbounded",
        scope_contract: str = "",
        result_projector: str = "",
    ) -> "OperationDescriptor":
        name = definition.get("name")
        description = definition.get("description")
        input_schema = definition.get("inputSchema")
        if not isinstance(name, str):
            raise OperationCatalogError("tool definition requires a string name")
        if not isinstance(description, str):
            raise OperationCatalogError(
                f"operation {name} requires a string description"
            )
        if not isinstance(input_schema, Mapping):
            raise OperationCatalogError(
                f"operation {name} requires an object input schema"
            )
        return cls(
            name=name,
            description=description,
            input_schema=input_schema,
            handler_name=handler_name,
            lifecycle=lifecycle,
            mutation=mutation,
            exposure=exposure,
            audience=audience,
            cost_hint=cost_hint,
            scope_contract=scope_contract,
            result_projector=result_projector,
        )

    def to_public_dict(self) -> dict[str, object]:
        return {
            **self.to_tool_definition(),
            "lifecycle": self.lifecycle,
            "mutation": self.mutation,
            "exposure": self.exposure,
            "audience": self.audience,
            "cost_hint": self.cost_hint,
            "scope_contract": self.scope_contract,
            "result_projector": self.result_projector,
        }

    def to_tool_definition(self) -> dict[str, object]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": dict(self.input_schema),
        }


class OperationCatalog:
    """Validated ordered registry shared by listing and dispatch."""

    def __init__(
        self,
        descriptors: Iterable[OperationDescriptor],
        *,
        backend: object | None = None,
    ) -> None:
        ordered: list[OperationDescriptor] = []
        by_name: dict[str, OperationDescriptor] = {}
        for descriptor in descriptors:
            if not isinstance(descriptor, OperationDescriptor):
                raise TypeError("catalog entries must be OperationDescriptor values")
            if descriptor.name in by_name:
                raise OperationCatalogError(
                    f"duplicate operation name: {descriptor.name}"
                )
            if descriptor.handler_name is not None and backend is not None:
                callback = getattr(backend, descriptor.handler_name, None)
                if not callable(callback):
                    raise OperationCatalogError(
                        f"operation {descriptor.name} handler "
                        f"{descriptor.handler_name} is unavailable"
                    )
            ordered.append(descriptor)
            by_name[descriptor.name] = descriptor
        if not ordered:
            raise OperationCatalogError("operation catalog must not be empty")
        self._ordered = tuple(ordered)
        self._by_name = by_name

    def descriptors(self) -> tuple[OperationDescriptor, ...]:
        return self._ordered

    def extend(
        self,
        descriptors: Iterable[OperationDescriptor],
    ) -> "OperationCatalog":
        combined = {descriptor.name: descriptor for descriptor in self._ordered}
        for descriptor in descriptors:
            current = combined.get(descriptor.name)
            if current is not None and current != descriptor:
                raise OperationCatalogError(
                    f"operation catalog drift: {descriptor.name}"
                )
            combined[descriptor.name] = descriptor
        return OperationCatalog(combined.values())

    def names(self) -> tuple[str, ...]:
        return tuple(descriptor.name for descriptor in self._ordered)

    def tool_definitions(self) -> list[dict[str, object]]:
        return [descriptor.to_tool_definition() for descriptor in self._ordered]

    def require(self, name: str) -> OperationDescriptor:
        try:
            return self._by_name[name]
        except KeyError as exc:
            raise ValueError(f"unknown openUBMC domain tool: {name}") from exc

    def validate_arguments(self, name: str, arguments: Mapping[str, object]) -> None:
        descriptor = self.require(name)
        errors = _instance_errors(arguments, descriptor.input_schema, path=name)
        if errors:
            raise ValueError(errors[0])
