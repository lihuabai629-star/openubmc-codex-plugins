"""Bounded, semantics-preserving summaries for structured bundle logs."""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import csv
import hashlib
import pathlib
import re
from collections import Counter

from log_bundle_redaction import redact_sensitive_text


MAX_SUMMARY_ITEMS = 20
SUPPORTED_STRUCTURED_PARSERS = frozenset(
    {
        "delimited_records",
        "pcie_topology_records",
        "mdb_properties",
    }
)
DELIMITER_NAMES = {
    ",": "comma",
    ";": "semicolon",
    "\t": "tab",
    "|": "pipe",
}
CABLE_RECORD_RE = re.compile(
    r"^\[BizTopoMonitor\]\s+(?P<kind>Port|Config):\s+"
    r"(?P<label_key>name|slot)=(?P<label>[^,]*),\s*"
    r"status=(?P<status>-?\d+),\s*unit=\["
    r"uid=(?P<uid>[^,\]]*),\s*index=(?P<index>-?\d+)"
    r"(?:,\s*port_id=(?P<port_id>-?\d+))?\]\s*$"
)
MDB_BLOCK_RE = re.compile(r"^(?P<object_path>/\S+)\s+(?P<interface>\S+)\s*$")
MDB_PROPERTY_RE = re.compile(r"^\.(?P<property>[A-Za-z_][\w.-]*)\s*$")
MDB_VALUE_RE = re.compile(r"^\s+value:\s+.*$")


def _bounded_counter(counter: Counter[str]) -> dict[str, int]:
    return {key: count for key, count in counter.most_common(MAX_SUMMARY_ITEMS)}


def _clean_header(value: str) -> str:
    cleaned = " ".join(value.strip().split())
    if not cleaned:
        return "<empty>"
    return cleaned[:80]


def _stable_identifier(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def _plausible_header(values: list[str]) -> bool:
    if not values:
        return False
    plausible = 0
    header_like = {
        "time", "timestamp", "date", "severity", "level", "message", "msg",
        "status", "event", "eventid", "id", "name", "type", "source",
        "description", "code", "value", "sensor", "property",
    }
    localized_header_markers = (
        "时间", "严重性", "级别", "消息", "状态", "事件", "名称", "类型",
        "来源", "描述", "代码", "数值", "传感器", "属性",
    )
    for value in values:
        cleaned = _clean_header(value)
        if cleaned == "<empty>" or "<redacted>" in cleaned:
            continue
        if re.search(r"\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}", cleaned):
            return False
        if re.fullmatch(r"-?\d+(?:\.\d+)?", cleaned):
            continue
        if re.fullmatch(r"[\w .()/\-\u4e00-\u9fff]{1,80}", cleaned):
            plausible += 1
    normalized = {re.sub(r"[^a-z0-9]", "", value.casefold()) for value in values}
    has_header_marker = bool(normalized & header_like) or any(
        marker in value for value in values for marker in localized_header_markers
    )
    return plausible >= max(1, (len(values) + 1) // 2) and has_header_marker


class StructuredSummaryCollector:
    """Observe decoded lines without causing a second file read."""

    def __init__(self, parser_name: str, path: pathlib.Path) -> None:
        self.parser_name = parser_name
        self.path = path
        self.line_count = 0
        self.record_count = 0

        self._csv_delimiter = ""
        self._csv_columns: list[str] = []
        self._csv_malformed_rows = 0
        self._csv_header_present = False

        self._cable_kind_counts: Counter[str] = Counter()
        self._cable_status_counts: dict[str, Counter[str]] = {}
        self._cable_missing_uid_count = 0
        self._cable_samples: dict[tuple[str, str], list[dict[str, object]]] = {}

        self._mdb_objects: set[str] = set()
        self._mdb_interfaces: Counter[str] = Counter()
        self._mdb_properties: Counter[str] = Counter()
        self._mdb_block_count = 0
        self._mdb_property_value_count = 0
        self._mdb_current_property = ""
        self._mdb_samples: list[dict[str, object]] = []

    def observe(
        self,
        line_number: int,
        line: str,
        in_time_window: bool = True,
    ) -> None:
        line, _ = redact_sensitive_text(line)
        if not in_time_window:
            # A delimited file's schema line commonly has no timestamp. Keep
            # only that first header candidate; never count an out-of-window
            # data record or feed it to the other structured parsers.
            if self.parser_name == "delimited_records" and not self._csv_delimiter:
                self._observe_delimited(line, count_record=False)
            return
        self.line_count += 1
        if self.parser_name == "delimited_records":
            self._observe_delimited(line, count_record=True)
        elif self.parser_name == "pcie_topology_records":
            self._observe_cable(line_number, line)
        elif self.parser_name == "mdb_properties":
            self._observe_mdb(line_number, line)

    def _observe_delimited(self, line: str, *, count_record: bool) -> None:
        if not line.strip():
            return
        if not self._csv_delimiter:
            counts = {delimiter: line.count(delimiter) for delimiter in DELIMITER_NAMES}
            delimiter, count = max(counts.items(), key=lambda item: item[1])
            if count <= 0:
                return
            self._csv_delimiter = delimiter
            try:
                first_row = next(csv.reader([line], delimiter=delimiter))
            except (csv.Error, StopIteration):
                self._csv_delimiter = ""
                return
            cleaned_columns = [_clean_header(value) for value in first_row]
            if _plausible_header(cleaned_columns):
                self._csv_columns = cleaned_columns
                self._csv_header_present = True
            elif count_record:
                self.record_count += 1
            return
        try:
            row = next(csv.reader([line], delimiter=self._csv_delimiter))
        except (csv.Error, StopIteration):
            self._csv_malformed_rows += 1
            return
        self.record_count += 1
        if self._csv_columns and len(row) != len(self._csv_columns):
            self._csv_malformed_rows += 1

    def _observe_cable(self, line_number: int, line: str) -> None:
        match = CABLE_RECORD_RE.match(line.strip())
        if not match:
            return
        values = match.groupdict()
        kind = values["kind"].casefold()
        status = values["status"]
        self.record_count += 1
        self._cable_kind_counts[kind] += 1
        self._cable_status_counts.setdefault(kind, Counter())[status] += 1
        if not values["uid"]:
            self._cable_missing_uid_count += 1
        sample_key = (kind, status)
        samples = self._cable_samples.setdefault(sample_key, [])
        if len(samples) < 2:
            sample: dict[str, object] = {
                "line_number": line_number,
                "record_kind": kind,
                "label_type": values["label_key"],
                "label_hash": _stable_identifier(values["label"]),
                "status_code": int(status),
                "unit_identifier_present": bool(values["uid"]),
                "unit_index": int(values["index"]),
            }
            if values["port_id"] is not None:
                sample["port_id"] = int(values["port_id"])
            samples.append(sample)

    def _observe_mdb(self, line_number: int, line: str) -> None:
        block_match = MDB_BLOCK_RE.match(line)
        if block_match:
            values = block_match.groupdict()
            self._mdb_block_count += 1
            object_path_hash = _stable_identifier(values["object_path"])
            self._mdb_objects.add(object_path_hash)
            self._mdb_interfaces[values["interface"]] += 1
            self._mdb_current_property = ""
            if len(self._mdb_samples) < 8:
                self._mdb_samples.append(
                    {
                        "line_number": line_number,
                        "object_path_hash": object_path_hash,
                        "interface": values["interface"],
                    }
                )
            return
        property_match = MDB_PROPERTY_RE.match(line)
        if property_match:
            self._mdb_current_property = property_match.group("property")
            self._mdb_properties[self._mdb_current_property] += 1
            return
        if self._mdb_current_property and MDB_VALUE_RE.match(line):
            self._mdb_property_value_count += 1
            self._mdb_current_property = ""

    def finish(self, relative_path: str) -> dict[str, object] | None:
        if self.parser_name == "delimited_records":
            if not self._csv_delimiter:
                return None
            return {
                "parser": self.parser_name,
                "path": relative_path,
                "observation_type": "schema_and_row_count",
                "interpretation": "structure_only",
                "delimiter": DELIMITER_NAMES[self._csv_delimiter],
                "columns": self._csv_columns[:MAX_SUMMARY_ITEMS],
                "column_count": len(self._csv_columns),
                "header_present": self._csv_header_present,
                "observed_record_count": self.record_count,
                "malformed_record_count": self._csv_malformed_rows,
            }
        if self.parser_name == "pcie_topology_records":
            if not self.record_count:
                return None
            samples = [sample for group in self._cable_samples.values() for sample in group]
            samples.sort(key=lambda item: int(item["line_number"]))
            return {
                "parser": self.parser_name,
                "path": relative_path,
                "observation_type": "topology_status_records",
                "interpretation": "status_codes_require_sourced_profile",
                "observed_record_count": self.record_count,
                "record_kind_counts": _bounded_counter(self._cable_kind_counts),
                "status_code_counts": {
                    kind: _bounded_counter(counter)
                    for kind, counter in sorted(self._cable_status_counts.items())
                },
                "records_without_unit_identifier": self._cable_missing_uid_count,
                "sample_records": samples[:MAX_SUMMARY_ITEMS],
                "sensitive_fields_omitted": ["uid", "label"],
            }
        if self.parser_name == "mdb_properties":
            if not self._mdb_block_count:
                return None
            self.record_count = self._mdb_block_count
            return {
                "parser": self.parser_name,
                "path": relative_path,
                "observation_type": "object_interface_property_inventory",
                "interpretation": "structure_only",
                "observed_record_count": self.record_count,
                "object_count": len(self._mdb_objects),
                "interface_block_count": self._mdb_block_count,
                "property_value_count": self._mdb_property_value_count,
                "interface_counts": _bounded_counter(self._mdb_interfaces),
                "property_counts": _bounded_counter(self._mdb_properties),
                "sample_blocks": self._mdb_samples,
                "property_values_omitted": True,
            }
        return None


def make_structured_collector(parser_name: object, path: pathlib.Path) -> StructuredSummaryCollector | None:
    if not isinstance(parser_name, str) or parser_name not in SUPPORTED_STRUCTURED_PARSERS:
        return None
    return StructuredSummaryCollector(parser_name, path)
