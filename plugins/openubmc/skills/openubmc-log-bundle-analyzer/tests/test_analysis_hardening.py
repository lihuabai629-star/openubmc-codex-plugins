from __future__ import annotations

import datetime as dt
import io
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock


SCRIPT_DIR = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from analyze_bundle import emit_result, safe_terminal_text  # type: ignore  # noqa: E402
from log_bundle_analysis import (  # type: ignore  # noqa: E402
    PathDiscoveryBudget,
    _PathDirectoryIndex,
    _expand_log_paths_bounded,
    _iter_bounded_glob,
    _iter_rotated_file_candidates_bounded,
    add_bundle_component_hints,
    analyze_bundle,
    build_timeline,
    collect_evidence_lines,
    load_reference_data,
    normalize_reference_data,
    parse_analysis_time_bound,
    select_logs_for_problem,
    validate_reference_data,
)
from log_bundle_common import BundleAnalysisError  # type: ignore  # noqa: E402
from log_bundle_findings import (  # type: ignore  # noqa: E402
    build_event_correlations,
    build_evidence_findings,
)


def catalog_for(
    name: str,
    relative_path: str,
    *,
    problem_term: str,
    file_keywords: list[str] | None = None,
    structured_parser: str = "",
    component: str = "component",
) -> dict[str, object]:
    file_definition: dict[str, object] = {
        "name": name,
        "paths": [relative_path],
        "component": component,
        "purpose": "test fixture",
        "keywords": file_keywords or [problem_term],
    }
    if structured_parser:
        file_definition["structured_parser"] = structured_parser
    return {
        "files": [file_definition],
        "rules": [
            {
                "match_keywords": [problem_term],
                "include": [name],
                "primary": [name],
            }
        ],
    }


class AssessmentHardeningTests(unittest.TestCase):
    def test_event_query_ignores_sensor_registration_but_keeps_real_event_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            event_dir = root / "dump_info" / "AppDump" / "event"
            log_dir = root / "dump_info" / "LogDump"
            event_dir.mkdir(parents=True)
            log_dir.mkdir(parents=True)
            (event_dir / "current_event.txt").write_text(
                "Event Num |Event Time |Alarm Level |Event Code |Event Description\n"
                "1 |2026-08-31 08:00:00 |Critical |0x0300000D |PSU input is lost\n",
                encoding="utf-8",
            )
            (event_dir / "sel.txt").write_text(
                "ID |Generation Time |Severity |Event Code |Status |Event Description\n"
                "2 |2026-08-31 07:59:00 |Major |0x03000009 |Asserted |PSU failure\n",
                encoding="utf-8",
            )
            (log_dir / "sensor.log").write_text(
                "[2026-08-31 07:58:00] sensor DiscreteSensor_DIMM000_0101 is registered\n",
                encoding="utf-8",
            )

            result = analyze_bundle(
                root,
                "当前告警、历史告警和系统事件",
                max_files=8,
                max_lines=3,
            )

        evidence_paths = {str(item["path"]) for item in result["evidence"]}
        self.assertEqual(result["assessment"], "evidence_found")
        self.assertTrue(any(path.endswith("current_event.txt") for path in evidence_paths))
        self.assertTrue(any(path.endswith("sel.txt") for path in evidence_paths))
        self.assertFalse(any(path.endswith("sensor.log") for path in evidence_paths))
        self.assertNotIn("is registered", "\n".join(str(item["line"]) for item in result["evidence"]))

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            (log_dir / "sensor.log").write_text(
                "[2026-08-31 08:00:00] sensor ThresholdSensor_DIMM000 is registered\n"
                "[2026-08-31 08:01:00] sensor threshold alarm asserted\n",
                encoding="utf-8",
            )

            sensor_result = analyze_bundle(root, "当前告警", max_files=8, max_lines=3)

        self.assertEqual(sensor_result["assessment"], "evidence_found")
        self.assertEqual(
            [
                item["line"]
                for item in sensor_result["evidence"]
                if str(item["path"]).endswith("sensor.log")
            ],
            ["[2026-08-31 08:01:00] sensor threshold alarm asserted"],
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            (log_dir / "sensor.log").write_text(
                "[2026-08-31 08:00:00] sensor DiscreteSensor_DIMM000 is registered\n",
                encoding="utf-8",
            )

            english_sensor_result = analyze_bundle(root, "sensor reading failure", max_files=8, max_lines=3)

        self.assertEqual(english_sensor_result["assessment"], "insufficient_bundle_evidence")
        self.assertFalse(
            any(str(item["path"]).endswith("sensor.log") for item in english_sensor_result["evidence"])
        )

    def test_generic_failure_only_stays_context_and_does_not_raise_assessment(self) -> None:
        reference = catalog_for(
            "security.log",
            "dump_info/LogDump/security.log",
            problem_term="login",
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            path = root / "dump_info" / "LogDump" / "security.log"
            path.parent.mkdir(parents=True)
            path.write_text(
                "2026-08-31 08:00:00 unrelated cache refresh failed\n",
                encoding="utf-8",
            )

            result = analyze_bundle(root, "login", reference_data=reference, max_files=1, max_lines=3)

        self.assertEqual(result["evidence_count"], 0)
        self.assertEqual(result["context_evidence_count"], 1)
        self.assertEqual(result["assessment"], "insufficient_bundle_evidence")

    def test_structure_only_observation_does_not_raise_assessment(self) -> None:
        reference = catalog_for(
            "eo_sel.csv",
            "dump_info/AppDump/event/eo_sel.csv",
            problem_term="history",
            structured_parser="delimited_records",
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            path = root / "dump_info" / "AppDump" / "event" / "eo_sel.csv"
            path.parent.mkdir(parents=True)
            path.write_text(
                "Time;Severity;Message\n"
                "2026-08-31 08:00:00;Info;ordinary record\n",
                encoding="utf-8",
            )

            result = analyze_bundle(root, "history", reference_data=reference, max_files=1, max_lines=3)

        self.assertEqual(result["structured_observation_count"], 1)
        self.assertEqual(result["assessment"], "insufficient_bundle_evidence")

    def test_structured_records_outside_time_window_are_not_counted(self) -> None:
        reference = catalog_for(
            "eo_sel.csv",
            "dump_info/AppDump/event/eo_sel.csv",
            problem_term="history",
            structured_parser="delimited_records",
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            path = root / "dump_info" / "AppDump" / "event" / "eo_sel.csv"
            path.parent.mkdir(parents=True)
            path.write_text(
                "Time;Severity;Message\n"
                "2026-01-01 08:00:00;Critical;old failure\n",
                encoding="utf-8",
            )

            result = analyze_bundle(
                root,
                "history",
                reference_data=reference,
                max_files=1,
                max_lines=3,
                since=dt.datetime(2026, 8, 31, 0, 0, 0),
                until=dt.datetime(2026, 8, 31, 23, 59, 59),
            )

        summary = result["structured_summaries"][0]
        self.assertTrue(summary["header_present"])
        self.assertEqual(summary["observed_record_count"], 0)
        self.assertTrue(summary["time_window_applied"])
        self.assertEqual(result["assessment"], "insufficient_bundle_evidence")


class TimeAndScanHardeningTests(unittest.TestCase):
    def test_date_only_until_includes_the_whole_day(self) -> None:
        until = parse_analysis_time_bound("2026-08-31", label="--analysis-until")
        self.assertEqual(until, dt.datetime(2026, 8, 31, 23, 59, 59, 999999))

        with tempfile.TemporaryDirectory() as tmp_dir:
            path = pathlib.Path(tmp_dir) / "security.log"
            path.write_text(
                "2026-08-31 23:59:59 login failed\n"
                "2026-09-01 00:00:00 login failed\n",
                encoding="utf-8",
            )
            evidence = collect_evidence_lines(
                path,
                match_terms=["login"],
                max_lines=3,
                until=until,
            )

        self.assertEqual(len(evidence), 1)
        self.assertIn("2026-08-31 23:59:59", evidence[0]["line"])

    def test_byte_limit_partial_line_is_discarded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = pathlib.Path(tmp_dir) / "app.log"
            path.write_text("error secret continues past the byte limit\n", encoding="utf-8")
            diagnostics: dict[str, object] = {}
            evidence = collect_evidence_lines(
                path,
                match_terms=["error"],
                max_lines=3,
                max_bytes=5,
                diagnostics=diagnostics,
            )

        self.assertEqual(evidence, [])
        warning_codes = {
            item["code"]
            for item in diagnostics["warnings"]
            if isinstance(item, dict)
        }
        self.assertIn("partial_line_discarded", warning_codes)
        self.assertIn("file_scan_truncated", warning_codes)

    def test_byte_limit_after_complete_line_reports_remaining_content(self) -> None:
        first_line = "2026-08-31 08:00:00 login failed\n"
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = pathlib.Path(tmp_dir) / "security.log"
            path.write_bytes((first_line + "second line remains\n").encode("utf-8"))
            diagnostics: dict[str, object] = {}
            evidence = collect_evidence_lines(
                path,
                match_terms=["login"],
                max_lines=3,
                max_bytes=len(first_line.encode("utf-8")),
                diagnostics=diagnostics,
            )

        self.assertEqual(len(evidence), 1)
        warning_codes = {
            item["code"]
            for item in diagnostics["warnings"]
            if isinstance(item, dict)
        }
        self.assertIn("file_scan_truncated", warning_codes)

    def test_analysis_scan_marks_file_limit_truncation_explicitly(self) -> None:
        reference = catalog_for(
            "security.log",
            "dump_info/LogDump/security.log",
            problem_term="login",
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            path = root / "dump_info" / "LogDump" / "security.log"
            path.parent.mkdir(parents=True)
            path.write_text(
                "2026-08-31 08:00:00 login failed\n" * 20,
                encoding="utf-8",
            )
            result = analyze_bundle(
                root,
                "login",
                reference_data=reference,
                max_files=1,
                max_lines=2,
                max_bytes_per_file=64,
                max_total_bytes=64,
            )

        self.assertTrue(result["scan"]["truncated"])
        self.assertTrue(result["selected_logs"][0]["scan_truncated"])

    def test_binary_marker_in_overlong_continuation_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = pathlib.Path(tmp_dir) / "candidate.log"
            path.write_bytes(b"a" * 10 + b"\x00" + b"b" * 10 + b"\n")
            diagnostics: dict[str, object] = {}
            evidence = collect_evidence_lines(
                path,
                match_terms=["error"],
                max_lines=3,
                max_line_bytes=8,
                diagnostics=diagnostics,
            )

        self.assertEqual(evidence, [])
        error_codes = {
            item["code"]
            for item in diagnostics["errors"]
            if isinstance(item, dict)
        }
        self.assertIn("binary_content_detected", error_codes)


class FindingAndCorrelationHardeningTests(unittest.TestCase):
    def test_findings_do_not_merge_different_components_or_semantic_codes(self) -> None:
        evidence = [
            {
                "log": "app.log",
                "component": "iam",
                "path": "dump_info/AppDump/iam/app.log",
                "line_number": 1,
                "line": "2026-08-31 08:00:00 request failed status=404",
                "timestamp": "2026-08-31T08:00:00",
                "match_class": "direct_failure",
            },
            {
                "log": "app.log",
                "component": "storage",
                "path": "dump_info/AppDump/storage/app.log",
                "line_number": 1,
                "line": "2026-08-31 08:00:00 request failed status=404",
                "timestamp": "2026-08-31T08:00:00",
                "match_class": "direct_failure",
            },
            {
                "log": "app.log",
                "component": "iam",
                "path": "dump_info/AppDump/iam/app.log",
                "line_number": 2,
                "line": "2026-08-31 08:00:01 request failed status=500",
                "timestamp": "2026-08-31T08:00:01",
                "match_class": "direct_failure",
            },
        ]

        findings = build_evidence_findings(evidence)

        self.assertEqual(len(findings), 3)
        self.assertEqual(len({item["finding_id"] for item in findings}), 3)

    def test_mixed_timezone_domains_are_not_correlated(self) -> None:
        timeline = build_timeline(
            [
                {
                    "log": "operation.log",
                    "component": "iam",
                    "path": "dump_info/LogDump/operation.log",
                    "line_number": 1,
                    "line": "operation failed",
                    "timestamp": "2026-08-31T08:00:00+00:00",
                    "match_class": "direct_failure",
                },
                {
                    "log": "app.log",
                    "component": "iam",
                    "path": "dump_info/LogDump/app.log",
                    "line_number": 1,
                    "line": "iam ERROR: backend failed",
                    "timestamp": "2026-08-31T08:00:01",
                    "match_class": "direct_failure",
                },
            ]
        )

        correlations, unmatched = build_event_correlations(timeline, window_seconds=300)

        self.assertEqual(correlations, [])
        self.assertEqual(len(unmatched), 1)
        self.assertEqual(unmatched[0]["reason"], "no_other_selected_log_evidence_within_window")

    def test_two_phase_scan_correlates_anchor_and_candidate_dropped_by_primary_sampling(self) -> None:
        reference = {
            "files": [
                {
                    "name": "operation.log",
                    "paths": ["dump_info/LogDump/operation.log"],
                    "component": "operation_logger",
                    "purpose": "test operation audit",
                    "keywords": ["incident"],
                },
                {
                    "name": "app.log",
                    "paths": ["dump_info/LogDump/app.log"],
                    "component": "business components",
                    "purpose": "test component runtime",
                    "keywords": ["incident"],
                },
            ],
            "rules": [
                {
                    "match_keywords": ["incident"],
                    "include": ["operation.log", "app.log"],
                    "primary": ["operation.log"],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            (log_dir / "operation.log").write_text(
                "2026-08-31 08:00:00 SSH,user@192.0.2.10,iam,incident failed\n"
                "2026-08-31 12:00:00 SSH,user@192.0.2.10,iam,incident failed\n",
                encoding="utf-8",
            )
            (log_dir / "app.log").write_text(
                "2026-08-31 08:00:02 iam ERROR: incident failed near anchor\n"
                "2026-08-31 13:00:00 iam ERROR: incident failed newest sample\n",
                encoding="utf-8",
            )

            result = analyze_bundle(
                root,
                "incident",
                reference_data=reference,
                max_files=2,
                max_lines=1,
            )

        # The ordinary evidence sample keeps only the newer line from each
        # file, but phase one still observed the older operation anchor and
        # phase two found the nearby older app line.
        self.assertEqual({item["line_number"] for item in result["evidence"]}, {2})
        correlation = next(
            item
            for item in result["event_correlations"]
            if item["anchor"]["line_number"] == 1
        )
        self.assertEqual(correlation["candidates"][0]["line_number"], 1)
        self.assertEqual(correlation["candidates"][0]["delta_seconds"], 2)
        self.assertTrue(correlation["candidate_scan_complete"])
        self.assertTrue(result["correlation_scan"]["complete"])
        self.assertEqual(result["correlation_scan"]["anchor_count_observed"], 2)
        self.assertEqual(result["correlation_scan"]["candidate_count_retained"], 1)

        finding_pointers = {
            (evidence["path"], evidence["line_number"])
            for finding in result["evidence_findings"]
            for evidence in finding["evidence"]
        }
        self.assertNotIn(("dump_info/LogDump/app.log", 1), finding_pointers)

    def test_correlation_scan_budget_exhaustion_is_explicit(self) -> None:
        reference = {
            "files": [
                {
                    "name": "operation.log",
                    "paths": ["dump_info/LogDump/operation.log"],
                    "component": "operation_logger",
                    "purpose": "test operation audit",
                    "keywords": ["incident"],
                },
                {
                    "name": "app.log",
                    "paths": ["dump_info/LogDump/app.log"],
                    "component": "business components",
                    "purpose": "test component runtime",
                    "keywords": ["incident"],
                },
            ],
            "rules": [
                {
                    "match_keywords": ["incident"],
                    "include": ["operation.log", "app.log"],
                    "primary": ["operation.log"],
                }
            ],
        }
        operation_line = "2026-08-31 08:00:00 SSH,user@192.0.2.10,iam,incident failed\n"
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            (log_dir / "operation.log").write_bytes(operation_line.encode("utf-8"))
            (log_dir / "app.log").write_text(
                "2026-08-31 08:00:02 iam ERROR: incident failed\n",
                encoding="utf-8",
            )

            result = analyze_bundle(
                root,
                "incident",
                reference_data=reference,
                max_files=2,
                max_lines=1,
                max_total_bytes=len(operation_line.encode("utf-8")),
            )

        scan = result["correlation_scan"]
        self.assertTrue(scan["attempted"])
        self.assertFalse(scan["complete"])
        self.assertFalse(scan["candidate_scan_complete"])
        self.assertEqual(scan["remaining_bytes_before_scan"], 0)
        self.assertIn(
            "correlation_scan_byte_limit_reached",
            {item["code"] for item in scan["warnings"]},
        )
        self.assertEqual(result["unmatched_event_anchors"][0]["reason"], "candidate_scan_incomplete")
        self.assertFalse(result["unmatched_event_anchors"][0]["candidate_scan_complete"])

    def test_correlation_scan_marks_incompatible_timezone_candidates_incomplete(self) -> None:
        reference = {
            "files": [
                {
                    "name": "operation.log",
                    "paths": ["dump_info/LogDump/operation.log"],
                    "component": "operation_logger",
                    "purpose": "test operation audit",
                    "keywords": ["incident"],
                },
                {
                    "name": "app.log",
                    "paths": ["dump_info/LogDump/app.log"],
                    "component": "business components",
                    "purpose": "test component runtime",
                    "keywords": ["incident"],
                },
            ],
            "rules": [
                {
                    "match_keywords": ["incident"],
                    "include": ["operation.log", "app.log"],
                    "primary": ["operation.log"],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            (log_dir / "operation.log").write_text(
                "2026-08-31T08:00:00+00:00 incident failed\n",
                encoding="utf-8",
            )
            (log_dir / "app.log").write_text(
                "2026-08-31T08:00:01 incident failed\n",
                encoding="utf-8",
            )

            result = analyze_bundle(
                root,
                "incident",
                reference_data=reference,
                max_files=2,
                max_lines=1,
            )

        scan = result["correlation_scan"]
        self.assertFalse(scan["complete"])
        self.assertFalse(scan["candidate_scan_complete"])
        self.assertIn(
            "correlation_timezone_domain_mismatch",
            {item["code"] for item in scan["warnings"]},
        )
        self.assertEqual(result["unmatched_event_anchors"][0]["reason"], "candidate_scan_incomplete")
        self.assertFalse(result["unmatched_event_anchors"][0]["candidate_scan_complete"])


class PathDiscoveryBudgetHardeningTests(unittest.TestCase):
    def test_hint_subbudget_preserves_core_budget(self) -> None:
        reference = catalog_for(
            "core.log",
            "dump_info/LogDump/core.log",
            problem_term="core",
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            appdump = root / "dump_info" / "AppDump"
            appdump.mkdir(parents=True)
            for index in range(4):
                (appdump / f"component_{index}").mkdir()
            log_path = root / "dump_info" / "LogDump" / "core.log"
            log_path.parent.mkdir(parents=True)
            log_path.write_text("core failed\n", encoding="utf-8")

            discovery_budget = PathDiscoveryBudget(max_entries=10)
            hinted = add_bundle_component_hints(
                root,
                reference,
                max_discovery_entries=2,
                discovery_budget=discovery_budget,
            )
            self.assertEqual(discovery_budget.entries_examined, 2)
            diagnostics = hinted["_bundle_component_hint_diagnostics"]
            self.assertIn("hint_entry_limit", diagnostics["limit_reasons"])

            paths, truncated = _expand_log_paths_bounded(
                root,
                ["dump_info/LogDump/core.log"],
                discovery_budget=discovery_budget,
            )

        self.assertFalse(truncated)
        self.assertEqual([path.name for path in paths], ["core.log"])
        self.assertGreater(discovery_budget.entries_examined, 2)

    def test_component_hint_rejects_glob_and_control_names(self) -> None:
        reference = catalog_for(
            "core.log",
            "dump_info/LogDump/core.log",
            problem_term="core",
        )
        unsafe_names = ["evil*", "evil?", "evil[", "evil\\name", "evil\x01name"]
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            appdump = root / "dump_info" / "AppDump"
            appdump.mkdir(parents=True)
            if sys.platform == "win32":
                entries = []
                for name in unsafe_names:
                    entry = mock.Mock()
                    entry.name = name
                    entry.path = str(appdump / name)
                    entry.is_symlink.return_value = False
                    entry.is_dir.return_value = True
                    entries.append(entry)
                # Windows cannot materialize glob/control names as literal directory entries.
                with mock.patch("log_bundle_analysis.os.scandir") as scandir:
                    scandir.return_value.__iter__.return_value = iter(entries)
                    hinted = add_bundle_component_hints(root, reference, problem="evil")
            else:
                for name in unsafe_names:
                    (appdump / name).mkdir()
                hinted = add_bundle_component_hints(root, reference, problem="evil")

        dynamic_paths = [
            path
            for item in hinted["files"]
            for path in item.get("paths", [])
            if isinstance(path, str) and path.startswith("dump_info/AppDump/")
        ]
        self.assertEqual(dynamic_paths, [])
        diagnostics = hinted["_bundle_component_hint_diagnostics"]
        self.assertEqual(diagnostics["invalid_directory_count"], len(unsafe_names))
        self.assertIn("invalid_component_name", diagnostics["limit_reasons"])

    def test_component_hint_rejects_catalog_unsafe_whitespace_names(self) -> None:
        reference = catalog_for(
            "core.log",
            "dump_info/LogDump/core.log",
            problem_term="core",
        )
        unsafe_names = [" leading", "trailing "]
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            appdump = root / "dump_info" / "AppDump"
            appdump.mkdir(parents=True)
            if sys.platform == "win32":
                entries = []
                for name in unsafe_names:
                    entry = mock.Mock()
                    entry.name = name
                    entry.path = str(appdump / name)
                    entry.is_symlink.return_value = False
                    entry.is_dir.return_value = True
                    entries.append(entry)
                # Win32 strips trailing spaces when creating ordinary directories.
                with mock.patch("log_bundle_analysis.os.scandir") as scandir:
                    scandir.return_value.__iter__.return_value = iter(entries)
                    hinted = add_bundle_component_hints(root, reference)
            else:
                for name in unsafe_names:
                    (appdump / name).mkdir()
                hinted = add_bundle_component_hints(root, reference)
            # A second normalization is what analyze_bundle performs; it must
            # remain valid even when the bundle contains odd directory names.
            normalize_reference_data(hinted, source="test hinted reference")

        diagnostics = hinted["_bundle_component_hint_diagnostics"]
        self.assertEqual(diagnostics["invalid_directory_count"], len(unsafe_names))
        self.assertEqual(
            [item for item in hinted["files"] if str(item.get("name", "")).startswith("bundle_component_")],
            [],
        )

    def test_component_hints_retain_lexicographically_smallest_scanned_set(self) -> None:
        reference = catalog_for(
            "core.log",
            "dump_info/LogDump/core.log",
            problem_term="component",
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            appdump = root / "dump_info" / "AppDump"
            appdump.mkdir(parents=True)
            for name in ("zeta", "alpha", "mu"):
                (appdump / name).mkdir()

            hinted = add_bundle_component_hints(root, reference, max_hints=2)

        generated = [
            item["component"]
            for item in hinted["files"]
            if isinstance(item, dict) and str(item.get("name", "")).startswith("bundle_component_")
        ]
        self.assertEqual(generated, ["alpha", "mu"])

    def test_shared_directory_index_reuses_parent_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            for name in ("first.log", "second.log", "first.log.1"):
                (log_dir / name).write_text("x\n", encoding="utf-8")
            budget = PathDiscoveryBudget(max_entries=100)
            index = _PathDirectoryIndex(root, budget)
            first, first_truncated = _expand_log_paths_bounded(
                root,
                ["dump_info/LogDump/first.log"],
                discovery_budget=budget,
                directory_index=index,
            )
            consumed_after_first = budget.entries_examined
            second, second_truncated = _expand_log_paths_bounded(
                root,
                ["dump_info/LogDump/second.log"],
                discovery_budget=budget,
                directory_index=index,
            )

        self.assertFalse(first_truncated)
        self.assertFalse(second_truncated)
        self.assertEqual([path.name for path in first], ["first.log", "first.log.1"])
        self.assertEqual([path.name for path in second], ["second.log"])
        self.assertEqual(budget.entries_examined, consumed_after_first)

    def test_direct_relative_rotation_target_uses_its_parent_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "logs"
            log_dir.mkdir()
            (log_dir / "app.log").write_text("x\n", encoding="utf-8")
            (log_dir / "app.log.1").write_text("x\n", encoding="utf-8")
            current = pathlib.Path.cwd()
            try:
                # The helper historically accepted relative targets.  Keep
                # that API working while using the bounded directory index.
                import os

                os.chdir(root)
                paths, truncated = _iter_rotated_file_candidates_bounded(
                    pathlib.Path("logs/app.log"),
                    max_candidates=2,
                )
            finally:
                os.chdir(current)

        self.assertFalse(truncated)
        self.assertEqual([path.name for path in paths], ["app.log", "app.log.1"])

    def test_directory_index_and_budget_must_match_for_glob(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            (root / "dump_info" / "LogDump").mkdir(parents=True)
            first_budget = PathDiscoveryBudget(max_entries=10)
            second_budget = PathDiscoveryBudget(max_entries=10)
            index = _PathDirectoryIndex(root, first_budget)
            with self.assertRaises(BundleAnalysisError) as raised:
                list(
                    _iter_bounded_glob(
                        root,
                        "dump_info/LogDump/*.log",
                        discovery_budget=second_budget,
                        directory_index=index,
                    )
                )
        self.assertEqual(raised.exception.code, "invalid_request")

    def test_wildcard_rotation_is_linear_and_complete_for_hundreds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            for index in range(350):
                (log_dir / f"app_{index:03d}.log").write_text("x\n", encoding="utf-8")
            diagnostics: dict[str, object] = {}
            budget = PathDiscoveryBudget(max_entries=2000)
            paths, truncated = _expand_log_paths_bounded(
                root,
                ["dump_info/LogDump/*.log"],
                max_paths=400,
                diagnostics=diagnostics,
                discovery_budget=budget,
            )

        self.assertFalse(truncated)
        self.assertEqual(len(paths), 350)
        self.assertEqual(diagnostics["limit_reasons"], [])
        self.assertLessEqual(int(diagnostics["entries_examined"]), 355)

    def test_exact_max_path_count_is_not_marked_truncated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            for index in range(3):
                (log_dir / f"app_{index}.log").write_text("x\n", encoding="utf-8")
            diagnostics: dict[str, object] = {}
            paths, truncated = _expand_log_paths_bounded(
                root,
                ["dump_info/LogDump/*.log"],
                max_paths=3,
                diagnostics=diagnostics,
            )

        self.assertFalse(truncated)
        self.assertEqual(len(paths), 3)
        self.assertNotIn("path_limit", diagnostics["limit_reasons"])

    def test_limit_reason_and_limit_are_consistent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            for index in range(3):
                (log_dir / f"app_{index}.log").write_text("x\n", encoding="utf-8")

            entry_diagnostics: dict[str, object] = {}
            _, entry_truncated = _expand_log_paths_bounded(
                root,
                ["dump_info/LogDump/*.log"],
                max_entries=1,
                diagnostics=entry_diagnostics,
            )
            path_diagnostics: dict[str, object] = {}
            _, path_truncated = _expand_log_paths_bounded(
                root,
                ["dump_info/LogDump/*.log"],
                max_paths=1,
                diagnostics=path_diagnostics,
            )

        self.assertTrue(entry_truncated)
        self.assertEqual(entry_diagnostics["limit_reasons"], ["entry_limit"])
        self.assertEqual(entry_diagnostics["entry_limit"], 1)
        self.assertTrue(path_truncated)
        self.assertEqual(path_diagnostics["limit_reasons"], ["path_limit"])
        self.assertEqual(path_diagnostics["path_limit"], 1)

    def test_missing_exact_path_cannot_escape_bundle_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir) / "bundle"
            root.mkdir()
            with self.assertRaises(BundleAnalysisError) as raised:
                _expand_log_paths_bounded(root, ["../missing/outside.log"])
            self.assertEqual(raised.exception.code, "bundle_layout_invalid")

            paths, truncated = _expand_log_paths_bounded(
                root,
                ["dump_info/LogDump/missing.log"],
            )
        self.assertEqual(paths, [])
        self.assertFalse(truncated)


class CatalogAndTerminalHardeningTests(unittest.TestCase):
    @staticmethod
    def valid_catalog() -> dict[str, object]:
        return {
            "files": [
                {
                    "name": "app.log",
                    "paths": ["dump_info/LogDump/app.log"],
                    "component": "app",
                    "purpose": "test fixture",
                    "keywords": ["app"],
                }
            ],
            "rules": [],
        }

    def test_catalog_rejects_unsafe_paths_undefined_rules_and_unknown_parsers(self) -> None:
        invalid_catalogs = [
            {
                "files": [{"name": "app.log", "paths": ["../outside.log"]}],
                "rules": [],
            },
            {
                "files": [{"name": "app.log", "paths": ["dump_info/LogDump/app.log"]}],
                "rules": [{"match_keywords": ["app"], "include": ["missing.log"], "primary": []}],
            },
            {
                "files": [
                    {
                        "name": "app.log",
                        "paths": ["dump_info/LogDump/app.log"],
                        "structured_parser": "arbitrary_parser",
                    }
                ],
                "rules": [],
            },
        ]

        for reference in invalid_catalogs:
            with self.subTest(reference=reference):
                with self.assertRaises(BundleAnalysisError) as raised:
                    validate_reference_data(reference)
                self.assertEqual(raised.exception.code, "reference_invalid")

    def test_catalog_rejects_non_package_paths_and_recursive_globs(self) -> None:
        unsafe_paths = [
            "\\tmp\\x",
            "a\\b",
            "a\x00b",
            "/",
            "////",
            "C:/x",
            "C:\\x",
            ".",
            "./",
            "a/./b",
            "a/../b",
            "dump_info/**/app.log",
        ]
        for path in unsafe_paths:
            with self.subTest(path=path):
                reference = self.valid_catalog()
                reference["files"][0]["paths"] = [path]  # type: ignore[index]
                with self.assertRaises(BundleAnalysisError) as raised:
                    validate_reference_data(reference)
                self.assertEqual(raised.exception.code, "reference_invalid")

    def test_catalog_rejects_malformed_keyword_and_rule_arrays(self) -> None:
        invalid_catalogs = []
        for keywords in (None, "app", [], [" "], ["app", 1], ["app", "APP"]):
            reference = self.valid_catalog()
            reference["files"][0]["keywords"] = keywords  # type: ignore[index]
            invalid_catalogs.append(reference)
        for evidence_keywords in (None, "alarm", [" "], ["alarm", 1], ["alarm", "ALARM"]):
            reference = self.valid_catalog()
            reference["files"][0]["evidence_keywords"] = evidence_keywords  # type: ignore[index]
            invalid_catalogs.append(reference)
        for match_keywords, includes, primary in (
            (None, ["app.log"], []),
            ([], ["app.log"], []),
            ("app", ["app.log"], []),
            (["app"], [], []),
            (["app"], [{}], []),
            (["app"], ["app.log", "app.log"], []),
            (["app"], ["app.log"], ["missing.log"]),
        ):
            reference = self.valid_catalog()
            reference["rules"] = [
                {
                    "match_keywords": match_keywords,
                    "include": includes,
                    "primary": primary,
                }
            ]
            invalid_catalogs.append(reference)

        duplicate = self.valid_catalog()
        duplicate["files"] = [*duplicate["files"], dict(duplicate["files"][0])]  # type: ignore[index]
        invalid_catalogs.append(duplicate)

        for reference in invalid_catalogs:
            with self.subTest(reference=reference):
                with self.assertRaises(BundleAnalysisError) as raised:
                    validate_reference_data(reference)
                self.assertEqual(raised.exception.code, "reference_invalid")

    def test_catalog_rejects_non_string_metadata_and_non_public_revisions(self) -> None:
        for field, value in (
            ("purpose", False),
            ("purpose", []),
            ("component", 0),
            ("component", {"name": "app"}),
            ("structured_parser", False),
            ("structured_parser", 0),
            ("structured_parser", []),
            ("scan_mode", False),
            ("scan_mode", 0),
            ("scan_mode", []),
            ("scan_mode", "binary"),
            ("coverage_class", False),
            ("coverage_class", "unknown"),
            ("semantic_level", False),
            ("semantic_level", "unknown"),
            ("artifact_format", False),
            ("artifact_format", "unknown-format"),
            ("route_mode", False),
            ("route_mode", "broad"),
            ("sensitivity", False),
            ("sensitivity", "secret"),
            ("include_rotations", 1),
            ("include_rotations", "false"),
        ):
            with self.subTest(field=field, value=value):
                reference = self.valid_catalog()
                reference["files"][0][field] = value  # type: ignore[index]
                with self.assertRaises(BundleAnalysisError) as raised:
                    validate_reference_data(reference)
                self.assertEqual(raised.exception.code, "reference_invalid")

        reference = self.valid_catalog()
        reference["files"][0]["source_revision"] = "private-revision"  # type: ignore[index]
        with self.assertRaises(BundleAnalysisError) as raised:
            validate_reference_data(reference)
        self.assertEqual(raised.exception.code, "reference_invalid")

        reference = self.valid_catalog()
        reference["files"][0]["coverage_class"] = "explicit_opaque"  # type: ignore[index]
        with self.assertRaises(BundleAnalysisError) as raised:
            validate_reference_data(reference)
        self.assertEqual(raised.exception.code, "reference_invalid")

        reference = self.valid_catalog()
        reference["files"][0].update(  # type: ignore[index]
            {
                "scan_mode": "metadata_only",
                "coverage_class": "semantic",
                "semantic_level": "purpose",
            }
        )
        validate_reference_data(reference)

        reference = self.valid_catalog()
        reference["files"][0].update(  # type: ignore[index]
            {
                "scan_mode": "metadata_only",
                "structured_parser": "delimited_records",
            }
        )
        with self.assertRaises(BundleAnalysisError) as raised:
            validate_reference_data(reference)
        self.assertEqual(raised.exception.code, "reference_invalid")

    def test_catalog_applies_neutral_defaults_and_requires_specific_public_sources(self) -> None:
        normalized = normalize_reference_data(self.valid_catalog())
        item = normalized["files"][0]
        self.assertEqual(item["definition_status"], "maintained_heuristic")
        self.assertEqual(item["source_type"], "repository_maintained")
        self.assertEqual(item["source_reference"], "repository-maintained heuristic")
        self.assertEqual(item["reliability"], "heuristic")
        self.assertEqual(item["coverage_class"], "semantic")
        self.assertEqual(item["semantic_level"], "purpose")
        self.assertEqual(item["artifact_format"], "text")
        self.assertEqual(item["route_mode"], "automatic")
        self.assertEqual(item["sensitivity"], "ordinary")

        opaque = self.valid_catalog()
        opaque["files"][0]["scan_mode"] = "metadata_only"  # type: ignore[index]
        self.assertEqual(
            normalize_reference_data(opaque)["files"][0]["coverage_class"],
            "explicit_opaque",
        )
        opaque_item = normalize_reference_data(opaque)["files"][0]
        self.assertEqual(opaque_item["semantic_level"], "purpose")
        self.assertEqual(opaque_item["route_mode"], "explicit_only")

        legacy = self.valid_catalog()
        legacy["files"][0]["source"] = "component documentation: private export"  # type: ignore[index]
        legacy_item = normalize_reference_data(legacy)["files"][0]
        self.assertEqual(legacy_item["source_type"], "repository_maintained")
        self.assertEqual(legacy_item["definition_status"], "maintained_heuristic")

        public = self.valid_catalog()
        public_item = public["files"][0]  # type: ignore[index]
        public_item.update(
            {
                "source_type": "public_repository",
                "source_reference": "https://example.com/project/blob/revision/app.log",
                "source_revision": "revision",
            }
        )
        self.assertEqual(
            normalize_reference_data(public)["files"][0]["definition_status"],
            "documented",
        )
        del public_item["source_revision"]
        with self.assertRaises(BundleAnalysisError):
            normalize_reference_data(public)

    def test_catalog_enforces_semantic_format_route_and_sensitivity_invariants(self) -> None:
        invalid_updates = (
            {"semantic_level": "path_only", "route_mode": "automatic"},
            {"artifact_format": "binary", "scan_mode": "text"},
            {"sensitivity": "configuration_sensitive", "scan_mode": "text"},
            {"semantic_level": "diagnostic"},
        )
        for updates in invalid_updates:
            with self.subTest(updates=updates):
                reference = self.valid_catalog()
                reference["files"][0].update(updates)  # type: ignore[index]
                with self.assertRaises(BundleAnalysisError) as raised:
                    validate_reference_data(reference)
                self.assertEqual(raised.exception.code, "reference_invalid")

        explicit_only = self.valid_catalog()
        explicit_only["files"][0].update(  # type: ignore[index]
            {"route_mode": "explicit_only", "scan_mode": "metadata_only"}
        )
        explicit_only["rules"] = [
            {"match_keywords": ["application failure"], "include": ["app.log"], "primary": ["app.log"]}
        ]
        self.assertEqual(select_logs_for_problem("application failure", explicit_only, max_files=4), [])
        selected = select_logs_for_problem("inspect app.log", explicit_only, max_files=4)
        self.assertEqual([item["name"] for item in selected], ["app.log"])
        self.assertEqual(selected[0]["semantic_level"], "purpose")
        self.assertEqual(selected[0]["route_mode"], "explicit_only")

        never = self.valid_catalog()
        never["files"][0]["route_mode"] = "never"  # type: ignore[index]
        self.assertEqual(select_logs_for_problem("inspect app.log", never, max_files=4), [])

    def test_repository_catalog_defines_observed_artifact_fallbacks_without_broad_routing(self) -> None:
        reference = load_reference_data()
        observed = {
            str(item["name"]): item
            for item in reference["files"]
            if isinstance(item, dict)
            and str(item.get("name", "")).startswith(("observed_", "opaque_"))
        }

        self.assertTrue(
            {
                "observed_logdump_artifact",
                "observed_appdump_artifact",
                "observed_rtosdump_artifact",
                "observed_osdump_artifact",
                "observed_splogdump_artifact",
                "observed_bma_artifact",
                "observed_device_artifact",
                "observed_thirdparty_artifact",
                "opaque_core_dump_artifact",
                "opaque_optbmc_artifact",
                "observed_dump_root_artifact",
            }.issubset(observed),
        )
        self.assertTrue(
            all(item["definition_status"] == "observed_path" for item in observed.values())
        )
        self.assertTrue(
            all(item["reliability"] == "observed_only" for item in observed.values())
        )
        for name in ("opaque_core_dump_artifact", "opaque_optbmc_artifact"):
            self.assertEqual(observed[name]["scan_mode"], "metadata_only")
            self.assertEqual(observed[name]["coverage_class"], "explicit_opaque")

        for problem in ("BMC login failed", "fan overtemperature", "object sync failed"):
            with self.subTest(problem=problem):
                selected = select_logs_for_problem(problem, reference, max_files=64)
                self.assertFalse(
                    any(
                        str(item["name"]).startswith(("observed_", "opaque_"))
                        for item in selected
                    )
                )

        explicit = select_logs_for_problem("inspect skynet_info.json", reference, max_files=1)
        self.assertEqual(explicit[0]["name"], "skynet_info.json")
        self.assertEqual(explicit[0]["scan_mode"], "metadata_only")

    def test_observed_artifact_fallbacks_cover_representative_bundle_files(self) -> None:
        representative_paths = (
            "dump_info/dump_log",
            "dump_info/dump_app_log",
            "dump_info/LogDump/storage/ctrllog/controller/dump.bin",
            "dump_info/AppDump/example/skynet_info.json",
            "dump_info/AppDump/hwdiscovery/Connector_Slot_01.sr",
            "dump_info/RTOSDump/other_info/ntp.conf",
            "dump_info/OSDump/console.jpeg",
            "dump_info/SpLogDump/version.json",
            "dump_info/BMALogDump/agent/trace.log",
            "dump_info/DeviceDump/controller/registers.bin",
            "dump_info/3rdDump/nginx_ssl_certificate.conf",
            "dump_info/CoreDump/core-files.tar.gz",
            "dump_info/OptBMC/save/factory_backup.tar.gz",
        )
        reference = load_reference_data()

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            for relative_path in representative_paths:
                path = root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fixture")

            covered: set[str] = set()
            discovery_budget = PathDiscoveryBudget(max_entries=10_000)
            directory_index = _PathDirectoryIndex(root, discovery_budget)
            for item in reference["files"]:
                paths, _ = _expand_log_paths_bounded(
                    root,
                    list(item["paths"]),
                    max_entries=10_000,
                    discovery_budget=discovery_budget,
                    directory_index=directory_index,
                )
                covered.update(path.relative_to(root).as_posix() for path in paths)

        self.assertEqual(set(representative_paths), covered)

    def test_metadata_only_artifact_definition_does_not_scan_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            artifact_path = root / "dump_info" / "CoreDump" / "core.tar.gz"
            artifact_path.parent.mkdir(parents=True)
            artifact_path.write_bytes(b"not-for-text-scanning")
            reference = {
                "files": [
                    {
                        "name": "opaque_core",
                        "paths": ["dump_info/CoreDump/*"],
                        "component": "CoreDump",
                        "purpose": "opaque crash artifact",
                        "keywords": ["core dump"],
                        "definition_status": "observed_path",
                        "source_type": "validated_bundle_structure",
                        "reliability": "observed_only",
                        "scan_mode": "metadata_only",
                        "semantic_level": "purpose",
                        "route_mode": "automatic",
                    }
                ],
                "rules": [
                    {
                        "match_keywords": ["core dump"],
                        "include": ["opaque_core"],
                        "primary": ["opaque_core"],
                    }
                ],
            }
            result = analyze_bundle(root, "core dump", reference_data=reference, max_files=1)

        selected = result["selected_logs"][0]
        self.assertEqual(selected["existing_path_count"], 1)
        self.assertEqual(selected["scanned_paths"], [])
        self.assertEqual(selected["scanned_path_count"], 0)
        self.assertEqual(selected["scan_mode"], "metadata_only")
        self.assertFalse(selected["scan_truncated"])
        self.assertEqual(result["scan"]["scanned_bytes"], 0)

    def test_public_sources_reject_private_hosts_and_credential_like_provenance(self) -> None:
        cases = (
            ("https://10.0.0.8/project/blob/revision/app.log", "revision"),
            ("https://localhost/project/blob/revision/app.log", "revision"),
            ("https://example.com/project/app.log?token=publictag", "revision"),
            ("https://example.com/project/app.log?sig=publictag", "revision"),
            ("https://example.com/project/app.log#sig=publictag", "revision"),
            ("https://example.com:99999/project/app.log", "revision"),
            ("https://example.com:bad/project/app.log", "revision"),
            ("HTTPS://example.com/project/app.log", "revision"),
            ("https://example.com:0443/project/app.log", "revision"),
            ("https://例子.测试/project/app.log", "revision"),
            ("https://foo_bar.example.com/project/app.log", "revision"),
            ("https://example.com/project/app.log", "token=publictag"),
        )
        for source_reference, source_revision in cases:
            with self.subTest(source_reference=source_reference, source_revision=source_revision):
                reference = self.valid_catalog()
                reference["files"][0].update(  # type: ignore[index]
                    {
                        "source_type": "public_repository",
                        "source_reference": source_reference,
                        "source_revision": source_revision,
                    }
                )
                with self.assertRaises(BundleAnalysisError) as raised:
                    normalize_reference_data(reference)
                self.assertEqual(raised.exception.code, "reference_invalid")

    def test_public_source_revision_that_resembles_an_identifier_is_preserved_in_output(self) -> None:
        payload = {
            "source_reference": "https://example.com/project/blob/revision/app.log",
            "source_revision": "192.0.2.7",
        }
        output = io.StringIO()
        with redirect_stdout(output):
            emit_result(
                {
                    "schema_version": "1.0",
                    "tool": "openubmc_log_bundle_analyzer",
                    "output_policy": {
                        "profile": "shareable",
                        "credential_redaction": True,
                        "common_identifier_redaction": True,
                        "location_redaction": True,
                    },
                    "ok": False,
                    "code": "test_error",
                    "error": "test error",
                    "request": {},
                    "result": payload,
                },
                json_mode=True,
            )
        rendered = output.getvalue()
        self.assertIn("192.0.2.7", rendered)

    def test_public_source_revision_reaches_all_derived_evidence_pointers(self) -> None:
        reference = {
            "files": [
                {
                    "name": "operation.log",
                    "paths": ["dump_info/LogDump/operation.log"],
                    "component": "operation",
                    "purpose": "operation audit",
                    "keywords": ["incident"],
                    "source_type": "public_repository",
                    "source_reference": "https://example.org/docs/operation.md",
                    "source_revision": "rev-42",
                },
                {
                    "name": "mdb_info.log",
                    "paths": ["dump_info/AppDump/app/mdb_info.log"],
                    "component": "app",
                    "purpose": "object inventory",
                    "keywords": ["incident"],
                    "structured_parser": "mdb_properties",
                    "source_type": "public_repository",
                    "source_reference": "https://example.org/docs/mdb.md",
                    "source_revision": "rev-42",
                },
                {
                    "name": "app.log",
                    "paths": ["dump_info/LogDump/app.log"],
                    "component": "app",
                    "purpose": "application errors",
                    "keywords": ["incident"],
                    "source_type": "public_repository",
                    "source_reference": "https://example.org/docs/app.md",
                    "source_revision": "rev-42",
                },
            ],
            "rules": [
                {
                    "match_keywords": ["incident"],
                    "include": ["operation.log", "app.log", "mdb_info.log"],
                    "primary": ["operation.log"],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            (log_dir / "operation.log").write_text(
                "2026-08-31T08:00:00 operation incident failed\n",
                encoding="utf-8",
            )
            (log_dir / "app.log").write_text(
                "2026-08-31T08:00:02 app incident failed\n",
                encoding="utf-8",
            )
            mdb_path = root / "dump_info" / "AppDump" / "app" / "mdb_info.log"
            mdb_path.parent.mkdir(parents=True)
            mdb_path.write_text(
                "/bmc/app/example bmc.example.Properties\n.State\n  value: failed\n",
                encoding="utf-8",
            )
            result = analyze_bundle(root, "incident", reference_data=reference, max_files=3, max_lines=2)

        self.assertTrue(result["evidence"])
        for item in [
            *result["selected_logs"],
            *result["evidence"],
            *result["timeline"],
            *result["evidence_findings"],
        ]:
            if isinstance(item, dict):
                if "source_type" in item:
                    self.assertEqual(item.get("source_revision"), "rev-42")
                if "representative" in item:
                    self.assertEqual(item["representative"].get("source_revision"), "rev-42")
                if "evidence" in item and isinstance(item["evidence"], list):
                    for pointer in item["evidence"]:
                        self.assertEqual(pointer.get("source_revision"), "rev-42")
        for window in result["correlation_windows"]:
            for pointer in window["evidence"]:
                self.assertEqual(pointer.get("source_revision"), "rev-42")
        for selected in result["selected_logs"]:
            for line in [*selected["evidence_lines"], *selected["context_lines"]]:
                self.assertEqual(line.get("source_revision"), "rev-42")
        self.assertTrue(result["structured_summaries"])
        self.assertEqual(result["structured_summaries"][0].get("source_revision"), "rev-42")
        self.assertTrue(result["event_correlations"])
        for correlation in result["event_correlations"]:
            self.assertEqual(correlation["anchor"].get("source_revision"), "rev-42")
            for pointer in correlation["candidates"]:
                self.assertEqual(pointer.get("source_revision"), "rev-42")

    def test_catalog_and_analysis_fail_closed_on_missing_or_malformed_root_contract(self) -> None:
        invalid_catalogs = [
            {},
            {"files": [], "rules": None},
            {"files": "broken", "rules": []},
        ]
        for reference in invalid_catalogs:
            with self.subTest(reference=reference):
                with self.assertRaises(BundleAnalysisError) as raised:
                    validate_reference_data(reference)
                self.assertEqual(raised.exception.code, "reference_invalid")

        with tempfile.TemporaryDirectory() as tmp_dir:
            with self.assertRaises(BundleAnalysisError) as raised:
                analyze_bundle(pathlib.Path(tmp_dir), "app", reference_data={})
        self.assertEqual(raised.exception.code, "reference_invalid")

    def test_path_and_component_discovery_use_fixed_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            for name in ("app.log", "app.log.1", "app.log.2", "app.log.3", "app.log.4"):
                (log_dir / name).write_text("app failed\n", encoding="utf-8")

            rotations, rotations_truncated = _iter_rotated_file_candidates_bounded(
                log_dir / "app.log",
                max_candidates=3,
            )
            self.assertTrue(rotations_truncated)
            self.assertEqual([path.name for path in rotations], ["app.log", "app.log.1", "app.log.2"])

            for index in range(5):
                component = root / "dump_info" / "AppDump" / f"target_{index}"
                component.mkdir(parents=True)
                (component / "app.log").write_text("target failed\n", encoding="utf-8")
            paths, paths_truncated = _expand_log_paths_bounded(
                root,
                ["dump_info/AppDump/*/app.log"],
                max_paths=3,
            )
            self.assertTrue(paths_truncated)
            self.assertEqual(len(paths), 3)

            reference = load_reference_data()
            hinted = add_bundle_component_hints(
                root,
                reference,
                problem=" ".join(f"target_{index}" for index in range(5)),
                max_hints=2,
            )
            discovery = hinted["bundle_component_hint_discovery"]
            self.assertFalse(discovery["complete"])
            self.assertEqual(discovery["matched_directory_count"], 5)
            self.assertEqual(discovery["retained_directory_count"], 2)

    def test_terminal_output_escapes_untrusted_control_characters(self) -> None:
        malicious = "line\x1b[2J\r\nSTATUS=forged\t\x07"
        rendered = safe_terminal_text(malicious)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\r", rendered)
        self.assertNotIn("\n", rendered)
        self.assertIn("\\x1b[2J\\r\\nSTATUS=forged\\t\\x07", rendered)

        payload = {
            "ok": True,
            "error": "",
            "result": {
                "source_kind": "extracted_directory",
                "bundle": {},
                "validation": {},
                "analysis": {
                    "summary": malicious,
                    "assessment": "insufficient_bundle_evidence",
                    "scan": {},
                    "selected_logs": [],
                    "evidence": [],
                    "timeline": [],
                    "evidence_findings": [],
                    "structured_summaries": [],
                    "event_correlations": [],
                },
            },
        }
        output = io.StringIO()
        with redirect_stdout(output):
            emit_result(payload, json_mode=False)
        lines = output.getvalue().splitlines()
        self.assertEqual(sum(line.startswith("STATUS=") for line in lines), 1)
        self.assertTrue(any("STATUS=forged" in line for line in lines))


if __name__ == "__main__":
    unittest.main()
