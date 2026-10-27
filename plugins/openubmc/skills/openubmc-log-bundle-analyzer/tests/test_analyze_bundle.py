from __future__ import annotations

import io
import gzip
import json
import pathlib
import re
import runpy
import sys
import tarfile
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock


SCRIPT_DIR = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import analyze_bundle as analyzer_cli  # type: ignore  # noqa: E402
import log_bundle_analysis  # type: ignore  # noqa: E402
import log_bundle_artifact  # type: ignore  # noqa: E402
import log_bundle_common  # type: ignore  # noqa: E402


class MainJsonValidationTests(unittest.TestCase):
    def test_json_mode_reports_missing_source_as_json_payload(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = analyzer_cli.main(["--json"])
        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "missing_source")


class AnalysisTests(unittest.TestCase):
    def test_generic_chinese_runtime_check_uses_bounded_core_logs(self) -> None:
        reference = log_bundle_analysis.load_reference_data()

        selected = log_bundle_analysis.select_logs_for_problem(
            "BMC运行状态与近期错误检查",
            reference,
            max_files=8,
        )

        self.assertEqual(
            [item["name"] for item in selected[:3]],
            ["app.log", "framework.log", "journalctl.log"],
        )

    def test_combined_overview_routes_primary_event_artifacts_before_runtime_context(self) -> None:
        reference = log_bundle_analysis.load_reference_data()

        selected = log_bundle_analysis.select_logs_for_problem(
            "整体检查近期错误和主要故障，给出关键证据和时间线",
            reference,
            max_files=8,
        )

        self.assertEqual(
            [item["name"] for item in selected],
            [
                "current_event.txt",
                "sel.txt",
                "app.log",
                "framework.log",
                "journalctl.log",
                "maintenance.log",
                "running.log",
                "alarm.log",
            ],
        )
        self.assertEqual(
            [item["score"] for item in selected],
            sorted((item["score"] for item in selected), reverse=True),
        )

    def test_select_logs_for_problem_prefers_rule_matches(self) -> None:
        reference = {
            "files": [
                {"name": "security.log", "paths": ["dump_info/LogDump/security.log"], "component": "security", "purpose": "auth", "keywords": ["auth", "login"]},
                {"name": "operation.log", "paths": ["dump_info/LogDump/operation.log"], "component": "operation", "purpose": "audit", "keywords": ["operation"]},
                {"name": "app.log", "paths": ["dump_info/LogDump/app.log"], "component": "application", "purpose": "generic", "keywords": ["error"]},
            ],
            "rules": [
                {"match_keywords": ["login", "auth", "登录失败"], "include": ["security.log", "operation.log"]},
            ],
        }
        selected = log_bundle_analysis.select_logs_for_problem("BMC login auth failure", reference, max_files=5)
        self.assertEqual([item["name"] for item in selected[:2]], ["security.log", "operation.log"])

    def test_component_directory_hints_select_standard_appdump_evidence_not_directory_placeholders(self) -> None:
        reference = log_bundle_analysis.load_reference_data()

        selected = log_bundle_analysis.select_logs_for_problem(
            "storage RAID 控制器对象状态异常",
            reference,
            max_files=20,
        )

        names = [item["name"] for item in selected]
        self.assertIn("mdb_info.log", names)
        self.assertIn("sync_property_trace.log", names)
        self.assertIn("rpc_records.log", names)
        self.assertNotIn("appdump_storage", names)
        mdb = next(item for item in selected if item["name"] == "mdb_info.log")
        self.assertEqual(mdb["paths"], ["dump_info/AppDump/storage/mdb_info.log"])

    def test_bundle_local_component_directory_routes_standard_evidence_without_static_semantics(self) -> None:
        reference = {
            "files": [
                {
                    "name": name,
                    "paths": [f"dump_info/AppDump/*/{name}"],
                    "component": "per-component",
                    "purpose": name,
                    "keywords": [name],
                }
                for name in log_bundle_analysis.APPDUMP_COMPONENT_EVIDENCE_LOGS
            ],
            "rules": [],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            appdump_component = root / "dump_info" / "AppDump" / "firmware_mgmt"
            appdump_component.mkdir(parents=True)
            for name in log_bundle_analysis.APPDUMP_COMPONENT_EVIDENCE_LOGS:
                (appdump_component / name).write_text("firmware mgmt state failed\n", encoding="utf-8")

            analysis = log_bundle_analysis.analyze_bundle(
                root,
                "firmware mgmt upgrade state",
                reference_data=reference,
                max_files=3,
                max_lines=1,
            )

        self.assertEqual(
            {item["name"] for item in analysis["selected_logs"]},
            set(log_bundle_analysis.APPDUMP_COMPONENT_EVIDENCE_LOGS),
        )
        for item in analysis["selected_logs"]:
            self.assertEqual(
                item["existing_paths"],
                [f"dump_info/AppDump/firmware_mgmt/{item['name']}"],
            )
            self.assertIn("bundle_local_component", item["routing_basis"])
            self.assertEqual(item["routing_reliability"], "local_only")

    def test_combined_rule_and_observed_component_problem_keeps_component_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            component_dir = root / "dump_info" / "AppDump" / "firmware_mgmt"
            log_dir.mkdir(parents=True)
            component_dir.mkdir(parents=True)
            (log_dir / "operation.log").write_text(
                "2026-08-31T08:00:00 firmware_mgmt operation failed\n",
                encoding="utf-8",
            )
            (log_dir / "app.log").write_text("firmware_mgmt failed\n", encoding="utf-8")
            (log_dir / "framework.log").write_text("firmware_mgmt failed\n", encoding="utf-8")
            for name in log_bundle_analysis.APPDUMP_COMPONENT_EVIDENCE_LOGS:
                (component_dir / name).write_text(
                    "2026-08-31T08:00:01 firmware_mgmt state failed\n",
                    encoding="utf-8",
                )

            analysis = log_bundle_analysis.analyze_bundle(
                root,
                "firmware_mgmt operation failed",
                max_files=8,
                max_lines=1,
            )

        selected = {item["name"]: item for item in analysis["selected_logs"]}
        for name in log_bundle_analysis.APPDUMP_COMPONENT_EVIDENCE_LOGS:
            self.assertIn(name, selected)
            self.assertEqual(
                selected[name]["existing_paths"],
                [f"dump_info/AppDump/firmware_mgmt/{name}"],
            )
            self.assertIn("bundle_local_component", selected[name]["routing_basis"])

    def test_candidate_files_preserve_maintained_or_community_provenance(self) -> None:
        reference = log_bundle_analysis.load_reference_data()

        masked = log_bundle_analysis.select_logs_for_problem("告警不显示，检查是否为屏蔽事件", reference, max_files=8)
        thermal = log_bundle_analysis.select_logs_for_problem("风扇型号与转速异常", reference, max_files=8)
        network = log_bundle_analysis.select_logs_for_problem("网卡链路状态异常", reference, max_files=8)

        self.assertIn("mask_event.txt", [item["name"] for item in masked])
        self.assertIn("current_event.txt", [item["name"] for item in masked])
        self.assertIn("sel.txt", [item["name"] for item in masked])
        self.assertIn("fan_info.txt", [item["name"] for item in thermal])
        self.assertIn("thermal_info.txt", [item["name"] for item in thermal])
        self.assertEqual(network[0]["name"], "network_adapter_net_card_info")
        selected = {
            item["name"]: item
            for item in [*masked, *thermal, *network]
            if item["name"]
            in {
                "current_event.txt",
                "sel.txt",
                "mask_event.txt",
                "fan_info.txt",
                "thermal_info.txt",
                "network_adapter_net_card_info",
            }
        }
        for name in {"current_event.txt", "mask_event.txt", "fan_info.txt", "thermal_info.txt"}:
            item = selected[name]
            self.assertEqual(item["definition_status"], "maintained_heuristic")
            self.assertEqual(item["source_type"], "repository_maintained")
            self.assertEqual(item["source_reference"], "repository-maintained heuristic")
            self.assertEqual(item["reliability"], "heuristic")
        for name, source_reference, source_revision in (
            (
                "sel.txt",
                "https://discuss.openubmc.cn/t/topic/290",
                "topic-290-post-1",
            ),
            (
                "network_adapter_net_card_info",
                "https://discuss.openubmc.cn/t/topic/2597/6",
                "topic-2597-post-6",
            ),
        ):
            item = selected[name]
            self.assertEqual(item["definition_status"], "community_supported")
            self.assertEqual(item["source_type"], "community_discussion")
            self.assertEqual(item["source_reference"], source_reference)
            self.assertEqual(item["source_revision"], source_revision)
            self.assertEqual(item["reliability"], "heuristic")

    def test_explicit_current_alarm_request_prioritizes_active_event_snapshot(self) -> None:
        reference = log_bundle_analysis.load_reference_data()

        selected = log_bundle_analysis.select_logs_for_problem(
            "当前告警、历史告警和系统事件",
            reference,
            max_files=8,
        )

        self.assertEqual(selected[0]["name"], "current_event.txt")
        self.assertEqual(
            {item["name"] for item in selected},
            {"current_event.txt", "sel.txt", "eo_sel.csv", "sensor.log", "alarm.log"},
        )

    def test_web_problem_selects_only_declared_nginx_text_logs_from_sensitive_sections(self) -> None:
        reference = log_bundle_analysis.load_reference_data()
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            third_party = root / "dump_info" / "3rdDump"
            core_dump = root / "dump_info" / "CoreDump"
            backup_dir = root / "dump_info" / "OptBMC" / "save"
            third_party.mkdir(parents=True)
            core_dump.mkdir(parents=True)
            backup_dir.mkdir(parents=True)
            (third_party / "access_log").write_text(
                "2026-08-31T08:00:00 GET /redfish/v1/ 502 upstream failed\n",
                encoding="utf-8",
            )
            (third_party / "access_log.1").write_text(
                "2026-08-31T07:59:00 GET / 503 upstream failed\n",
                encoding="utf-8",
            )
            (third_party / "error_log").write_text(
                "2026-08-31T08:00:00 nginx upstream connection failed\n",
                encoding="utf-8",
            )
            (third_party / "nginx.conf").write_text("password=do-not-scan\n", encoding="utf-8")
            (core_dump / "core-files.tar.gz").write_bytes(b"opaque-core")
            (backup_dir / "factory_backup.tar.gz").write_bytes(b"opaque-backup")

            analysis = log_bundle_analysis.analyze_bundle(
                root,
                "Web/HTTPS 访问失败",
                reference_data=reference,
                max_files=5,
                max_lines=3,
            )

        selected_names = [item["name"] for item in analysis["selected_logs"]]
        self.assertEqual(selected_names[:2], ["nginx_access_log", "nginx_error_log"])
        selected_paths = {
            path
            for item in analysis["selected_logs"]
            for path in item["existing_paths"]
        }
        self.assertIn("dump_info/3rdDump/access_log", selected_paths)
        self.assertIn("dump_info/3rdDump/access_log.1", selected_paths)
        self.assertIn("dump_info/3rdDump/error_log", selected_paths)
        self.assertFalse(any("nginx.conf" in path for path in selected_paths))
        self.assertFalse(any("core-files" in path or "factory_backup" in path for path in selected_paths))

    def test_select_logs_for_problem_ignores_generic_file_keywords(self) -> None:
        reference = {
            "files": [
                {"name": "security.log", "paths": ["dump_info/LogDump/security.log"], "component": "security", "purpose": "auth", "keywords": ["login"]},
                {"name": "journalctl.log", "paths": ["dump_info/RTOSDump/sysinfo/journalctl.log"], "component": "systemd", "purpose": "systemd", "keywords": ["systemd", "失败"]},
            ],
            "rules": [
                {"match_keywords": ["登录失败"], "include": ["security.log"]},
            ],
        }
        selected = log_bundle_analysis.select_logs_for_problem("BMC 登录失败", reference, max_files=5)
        self.assertEqual([item["name"] for item in selected], ["security.log"])

    def test_analyze_bundle_collects_matching_evidence(self) -> None:
        reference = {
            "files": [
                {
                    "name": "security.log",
                    "paths": ["dump_info/LogDump/security.log"],
                    "component": "security",
                    "purpose": "auth events",
                    "keywords": ["auth", "login", "failure"],
                }
            ],
            "rules": [
                {"match_keywords": ["login", "auth"], "include": ["security.log"]},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_file = root / "dump_info" / "LogDump" / "security.log"
            log_file.parent.mkdir(parents=True)
            log_file.write_text("2026-04-07 auth failed for Administrator\n", encoding="utf-8")
            analysis = log_bundle_analysis.analyze_bundle(root, "login auth failed", reference_data=reference, max_files=5, max_lines=3)
        self.assertEqual(analysis["selected_logs"][0]["name"], "security.log")
        self.assertIn("auth failed", analysis["selected_logs"][0]["evidence_lines"][0]["line"])

    def test_collect_evidence_lines_uses_generic_failure_terms_alongside_problem_keywords(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = pathlib.Path(tmp_dir) / "security.log"
            path.write_text("2026-04-07 auth failed for Administrator\n", encoding="utf-8")
            evidence = log_bundle_analysis.collect_evidence_lines(path, match_terms=["登录失败"], max_lines=3)
        self.assertIn("auth failed", evidence[0]["line"])

    def test_collect_evidence_lines_prefers_problem_keyword_matches_over_generic_failed_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = pathlib.Path(tmp_dir) / "operation.log"
            path.write_text(
                "\n".join(
                    [
                        "2026-04-07 firmware upgrade failed",
                        "2026-04-07 User Administrator login failed",
                        "2026-04-07 another generic failure",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            evidence = log_bundle_analysis.collect_evidence_lines(path, match_terms=["login"], max_lines=3)
        self.assertEqual(evidence[0]["line"], "2026-04-07 User Administrator login failed")

    def test_analyze_bundle_uses_file_keywords_for_rule_matched_logs(self) -> None:
        reference = {
            "files": [
                {
                    "name": "operation.log",
                    "paths": ["dump_info/LogDump/operation.log"],
                    "component": "operation",
                    "purpose": "user operations audit",
                    "keywords": ["login"],
                }
            ],
            "rules": [
                {"match_keywords": ["登录失败"], "include": ["operation.log"]},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_file = root / "dump_info" / "LogDump" / "operation.log"
            log_file.parent.mkdir(parents=True)
            log_file.write_text(
                "2026-04-07 firmware upgrade failed\n"
                "2026-04-07 User Administrator login failed\n",
                encoding="utf-8",
            )
            analysis = log_bundle_analysis.analyze_bundle(root, "BMC 登录失败", reference_data=reference, max_files=5, max_lines=3)
        evidence_lines = analysis["selected_logs"][0]["evidence_lines"]
        self.assertEqual(evidence_lines[0]["line"], "2026-04-07 User Administrator login failed")

    def test_analyze_bundle_prefers_exact_login_failed_phrase_over_newer_authentication_failures(self) -> None:
        reference = {
            "files": [
                {
                    "name": "security.log",
                    "paths": ["dump_info/LogDump/security.log"],
                    "component": "security",
                    "purpose": "auth and security events",
                    "keywords": ["login", "auth", "失败"],
                }
            ],
            "rules": [
                {"match_keywords": ["登录失败"], "include": ["security.log"]},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_file = root / "dump_info" / "LogDump" / "security.log"
            log_file.parent.mkdir(parents=True)
            log_file.write_text(
                "2026-03-31T08:25:00+00:00 sshd[2662]: Received disconnect from 10.0.0.1:11: Too many authentication failures\n"
                "2026-03-31T08:24:52+00:00 security: User Administrator(123) login failed\n",
                encoding="utf-8",
            )

            analysis = log_bundle_analysis.analyze_bundle(
                root,
                "BMC 登录失败",
                reference_data=reference,
                max_files=1,
                max_lines=2,
            )

        evidence_lines = analysis["selected_logs"][0]["evidence_lines"]
        self.assertEqual(
            evidence_lines[0]["line"],
            "2026-03-31T08:24:52+00:00 security: User Administrator(123) login failed",
        )

    def test_expand_log_paths_includes_rotated_files_newest_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            for name in ["app.log.2.gz", "app.log", "app.log.1.gz", "app.log.old"]:
                (log_dir / name).write_text("x\n", encoding="utf-8")

            paths = log_bundle_analysis.expand_log_paths(root, ["dump_info/LogDump/app.log"])

        self.assertEqual([path.name for path in paths], ["app.log", "app.log.1.gz", "app.log.2.gz"])

    def test_collect_evidence_lines_returns_latest_matches_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = pathlib.Path(tmp_dir) / "operation.log"
            path.write_text(
                "2026-03-11 User Administrator login failed\n"
                "2026-03-12 unrelated operation\n"
                "2026-03-31 User Administrator login failed\n",
                encoding="utf-8",
            )
            evidence = log_bundle_analysis.collect_evidence_lines(path, match_terms=["login"], max_lines=2)

        self.assertEqual([item["line_number"] for item in evidence], [3, 1])

    def test_analyze_bundle_prioritizes_component_specific_appdump_paths(self) -> None:
        reference = {
            "files": [
                {
                    "name": "sync_property_trace.log",
                    "paths": ["dump_info/AppDump/*/sync_property_trace.log"],
                    "component": "per-component",
                    "purpose": "sync trace",
                    "keywords": ["对象", "不同步", "sync"],
                }
            ],
            "rules": [
                {"match_keywords": ["对象", "不同步"], "include": ["sync_property_trace.log"]},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            account_log = root / "dump_info" / "AppDump" / "account" / "sync_property_trace.log"
            cooling_log = root / "dump_info" / "AppDump" / "cooling" / "sync_property_trace.log"
            account_log.parent.mkdir(parents=True)
            cooling_log.parent.mkdir(parents=True)
            account_log.write_text("类名 对象名 同步属性名: 属性值 表达式\n", encoding="utf-8")
            cooling_log.write_text("2026-04-07 cooling object sync failed\n", encoding="utf-8")

            analysis = log_bundle_analysis.analyze_bundle(
                root,
                "cooling 对象不同步",
                reference_data=reference,
                max_files=1,
                max_lines=1,
            )

        evidence = analysis["selected_logs"][0]["evidence_lines"][0]
        self.assertIn("/cooling/", evidence["path"])
        self.assertIn("cooling object sync failed", evidence["line"])

    def test_collect_evidence_lines_skips_low_signal_template_headers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = pathlib.Path(tmp_dir) / "sync_property_trace.log"
            path.write_text(
                "类名 对象名 同步属性名: 属性值 表达式\n"
                "表达式参数: 同步源服务 同步源资源树路径 同步源资源树接口 同步源属性\n"
                "2026-04-07 cooling property sync failed\n",
                encoding="utf-8",
            )
            evidence = log_bundle_analysis.collect_evidence_lines(path, match_terms=["sync"], max_lines=3)

        self.assertEqual([item["line"] for item in evidence], ["2026-04-07 cooling property sync failed"])

    def test_analyze_bundle_prefers_more_specific_evidence_across_wildcard_paths(self) -> None:
        reference = {
            "files": [
                {
                    "name": "mdb_info.log",
                    "paths": ["dump_info/AppDump/*/mdb_info.log"],
                    "component": "per-component",
                    "purpose": "object tree",
                    "keywords": ["对象", "object", "sync"],
                }
            ],
            "rules": [
                {"match_keywords": ["对象"], "include": ["mdb_info.log"]},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            account_log = root / "dump_info" / "AppDump" / "account" / "mdb_info.log"
            hwproxy_log = root / "dump_info" / "AppDump" / "hwproxy" / "mdb_info.log"
            account_log.parent.mkdir(parents=True)
            hwproxy_log.parent.mkdir(parents=True)
            account_log.write_text("/bmc/kepler/AccountService  bmc.kepler.Object.Properties\n", encoding="utf-8")
            hwproxy_log.write_text("2026-04-07 hwproxy object sync failed\n", encoding="utf-8")

            analysis = log_bundle_analysis.analyze_bundle(
                root,
                "对象不更新",
                reference_data=reference,
                max_files=1,
                max_lines=1,
            )

        evidence = analysis["selected_logs"][0]["evidence_lines"][0]
        self.assertIn("/hwproxy/", evidence["path"])
        self.assertEqual(evidence["line"], "2026-04-07 hwproxy object sync failed")

    def test_analyze_bundle_limits_existing_paths_in_output(self) -> None:
        reference = {
            "files": [
                {
                    "name": "mdb_info.log",
                    "paths": ["dump_info/AppDump/*/mdb_info.log"],
                    "component": "per-component",
                    "purpose": "object tree",
                    "keywords": ["对象"],
                }
            ],
            "rules": [
                {"match_keywords": ["对象"], "include": ["mdb_info.log"]},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            for index in range(12):
                log_path = root / "dump_info" / "AppDump" / f"comp_{index}" / "mdb_info.log"
                log_path.parent.mkdir(parents=True)
                log_path.write_text(f"2026-04-07 object {index} failed\n", encoding="utf-8")

            analysis = log_bundle_analysis.analyze_bundle(
                root,
                "对象不更新",
                reference_data=reference,
                max_files=1,
                max_lines=1,
            )

        selected = analysis["selected_logs"][0]
        self.assertEqual(selected["existing_path_count"], 12)
        self.assertTrue(selected["existing_paths_truncated"])
        self.assertEqual(len(selected["existing_paths"]), 10)

    def test_parse_log_timestamp_supports_space_and_rfc3339_formats(self) -> None:
        naive = log_bundle_analysis.parse_log_timestamp("2026-03-31 06:28:15 WEB login failed")
        aware = log_bundle_analysis.parse_log_timestamp("2026-03-31T08:24:52.593445+00:00 security: login failed")

        self.assertEqual(naive, "2026-03-31T06:28:15")
        self.assertEqual(aware, "2026-03-31T08:24:52.593445+00:00")

    def test_collect_evidence_lines_prefers_newer_timestamp_over_later_line_position(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = pathlib.Path(tmp_dir) / "security.log"
            path.write_text(
                "2026-03-31T08:24:52.593445+00:00 security: User Administrator login failed\n"
                "2026-03-17T05:55:34.429447+00:00 security: User Administrator login failed\n"
                "2026-03-01T00:00:00+00:00 security: User Administrator login failed\n"
                "2026-03-30T00:00:00+00:00 security: User Administrator login failed\n",
                encoding="utf-8",
            )
            evidence = log_bundle_analysis.collect_evidence_lines(path, match_terms=["login"], max_lines=3)

        self.assertEqual(
            [item["timestamp"] for item in evidence],
            [
                "2026-03-31T08:24:52.593445+00:00",
                "2026-03-30T00:00:00+00:00",
                "2026-03-17T05:55:34.429447+00:00",
            ],
        )

    def test_collect_evidence_lines_filters_by_time_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = pathlib.Path(tmp_dir) / "operation.log"
            path.write_text(
                "2026-03-30 06:28:15 User Administrator login failed\n"
                "2026-03-31 06:28:15 User Administrator login failed\n"
                "2026-04-01 06:28:15 User Administrator login failed\n",
                encoding="utf-8",
            )
            evidence = log_bundle_analysis.collect_evidence_lines(
                path,
                match_terms=["login"],
                max_lines=5,
                since=log_bundle_analysis.parse_analysis_time_bound("2026-03-31T00:00:00", label="since"),
                until=log_bundle_analysis.parse_analysis_time_bound("2026-03-31T23:59:59", label="until"),
            )

        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["timestamp"], "2026-03-31T06:28:15")

    def test_parse_args_accepts_analysis_time_window(self) -> None:
        args = analyzer_cli.parse_args(["--analysis-since", "2026-03-31T00:00:00", "--analysis-until", "2026-03-31T23:59:59"])
        self.assertEqual(args.analysis_since, "2026-03-31T00:00:00")
        self.assertEqual(args.analysis_until, "2026-03-31T23:59:59")


class BoundedAnalysisTests(unittest.TestCase):
    def test_damaged_gzip_is_reported_as_incomplete_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            (log_dir / "security.log.1.gz").write_bytes(b"damaged-gzip")

            result = log_bundle_analysis.analyze_bundle(root, "BMC 登录失败", max_files=2, max_lines=2)

        self.assertEqual(result["assessment"], "analysis_incomplete")
        self.assertFalse(result["scan"]["complete"])
        self.assertIn("log_read_failed", {item["code"] for item in result["scan"]["errors"]})

    def test_binary_candidate_is_not_treated_as_empty_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            (log_dir / "security.log").write_bytes(b"login\x00failed\n")

            result = log_bundle_analysis.analyze_bundle(root, "BMC 登录失败", max_files=2, max_lines=2)

        self.assertEqual(result["assessment"], "analysis_incomplete")
        self.assertIn("binary_content_detected", {item["code"] for item in result["scan"]["errors"]})

    def test_gzip_rotation_recovers_text_after_bounded_nul_padding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            payload = (
                b"2026-08-31 07:59:00 WEB,user@example,iam,logout successfully\n"
                + b"\x00" * 32
                + b"2026-08-31 08:00:00 WEB,user@example,iam,login failed\n"
            )
            (log_dir / "operation.log.1.gz").write_bytes(gzip.compress(payload))

            result = log_bundle_analysis.analyze_bundle(
                root,
                "BMC login failed",
                max_files=4,
                max_lines=3,
            )

        self.assertEqual(result["assessment"], "evidence_found_with_gaps")
        self.assertTrue(any("login failed" in item["line"] for item in result["evidence"]))
        warnings = [
            item for item in result["scan"]["warnings"]
            if item["code"] == "nul_padding_removed"
        ]
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0]["bytes_removed"], 32)
        self.assertNotIn("binary_content_detected", {item["code"] for item in result["scan"]["errors"]})

    def test_mixed_binary_after_nul_prefix_still_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            (log_dir / "security.log").write_bytes(
                b"\x00" * 32 + b"\x01\xfflogin failed\n"
            )

            result = log_bundle_analysis.analyze_bundle(
                root,
                "BMC login failed",
                max_files=4,
                max_lines=3,
            )

        self.assertEqual(result["assessment"], "analysis_incomplete")
        self.assertIn("binary_content_detected", {item["code"] for item in result["scan"]["errors"]})

    def test_permission_failure_is_reported_as_incomplete_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            (log_dir / "security.log").write_text("login failed\n", encoding="utf-8")

            with mock.patch(
                "log_bundle_analysis.open",
                side_effect=PermissionError("permission denied"),
                create=True,
            ):
                result = log_bundle_analysis.analyze_bundle(root, "BMC 登录失败", max_files=2, max_lines=2)

        self.assertEqual(result["assessment"], "analysis_incomplete")
        self.assertIn("log_read_failed", {item["code"] for item in result["scan"]["errors"]})

    def test_non_utf8_text_uses_visible_encoding_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            (log_dir / "security.log").write_bytes(
                "2026-08-31T08:00:00 登录失败\n".encode("gb18030")
            )

            result = log_bundle_analysis.analyze_bundle(root, "BMC 登录失败", max_files=2, max_lines=2)

        self.assertEqual(result["assessment"], "evidence_found")
        self.assertIn("encoding_fallback_used", {item["code"] for item in result["scan"]["warnings"]})
        self.assertIn("登录失败", result["evidence"][0]["line"])

    def test_overlong_line_is_skipped_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            (log_dir / "security.log").write_text(
                "x" * 128 + "\n2026-08-31T08:00:00 login failed\n",
                encoding="utf-8",
            )

            result = log_bundle_analysis.analyze_bundle(
                root,
                "BMC login failed",
                max_files=5,
                max_lines=2,
                max_line_bytes=64,
            )

        self.assertEqual(result["assessment"], "evidence_found_with_gaps")
        self.assertIn("line_too_long", {item["code"] for item in result["scan"]["warnings"]})
        self.assertEqual(result["evidence"][0]["line_number"], 2)

    def test_wildcard_paths_are_physically_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            for component in ("account", "cooling", "storage"):
                path = root / "dump_info" / "AppDump" / component / "mdb_info.log"
                path.parent.mkdir(parents=True)
                path.write_text(f"2026-08-31T08:00:00 {component} object failed\n", encoding="utf-8")

            result = log_bundle_analysis.analyze_bundle(
                root,
                "对象缺失",
                max_files=1,
                max_lines=2,
                max_paths_per_log=1,
            )

        selected = result["selected_logs"][0]
        self.assertEqual(selected["existing_path_count"], 3)
        self.assertEqual(selected["scanned_path_count"], 1)
        self.assertTrue(selected["scan_truncated"])
        self.assertEqual(result["assessment"], "evidence_found_with_gaps")

    def test_total_scan_byte_budget_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            (log_dir / "security.log").write_text(
                "2026-08-31T08:00:00 login failed\n" * 20,
                encoding="utf-8",
            )

            result = log_bundle_analysis.analyze_bundle(
                root,
                "BMC 登录失败",
                max_files=2,
                max_lines=2,
                max_bytes_per_file=128,
                max_total_bytes=128,
            )

        self.assertEqual(result["scan"]["scanned_bytes"], 128)
        self.assertIn("file_scan_truncated", {item["code"] for item in result["scan"]["warnings"]})
        self.assertEqual(result["assessment"], "evidence_found_with_gaps")

    def test_timeline_is_chronological_and_correlation_is_noncausal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dump = root / "dump_info" / "LogDump"
            journal_dir = root / "dump_info" / "RTOSDump" / "sysinfo"
            log_dump.mkdir(parents=True)
            journal_dir.mkdir(parents=True)
            (log_dump / "framework.log").write_text(
                "2026-08-31T17:00:01+08:00 service startup failed\n",
                encoding="utf-8",
            )
            (journal_dir / "journalctl.log").write_text(
                "2026-08-31T09:00:03+00:00 systemd startup failed\n",
                encoding="utf-8",
            )

            result = log_bundle_analysis.analyze_bundle(root, "service startup failed", max_files=4, max_lines=2)

        self.assertEqual([item["sequence"] for item in result["timeline"]], [1, 2])
        self.assertTrue(result["timeline"][0]["path"].endswith("framework.log"))
        self.assertTrue(result["timeline"][1]["path"].endswith("journalctl.log"))
        self.assertEqual(result["correlation_windows"][0]["interpretation"], "temporal_proximity_only")

    def test_mixed_timestamp_domains_are_partitioned_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dump = root / "dump_info" / "LogDump"
            journal_dir = root / "dump_info" / "RTOSDump" / "sysinfo"
            log_dump.mkdir(parents=True)
            journal_dir.mkdir(parents=True)
            (log_dump / "framework.log").write_text(
                "2026-08-10T09:10:22 service startup failed\n",
                encoding="utf-8",
            )
            (journal_dir / "journalctl.log").write_text(
                "2026-08-28T07:20:21+00:00 systemd startup failed\n",
                encoding="utf-8",
            )

            result = log_bundle_analysis.analyze_bundle(root, "service startup failed", max_files=4, max_lines=2)

        timeline = result["timeline"]
        self.assertEqual([item["time_domain"] for item in timeline], ["timezone_aware", "timezone_unspecified"])
        self.assertEqual([item["sequence_scope"] for item in timeline], ["time_domain", "time_domain"])
        self.assertEqual([item["domain_sequence"] for item in timeline], [1, 1])
        warning_codes = {item["code"] for item in result["scan"]["warnings"]}
        self.assertIn("timeline_time_domain_partitioned", warning_codes)
        self.assertEqual(result["assessment"], "evidence_found_with_gaps")
        self.assertEqual(result["correlation_windows"], [])

    def test_structured_mdb_summary_reports_inventory_without_property_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            path = root / "dump_info" / "AppDump" / "storage" / "mdb_info.log"
            path.parent.mkdir(parents=True)
            path.write_text(
                "/bmc/kepler/Systems/1/Storage bmc.kepler.Object.Properties\n"
                ".ObjectName\n"
                "  signature: s\n"
                "  value: \"Storage\"\n"
                "  readonly: true\n",
                encoding="utf-8",
            )

            result = log_bundle_analysis.analyze_bundle(root, "storage 对象缺失", max_files=4, max_lines=2)

        summary = next(item for item in result["structured_summaries"] if item["parser"] == "mdb_properties")
        self.assertEqual(summary["object_count"], 1)
        self.assertEqual(summary["property_value_count"], 1)
        self.assertTrue(summary["property_values_omitted"])
        self.assertNotIn("Storage", json.dumps(summary["property_counts"], ensure_ascii=False))

    def test_structured_csv_summary_detects_schema_without_copying_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            path = root / "dump_info" / "AppDump" / "event" / "eo_sel.csv"
            path.parent.mkdir(parents=True)
            path.write_text(
                "Time;Severity;Message\n"
                "2026-08-31 08:00:00;Critical;Sensitive event detail\n"
                "2026-08-31 08:01:00;OK;Recovered\n",
                encoding="utf-8",
            )

            result = log_bundle_analysis.analyze_bundle(root, "历史事件", max_files=4, max_lines=2)

        summary = next(item for item in result["structured_summaries"] if item["parser"] == "delimited_records")
        self.assertEqual(summary["delimiter"], "semicolon")
        self.assertEqual(summary["columns"], ["Time", "Severity", "Message"])
        self.assertEqual(summary["observed_record_count"], 2)
        self.assertTrue(summary["header_present"])
        self.assertNotIn("Sensitive event detail", json.dumps(summary, ensure_ascii=False))

    def test_pcie_topology_summary_keeps_status_codes_opaque_and_omits_uid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            path = root / "dump_info" / "AppDump" / "pcie_device" / "cable_info"
            path.parent.mkdir(parents=True)
            path.write_text(
                "[BizTopoMonitor] Port: name=A1a, status=1, unit=[uid=111111111111111111, index=1, port_id=17]\n"
                "[BizTopoMonitor] Port: name=A1c, status=0, unit=[uid=, index=0, port_id=0]\n"
                "[BizTopoMonitor] Config: slot=SEU-5, status=255, unit=[uid=222222222222222222, index=0]\n",
                encoding="utf-8",
            )

            result = log_bundle_analysis.analyze_bundle(root, "PCIe 线缆缺卡或端口接错", max_files=5, max_lines=2)

        summary = next(item for item in result["structured_summaries"] if item["parser"] == "pcie_topology_records")
        self.assertEqual(result["selected_logs"][0]["name"], "cable_info")
        self.assertEqual(summary["observed_record_count"], 3)
        self.assertEqual(summary["status_code_counts"]["config"]["255"], 1)
        self.assertEqual(summary["interpretation"], "status_codes_require_sourced_profile")
        self.assertEqual(summary["sensitive_fields_omitted"], ["uid", "label"])
        self.assertTrue(all("label_hash" in item and "label" not in item for item in summary["sample_records"]))
        self.assertNotIn("111111111111111111", json.dumps(result, ensure_ascii=False))
        self.assertEqual(result["assessment"], "evidence_found")

    def test_evidence_findings_have_stable_ids_and_deduplicate_repeated_signals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            path = root / "dump_info" / "LogDump" / "security.log"
            path.parent.mkdir(parents=True)
            path.write_text(
                "2026-08-31 08:00:00 User admin authentication failed\n"
                "2026-08-31 08:00:01 User operator authentication failed\n"
                "2026-08-31 08:00:02 User root authentication failed\n",
                encoding="utf-8",
            )

            first = log_bundle_analysis.analyze_bundle(root, "BMC login failed", max_files=5, max_lines=5)
            second = log_bundle_analysis.analyze_bundle(root, "BMC login failed", max_files=5, max_lines=5)

        finding = first["evidence_findings"][0]
        self.assertEqual(finding["sampled_occurrence_count"], 3)
        self.assertTrue(finding["count_complete"])
        self.assertFalse(finding["count_is_lower_bound"])
        self.assertEqual(finding["evidence_strength"], "direct_signal")
        self.assertEqual(finding["finding_id"], second["evidence_findings"][0]["finding_id"])
        self.assertEqual(finding["revision"], 1)

    def test_operation_event_anchor_correlates_by_time_and_shared_component(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            (log_dir / "operation.log").write_text(
                "2026-08-31 08:00:00 SSH,admin@10.0.0.1,iam,operation failed\n",
                encoding="utf-8",
            )
            (log_dir / "app.log").write_text(
                "2026-08-31 08:00:02 iam ERROR: authentication backend failed\n",
                encoding="utf-8",
            )

            result = log_bundle_analysis.analyze_bundle(root, "操作失败并关联 app.log", max_files=4, max_lines=3)

        correlation = result["event_correlations"][0]
        self.assertIn("shared_component", correlation["basis"])
        self.assertEqual(correlation["candidates"][0]["shared_components"], ["iam"])
        self.assertEqual(correlation["candidates"][0]["delta_seconds"], 2)
        self.assertEqual(correlation["interpretation"], "candidate_context_not_causality")



class ExtractArchiveTests(unittest.TestCase):
    def test_extract_archive_returns_bundle_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = pathlib.Path(tmp_dir)
            bundle_source = tmp_path / "source" / "openUBMC_20260402-1015"
            log_file = bundle_source / "dump_info" / "LogDump" / "app.log"
            log_file.parent.mkdir(parents=True)
            log_file.write_text("error line\n", encoding="utf-8")

            archive_path = tmp_path / "openUBMC_20260402-1015.tar.gz"
            with tarfile.open(archive_path, "w:gz") as tar:
                tar.add(bundle_source, arcname=bundle_source.name)

            extract_parent = tmp_path / "extract"
            result = log_bundle_artifact.extract_archive(archive_path, extract_parent)

            self.assertTrue((result.bundle_root / "dump_info" / "LogDump" / "app.log").exists())
            self.assertTrue(result.extract_dir.exists())

    def test_extract_archive_rejects_symbolic_links(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = pathlib.Path(tmp_dir)
            archive_path = tmp_path / "unsafe.tar"
            member = tarfile.TarInfo("bundle/dump_info/LogDump/app.log")
            member.type = tarfile.SYMTYPE
            member.linkname = "/etc/passwd"
            with tarfile.open(archive_path, "w") as archive:
                archive.addfile(member)

            with self.assertRaisesRegex(log_bundle_common.BundleAnalysisError, "Unsupported archive member"):
                log_bundle_artifact.extract_archive(archive_path, tmp_path / "extract")

    def test_extract_archive_rejects_nonportable_member_names(self) -> None:
        for member_name in (
            "bundle/dump_info/bad\\name.txt",
            "bundle/dump_info/bad\x01name.txt",
            "bundle/dump_info/bad\x7fname.txt",
        ):
            with self.subTest(member_name=repr(member_name)):
                with tempfile.TemporaryDirectory() as tmp_dir:
                    tmp_path = pathlib.Path(tmp_dir)
                    archive_path = tmp_path / "unsafe-name.tar"
                    payload = b"opaque\n"
                    member = tarfile.TarInfo(member_name)
                    member.size = len(payload)
                    with tarfile.open(archive_path, "w") as archive:
                        archive.addfile(member, io.BytesIO(payload))

                    with self.assertRaises(log_bundle_common.BundleAnalysisError) as raised:
                        log_bundle_artifact.extract_archive(archive_path, tmp_path / "extract")

                self.assertEqual(raised.exception.code, "extract_failed")


class ValidationTests(unittest.TestCase):
    def test_validate_bundle_reports_sections_and_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_file = root / "dump_info" / "LogDump" / "security.log"
            log_file.parent.mkdir(parents=True)
            log_file.write_text("login failed\n", encoding="utf-8")

            result = log_bundle_artifact.validate_bundle_structure(root)

            self.assertTrue(result["valid"])
            self.assertEqual(result["present_sections"], ["LogDump"])
            self.assertEqual(result["sections"]["LogDump"]["file_count"], 1)
            self.assertIn("missing_section:AppDump", result["warnings"])

    def test_validate_bundle_recognizes_observed_sections_and_summarizes_root_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            dump_info = root / "dump_info"
            for section, relative_file in {
                "3rdDump": "access_log",
                "CoreDump": "core-files.tar.gz",
                "OptBMC": "save/factory_backup.tar.gz",
            }.items():
                artifact = dump_info / section / relative_file
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_bytes(b"opaque")
            (dump_info / "dump_log").write_bytes(b"123")
            (dump_info / "dump_app_log").write_bytes(b"12345")

            result = log_bundle_artifact.validate_bundle_structure(root)

        self.assertEqual(result["present_sections"], ["3rdDump", "CoreDump", "OptBMC"])
        self.assertEqual(result["unknown_sections"], [])
        self.assertEqual(result["sections"]["OptBMC"]["subdirectory_count"], 1)
        self.assertEqual(
            result["sections"]["OptBMC"]["subdirectories"],
            [{"name": "save", "file_count": 1}],
        )
        self.assertEqual(
            result["root_files"],
            [
                {"path": "dump_info/dump_app_log", "size_bytes": 5},
                {"path": "dump_info/dump_log", "size_bytes": 3},
            ],
        )

    def test_locate_bundle_root_rejects_ambiguous_layout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            (root / "first" / "dump_info").mkdir(parents=True)
            (root / "second" / "dump_info").mkdir(parents=True)

            with self.assertRaisesRegex(log_bundle_common.BundleAnalysisError, "multiple dump_info"):
                log_bundle_artifact.locate_bundle_root(root)

    def test_validate_bundle_requires_recognized_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            (root / "dump_info" / "VendorOnly").mkdir(parents=True)

            with self.assertRaisesRegex(log_bundle_common.BundleAnalysisError, "recognized log sections"):
                log_bundle_artifact.validate_bundle_structure(root)


class EvidenceSafetyTests(unittest.TestCase):
    def test_evidence_redacts_secret_assignments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = pathlib.Path(tmp_dir) / "security.log"
            path.write_text(
                "2026-08-31T08:00:00 login failed password=hunter2 token=abc123\n",
                encoding="utf-8",
            )

            evidence = log_bundle_analysis.collect_evidence_lines(
                path,
                match_terms=["login"],
                max_lines=1,
            )

            self.assertTrue(evidence[0]["redacted"])
            self.assertNotIn("hunter2", evidence[0]["line"])
            self.assertNotIn("abc123", evidence[0]["line"])


class LocalArchiveCliTests(unittest.TestCase):
    def test_local_archive_cli_validates_and_emits_relative_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = pathlib.Path(tmp_dir)
            source = tmp_path / "source" / "bundle"
            security = source / "dump_info" / "LogDump" / "security.log"
            security.parent.mkdir(parents=True)
            security.write_text(
                "2026-08-31T08:00:00 login failed for user test\n",
                encoding="utf-8",
            )
            archive_path = tmp_path / "bundle.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(source, arcname="bundle")

            output = io.StringIO()
            with redirect_stdout(output):
                returncode = analyzer_cli.main(
                    [
                        "--bundle",
                        str(archive_path),
                        "--extract-dir",
                        str(tmp_path / "extract"),
                        "--problem",
                        "BMC login failed",
                        "--json",
                    ]
                )

            payload = json.loads(output.getvalue())
            self.assertEqual(returncode, 0)
            self.assertEqual(payload["schema_version"], "1.0")
            self.assertTrue(payload["result"]["validation"]["valid"])
            self.assertEqual(len(payload["result"]["bundle"]["sha256"]), 64)
            evidence = payload["result"]["analysis"]["evidence"]
            self.assertEqual(evidence[0]["path"], "dump_info/LogDump/security.log")
            self.assertEqual(evidence[0]["line_number"], 1)


class SkillContractTests(unittest.TestCase):
    def test_skill_metadata_matches_repository_contract(self) -> None:
        skill_root = pathlib.Path(__file__).resolve().parents[1]
        skill_text = (skill_root / "SKILL.md").read_text(encoding="utf-8")
        frontmatter_match = re.match(r"\A---\n(.*?)\n---\n", skill_text, re.DOTALL)

        self.assertIsNotNone(frontmatter_match)
        frontmatter = frontmatter_match.group(1)
        top_level_keys = {
            line.partition(":")[0].strip()
            for line in frontmatter.splitlines()
            if line and not line[0].isspace() and ":" in line
        }
        self.assertEqual(top_level_keys, {"name", "description"})

        manifest = json.loads((skill_root / "skill.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["manifestVersion"], 1)
        self.assertEqual(manifest["name"], "openubmc-log-bundle-analyzer")

    def test_manifest_lists_existing_files_and_no_runtime_dependency(self) -> None:
        skill_root = pathlib.Path(__file__).resolve().parents[1]
        manifest = json.loads((skill_root / "skill.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["name"], "openubmc-log-bundle-analyzer")
        for relative in manifest["files"]:
            self.assertTrue((skill_root / relative).is_file(), relative)
        text_suffixes = {"", ".json", ".log", ".md", ".py", ".txt", ".yaml"}
        text_files = [
            path
            for path in skill_root.rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix in text_suffixes
        ]
        combined = "\n".join(path.read_text(encoding="utf-8") for path in text_files)
        self.assertIn("relevant observability system", combined)
        forbidden_dependency = "openubmc" + "-debug"
        self.assertNotIn(forbidden_dependency, combined)
        self.assertIn("LICENSE", manifest["files"])
        self.assertEqual(
            manifest["dependencies"],
            {"python": ">=3.10, standard library only"},
        )
        self.assertNotIn("relatedSkills", manifest)

    def test_source_references_are_neutral_or_specific_public_urls(self) -> None:
        skill_root = pathlib.Path(__file__).resolve().parents[1]
        document = json.loads((skill_root / "references" / "logs.json").read_text(encoding="utf-8"))
        neutral = "repository-maintained heuristic"
        for item in document.get("files", []):
            if not isinstance(item, dict) or not item.get("source_reference"):
                continue
            source_reference = str(item["source_reference"])
            if source_reference == neutral:
                self.assertEqual(item.get("definition_status"), "maintained_heuristic", item.get("name"))
                self.assertEqual(item.get("source_type"), "repository_maintained", item.get("name"))
                self.assertEqual(item.get("reliability"), "heuristic", item.get("name"))
                continue
            self.assertRegex(
                source_reference,
                r"^https://[^/\s]+/.+",
                item.get("name"),
            )
            self.assertTrue(str(item.get("source_revision", "")).strip(), item.get("name"))
            self.assertNotRegex(source_reference, r"(?i)(documentation:|discussion:|validated .* structure)")
    def test_evals_cover_positive_and_negative_routing(self) -> None:
        skill_root = pathlib.Path(__file__).resolve().parents[1]
        document = json.loads((skill_root / "evals" / "evals.json").read_text(encoding="utf-8"))
        self.assertEqual(document["skill_name"], "openubmc-log-bundle-analyzer")
        self.assertGreaterEqual(len(document["evals"]), 10)
        prompts = "\n".join(item["prompt"] for item in document["evals"])
        self.assertIn("Prometheus", prompts)
        self.assertIn("systemctl", prompts)
        self.assertIn("CoreDump", prompts)
        self.assertIn("当前告警", prompts)
        self.assertIn("风扇型号", prompts)
        self.assertIn("firmware_mgmt", prompts)
        self.assertIn("时间顺序", prompts)
        self.assertIn("分析不完整", prompts)
        artifact_backed = [item for item in document["evals"] if item.get("files")]
        self.assertGreaterEqual(len(artifact_backed), 4)
        for item in artifact_backed:
            for relative in item["files"]:
                self.assertTrue((skill_root / relative).exists(), relative)

    def test_artifact_backed_behavior_evals_execute(self) -> None:
        skill_root = pathlib.Path(__file__).resolve().parents[1]
        namespace = runpy.run_path(str(skill_root / "evals" / "run_behavior_evals.py"))
        result = namespace["run_behavior_evals"]()
        self.assertTrue(result["ok"])
        self.assertGreaterEqual(result["count"], 4)


if __name__ == "__main__":
    unittest.main()
