from __future__ import annotations

import io
import json
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock


SCRIPT_DIR = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from log_bundle_artifact import (  # type: ignore  # noqa: E402
    ensure_bundle_path,
    locate_bundle_root,
    validate_bundle_structure,
)
from log_bundle_analysis import analyze_bundle  # type: ignore  # noqa: E402
import analyze_bundle as analyzer_cli  # type: ignore  # noqa: E402
from log_bundle_common import BundleAnalysisError  # type: ignore  # noqa: E402
from log_bundle_redaction import redact_public_text, redact_sensitive_text  # type: ignore  # noqa: E402
from log_bundle_structured import make_structured_collector  # type: ignore  # noqa: E402


class BundlePathBoundaryTests(unittest.TestCase):
    def make_symlink(self, link: pathlib.Path, target: pathlib.Path, *, directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=directory)
        except OSError as exc:
            if getattr(exc, "winerror", None) == 1314:
                self.skipTest("Windows requires Developer Mode or a symlink privilege for this fixture")
            raise

    def test_locate_bundle_root_rejects_dump_info_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = pathlib.Path(tmp_dir)
            source = base / "outside" / "dump_info"
            source.mkdir(parents=True)
            candidate = base / "candidate"
            candidate.mkdir()
            self.make_symlink(candidate / "dump_info", source, directory=True)

            with self.assertRaisesRegex(BundleAnalysisError, "symbolic links"):
                locate_bundle_root(candidate)

    def test_validate_bundle_rejects_dump_info_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = pathlib.Path(tmp_dir)
            source = base / "outside" / "dump_info" / "LogDump"
            source.mkdir(parents=True)
            (source / "security.log").write_text("outside\n", encoding="utf-8")
            candidate = base / "candidate"
            candidate.mkdir()
            self.make_symlink(candidate / "dump_info", source.parent, directory=True)

            with self.assertRaisesRegex(BundleAnalysisError, "symbolic links"):
                validate_bundle_structure(candidate)

    def test_validate_bundle_rejects_nested_file_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = pathlib.Path(tmp_dir)
            root = base / "bundle"
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            outside = base / "outside.log"
            outside.write_text("password=outside-secret\n", encoding="utf-8")
            self.make_symlink(log_dir / "security.log", outside)

            with self.assertRaisesRegex(BundleAnalysisError, "symbolic links"):
                validate_bundle_structure(root)

    def test_ensure_bundle_path_rejects_parent_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = pathlib.Path(tmp_dir)
            root = base / "bundle"
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            safe_file = log_dir / "security.log"
            safe_file.write_text("login failed\n", encoding="utf-8")
            outside = base / "outside.log"
            outside.write_text("outside\n", encoding="utf-8")
            self.assertEqual(ensure_bundle_path(root, safe_file), safe_file.resolve())
            with self.assertRaisesRegex(BundleAnalysisError, "escapes the bundle root"):
                ensure_bundle_path(root, pathlib.Path("../outside.log"))

    def test_ensure_bundle_path_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir) / "bundle"
            root.mkdir()
            outside = pathlib.Path(tmp_dir) / "outside.log"
            outside.write_text("outside\n", encoding="utf-8")
            linked_file = root / "linked.log"
            self.make_symlink(linked_file, outside)
            with self.assertRaisesRegex(BundleAnalysisError, "symbolic links"):
                ensure_bundle_path(root, linked_file)


class RedactionBoundaryTests(unittest.TestCase):
    def test_shareable_text_redacts_common_host_account_and_asset_identifiers(self) -> None:
        raw = (
            "User Administrator(123) authentication failed from [fe80::1%eth0] "
            "client_ip=10.0.0.8 mac=AA:BB:CC:DD:EE:FF serial_number=SN-123 "
            '"Mozilla/5.0 (X11; Linux x86_64)" /root/private/report.json'
        )
        safe, changed = redact_public_text(raw)

        self.assertTrue(changed)
        for value in (
            "Administrator",
            "fe80::1",
            "eth0",
            "10.0.0.8",
            "AA:BB:CC:DD:EE:FF",
            "SN-123",
            "Mozilla/5.0",
            "/root/private/report.json",
        ):
            self.assertNotIn(value, safe)

    def test_shareable_text_redacts_common_identifier_variants(self) -> None:
        raw = (
            "serialNumber=SN123 DeviceSerialNumber=ABC789 deviceSerial=DSN "
            "assetTag=AT1 serial_no=XYZ Serial Number: SN456 S/N ABC123 "
            "BN:02314UVX boardNumber=02314EWC PartNum=PN-A "
            "OriginalPartNumber=ORIG-A Original Part Number: ORIG-B "
            "Board Part Number: BOARD-A Product Part Number=PRODUCT-A "
            "Card Part Number: CARD-A Material Number=MATERIAL-A "
            "Fan | Model | PartNum | Device |\\nFan1 | AVC | 02314EWC | Fan1 | "
            "device aabb.ccdd.eeff failed; client okhttp/4.9 request failed; "
            "SSH,alice,iam,operation failed; DNS lookup bmc-prod.example.com failed"
        )

        safe, changed = redact_public_text(raw)

        self.assertTrue(changed)
        for value in (
            "SN123",
            "ABC789",
            "DSN",
            "AT1",
            "XYZ",
            "SN456",
            "ABC123",
            "02314UVX",
            "02314EWC",
            "PN-A",
            "ORIG-A",
            "ORIG-B",
            "BOARD-A",
            "PRODUCT-A",
            "CARD-A",
            "MATERIAL-A",
            "aabb.ccdd.eeff",
            "okhttp/4.9",
            "alice",
            "bmc-prod.example.com",
        ):
            self.assertNotIn(value, safe)

    def test_shareable_identifier_labels_preserve_non_value_text(self) -> None:
        raw = (
            "part number(col 11) part number unavailable board number of failures "
            "product part number changed"
        )

        self.assertEqual(redact_public_text(raw), (raw, False))

    def test_shareable_asset_context_redacts_identifiers_and_preserves_diagnostics(self) -> None:
        raw = "unit 12345678901234567890 linked to connector CPU1; SN(SAMPLE-SERIAL-1) failed"

        safe, changed = redact_public_text(raw)

        self.assertTrue(changed)
        self.assertNotIn("12345678901234567890", safe)
        self.assertNotIn("SAMPLE-SERIAL-1", safe)
        self.assertIn("unit <redacted>-asset linked to connector CPU1", safe)
        self.assertIn("SN(<redacted>-asset) failed", safe)

    def test_shareable_asset_context_preserves_hashes_and_unrelated_unit_text(self) -> None:
        raw = 'object_path_hash="0123456789abcdef01234567"; unit 42 test failed; SN()'

        self.assertEqual(redact_public_text(raw), (raw, False))

    def test_shareable_path_redaction_covers_custom_roots_without_hiding_redfish_uris(self) -> None:
        raw = (
            "failed at /acme/private/customer-a/report.tar.gz and at /secret and /workspace; "
            r"copy from \\server\share\customer\report.log; "
            "Location: /redfish/v1/TaskService/Tasks/42; "
            "object=/xyz/openbmc_project/state/bmc0; /bmc/example/object"
        )

        safe, changed = redact_public_text(raw)

        self.assertTrue(changed)
        self.assertNotIn("/acme/private/customer-a/report.tar.gz", safe)
        self.assertNotIn("/secret", safe)
        self.assertNotIn("/workspace", safe)
        self.assertNotIn(r"\\server\share\customer\report.log", safe)
        self.assertIn("/redfish/v1/TaskService/Tasks/42", safe)
        self.assertIn("/xyz/openbmc_project/state/bmc0", safe)
        self.assertIn("/bmc/example/object", safe)

    def test_shareable_path_redaction_does_not_damage_table_values(self) -> None:
        raw = (
            "Fan Module1 | present /present | 13860 /10560 | 16900 /12800 | "
            "AVC 8080+ | 02314EWC | Fan1"
        )

        safe, changed = redact_public_text(raw)

        self.assertTrue(changed)
        self.assertIn("present /present", safe)
        self.assertIn("13860 /10560", safe)
        self.assertIn("16900 /12800", safe)
        self.assertNotIn("02314EWC", safe)

    def test_exact_location_redaction_respects_path_component_boundaries(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            analyzer_cli.emit_result(
                {
                    "bundle": "/tmp",
                    "error": (
                        "failed at /usr/lib/tmpfiles.d/var.conf; marker /tmpfiles and /datafile; "
                        "collected /tmp/customer/report"
                    ),
                },
                json_mode=True,
            )

        payload = json.loads(output.getvalue())
        self.assertEqual(payload["bundle"], "<redacted-path>")
        self.assertEqual(
            payload["error"],
            "failed at <redacted>-path; marker /tmpfiles and /datafile; collected <redacted-path>",
        )

    def test_redacts_common_header_json_query_and_assignment_forms(self) -> None:
        cases = {
            "Authorization: Bearer bearer-secret-token": ["bearer-secret-token"],
            "Proxy-Authorization: Basic cHJveHk6c2VjcmV0": ["cHJveHk6c2VjcmV0"],
            "ProxyAuthorization: Basic YWRtaW46c2VjcmV0": ["YWRtaW46c2VjcmV0"],
            "HTTP_AUTHORIZATION: Bearer prefixed-header-secret": ["prefixed-header-secret"],
            "Cookie: sid=cookie-secret; csrf=csrf-secret": ["cookie-secret", "csrf-secret"],
            '{"password": "quoted password", "refresh_token": "refresh-secret"}': [
                "quoted password",
                "refresh-secret",
            ],
            "https://bmc/redfish/v1/?access_token=query-secret&mode=read": ["query-secret"],
            "login failed password=hunter2 token=token-secret api_key=api-secret": [
                "hunter2",
                "token-secret",
                "api-secret",
            ],
            "session=session-secret client_secret='client secret'": [
                "session-secret",
                "client secret",
            ],
            "request rejected Bearer standalone-bearer-secret": ["standalone-bearer-secret"],
            "curl --password=cli-secret https://admin:url-secret@bmc.example": [
                "cli-secret",
                "url-secret",
            ],
            "tool --password 'spaced cli secret' --mode read": ["spaced cli secret"],
            "tool --redfish-password redfish-secret --ip bmc.example": ["redfish-secret"],
            "MY_SERVICE_ACCESS_TOKEN=environment-secret": ["environment-secret"],
            "auth.password=dot-qualified-secret": ["dot-qualified-secret"],
        }

        for raw, secrets in cases.items():
            with self.subTest(raw=raw):
                safe, changed = redact_sensitive_text(raw)
                self.assertTrue(changed)
                self.assertIn("<redacted>", safe)
                for secret in secrets:
                    self.assertNotIn(secret, safe)

    def test_redaction_preserves_json_shape_and_is_idempotent(self) -> None:
        raw = (
            '{"password": "quoted password", "access_token": {"nested": "secret"}, '
            '"enabled": true, "mode": "read"}'
        )
        safe, changed = redact_sensitive_text(raw)

        self.assertTrue(changed)
        self.assertEqual(json.loads(safe)["password"], "<redacted>")
        self.assertEqual(json.loads(safe)["access_token"], "<redacted>")
        self.assertTrue(json.loads(safe)["enabled"])
        self.assertEqual(json.loads(safe)["mode"], "read")
        self.assertEqual(redact_sensitive_text(safe), (safe, False))

    def test_unrelated_identifier_is_not_treated_as_token_assignment(self) -> None:
        line = "not_a_token_name=keep status=ok"
        self.assertEqual(redact_sensitive_text(line), (line, False))

    def test_complete_analysis_payload_contains_no_original_secrets(self) -> None:
        reference = {
            "files": [
                {
                    "name": "security.log",
                    "paths": ["dump_info/LogDump/security.log"],
                    "component": "security",
                    "purpose": "authentication events",
                    "keywords": ["login"],
                }
            ],
            "rules": [
                {
                    "match_keywords": ["login"],
                    "include": ["security.log"],
                    "primary": ["security.log"],
                }
            ],
        }
        secrets = ["bearer-secret", "json-secret", "query-secret"]
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            path = root / "dump_info" / "LogDump" / "security.log"
            path.parent.mkdir(parents=True)
            path.write_text(
                "2026-08-31T08:00:00 login failed Authorization: Bearer bearer-secret\n"
                '2026-08-31T08:00:01 login failed {"password":"json-secret"}\n'
                "2026-08-31T08:00:02 login failed access_token=query-secret\n",
                encoding="utf-8",
            )
            result = analyze_bundle(
                root,
                "login failed",
                reference_data=reference,
                max_files=1,
                max_lines=5,
            )

        rendered = json.dumps(result, ensure_ascii=False)
        for secret in secrets:
            self.assertNotIn(secret, rendered)
        self.assertIn("<redacted>", rendered)

    def test_cli_defaults_to_shareable_output_and_opt_in_preserves_only_non_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir) / "customer-bundle"
            path = root / "dump_info" / "LogDump" / "security.log"
            path.parent.mkdir(parents=True)
            path.write_text(
                "2026-08-31T08:00:00 login failed for User Administrator from 10.0.0.8 "
                "mac=AA:BB:CC:DD:EE:FF serial_number=SN-123 "
                'User-Agent: Mozilla/5.0 password=credential-secret\n',
                encoding="utf-8",
            )

            def run(*extra: str) -> dict[str, object]:
                output = io.StringIO()
                with redirect_stdout(output):
                    code = analyzer_cli.main(
                        [
                            "--bundle-dir",
                            str(root),
                            "--problem",
                            "login failed from 10.0.0.8",
                            "--json",
                            *extra,
                        ]
                    )
                self.assertEqual(code, 0)
                return json.loads(output.getvalue())

            shareable = run()
            sensitive_context = run("--include-sensitive-context")

        self.assertEqual(shareable["output_policy"]["profile"], "shareable")
        shareable_text = json.dumps(shareable, ensure_ascii=False)
        for value in (
            "10.0.0.8",
            "Administrator",
            "AA:BB:CC:DD:EE:FF",
            "SN-123",
            "Mozilla/5.0",
            "credential-secret",
        ):
            self.assertNotIn(value, shareable_text)
        self.assertEqual(shareable["request"]["bundle_dir"], "<redacted-path>")
        self.assertEqual(shareable["result"]["bundle"]["bundle_root"], "<redacted-path>")

        self.assertEqual(sensitive_context["output_policy"]["profile"], "sensitive_context")
        sensitive_text = json.dumps(sensitive_context, ensure_ascii=False)
        self.assertEqual(sensitive_context["request"]["bundle_dir"], str(root))
        self.assertEqual(sensitive_context["result"]["bundle"]["bundle_root"], str(root))
        for value in ("10.0.0.8", "Administrator", "AA:BB:CC:DD:EE:FF", "SN-123", "Mozilla/5.0"):
            self.assertIn(value, sensitive_text)
        self.assertNotIn("credential-secret", sensitive_text)

    def test_unexpected_cli_exception_returns_stable_redacted_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            (root / "dump_info" / "LogDump").mkdir(parents=True)
            output = io.StringIO()
            with mock.patch(
                "analyze_bundle.validate_bundle_structure",
                side_effect=RuntimeError(f"unexpected failure at {root} from 10.0.0.8"),
            ), redirect_stdout(output):
                code = analyzer_cli.main(
                    ["--bundle-dir", str(root), "--problem", "login failed", "--json"]
                )

        payload = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "runtime_error")
        self.assertNotIn(str(root), output.getvalue())
        self.assertNotIn("10.0.0.8", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())

    def test_shareable_cli_error_redacts_custom_input_path(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            code = analyzer_cli.main(
                ["--bundle-dir", "/acme/private/customer-a/missing", "--validate-only", "--json"]
            )
        self.assertEqual(code, 1)
        self.assertNotIn("/acme/private/customer-a/missing", output.getvalue())

    def test_empty_unexpected_exception_uses_non_empty_stable_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            (root / "dump_info" / "LogDump").mkdir(parents=True)
            output = io.StringIO()
            with mock.patch(
                "analyze_bundle.validate_bundle_structure",
                side_effect=RuntimeError(),
            ), redirect_stdout(output):
                code = analyzer_cli.main(
                    ["--bundle-dir", str(root), "--validate-only", "--json"]
                )

        payload = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "runtime_error")
        self.assertTrue(payload["error"])


class StructuredRedactionTests(unittest.TestCase):
    def test_mdb_samples_only_receive_redacted_lines(self) -> None:
        collector = make_structured_collector(
            "mdb_properties",
            pathlib.Path("mdb_info.log"),
        )
        self.assertIsNotNone(collector)
        assert collector is not None
        collector.observe(
            1,
            "/bmc/kepler/Sessions/token=session-secret bmc.kepler.Object.Properties",
        )

        summary = collector.finish("dump_info/AppDump/account/mdb_info.log")
        self.assertIsNotNone(summary)
        rendered = json.dumps(summary, ensure_ascii=False)
        self.assertNotIn("session-secret", rendered)
        self.assertNotIn("object_path", summary["sample_blocks"][0])
        self.assertRegex(summary["sample_blocks"][0]["object_path_hash"], r"^[0-9a-f]{16}$")

    def test_topology_samples_redact_sensitive_labels_before_parsing(self) -> None:
        collector = make_structured_collector(
            "pcie_topology_records",
            pathlib.Path("cable_info"),
        )
        self.assertIsNotNone(collector)
        assert collector is not None
        collector.observe(
            1,
            "[BizTopoMonitor] Port: name=password=label-secret, status=1, "
            "unit=[uid=device-secret, index=1, port_id=17]",
        )

        summary = collector.finish("dump_info/AppDump/pcie_device/cable_info")
        self.assertIsNotNone(summary)
        rendered = json.dumps(summary, ensure_ascii=False)
        self.assertNotIn("label-secret", rendered)
        self.assertNotIn("device-secret", rendered)
        self.assertNotIn("label", summary["sample_records"][0])
        self.assertRegex(summary["sample_records"][0]["label_hash"], r"^[0-9a-f]{16}$")
        self.assertEqual(summary["sensitive_fields_omitted"], ["uid", "label"])

    def test_out_of_window_lines_are_not_observed(self) -> None:
        collector = make_structured_collector(
            "pcie_topology_records",
            pathlib.Path("cable_info"),
        )
        self.assertIsNotNone(collector)
        assert collector is not None
        collector.observe(
            1,
            "[BizTopoMonitor] Port: name=A1, status=1, unit=[uid=secret, index=1]",
            False,
        )

        self.assertIsNone(collector.finish("dump_info/AppDump/pcie_device/cable_info"))

    def test_delimited_header_is_retained_without_counting_out_of_window_rows(self) -> None:
        collector = make_structured_collector(
            "delimited_records",
            pathlib.Path("eo_sel.csv"),
        )
        self.assertIsNotNone(collector)
        assert collector is not None
        collector.observe(1, "Time;Severity;Message", False)
        collector.observe(2, "2020-01-01;Critical;old record", False)
        collector.observe(3, "2026-08-31;OK;in-window record", True)

        summary = collector.finish("dump_info/AppDump/event/eo_sel.csv")
        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["columns"], ["Time", "Severity", "Message"])
        self.assertEqual(summary["observed_record_count"], 1)


if __name__ == "__main__":
    unittest.main()
