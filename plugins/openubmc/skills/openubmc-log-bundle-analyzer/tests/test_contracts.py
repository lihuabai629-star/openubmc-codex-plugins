from __future__ import annotations

import copy
import importlib.util
import io
import json
import pathlib
import runpy
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock


SKILL_ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
EVALS = SKILL_ROOT / "evals"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
if str(EVALS) not in sys.path:
    sys.path.insert(0, str(EVALS))

import analyze_bundle as analyzer  # noqa: E402
import log_bundle_analysis as analysis  # noqa: E402
import run_behavior_evals as behavior_evals  # noqa: E402


JSONSCHEMA_AVAILABLE = importlib.util.find_spec("jsonschema") is not None
if JSONSCHEMA_AVAILABLE:
    from jsonschema.exceptions import ValidationError
    from jsonschema.validators import validator_for


class OutputSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(
            (SKILL_ROOT / "references" / "analysis-output.schema.json").read_text(encoding="utf-8")
        )
        cls.fixture_workspace = tempfile.TemporaryDirectory(prefix="openubmc-contract-fixture-")
        cls.login_fixture = behavior_evals.materialize_analysis_fixture(
            "evals/fixtures/login-bundle",
            pathlib.Path(cls.fixture_workspace.name) / "login-bundle",
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_workspace.cleanup()

    def run_json_cli(self, arguments: list[str]) -> tuple[int, dict[str, object]]:
        output = io.StringIO()
        with redirect_stdout(output):
            return_code = analyzer.main([*arguments, "--json"])
        return return_code, json.loads(output.getvalue())

    def test_schema_version_matches_cli_contract(self) -> None:
        self.assertEqual(self.schema["properties"]["schema_version"]["const"], analyzer.SCHEMA_VERSION)

    def test_public_source_pattern_matches_catalog_validator(self) -> None:
        self.assertEqual(
            self.schema["$defs"]["publicSourceReference"]["pattern"],
            analysis.PUBLIC_SOURCE_REFERENCE_RE.pattern,
        )

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, "jsonschema is only needed for contract-development tests")
    def test_schema_is_valid_draft_2020_12(self) -> None:
        validator = validator_for(self.schema)
        validator.check_schema(self.schema)

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, "jsonschema is only needed for contract-development tests")
    def test_schema_accepts_successful_analysis_payload(self) -> None:
        return_code, payload = self.run_json_cli(
            [
                "--bundle-dir",
                str(self.login_fixture),
                "--problem",
                "BMC 登录失败",
            ]
        )
        self.assertEqual(return_code, 0)
        for finding in payload["result"]["analysis"]["evidence_findings"]:
            self.assertIn("sampled_occurrence_count", finding)
            self.assertIn("sampled_first_timestamp", finding)
            self.assertIn("sampled_last_timestamp", finding)
            self.assertNotIn("occurrence_count", finding)
            self.assertNotIn("first_timestamp", finding)
            self.assertNotIn("last_timestamp", finding)
        validator_for(self.schema)(self.schema).validate(payload)

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, "jsonschema is only needed for contract-development tests")
    def test_schema_accepts_structured_summary_payload(self) -> None:
        return_code, payload = self.run_json_cli(
            [
                "--bundle-dir",
                str(SKILL_ROOT / "evals" / "fixtures" / "structured-bundle"),
                "--problem",
                "PCIe 线缆缺卡或端口接错",
            ]
        )
        self.assertEqual(return_code, 0)
        summaries = payload["result"]["analysis"]["structured_summaries"]
        self.assertTrue(summaries)
        for summary in summaries:
            self.assertIn("observed_record_count", summary)
            self.assertIsInstance(summary["complete"], bool)
            self.assertIsInstance(summary["truncated"], bool)
            self.assertIsInstance(summary["bytes_observed"], int)
            self.assertIsInstance(summary["time_window_applied"], bool)
            self.assertNotIn("record_count", summary)
            for sample in summary.get("sample_records", []):
                self.assertIn("label_hash", sample)
                self.assertNotIn("label", sample)
            for sample in summary.get("sample_blocks", []):
                self.assertIn("object_path_hash", sample)
                self.assertNotIn("object_path", sample)
        validator_for(self.schema)(self.schema).validate(payload)

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, "jsonschema is only needed for contract-development tests")
    def test_schema_enforces_selected_log_provenance_profiles(self) -> None:
        return_code, payload = self.run_json_cli(
            [
                "--bundle-dir",
                str(self.login_fixture),
                "--problem",
                "BMC 登录失败",
            ]
        )
        self.assertEqual(return_code, 0)
        validator = validator_for(self.schema)(self.schema)

        public_payload = copy.deepcopy(payload)
        selected = public_payload["result"]["analysis"]["selected_logs"][0]
        selected.update(
            {
                "source_type": "public_repository",
                "definition_status": "documented",
                "reliability": "documented",
                "source_reference": "https://example.com/project/blob/revision/security.log",
                "source_revision": "revision",
            }
        )
        validator.validate(public_payload)

        mismatched = copy.deepcopy(public_payload)
        mismatched["result"]["analysis"]["selected_logs"][0]["reliability"] = "heuristic"
        with self.assertRaises(ValidationError):
            validator.validate(mismatched)

        signed_url = copy.deepcopy(public_payload)
        signed_url["result"]["analysis"]["selected_logs"][0]["source_reference"] += "?sig=secret"
        with self.assertRaises(ValidationError):
            validator.validate(signed_url)

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, "jsonschema is only needed for contract-development tests")
    def test_schema_accepts_success_without_analysis(self) -> None:
        return_code, payload = self.run_json_cli(
            [
                "--bundle-dir",
                str(self.login_fixture),
                "--validate-only",
            ]
        )
        self.assertEqual(return_code, 0)
        self.assertNotIn("analysis", payload["result"])
        validator_for(self.schema)(self.schema).validate(payload)

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, "jsonschema is only needed for contract-development tests")
    def test_schema_requires_validate_only_mode_discriminator(self) -> None:
        return_code, payload = self.run_json_cli(
            [
                "--bundle-dir",
                str(self.login_fixture),
                "--validate-only",
            ]
        )
        self.assertEqual(return_code, 0)
        del payload["request"]["validate_only"]
        with self.assertRaises(ValidationError):
            validator_for(self.schema)(self.schema).validate(payload)

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, "jsonschema is only needed for contract-development tests")
    def test_schema_caps_derived_source_revisions(self) -> None:
        revision_schema = self.schema["$defs"]["sourceRevision"]
        validator = validator_for(self.schema)(revision_schema)
        validator.validate("r" * 256)
        with self.assertRaises(ValidationError):
            validator.validate("r" * 257)

        revision_fields: list[tuple[str, object]] = []

        def collect_revision_fields(value: object, path: str = "$") -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    child_path = f"{path}.{key}"
                    if key == "source_revision":
                        revision_fields.append((child_path, item))
                    collect_revision_fields(item, child_path)
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    collect_revision_fields(item, f"{path}[{index}]")

        collect_revision_fields(self.schema)
        self.assertTrue(revision_fields)
        for path, field_schema in revision_fields:
            with self.subTest(path=path):
                self.assertEqual(field_schema, {"$ref": "#/$defs/sourceRevision"})

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, "jsonschema is only needed for contract-development tests")
    def test_schema_requires_timeline_ordering_metadata(self) -> None:
        return_code, payload = self.run_json_cli(
            [
                "--bundle-dir",
                str(self.login_fixture),
                "--problem",
                "BMC 登录失败",
            ]
        )
        self.assertEqual(return_code, 0)
        self.assertTrue(payload["result"]["analysis"]["timeline"])
        validator = validator_for(self.schema)(self.schema)

        for field in ("sequence_scope", "domain_sequence", "time_domain"):
            with self.subTest(field=field):
                missing = copy.deepcopy(payload)
                del missing["result"]["analysis"]["timeline"][0][field]
                with self.assertRaises(ValidationError):
                    validator.validate(missing)

        invalid = copy.deepcopy(payload)
        invalid["result"]["analysis"]["timeline"][0]["time_domain"] = "mixed"
        with self.assertRaises(ValidationError):
            validator.validate(invalid)

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, "jsonschema is only needed for contract-development tests")
    def test_schema_accepts_sensitive_context_profile(self) -> None:
        return_code, payload = self.run_json_cli(
            [
                "--bundle-dir",
                str(self.login_fixture),
                "--validate-only",
                "--include-sensitive-context",
            ]
        )
        self.assertEqual(return_code, 0)
        self.assertEqual(payload["output_policy"]["profile"], "sensitive_context")
        self.assertFalse(payload["output_policy"]["common_identifier_redaction"])
        self.assertNotIn("identifier_redaction", payload["output_policy"])
        validator_for(self.schema)(self.schema).validate(payload)

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, "jsonschema is only needed for contract-development tests")
    def test_schema_accepts_error_payload(self) -> None:
        return_code, payload = self.run_json_cli([])
        self.assertEqual(return_code, 1)
        self.assertFalse(payload["ok"])
        validator_for(self.schema)(self.schema).validate(payload)

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, "jsonschema is only needed for contract-development tests")
    def test_removed_remote_source_arguments_are_rejected(self) -> None:
        return_code, payload = self.run_json_cli(["--ip", "bmc.example.com"])
        self.assertEqual(return_code, 2)
        self.assertEqual(payload["code"], "argument_error")
        self.assertFalse(payload["ok"])
        validator_for(self.schema)(self.schema).validate(payload)

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, "jsonschema is only needed for contract-development tests")
    def test_schema_accepts_non_empty_runtime_error_payload(self) -> None:
        fixture = self.login_fixture
        with mock.patch("analyze_bundle.validate_bundle_structure", side_effect=RuntimeError()):
            return_code, payload = self.run_json_cli(
                ["--bundle-dir", str(fixture), "--validate-only"]
            )
        self.assertEqual(return_code, 1)
        self.assertEqual(payload["code"], "runtime_error")
        self.assertTrue(payload["error"])
        validator_for(self.schema)(self.schema).validate(payload)

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, "jsonschema is only needed for contract-development tests")
    def test_schema_accepts_error_with_partial_analysis(self) -> None:
        fixture = self.login_fixture
        with tempfile.TemporaryDirectory() as tmp_dir:
            archive = pathlib.Path(tmp_dir) / "bundle.tar.gz"
            archive.write_bytes(b"placeholder")
            extract_result = analyzer.ExtractionResult(
                extract_dir=fixture,
                bundle_root=fixture,
            )
            with mock.patch("analyze_bundle.tarfile.is_tarfile", return_value=True), mock.patch(
                "analyze_bundle.extract_archive",
                return_value=extract_result,
            ), mock.patch(
                "analyze_bundle.sha256_file",
                side_effect=["a" * 64, "b" * 64],
            ):
                return_code, payload = self.run_json_cli(
                    ["--bundle", str(archive), "--problem", "BMC 登录失败"]
                )

        self.assertEqual(return_code, 1)
        self.assertEqual(payload["code"], "bundle_identity_changed")
        self.assertIn("analysis", payload["result"])
        validator_for(self.schema)(self.schema).validate(payload)

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, "jsonschema is only needed for contract-development tests")
    def test_schema_accepts_invalid_numeric_option_payloads(self) -> None:
        for arguments in (
            ["--analysis-max-files", "0"],
            ["--analysis-max-lines", str(analyzer.MAX_ANALYSIS_MAX_LINES + 1)],
            ["--analysis-max-total-bytes", str(analyzer.MAX_ANALYSIS_MAX_TOTAL_BYTES + 1)],
        ):
            with self.subTest(arguments=arguments):
                return_code, payload = self.run_json_cli(arguments)
                self.assertEqual(return_code, 1)
                self.assertEqual(payload["code"], "invalid_request")
                validator_for(self.schema)(self.schema).validate(payload)


class CommunityContractTests(unittest.TestCase):
    def test_manifest_is_a_bidirectional_file_inventory(self) -> None:
        manifest = json.loads((SKILL_ROOT / "skill.json").read_text(encoding="utf-8"))
        listed = set(manifest["files"])
        actual = {
            path.relative_to(SKILL_ROOT).as_posix()
            for path in SKILL_ROOT.rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and ".pytest_cache" not in path.parts
            and path.suffix != ".pyc"
        }
        self.assertEqual(listed, actual)

    def test_fixture_sources_materialize_production_log_names(self) -> None:
        with tempfile.TemporaryDirectory(prefix="openubmc-fixture-contract-") as tmp_dir:
            restored = behavior_evals.materialize_analysis_fixture(
                "evals/fixtures/login-bundle",
                pathlib.Path(tmp_dir) / "login-bundle",
            )
            self.assertTrue((restored / "dump_info" / "LogDump" / "security.log").is_file())
            self.assertTrue((restored / "dump_info" / "LogDump" / "operation.log").is_file())

    def test_normal_analysis_uses_progressive_disclosure(self) -> None:
        skill_text = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertNotIn("Read [references/logs.json]", skill_text)
        self.assertIn("normal analysis does not require loading these catalog references into context", skill_text)
        self.assertIn("References to load only when needed", skill_text)

    def test_declared_evals_drive_the_behavior_runner(self) -> None:
        document = json.loads((SKILL_ROOT / "evals" / "evals.json").read_text(encoding="utf-8"))
        executable = [item for item in document["evals"] if item.get("execution")]
        self.assertGreaterEqual(len(executable), 5)
        for item in executable:
            execution = item["execution"]
            if execution.get("fixture"):
                self.assertIn(execution["fixture"], item["files"])
            else:
                self.assertEqual(execution.get("generator"), "damaged_gzip")
            self.assertTrue(execution.get("checks") or execution.get("golden"))

        namespace = runpy.run_path(str(SKILL_ROOT / "evals" / "run_behavior_evals.py"))
        result = namespace["run_behavior_evals"]()
        self.assertTrue(result["ok"])
        self.assertEqual(result["declared_eval_count"], len(document["evals"]))
        self.assertEqual(result["executable_eval_count"], len(executable))
        self.assertGreaterEqual(result["route_negative_case_count"], 6)


if __name__ == "__main__":
    unittest.main()
