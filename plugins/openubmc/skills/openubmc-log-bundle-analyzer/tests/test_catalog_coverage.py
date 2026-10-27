from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest


SCRIPT_DIR = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from audit_catalog_coverage import audit_catalog_coverage  # type: ignore  # noqa: E402
from log_bundle_analysis import analyze_bundle, load_reference_data  # type: ignore  # noqa: E402


def write_fixture(root: pathlib.Path, relative_path: str, content: bytes = b"fixture\n") -> None:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


class CatalogCoverageTests(unittest.TestCase):
    def test_audit_distinguishes_semantic_opaque_fallback_and_uncovered_paths(self) -> None:
        reference = {
            "files": [
                {
                    "name": "semantic.log",
                    "paths": ["dump_info/LogDump/semantic.log"],
                    "component": "fixture",
                    "purpose": "semantic fixture",
                    "keywords": ["semantic"],
                },
                {
                    "name": "opaque.bin",
                    "paths": ["dump_info/LogDump/opaque.bin"],
                    "component": "fixture",
                    "purpose": "opaque fixture",
                    "keywords": ["opaque"],
                    "definition_status": "observed_path",
                    "source_type": "validated_bundle_structure",
                    "reliability": "observed_only",
                    "scan_mode": "metadata_only",
                },
                {
                    "name": "logdump_fallback",
                    "paths": ["dump_info/LogDump/*"],
                    "component": "LogDump",
                    "purpose": "section fallback",
                    "keywords": ["unknown artifact"],
                    "definition_status": "observed_path",
                    "source_type": "validated_bundle_structure",
                    "reliability": "observed_only",
                    "scan_mode": "metadata_only",
                    "coverage_class": "generic_fallback",
                },
            ],
            "rules": [],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            write_fixture(root, "dump_info/LogDump/semantic.log")
            write_fixture(root, "dump_info/LogDump/opaque.bin")
            write_fixture(root, "dump_info/LogDump/unknown.dat")
            write_fixture(root, "dump_info/UnknownDump/uncovered.dat")
            result = audit_catalog_coverage(root, reference_data=reference)

        self.assertEqual(result["total_file_count"], 4)
        self.assertEqual(
            result["coverage_counts"],
            {"semantic": 1, "explicit_opaque": 1, "generic_fallback": 1},
        )
        self.assertEqual(result["uncovered_path_count"], 1)
        self.assertFalse(result["catalog_covers_all_paths"])
        self.assertEqual(result["generic_fallback_by_section"], {"LogDump": 1})
        self.assertEqual(
            result["semantic_level_counts"],
            {"path_only": 2, "purpose": 1, "structure": 0, "diagnostic": 0},
        )
        self.assertEqual(result["route_mode_counts"], {"automatic": 1, "explicit_only": 2, "never": 0})
        self.assertEqual(result["scan_mode_counts"], {"text": 1, "metadata_only": 2})
        self.assertEqual(result["purpose_definition_coverage_percent"], 25.0)
        self.assertEqual(result["structure_definition_coverage_percent"], 0.0)
        self.assertEqual(result["diagnostic_definition_coverage_percent"], 0.0)

    def test_audit_flags_same_priority_definition_ambiguity(self) -> None:
        reference = {
            "files": [
                {
                    "name": name,
                    "paths": ["dump_info/LogDump/shared.log"],
                    "component": "fixture",
                    "purpose": "semantic fixture",
                    "keywords": [name],
                }
                for name in ("first", "second")
            ],
            "rules": [],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            write_fixture(root, "dump_info/LogDump/shared.log")
            result = audit_catalog_coverage(root, reference_data=reference)

        self.assertEqual(result["coverage_counts"]["semantic"], 1)
        self.assertEqual(result["ambiguous_path_count"], 1)
        self.assertTrue(result["has_ambiguous_top_definitions"])
        self.assertEqual(
            result["ambiguous_path_samples"][0]["definitions"],
            ["first", "second"],
        )

    def test_audit_flags_conflicting_semantic_and_opaque_contracts(self) -> None:
        reference = {
            "files": [
                {
                    "name": "smart_text",
                    "paths": ["dump_info/LogDump/SMARTAttribute"],
                    "component": "storage",
                    "purpose": "text SMART snapshot",
                    "keywords": ["smart text"],
                },
                {
                    "name": "smart_opaque_rotation",
                    "paths": ["dump_info/LogDump/SMARTAttribute.*"],
                    "component": "storage",
                    "purpose": "opaque SMART rotation",
                    "keywords": ["smart opaque"],
                    "definition_status": "observed_path",
                    "source_type": "validated_bundle_structure",
                    "reliability": "observed_only",
                    "scan_mode": "metadata_only",
                },
            ],
            "rules": [],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            write_fixture(root, "dump_info/LogDump/SMARTAttribute.1")
            result = audit_catalog_coverage(root, reference_data=reference)

        self.assertEqual(result["conflicting_coverage_class_count"], 1)
        self.assertTrue(result["has_conflicting_coverage_classes"])
        self.assertEqual(
            result["conflicting_coverage_class_samples"][0],
            {
                "path": "dump_info/LogDump/SMARTAttribute.1",
                "coverage_classes": ["explicit_opaque", "semantic"],
                "definitions": ["smart_text", "smart_opaque_rotation"],
            },
        )

    def test_repository_catalog_covers_confirmed_path_families(self) -> None:
        paths = (
            "dump_info/AppDump/network_adapter/netcard/netcard_info.txt",
            "dump_info/AppDump/network_adapter/netcard/netcard_info.txt.1",
            "dump_info/LogDump/netcard/netcard_info.txt",
            "dump_info/LogDump/netcard/netcard_info.txt.1",
            "dump_info/LogDump/storage/phy/PCIe_Card_21/PCIe_Card_21_PHY_Error_Count.csv",
            "dump_info/LogDump/storage/phy/PCIe_Card_21/PCIe_Card_21_PHY_Error_Count.1.csv",
            "dump_info/AppDump/event/event.db",
            "dump_info/AppDump/event/event_reset.db",
            "dump_info/AppDump/network_adapter/pciecard/card/error_log_1.bin",
            "dump_info/LogDump/pciecard/card/error_log_1.bin",
            "dump_info/LogDump/pciecard/card/operate_log_1.bin",
            "dump_info/RTOSDump/versioninfo/server_config.txt",
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            for relative_path in paths:
                write_fixture(root, relative_path)
            result = audit_catalog_coverage(root, reference_data=load_reference_data())

        self.assertEqual(result["total_file_count"], len(paths))
        self.assertEqual(
            result["coverage_counts"],
            {"semantic": 6, "explicit_opaque": 6, "generic_fallback": 0},
        )
        self.assertEqual(result["uncovered_path_count"], 0)
        self.assertEqual(result["ambiguous_path_count"], 0)

    def test_repository_catalog_separates_known_purpose_from_payload_scanning(self) -> None:
        paths = (
            "dump_info/AppDump/bios/1/currentvalue.json",
            "dump_info/AppDump/chassis/LedInfo",
            "dump_info/AppDump/mctpd/mctp_info",
            "dump_info/LogDump/lastlog",
            "dump_info/LogDump/kbox_info.1",
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            for relative_path in paths:
                write_fixture(root, relative_path)
            result = audit_catalog_coverage(root, reference_data=load_reference_data())

        self.assertEqual(result["coverage_counts"], {"semantic": 2, "explicit_opaque": 2, "generic_fallback": 1})
        self.assertEqual(
            result["semantic_level_counts"],
            {"path_only": 1, "purpose": 2, "structure": 2, "diagnostic": 0},
        )
        self.assertEqual(result["scan_mode_counts"], {"text": 2, "metadata_only": 3})
        self.assertEqual(result["route_mode_counts"], {"automatic": 2, "explicit_only": 3, "never": 0})
        self.assertEqual(result["uncovered_path_count"], 0)
        self.assertEqual(result["ambiguous_path_count"], 0)

    def test_smart_base_and_numeric_suffix_artifacts_keep_distinct_scan_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            write_fixture(root, "dump_info/LogDump/storage/drivelog/Disk0/SMARTAttribute")
            write_fixture(root, "dump_info/LogDump/storage/drivelog/Disk0/SMARTAttribute.1")

            semantic = analyze_bundle(root, "检查 storage_smartattribute", max_files=1)
            opaque = analyze_bundle(root, "检查 storage_smartattribute_rotations", max_files=1)
            coverage = audit_catalog_coverage(root, reference_data=load_reference_data())

        semantic_log = semantic["selected_logs"][0]
        self.assertEqual(semantic_log["scan_mode"], "text")
        self.assertEqual(
            semantic_log["existing_paths"],
            ["dump_info/LogDump/storage/drivelog/Disk0/SMARTAttribute"],
        )
        opaque_log = opaque["selected_logs"][0]
        self.assertEqual(opaque_log["scan_mode"], "metadata_only")
        self.assertEqual(
            opaque_log["existing_paths"],
            ["dump_info/LogDump/storage/drivelog/Disk0/SMARTAttribute.1"],
        )
        self.assertEqual(coverage["coverage_counts"]["semantic"], 1)
        self.assertEqual(coverage["coverage_counts"]["explicit_opaque"], 1)
        self.assertEqual(coverage["conflicting_coverage_class_count"], 0)

    def test_unstable_binary_and_embedded_nul_artifacts_are_metadata_only(self) -> None:
        cases = (
            (
                "dump_info/LogDump/pciecard/card/operate_log_1.bin",
                "检查 pcie_operate_log.bin",
                b"readable prefix\x00embedded padding\n",
                "pcie_operate_log.bin",
            ),
            (
                "dump_info/RTOSDump/versioninfo/server_config.txt",
                "检查 server_config.txt",
                b"FirmwareVersion=10B6\x000B6\n",
                "server_config.txt",
            ),
            (
                "dump_info/AppDump/event/event.db",
                "检查 event.db",
                b"SQLite format 3\x00binary payload",
                "event.db",
            ),
        )
        for relative_path, problem, content, expected_name in cases:
            with self.subTest(relative_path=relative_path), tempfile.TemporaryDirectory() as tmp_dir:
                root = pathlib.Path(tmp_dir)
                write_fixture(root, relative_path, content)
                result = analyze_bundle(root, problem, max_files=1)

            selected = result["selected_logs"][0]
            self.assertEqual(selected["name"], expected_name)
            self.assertEqual(selected["scan_mode"], "metadata_only")
            self.assertEqual(selected["existing_path_count"], 1)
            self.assertEqual(selected["scanned_path_count"], 0)
            self.assertEqual(selected["scanned_paths"], [])
            self.assertEqual(result["scan"]["scanned_bytes"], 0)
            self.assertEqual(result["scan"]["errors"], [])

    def test_explicit_bundle_filename_selects_generic_appdump_fallback(self) -> None:
        relative_path = "dump_info/AppDump/product_mgmt/hardware_inventory.json"
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            write_fixture(root, relative_path, b'{"serial_number":"must-not-be-scanned"}\n')

            result = analyze_bundle(root, "检查 hardware_inventory.json")

        self.assertEqual(len(result["selected_logs"]), 1)
        selected = result["selected_logs"][0]
        self.assertEqual(selected["name"], "hardware_inventory.json")
        self.assertEqual(selected["existing_paths"], [relative_path])
        self.assertEqual(selected["scan_mode"], "metadata_only")
        self.assertEqual(selected["scanned_path_count"], 0)
        self.assertEqual(selected["routing_basis"], ["explicit_bundle_path"])
        self.assertEqual(result["scan"]["scanned_bytes"], 0)

    def test_explicit_opaque_bundle_filename_does_not_select_component_companions(self) -> None:
        event_paths = (
            "dump_info/AppDump/event/event.db",
            "dump_info/AppDump/event/mdb_info.log",
            "dump_info/AppDump/event/rpc_records.log",
            "dump_info/AppDump/event/sync_property_trace.log",
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            for relative_path in event_paths:
                write_fixture(root, relative_path, b"2026-08-31 event sync failed\n")

            result = analyze_bundle(root, "检查 event.db")

        self.assertEqual([item["name"] for item in result["selected_logs"]], ["event.db"])
        selected = result["selected_logs"][0]
        self.assertEqual(selected["existing_paths"], [event_paths[0]])
        self.assertEqual(selected["scan_mode"], "metadata_only")
        self.assertEqual(selected["scanned_path_count"], 0)
        self.assertEqual(selected["routing_basis"], ["explicit_bundle_path"])
        self.assertEqual(result["assessment"], "insufficient_bundle_evidence")
        self.assertEqual(result["scan"]["scanned_bytes"], 0)

    def test_symptom_slash_does_not_trigger_explicit_bundle_path_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            write_fixture(
                root,
                "dump_info/3rdDump/access_log",
                b"2026-09-02 GET /redfish/v1/ 502 upstream failed\n",
            )
            write_fixture(
                root,
                "dump_info/3rdDump/error_log",
                b"2026-09-02 upstream connection failed\n",
            )
            for index in range(20):
                write_fixture(
                    root,
                    f"dump_info/AppDump/decoy_{index}/nested/status.txt",
                )

            plain = analyze_bundle(root, "Web HTTPS 访问失败")
            with_slash = analyze_bundle(root, "Web/HTTPS 访问失败")

        self.assertEqual(
            [item["name"] for item in with_slash["selected_logs"]],
            [item["name"] for item in plain["selected_logs"]],
        )
        self.assertEqual(
            with_slash["scan"]["path_discovery"]["entries_examined"],
            plain["scan"]["path_discovery"]["entries_examined"],
        )

    def test_ip_address_does_not_trigger_explicit_bundle_path_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            write_fixture(
                root,
                "dump_info/LogDump/security.log",
                b"2026-09-02 login failed\n",
            )
            write_fixture(
                root,
                "dump_info/LogDump/operation.log",
                b"2026-09-02 login failed\n",
            )
            for index in range(20):
                write_fixture(
                    root,
                    f"dump_info/AppDump/decoy_{index}/nested/status.txt",
                )

            plain = analyze_bundle(root, "BMC 登录失败")
            with_ip = analyze_bundle(root, "BMC 10.0.0.1 登录失败")

        self.assertEqual(
            [item["name"] for item in with_ip["selected_logs"]],
            [item["name"] for item in plain["selected_logs"]],
        )
        self.assertEqual(
            with_ip["scan"]["path_discovery"]["entries_examined"],
            plain["scan"]["path_discovery"]["entries_examined"],
        )

    def test_explicit_rotation_does_not_inherit_missing_wildcard_base_contract(self) -> None:
        reference = {
            "files": [
                {
                    "name": "wildcard_text",
                    "paths": ["dump_info/LogDump/*.log"],
                    "component": "fixture",
                    "purpose": "wildcard text fixture",
                    "keywords": ["wildcard"],
                },
                {
                    "name": "logdump_fallback",
                    "paths": ["dump_info/LogDump/*"],
                    "component": "LogDump",
                    "purpose": "fallback fixture",
                    "keywords": ["unknown artifact"],
                    "definition_status": "observed_path",
                    "source_type": "validated_bundle_structure",
                    "reliability": "observed_only",
                    "scan_mode": "metadata_only",
                    "coverage_class": "generic_fallback",
                },
            ],
            "rules": [],
        }
        relative_path = "dump_info/LogDump/orphan.log.1"
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            write_fixture(root, relative_path, b"orphan failed\n")

            result = analyze_bundle(
                root,
                "检查 orphan.log.1",
                reference_data=reference,
            )

        selected = result["selected_logs"][0]
        self.assertEqual(selected["name"], "orphan.log.1")
        self.assertEqual(selected["scan_mode"], "metadata_only")
        self.assertEqual(selected["existing_paths"], [relative_path])
        self.assertEqual(selected["scanned_path_count"], 0)
        self.assertEqual(result["scan"]["scanned_bytes"], 0)

    def test_explicit_rotation_inherits_existing_wildcard_base_contract(self) -> None:
        reference = {
            "files": [
                {
                    "name": "wildcard_text",
                    "paths": ["dump_info/LogDump/*.log"],
                    "component": "fixture",
                    "purpose": "wildcard text fixture",
                    "keywords": ["wildcard", "failed"],
                },
                {
                    "name": "logdump_fallback",
                    "paths": ["dump_info/LogDump/*"],
                    "component": "LogDump",
                    "purpose": "fallback fixture",
                    "keywords": ["unknown artifact"],
                    "definition_status": "observed_path",
                    "source_type": "validated_bundle_structure",
                    "reliability": "observed_only",
                    "scan_mode": "metadata_only",
                    "coverage_class": "generic_fallback",
                },
            ],
            "rules": [],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            write_fixture(root, "dump_info/LogDump/service.log", b"service healthy\n")
            write_fixture(root, "dump_info/LogDump/service.log.1", b"service failed\n")

            result = analyze_bundle(
                root,
                "检查 service.log.1",
                reference_data=reference,
            )

        selected = result["selected_logs"][0]
        self.assertEqual(selected["name"], "service.log.1")
        self.assertEqual(selected["scan_mode"], "text")
        self.assertEqual(
            selected["existing_paths"],
            ["dump_info/LogDump/service.log.1"],
        )
        self.assertEqual(selected["scanned_path_count"], 1)


if __name__ == "__main__":
    unittest.main()
