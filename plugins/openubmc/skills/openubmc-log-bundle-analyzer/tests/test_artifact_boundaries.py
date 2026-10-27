from __future__ import annotations

import collections
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT_DIR = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import log_bundle_artifact as artifact  # type: ignore  # noqa: E402
from log_bundle_common import BundleAnalysisError  # type: ignore  # noqa: E402


class RootDiscoveryBoundaryTests(unittest.TestCase):
    def test_locate_bundle_root_enforces_entry_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            (root / "one").mkdir()
            (root / "two").mkdir()
            (root / "three" / "dump_info").mkdir(parents=True)

            with mock.patch.object(artifact, "MAX_DIRECTORY_ENTRIES", 2):
                with self.assertRaises(BundleAnalysisError) as raised:
                    artifact.locate_bundle_root(root)

        self.assertEqual(raised.exception.code, "bundle_limits_exceeded")

    def test_locate_bundle_root_enforces_depth_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            (root / "one" / "two" / "dump_info").mkdir(parents=True)

            with mock.patch.object(artifact, "MAX_DIRECTORY_DEPTH", 2):
                with self.assertRaises(BundleAnalysisError) as raised:
                    artifact.locate_bundle_root(root)

        self.assertEqual(raised.exception.code, "bundle_limits_exceeded")


class ExtractedDirectoryBoundaryTests(unittest.TestCase):
    def test_validate_bundle_rejects_nonportable_entry_names(self) -> None:
        for relative_name in ("bad\\name.txt", "bad\x01name.txt", "bad\x7fname.txt"):
            with self.subTest(relative_name=repr(relative_name)):
                with tempfile.TemporaryDirectory() as tmp_dir:
                    root = pathlib.Path(tmp_dir)
                    log_dir = root / "dump_info" / "LogDump"
                    log_dir.mkdir(parents=True)
                    (log_dir / "app.log").write_text("error\n", encoding="utf-8")
                    if os.name == "nt":
                        entry = mock.Mock()
                        entry.name = relative_name
                        # Windows interprets backslashes as separators and rejects control names.
                        with mock.patch.object(artifact.os, "scandir") as scandir:
                            scandir.return_value.__iter__.return_value = iter([entry])
                            with self.assertRaises(BundleAnalysisError) as raised:
                                artifact.validate_bundle_structure(root)
                    else:
                        (root / "dump_info" / relative_name).write_text("opaque\n", encoding="utf-8")
                        with self.assertRaises(BundleAnalysisError) as raised:
                            artifact.validate_bundle_structure(root)

                self.assertEqual(raised.exception.code, "bundle_layout_invalid")

    def test_validate_bundle_rejects_nonportable_nested_component_names(self) -> None:
        for component_name in ("bad\\component", "bad\x01component", "bad\x7fcomponent"):
            with self.subTest(component_name=repr(component_name)):
                with tempfile.TemporaryDirectory() as tmp_dir:
                    root = pathlib.Path(tmp_dir)
                    appdump = root / "dump_info" / "AppDump"
                    appdump.mkdir(parents=True)
                    entry = mock.Mock()
                    entry.name = component_name
                    original_scandir = artifact.os.scandir

                    def scandir(directory):
                        if pathlib.Path(directory) != appdump:
                            return original_scandir(directory)
                        entries = mock.MagicMock()
                        entries.__iter__.return_value = iter([entry])
                        return entries

                    if os.name == "nt":
                        with mock.patch.object(artifact.os, "scandir", side_effect=scandir):
                            with self.assertRaises(BundleAnalysisError) as raised:
                                artifact.validate_bundle_structure(root)
                    else:
                        component_dir = appdump / component_name
                        component_dir.mkdir()
                        (component_dir / "mdb_info.log").write_text("object\n", encoding="utf-8")
                        with self.assertRaises(BundleAnalysisError) as raised:
                            artifact.validate_bundle_structure(root)

                self.assertEqual(raised.exception.code, "bundle_layout_invalid")

    def test_validate_bundle_enforces_entry_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            (log_dir / "one.log").write_text("one\n", encoding="utf-8")
            (log_dir / "two.log").write_text("two\n", encoding="utf-8")

            with mock.patch.object(artifact, "MAX_DIRECTORY_ENTRIES", 2):
                with self.assertRaises(BundleAnalysisError) as raised:
                    artifact.validate_bundle_structure(root)

        self.assertEqual(raised.exception.code, "bundle_limits_exceeded")

    def test_validate_bundle_enforces_depth_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            deep_file = root / "dump_info" / "LogDump" / "one" / "two" / "app.log"
            deep_file.parent.mkdir(parents=True)
            deep_file.write_text("error\n", encoding="utf-8")

            with mock.patch.object(artifact, "MAX_DIRECTORY_DEPTH", 3):
                with self.assertRaises(BundleAnalysisError) as raised:
                    artifact.validate_bundle_structure(root)

        self.assertEqual(raised.exception.code, "bundle_limits_exceeded")

    def test_validate_bundle_enforces_file_byte_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_file = root / "dump_info" / "LogDump" / "app.log"
            log_file.parent.mkdir(parents=True)
            log_file.write_bytes(b"12345")

            with mock.patch.object(artifact, "MAX_DIRECTORY_BYTES", 4):
                with self.assertRaises(BundleAnalysisError) as raised:
                    artifact.validate_bundle_structure(root)

        self.assertEqual(raised.exception.code, "bundle_limits_exceeded")

    def test_validate_bundle_scans_each_directory_once_and_preserves_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            dump_info = root / "dump_info"
            (dump_info / "LogDump").mkdir(parents=True)
            (dump_info / "LogDump" / "app.log").write_text("error\n", encoding="utf-8")
            (dump_info / "AppDump" / "account" / "nested").mkdir(parents=True)
            (dump_info / "AppDump" / "account" / "mdb_info.log").write_text(
                "object\n",
                encoding="utf-8",
            )
            (dump_info / "AppDump" / "account" / "nested" / "trace.log").write_text(
                "trace\n",
                encoding="utf-8",
            )
            (dump_info / "VendorOnly" / "details").mkdir(parents=True)
            (dump_info / "VendorOnly" / "details" / "vendor.log").write_text(
                "vendor\n",
                encoding="utf-8",
            )
            (dump_info / "summary.txt").write_bytes(b"summary")

            scanned: list[pathlib.Path] = []
            real_scandir = os.scandir

            def recording_scandir(path: os.PathLike[str] | str):
                scanned.append(pathlib.Path(path).resolve())
                return real_scandir(path)

            with mock.patch.object(artifact.os, "scandir", side_effect=recording_scandir):
                result = artifact.validate_bundle_structure(root)

        self.assertEqual(collections.Counter(scanned).most_common(1)[0][1], 1)
        self.assertEqual(result["sections"]["LogDump"]["file_count"], 1)
        self.assertEqual(result["sections"]["AppDump"]["file_count"], 2)
        self.assertEqual(result["total_file_count"], 5)
        self.assertEqual(
            result["sections"]["AppDump"]["subdirectories"],
            [{"name": "account", "file_count": 2}],
        )
        self.assertEqual(result["unknown_sections"], ["VendorOnly"])
        self.assertEqual(
            result["root_files"],
            [{"path": "dump_info/summary.txt", "size_bytes": 7}],
        )

    def test_validate_bundle_rejects_special_files(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO is not supported on this platform")
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            log_dir = root / "dump_info" / "LogDump"
            log_dir.mkdir(parents=True)
            fifo = log_dir / "unexpected.fifo"
            os.mkfifo(fifo)

            with self.assertRaises(BundleAnalysisError) as raised:
                artifact.validate_bundle_structure(root)

        self.assertEqual(raised.exception.code, "bundle_layout_invalid")


if __name__ == "__main__":
    unittest.main()
