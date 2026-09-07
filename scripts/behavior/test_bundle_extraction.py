from __future__ import annotations
import io
import os
import pathlib
import sys
import tarfile
import tempfile
import unittest

SCRIPT_DIR = pathlib.Path(os.environ['OPENUBMC_TEST_PLUGIN_ROOT']) / 'skills/openubmc-log-analyzer/scripts' if os.environ.get('OPENUBMC_TEST_PLUGIN_ROOT') else pathlib.Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPT_DIR))
import pull_bundle


class ExtractArchiveTests(unittest.TestCase):
    def test_invalid_bundles_fail_without_a_partial_result(self) -> None:
        for failure in ("corrupt", "traversal", "symlink", "missing-layout"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as raw:
                root = pathlib.Path(raw)
                archive_path = root / "bundle.tar"
                with tarfile.open(archive_path, "w") as archive:
                    member = tarfile.TarInfo("dump_info/LogDump/partial.log")
                    if failure == "missing-layout":
                        member.name = "partial.log"
                    member.size = 6
                    archive.addfile(member, io.BytesIO(b"error\n"))
                    if failure in ("traversal", "symlink"):
                        unsafe = tarfile.TarInfo("../escape" if failure == "traversal" else "link")
                        if failure == "symlink":
                            unsafe.type = tarfile.SYMTYPE
                            unsafe.linkname = "../escape"
                        archive.addfile(unsafe)
                if failure == "corrupt":
                    archive_path.write_bytes(b"not a tar archive")
                with self.assertRaises(pull_bundle.BundlePullError):
                    pull_bundle.extract_archive(archive_path, root / "extract")
                self.assertFalse((root / "escape").exists())
                self.assertFalse(any((root / "extract").iterdir()))

    def test_same_name_bundle_contains_only_current_members(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            archive_path = root / "bundle.tar.gz"
            for name in ("old.log", "new.log", "new.log"):
                with tarfile.open(archive_path, "w:gz") as archive:
                    member = tarfile.TarInfo("dump_info/LogDump/" + name)
                    member.size = 6
                    archive.addfile(member, io.BytesIO(b"error\n"))
                result = pull_bundle.extract_archive(archive_path, root / "extract")
                files = {path.name for path in result.bundle_root.rglob("*.log")}
                self.assertEqual(files, {name})

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
            result = pull_bundle.extract_archive(archive_path, extract_parent)

            self.assertTrue((result.bundle_root / "dump_info" / "LogDump" / "app.log").exists())
            self.assertTrue(result.extract_dir.exists())



if __name__ == "__main__":
    unittest.main()
