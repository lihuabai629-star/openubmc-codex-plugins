"""Native Windows export ACL, idempotency and explicit retention acceptance."""
import os
import importlib
import runpy
import subprocess
from pathlib import Path
import tempfile
import time
import unittest

tool = Path(__file__).resolve().parents[1] / "tools/record_export.py"
if not tool.is_file():
    tool = Path(__file__).resolve().parents[2] / "plugins/openubmc/skills/openubmc-target-runtime/tools/record_export.py"
api = runpy.run_path(str(tool))
RecordExportStore = api["RecordExportStore"]
export_task_records = api["export_task_records"]
HostContinuity = importlib.import_module(api["RECORD_PACKAGE_NAME"] + ".host_continuity").HostContinuity
windows_private = importlib.import_module(api["RECORD_PACKAGE_NAME"] + ".windows_private")



@unittest.skipUnless(os.name == "nt", "requires native Windows ACL APIs")
class WindowsRecordExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # The runner may create fixture objects with Administrators as owner.
        # Only this newly created disposable root is normalized; existing user
        # directories continue to be rejected by the production authority.
        windows_private._harden(self.root, directory=True)
        handoff = HostContinuity(self.root / "host", record_schema_version=2).handoff("task", read_run=lambda run: None)
        self.document = export_task_records(handoff, producer_commit="b" * 40)

    def test_export_creates_private_acl_and_identical_write_reuses_same_file(self):
        verify_private_path = windows_private.verify_private_path
        store = RecordExportStore(self.root / "exports")
        path = store.write(self.document)
        verify_private_path(store.root)
        verify_private_path(path)
        self.assertEqual(store.write(self.document), path)
        self.assertEqual(path.stat().st_nlink, 1)

    def test_preview_preserves_export_and_apply_only_removes_qualified_file(self):
        store = RecordExportStore(self.root / "exports")
        path = store.write(self.document)
        other = store.root / "user.json"
        other.write_text("user document")
        cutoff = time.time() + 10
        self.assertEqual(store.prune(before_timestamp=cutoff), [path.name])
        self.assertTrue(path.exists())
        self.assertEqual(store.prune(before_timestamp=cutoff, dry_run=False), [path.name])
        self.assertFalse(path.exists())
        self.assertTrue(other.exists())

    def test_existing_shared_directory_is_rejected_without_repairing_it(self):
        WindowsPrivateError = windows_private.WindowsPrivateError
        target = self.root / "shared"
        target.mkdir()
        subprocess.run(["icacls.exe", str(target), "/grant", "*S-1-5-32-545:(R)"],
                       check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        with self.assertRaises((ValueError, WindowsPrivateError)):
            RecordExportStore(target).write(self.document)
        self.assertEqual(list(target.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
