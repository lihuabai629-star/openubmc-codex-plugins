"""The reviewed contract selector must cross the packaged native boundary."""
import json
from pathlib import Path
import subprocess
import unittest

PLUGIN = Path(__file__).resolve().parents[2] / "plugins/openubmc"


class ContractSelectorTests(unittest.TestCase):
    def test_operator_selector_reaches_native_backend_without_ambient_secrets(self):
        manifest = json.loads((PLUGIN / ".mcp.json").read_text())
        self.assertIn("OPENUBMC_MDB_PROPERTY_CONTRACTS",
                      manifest["mcpServers"]["openubmc-target-runtime"]["env_vars"])
        script = """const {createHostAdapter}=require(process.argv[1]);
const a=createHostAdapter({pluginRoot:process.argv[2],hostPlatform:'win32',environment:{
  USERPROFILE:'C:\\\\operator',LOCALAPPDATA:'C:\\\\operator\\\\AppData\\\\Local',
  OPENUBMC_MDB_PROPERTY_CONTRACTS:'C:\\\\operator\\\\reviewed-contracts.json',
  OPENUBMC_CREDENTIALS_FILE:'ambient-secret',OPENUBMC_KB_PASSWORD:'ambient-secret'}});
process.stdout.write(JSON.stringify(a.childEnvironment));"""
        result = subprocess.run(["node", "-e", script, str(PLUGIN / "scripts/openubmc-bootstrap-host.js"), str(PLUGIN)],
                                check=True, capture_output=True, text=True, timeout=15)
        environment = json.loads(result.stdout)
        self.assertEqual(environment["OPENUBMC_MDB_PROPERTY_CONTRACTS"], r"C:\operator\reviewed-contracts.json")
        self.assertEqual(environment["OPENUBMC_EXECUTION_HOST"], "windows-native")
        self.assertNotIn("ambient-secret", environment.values())


if __name__ == "__main__":
    unittest.main()
