"""The reviewed contract selector must cross the packaged native boundary."""
import json
from pathlib import Path
import subprocess
import unittest

PLUGIN = Path(__file__).resolve().parents[2] / "plugins/openubmc"


class ContractSelectorTests(unittest.TestCase):
    def test_operator_selector_reaches_linux_backend(self):
        manifest = json.loads((PLUGIN / ".mcp.json").read_text())
        self.assertIn("OPENUBMC_MDB_PROPERTY_CONTRACTS",
                      manifest["mcpServers"]["openubmc-target-runtime"]["env_vars"])
        script = """const {createHostAdapter}=require(process.argv[1]);
const a=createHostAdapter({pluginRoot:process.argv[2],hostPlatform:'linux',environment:{
  OPENUBMC_MDB_PROPERTY_CONTRACTS:'/tmp/operator/reviewed-contracts.json',
  HOME:process.env.HOME}});
process.stdout.write(JSON.stringify({environment:a.childEnvironment,execution_host:a.executionHost}));"""
        result = subprocess.run(["node", "-e", script, str(PLUGIN / "scripts/openubmc-bootstrap-host.js"), str(PLUGIN)],
                                check=True, capture_output=True, text=True, timeout=15)
        report = json.loads(result.stdout)
        environment = report["environment"]
        self.assertEqual(environment["OPENUBMC_MDB_PROPERTY_CONTRACTS"], "/tmp/operator/reviewed-contracts.json")
        self.assertEqual(report["execution_host"], "linux")


if __name__ == "__main__":
    unittest.main()
