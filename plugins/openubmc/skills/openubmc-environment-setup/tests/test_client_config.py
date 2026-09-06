#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CLIENT_CONFIG = ROOT / "scripts" / "client_config.py"


def load_client_config():
    spec = importlib.util.spec_from_file_location(
        "openubmc_environment_client_config", CLIENT_CONFIG
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ClientConfigTests(unittest.TestCase):
    def test_skill_package_includes_client_configuration_module(self) -> None:
        manifest = json.loads((ROOT / "skill.json").read_text(encoding="utf-8"))

        self.assertIn("scripts/client_config.py", manifest["files"])

    def test_parse_toml_mcp_entry_ignores_multiline_string_structure(self) -> None:
        self.assertTrue(
            CLIENT_CONFIG.is_file(), "client configuration module is missing"
        )
        client_config = load_client_config()
        document = '''
notes = """
[mcp_servers.fake]
command = "/should/not/be/parsed"
"""

[mcp_servers."openubmc\u002dtarget\u002druntime"]
command = "/opt/openubmc-target-runtime"
'''

        self.assertEqual(
            client_config.parse_toml_mcp_entry(
                document,
                "openubmc-target-runtime",
                allow_missing_args=True,
            ),
            {
                "type": "stdio",
                "command": "/opt/openubmc-target-runtime",
                "args": [],
            },
        )

    def test_migrate_toml_alias_renames_escaped_table_without_reformatting(self) -> None:
        client_config = load_client_config()
        original = (
            'title = "keep"\n\n'
            '[mcp_servers."openubmc\\u002dstudio"]\n'
            'command = "/opt/external-kb"\n'
            'args = ["serve", "--stdio"]\n'
        )

        migration = client_config.migrate_toml_alias(
            original,
            legacy_name="openubmc-studio",
            current_name="openubmc-kb",
            default_url="http://localhost:9876/mcp",
            current_managed=False,
        )

        self.assertEqual(migration.action, "renamed")
        self.assertEqual(
            migration.text,
            'title = "keep"\n\n'
            '[mcp_servers.openubmc-kb]\n'
            'command = "/opt/external-kb"\n'
            'args = ["serve", "--stdio"]\n',
        )

    def test_migrate_json_alias_removes_only_installer_default_duplicate(self) -> None:
        client_config = load_client_config()
        original = json.dumps(
            {
                "keep": True,
                "mcpServers": {
                    "openubmc-kb": {"type": "stdio", "command": "/managed", "args": []},
                    "openubmc-studio": {
                        "type": "http",
                        "url": "http://localhost:9876/mcp",
                    },
                },
            }
        )

        migration = client_config.migrate_json_alias(
            original,
            legacy_name="openubmc-studio",
            current_name="openubmc-kb",
            default_url="http://localhost:9876/mcp",
            current_managed=True,
        )

        self.assertEqual(migration.action, "removed")
        document = json.loads(migration.text)
        self.assertTrue(document["keep"])
        self.assertEqual(set(document["mcpServers"]), {"openubmc-kb"})

    def test_parse_json_mcp_entry_preserves_custom_external_fields(self) -> None:
        client_config = load_client_config()
        entry = {
            "type": "stdio",
            "command": "/opt/external-runtime",
            "env": {"MODE": "read-only"},
        }

        self.assertEqual(
            client_config.parse_json_mcp_entry(
                json.dumps({"mcpServers": {"openubmc-target-runtime": entry}}),
                "openubmc-target-runtime",
            ),
            entry,
        )


if __name__ == "__main__":
    unittest.main()
