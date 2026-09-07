# Python entrypoints

Run the packaged scripts from an external working directory:

```bash
python3 <plugin-root>/skills/openubmc-debug/scripts/target_runtime_cli.py --help
python3 -I -B <plugin-root>/skills/openubmc-debug/scripts/target_runtime_cli.py --help
```

Python entrypoints check the package before importing sibling modules and use a fresh
temporary cache location with bytecode writing disabled. Keep logs, extracted files,
configuration and other output outside the plugin directory. The MCP entries in `.mcp.json`
select the required interpreter flags automatically.

For a Python integration that imports a packaged script, initialize the process before
the first plugin import:

```python
from pathlib import Path
import runpy

plugin_root = Path("/absolute/plugin-root")
entry = plugin_root / "skills/openubmc-debug/scripts/target_runtime_cli.py"
guard = runpy.run_path(str(entry.with_name("_plugin_entrypoint.py")))
import_scope = guard["initialize"](entry)

import target_runtime_cli

target_runtime_cli.main(["--help"])
```

Keep `import_scope` alive while using the imported modules. Initialization verifies the
package and makes its script directory available to the current process. Python children
are separate interpreters: invoke a packaged entrypoint and pass `-B` explicitly, including
when using `-I`.

Direct imports without initialization are outside this invocation contract. An external
importer can write a module's own cache before its code runs; `-B` alone can still read
existing bytecode. The package cache is not a Python `site-packages` directory.

If integrity verification reports unexpected bytecode or another changed file, restore the
verified distribution through the plugin installation flow. The integrity check continues
to reject extra files rather than treating them as trusted executable code.
