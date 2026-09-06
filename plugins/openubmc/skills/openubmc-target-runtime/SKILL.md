---
name: openubmc-runtime-support
description: Explain the packaged Runtime engine identity and recovery authority when inspecting an OpenUBMC plugin installation.
---

Use the plugin's `scripts/pluginctl.py doctor` command to inspect package identity and startup readiness. The `observe` and `execute` MCP tools own operational workflows. Runtime state and MutationJournal records remain external to the plugin and survive installation changes.
