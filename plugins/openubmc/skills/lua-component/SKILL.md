---
name: openubmc-lua-component
description: Compatibility entry for users who explicitly request the former openUBMC Lua component skill. Do not select automatically. Continue the source change through openubmc-developer with its handwritten Lua reference; this entry owns no separate workflow.
---

# openUBMC Lua Component Compatibility Entry

Use this entry only when the user explicitly names `$openubmc-lua-component`.

Continue with `openubmc-developer` as the single source-change workflow and select its `references/lua-component.md` domain reference. Keep adjacent Lua unit tests in that same workflow.

Do not load MDB/MDS, mapping, testing, review, build or runtime skills merely because they appear in the caller chain. Add another Developer reference only when the confirmed authored edit set crosses that boundary. Enter another skill only when the user separately requested its independent stage.

The canonical Lua development rules live in `openubmc-developer`; do not duplicate or evolve them here.
