# Localized Mechanism Checks

Use this reference only after the normal evidence path has narrowed the problem to a runtime mechanism. Preserve the evidence boundary: collect the actual unit, config, service, object, source path, compiler flags, and logs before assigning cause. Do not turn generic Linux advice into an openUBMC claim.

## Systemd and Skynet Startup

- With an already authorized read-only host interface, capture `systemctl status <service>` and `journalctl -u <service> -n 100`; inspect the actual unit's `ExecStart`, `config.cfg`, dependencies, resource limits, and `src/service/main.lua`. The built-in diagnostic collector has no systemd command lane; without that external interface, report the current unit state and its cause as unverified.
- For a component that did not start, trace `config:set_start(...)`, `config:include_app(...)`, `MODULE_NAME`, configured thread count, `sd_bus` setup, and the service entrypoint. Do not infer a missing component or an acceptable thread count without source or runtime evidence.

## MDB and D-Bus

- Establish the real `<bus-name>` and `<object-path>`, then inspect with `source /etc/profile`, `busctl --user tree <bus-name>`, and `busctl --user introspect <bus-name> <object-path>` when the selected read-only lane permits it.
- If an object is absent, trace the actual MDS/MDB definitions, generated boundary, and component initialization; a failed query alone does not prove the object should exist or that code generation is the cause.

## Lua Coroutine and Tasks

- Treat `skynet.fork` as a coroutine, not an operating-system thread. `skynet.sleep(100)` is one second because the unit is 1/100 second.
- Check for long blocking work, incorrect sleep-unit conversion, duplicate schedules, and tasks that are not stopped when their owner exits.

## ASAN-family Reports

- Record sanitizer compile options, `ASAN_OPTIONS`/`UBSAN_OPTIONS`/`LSAN_OPTIONS`, trigger command, and log location before interpreting a report.
- For persistent processes, use the documented exit-detection procedure; do not assume that an absent leak report proves the process is clean or substitute an unrelated generic tool first.

## OpenUBMC Names

- Keep `openUBMC` distinct from `OpenBMC`. Do not assume `xyz.openbmc_project.*` or `/xyz/openbmc_project/*` names apply.
- Never invent service names such as `openubmc-manager`. Use a bus name, object path, component, or service only after it is evidenced in the target, repository, or supported documentation.
