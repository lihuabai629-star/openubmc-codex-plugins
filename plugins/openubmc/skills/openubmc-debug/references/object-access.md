# Remote Object Evidence

Use this card after preflight reports `remote_object` capability.

The bundled object helpers currently use SSH to reach the user bus. Treat that as an implementation detail and record the actual transport. Select the semantic tool from the question:

- `mdbctl_remote.py`: model-oriented class/object/property/method exploration through reviewed read-only commands.
- `busctl_remote.py`: exact service/path/interface/property evidence; generic method calls are blocked.
- `active_alarms.py`: current active alarms with live introspection.

Prefer `mdbctl` for broad openUBMC model exploration and `busctl` for exact D-Bus semantics. A failed `mdbctl` command does not prove the object is absent; cross-check exact service/path/interface using the available object capability.

Capture service, object path, interface, member/property, method signature, returned state, target
time, exit/status, and business-error text. Return to the Skill entrypoint and load only the access
card selected there; this overview does not route another reference.

The bundled helpers have no write override. A blocked command or method is an authorization/ownership boundary, not a prompt to bypass the helper.
