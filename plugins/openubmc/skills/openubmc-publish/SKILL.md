---
name: openubmc-publish
description: Upload already-built openUBMC Conan component packages to an existing Conan remote and verify the exact local and remote refs. Use when the user directly requests component-package publication or continues a build task whose publish stage, artifact refs, and remote are already established. Do not use to build packages, change remotes, publish HPM firmware, or upgrade BMCs.
---

# openUBMC Publish

When the task enters another workflow stage, read [the phase handoff](<../openubmc-debug/references/skill-routing.md>)
and load its owner before acting; carry the existing Run and authorization.

Publish owns only the external upload of an already-built Conan component
package. It never runs bmcgo build, edits a version or manifest, creates a
remote, logs in, uploads an HPM, or upgrades a BMC.

## Required input

Reuse established task facts instead of asking the user to repeat them. Require:

- a direct publish request or a current-task build handoff that already includes the publish stage;
- an existing Conan remote alias from the request, handoff, or unambiguous current task context;
- full binary references from the verified build, binding recipe revision, package ID and package revision.

The direct request authorizes that named upload; do not ask for a second confirmation. If the
current task contains one verified package ref and one established remote, use them directly. Stop
only when multiple materially different refs or remotes remain plausible after inspecting the build
result and local Conan configuration.

Use an exact ref such as:

~~~text
name/version@openubmc/stable#recipe-revision:package-id#package-revision
~~~

Resolve the full identity from the build output and local listing. A recipe-only
upload selects other cached binaries; it is not a bounded package publication.

## Workflow

Use `scripts/publish_package.py --ref '<full-binary-ref>' --remote <remote>` to
verify the local identity and prepare the exact command. Add `--upload` for the
authorized publication. The helper uploads only that binary revision with
`--check`, then queries the same full reference on the named remote. For several
authorized binaries, run it once per verified full reference.

Treat success as upload rc=0 plus the remote listing. Report the exact ref and
remote, but never report credential values.

Failures return a classified `code`, failed `step`, and `diagnostic_path`. Raw Conan output
is saved only in a private per-attempt file under `$XDG_STATE_HOME/openubmc/conan-publish`
(default `~/.local/state/openubmc/conan-publish`). Inspect that file locally before deciding
whether to retry; keep its raw output out of chat. `diagnostics_saved=false` means saving
failed. Authentication, permission, TLS and network failures require their own remedies;
an unknown upload result needs the exact remote listing before any retry.

## Boundaries

This Skill uploads an already-built Conan component with `conan upload`;
Conan has no `conan publish` command.

Do not use bmcgo build -u: it rebuilds before uploading and may force remote
state. Do not use bmcgo publish as a synonym for this Skill; it is a product
build target, not a Conan upload. Do not use --force, --only-recipe, or a
wildcard upload unless the user explicitly expands this scope.
