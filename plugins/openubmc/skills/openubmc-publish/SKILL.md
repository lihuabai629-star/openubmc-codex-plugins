---
name: openubmc-publish
description: Upload already-built openUBMC Conan component packages to an existing Conan remote and verify the exact local and remote refs. Use when the user directly requests component-package publication or continues a build task whose publish stage, artifact refs, and remote are already established. Do not use to build packages, change remotes, publish HPM firmware, or upgrade BMCs.
---

# openUBMC Publish

Publish owns only the external upload of an already-built Conan component
package. It never runs bmcgo build, edits a version or manifest, creates a
remote, logs in, uploads an HPM, or upgrades a BMC.

## Required input

Reuse established task facts instead of asking the user to repeat them. Require:

- a direct publish request or a current-task build handoff that already includes the publish stage;
- an existing Conan remote alias from the request, handoff, or unambiguous current task context;
- one or more exact Conan recipe refs, including a recipe revision when needed.

The direct request authorizes that named upload; do not ask for a second confirmation. If the
current task contains one verified package ref and one established remote, use them directly. Stop
only when multiple materially different refs or remotes remain plausible after inspecting the build
result and local Conan configuration.

Use an exact ref such as:

~~~text
name/version@openubmc/stable#recipe-revision
~~~

If a base ref resolves to more than one local recipe revision, first match the verified build
artifact identity. Do not guess a remote or use a wildcard.

## Workflow

1. Confirm the package exists locally:

   ~~~bash
   conan list '<exact-ref>:*' -c --format=json
   ~~~

2. Upload the existing package:

   ~~~bash
   conan upload '<exact-ref>' -r <user-named-remote> -c
   ~~~

3. Confirm the same exact ref is visible remotely:

   ~~~bash
   conan list '<exact-ref>:*' -r <user-named-remote> --format=json
   ~~~

Treat success as upload rc=0 plus the remote listing. Report the exact ref and
remote, but never report credential values.

## Boundaries

Do not use bmcgo build -u: it rebuilds before uploading and may force remote
state. Do not use bmcgo publish as a synonym for this Skill; it is a product
build target, not a Conan upload. Do not use --force, --only-recipe, or a
wildcard upload unless the user explicitly expands this scope.
