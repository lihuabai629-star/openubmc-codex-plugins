# Build routing and tool equivalence

The packaged Build Skill owns local `bmcgo` validation, Conan dependency/build diagnosis, component package, and product artifact plans. Bingo builds and Bingo CLI development return an unsupported route. Explicit build-environment installation goes to the separately available `openubmc-env-init`; if absent, report that gap without installing the plugin. Package publication goes to `openubmc-publish`.

The public preflight receipt is generated with `scripts/build_route.py --request ... --workspace ...`. A product or component request must pass its workspace precondition before a command is selected. A missing precondition stops the route and does not fall through to another build system.

Failure analysis selects `diagnose` with no build command. `bmcgo build` alone
is component validation; board selection identifies a product command. A later
upload request stays pending while the current build completes. Publication-only
requests hand off without carrying a build executable into Publish.

Replacing the selected tool first produces a claim receipt. `build_route.py` leaves
`ready=false` and `plan_binding_required=true` even when the claim has every field.
`create_build_plan.py` checks the claim against the frozen checkout identity,
explicit command profile and options, dependency baseline lock, expected artifact,
and required release gates before writing a Plan. Missing or unmatched evidence
stops the substitution. A validation command without those product bindings cannot
claim equivalence to the routed build tool; use the routed tool after its preconditions pass.

Representative ownership examples:

| Request | Owner | Mode |
| --- | --- | --- |
| `bmcgo build -b openUBMC` / “构建产品 HPM” | `openubmc-build` | `product-artifact` |
| “编译组件并运行单测” | `openubmc-build` | `validate` |
| “安装构建环境” | `openubmc-env-init` (if available) | handoff |
