# Build routing and tool equivalence

The packaged Build Skill owns local `bmcgo` validation, component package, and product artifact plans. An explicit `bingo` build command or Bingo configuration is handed to `openubmc-bingo-build`; Bingo CLI development is handed to `openubmc-bingo-development`; environment installation is handed to `openubmc-environment-setup`; package publication is handed to `openubmc-publish`.

The public preflight receipt is generated with `scripts/build_route.py --request ... --workspace ...`. A product or component request must pass its workspace precondition before a command is selected. A missing precondition stops the route and does not fall through to another build system.

Replacing the selected tool first produces a claim receipt. `build_route.py` leaves
`ready=false` and `plan_binding_required=true` even when the claim has every field.
`create_build_plan.py` checks the claim against the frozen checkout identity,
explicit command profile and options, dependency baseline lock, expected artifact,
and required release gates before writing a Plan. Missing or unmatched evidence
stops the substitution. A validation command without those product bindings cannot
claim equivalence to the routed build tool; use the routed tool or an explicit Bingo
handoff.

Representative ownership examples:

| Request | Owner | Mode |
| --- | --- | --- |
| `bmcgo build -b openUBMC` / “构建产品 HPM” | `openubmc-build` | `product-artifact` |
| “编译组件并运行单测” | `openubmc-build` | `validate` |
| `bingo build` / “用 bingo 构建组件” | `openubmc-bingo-build` | handoff |
| `bingo build -t publish -b <board> -bt release --stage stable` | `openubmc-bingo-build` | handoff |
| “开发 bingo 构建工具” | `openubmc-bingo-development` | handoff |
| “安装构建环境” | `openubmc-environment-setup` | handoff |
