# Build routing and tool equivalence

The packaged Build Skill owns local `bmcgo` validation, component package, and product artifact plans. An explicit `bingo` build command or Bingo configuration is handed to `openubmc-bingo-build`; Bingo CLI development is handed to `openubmc-bingo-development`; environment installation is handed to `openubmc-environment-setup`; package publication is handed to `openubmc-publish`.

The public preflight receipt is generated with `scripts/build_route.py --request ... --workspace ...`. A product or component request must pass its workspace precondition before a command is selected. A missing precondition stops the route and does not fall through to another build system.

Replacing the selected tool requires an equivalence receipt. It must bind the same source identity, profile, options, dependency graph, expected artifact, and release gates. A missing field is a preflight failure; a successful command alone is not proof of equivalence.

Representative ownership examples:

| Request | Owner | Mode |
| --- | --- | --- |
| `bmcgo build -b openUBMC` / “构建产品 HPM” | `openubmc-build` | `product-artifact` |
| “编译组件并运行单测” | `openubmc-build` | `validate` |
| `bingo build` / “用 bingo 构建组件” | `openubmc-bingo-build` | handoff |
| `bingo build -t publish -b <board> -bt release --stage stable` | `openubmc-bingo-build` | handoff |
| “开发 bingo 构建工具” | `openubmc-bingo-development` | handoff |
| “安装构建环境” | `openubmc-environment-setup` | handoff |
