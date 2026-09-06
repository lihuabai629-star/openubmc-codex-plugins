# Separate WSL build environments

When development and product packaging run in different WSL distributions, identify the distribution and workspace for each operation before running a build.

```bash
wsl.exe --list --verbose
wsl.exe -d <distribution> -- bash -lc 'pwd'
```

Run manifest-side `bmcgo` commands from the selected product manifest root. Component source trees and the manifest must use compatible versions. Paths in one distribution need not exist in another.

Skill helpers run in the environment containing the selected `SKILL.md`. Run each helper inside the environment that can access the intended checkout. Pass long shell scripts over standard input to avoid nested quoting.

Use bounded read-only checks to identify the build tool, workspace, and product. Do not infer a successful build from an HPM filename: require the recorded build result and artifact verification. Separate distributions do not share checkout or build locks unless an external lock owner coordinates them.
