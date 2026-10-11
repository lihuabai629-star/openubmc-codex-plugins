# 2.1.6

Windows startup probes run the already verified execution snapshot, avoiding a
second scan of the plugin across the Windows/WSL filesystem boundary. Each MCP
preflight checks its own capability and shares package verification with orphan
cleanup. Protocol probes retain their bounded timeout and report timeouts
separately from missing dependencies. Package text uses LF on every checkout.

Trusted session and prompt hooks point to the installed workflow guide, including
when the backend is unavailable. Each workflow Skill links to the guide for
phase changes. The guide selects the current owner and carries existing Run
identity and authorization. Hook delivery alone does not establish that a model
read a Skill or completed a stage.

Bingo command/source references and dependency/profile compatibility guidance
are available from the corresponding packaged Skills. Name-based loose-Skill
disables are recognized when Windows and WSL expose different paths.

Dependency preparation rejects npm installations missing their direct packages,
even when npm reports a zero exit code after a registry failure.
