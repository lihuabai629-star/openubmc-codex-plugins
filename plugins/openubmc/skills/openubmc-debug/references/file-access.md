# Live File Evidence

Use this card after selecting the `remote_log_file` evidence path and confirming a read-only file capability.

Keep the task repository as the working directory and invoke helpers from `$HOME/.agents/skills/openubmc-debug`.

The bundled `read_remote_file.py` helper currently uses Telnet. Use it when preflight reports the
capability. Otherwise use another validated read-only channel or request an offline copy.

```bash
python "$HOME/.agents/skills/openubmc-debug/scripts/read_remote_file.py" --ip <ip> --path /etc/version.json --json --compact-json
python "$HOME/.agents/skills/openubmc-debug/scripts/read_remote_file.py" --ip <ip> --path /proc/uptime --sed-range 1:1 --json --compact-json
python "$HOME/.agents/skills/openubmc-debug/scripts/read_remote_file.py" --ip <ip> --path /etc/os-release --grep version,name --json --compact-json
```

Bound reads with `--head`, `--tail`, `--grep`, `--sed-range`, or a small known file. Use `collect_logs.py` for log timelines and rotations. Record path, command, target timestamp, line count, truncation/filtering, and failure code.

Use `--command-timeout` to bound the remote read independently from `--connect-timeout` and `--prompt-timeout`. When a parent workflow has a smaller remaining deadline, pass that smaller value to the helper rather than allowing its per-command timeout to outlive the workflow.

`--max-bytes` is an evidence boundary, not proof that the returned prefix is the whole result. The helper probes one byte beyond the limit and returns `result.bytes_returned`, `result.truncated`, and `result.content_complete`. When `truncated: true`, it returns only the bounded prefix, adds `content_truncated_at_max_bytes`, and sets `content_complete: false`. Such a result may support a positive hit inside the prefix, but it cannot establish absence or a complete negative finding; narrow the selector or raise the bound deliberately and re-read.

Internal development mode accepts any explicitly supplied absolute path, including credential-labelled or
system-sensitive locations. The remote guard still accepts only a regular, non-symlink file. A
directory, pipe, socket, device, or symlink fails closed even when it is readable; resolve a symlink
to its actual regular-file path before retrying. Returned lines and errors are preserved exactly
within the selected byte and line bounds.

Transport timeout, incomplete framing, non-regular files, rejected symlinks, unreadable files, missing files, and truncated prefixes are limitations or incomplete evidence. They are not successful complete empty content.

Login/expect data has a 64 KiB ceiling and each command response has an 8 MiB transport ceiling.
`telnet_output_limit_exceeded` closes the connection, returns `125`, and never copies the captured
prefix into public JSON; a private debug dump remains bounded by the same ceiling.
