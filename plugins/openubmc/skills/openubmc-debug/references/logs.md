# Runtime Log Evidence

Use this card after preflight reports `remote_log_file` capability, or analyze an offline bundle with `openubmc-log-analyzer`.

Keep the task repository as the working directory and invoke helpers from `$HOME/.agents/skills/openubmc-debug`.

The bundled `collect_logs.py` helper currently uses Telnet. If the capability is unavailable, use
another validated read-only channel or request a log bundle.

Common live logs include `app.log`, `framework.log`, and their rotations. Discover actual files on the target instead of assuming every image has the same set.

```bash
python "$HOME/.agents/skills/openubmc-debug/scripts/collect_logs.py" \
  --ip <ip> \
  --logs app.log,framework.log \
  --grep '<literal>' \
  --lines 200 \
  --max-bytes 262144 \
  --since-boot \
  --json --compact-json
```

Use `--include-rotated` only when the time window needs rotations. Bound line count, rotation count, bytes, and keywords. `--rotated-limit` accepts only positive values and has a hard cap of 32 files per requested log; zero never means “all”. Rotation discovery is itself bounded by both candidate count and bytes before Telnet receives the result. `rotation_discovery_truncated` means rotated-file enumeration was incomplete, so the helper falls back to the explicitly requested current path instead of treating omitted rotations as absent.

`--max-bytes` applies independently to each selected current or rotated log. Its default is 256 KiB and its hard cap is 4 MiB. The remote pipeline emits at most `max_bytes + 1` probe bytes, and the local parser returns at most `max_bytes`. Every entry exposes `bytes_returned`, `truncated`, and `content_complete`. A successful bounded prefix remains `ok: true` with `code: ok`, but `truncated: true`, `content_complete: false`, and `content_truncated_at_max_bytes` explicitly make the evidence incomplete. Such a prefix can support a positive hit that it contains; an empty or non-matching truncated prefix cannot support a complete negative finding. Narrow the selector or deliberately raise the limit and re-read.

Preserve whether boot time was available, whether `since-boot` was actually applied, and the collected numeric `result.utc_offset_minutes` used to interpret local timestamps. If the offset is unavailable, keep timestamp correlation incomparable instead of assuming UTC.

Set `--command-timeout` for each Telnet metadata or log-read command independently from connection and login timeouts. A combined workflow must pass a value no larger than its remaining global deadline.

Each selected current or rotated log must remain under `/var/log`, have no symbolic-link component, and resolve to a regular file. The remote guard checks every path component before reading: a symlink, non-directory parent, device, pipe, directory, or out-of-scope discovery result fails closed as `log_path_unsafe`; a missing leaf is `log_file_not_found`; an inaccessible parent or unreadable regular leaf is `log_file_unreadable`. Returned text, JSON, errors, and `--output-dir` files preserve the collected content within the configured bounds.

Telnet is an interactive line transport. The helper keeps each fully framed
remote command below a conservative input-line boundary and batches long keyword
sets without changing the requested literal terms. A single oversized keyword,
unsafe filename, incomplete frame, timeout, or closed connection fails with a
bounded stable error; raw unframed terminal output is never copied wholesale
into the JSON error.

Login/expect data has a 64 KiB ceiling and each command response has an 8 MiB transport ceiling.
`telnet_output_limit_exceeded` closes the connection, returns `125`, and omits the received prefix
from public JSON. A private debug dump keeps at most the configured ceiling.

Each entry must distinguish file not found, unreadable file, transport/command failure, successful empty filter result, and successful non-empty evidence. Use `log_file_not_found` and `log_file_unreadable` for the first two cases. Separately classify a symlink, unsafe parent, or non-regular leaf as `log_path_unsafe`; none of these failures may be converted into an empty negative finding.

For alarm correlation, first read current alarms, then run a separate since-boot query using stable `EventName`/`EventCode`. Keep a user keyword query as independent evidence. Claim an identity timeline only when state transition, runtime instance/component, and target timestamp occur on the same log reference. If sample/reading and threshold/limit are required, they must occur on that identity-aligned reference rather than on unrelated lines.
