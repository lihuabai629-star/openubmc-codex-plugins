# Conan Remote Authentication

Use this before component upload, manifest dependency resolution, or product builds that need Conan remotes.

## Rules

- Prove auth with `conan remote auth`; `conan remote list-users` can show stale `authenticated: True`.
- Scan auth output for per-remote errors because Conan 2 can return exit code 0 while printing `error:`.
- Use Conan 2 environment variables for credentials. Do not write real passwords into skill files, repos, shell history, or command-line arguments.
- Quote credential variables and preserve punctuation exactly; punctuation such as a trailing comma can be part of a password.
- Do not disable a remote as an auth workaround for product builds unless the user explicitly agrees the remote is not needed.

## Environment Variables

Remote-specific suffixes are the remote names uppercased with `-` replaced by `_`.

```bash
export CONAN_LOGIN_USERNAME_OPENUBMC_SDK=<user>
export CONAN_PASSWORD_OPENUBMC_SDK=<password>
export CONAN_LOGIN_USERNAME_OPENUBMC_OPENSOURCE=<user>
export CONAN_PASSWORD_OPENUBMC_OPENSOURCE=<password>
export CONAN_LOGIN_USERNAME_LOCAL=<user>
export CONAN_PASSWORD_LOCAL=<password>
```

## Preflight

For a remote that a build must use, do not pass `--with-user`; missing credentials should fail clearly.

```bash
for remote in openubmc_sdk openubmc_opensource local; do
  log="$(mktemp)"
  if ! (
    set -o pipefail
    conan remote auth "$remote" --force -cc core:non_interactive=True 2>&1 | tee "$log"
  ); then
    rm -f "$log"
    echo "Conan auth command failed for $remote" >&2
    exit 1
  fi
  if grep -Eiq '(^|[[:space:]])error:|Wrong user|Wrong password|Authentication error|interactive mode disabled' "$log"; then
    rm -f "$log"
    echo "Conan auth failed for $remote" >&2
    exit 1
  fi
  rm -f "$log"
done
```

If auth fails with `Wrong user or password`, clear only that remote and retry with corrected environment variables:

```bash
conan remote logout <remote>
CONAN_LOGIN_USERNAME_<REMOTE_SUFFIX>=<user> \
CONAN_PASSWORD_<REMOTE_SUFFIX>=<password> \
  conan remote auth <remote> --force -cc core:non_interactive=True
```

## Missing Binaries

When a product build reports a missing binary package, treat it as a remote/auth/resolution problem first. Do not rewrite Git URLs or build a local source fallback for a product dependency unless the user explicitly asks for a local workaround; product builds are expected to resolve stable dependencies from Conan remotes after auth is proven.

## Proxy Hangs

If Conan graph/dependency resolution stalls, inspect proxy variables as well as auth. `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and lowercase variants can route Conan through a dead local proxy. Fix the proxy or run with the proxy set unset plus an appropriate `NO_PROXY`.
