# Credential exposure response

Use this runbook when a BMC, OS, Redfish, KB, or Conan credential may have
appeared in a Codex task transcript, command argument, environment snapshot,
process inspection, Runtime record, or diagnostic log.

## Establish the affected identity

Treat a credential as exposed when a task used its account during the affected
time window and the containment status cannot be proved. Identify the account by
target address, purpose, transport, local credential record name, and activated
configuration revision. Do not paste the old value into a task, terminal command,
issue, or search query to prove a match.

For a shared default record, include every BMC or OS that selected it. An exact IP
override limits the affected set to that override. SSH and Redfish may reference
the same BMC account, while an associated OS record remains a separate identity.
KB OAuth accounts, OAuth client secrets, cached tokens, Conan remotes, and SSH
private keys follow their own authority and rotation procedure.

## Rotate without losing recovery access

1. Keep an independent recovery path to the device or service. Do not revoke the
   only working administrator account before the replacement is verified.
2. Create or rotate the credential at its owning authority: the BMC or OS account
   manager, the identity provider, the Conan remote, or the SSH key authority.
3. Open the installed plugin's local configuration page from the configuration URL
   reported by installation, doctor, or a configuration-required request. Save the
   replacement into a new private revision and activate it. Do not modify files in
   the immutable plugin directory.
4. Run the page's capability check for each affected purpose. BMC SSH and Redfish
   checks must succeed against the intended BMC identity; an associated OS check
   must succeed against its own address and account. A network failure is not an
   authentication result.
5. Start a new task or cross a documented Runtime request boundary so existing
   in-memory credential leases are replaced. Do not copy a password into chat to
   update an older task.
6. Revoke the old password, token, client secret, or key only after the replacement
   checks succeed. For a shared default record, verify every required target before
   revocation.
7. Follow the local retention policy for affected transcripts, shell history,
   crash reports, and exported logs. Preserve non-secret incident evidence such as
   task identity, timestamps, target references, error codes, and the activated
   revision. Never attach the exposed value to the incident record.

## Recovery outcomes

| Result | Meaning | Next action |
| --- | --- | --- |
| `credentials_missing` | No complete local record was selected | Configure or select the intended local record |
| `credentials_conflict` | Explicit local selectors or normalized overrides disagree | Resolve the conflicting selectors; do not guess a source |
| `credentials_invalid` | The selected source is unsafe or malformed | Repair ownership, permissions, format, or activation metadata |
| Authentication rejected | The target or service was reached but rejected the selected identity | Verify the account at its authority, then rotate or re-login |
| Transport failed | The target or service was not reached reliably | Repair routing, TLS, host identity, proxy, or availability before changing credentials |

Authentication rejection never falls back from an exact target override to a
global default. A successful local save or activation proves configuration state,
not remote authentication.

## Closeout evidence

Record only the affected account label, target or service identity, old and new
configuration revision identifiers, rotation time, capability-check result, and
revocation status. Close the response only after the old credential is revoked or
an explicit owner and deadline are recorded for the remaining revocation work.
