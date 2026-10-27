"""Redact credential-like values before log data reaches another consumer.

The analyzer deliberately keeps the redaction policy small and dependency-free.
It is used for both evidence lines and structured observers, so a parser cannot
accidentally retain a value that the text scanner would have hidden later.
The function preserves the surrounding log text and only replaces the value
portion of an assignment/header whenever possible.
"""

from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import ipaddress
import re


REDACTED_VALUE = "<redacted>"

# Keep this list intentionally broader than the names currently emitted by
# openUBMC.  Log bundles may include proxy, Redfish, SSH, or web-server output
# from adjacent components, and missing one common spelling is a data leak.
SENSITIVE_KEYS = (
    "proxy-authorization",
    "proxy_authorization",
    "proxyauthorization",
    "client_secret",
    "client-secret",
    "clientsecret",
    "refresh_token",
    "refresh-token",
    "refreshtoken",
    "access_token",
    "access-token",
    "accesstoken",
    "id_token",
    "id-token",
    "idtoken",
    "auth_token",
    "auth-token",
    "authtoken",
    "x_auth_token",
    "x-auth-token",
    "xauthtoken",
    "x_api_key",
    "x-api-key",
    "xapikey",
    "api_key",
    "api-key",
    "apikey",
    "session_id",
    "session-id",
    "sessionid",
    "private_key",
    "private-key",
    "privatekey",
    "ssh_key",
    "ssh-key",
    "sshkey",
    "oauth_token",
    "oauth-token",
    "oauthtoken",
    "csrf_token",
    "csrf-token",
    "password_hash",
    "password-hash",
    "passwordhash",
    "user_password",
    "user-password",
    "userpassword",
    "login_password",
    "login-password",
    "loginpassword",
    "redfish_password",
    "redfish-password",
    "redfishpassword",
    "ssh_password",
    "ssh-password",
    "sshpassword",
    "sshpass",
    "secret_key",
    "secret-key",
    "secretkey",
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "passphrase",
    "passcode",
    "pwd",
    "token",
    "secret",
    "credential",
    "credentials",
    "session",
    # UID has historically been omitted from topology samples and can identify
    # a device or account in other dump formats as well.
    "uid",
)

_KEY_ALTERNATION = "|".join(
    re.escape(key) for key in sorted(SENSITIVE_KEYS, key=len, reverse=True)
)

# A key may be quoted (JSON), hyphenated (HTTP headers), or written as a plain
# shell-style assignment.  The one-character negative lookbehind prevents
# matching the ``token`` suffix in an unrelated identifier such as
# ``not_a_token_name``.
SENSITIVE_ASSIGNMENT_RE = re.compile(
    rf"(?<![A-Za-z0-9_-])(?P<prefix>(?:--?)?[\"']?"
    rf"(?:(?:[A-Za-z][A-Za-z0-9]*[_-])+)?(?:{_KEY_ALTERNATION})[\"']?\s*[:=]\s*)",
    re.IGNORECASE,
)

CLI_SECRET_OPTION_RE = re.compile(
    rf"(?<!\S)(?P<prefix>--(?:(?:[A-Za-z][A-Za-z0-9]*[_-])+)?"
    rf"(?:{_KEY_ALTERNATION})\s+)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|\S+)",
    re.IGNORECASE,
)

# Some logs contain an authentication scheme without a key (for example a
# copied HTTP header fragment).  This pass is a backstop; keyed values are
# handled first and therefore do not get partially redacted.
AUTH_SCHEME_RE = re.compile(
    r"(?i)\b(?P<scheme>Bearer|Basic|Digest|Negotiate)\s+(?P<value>[A-Za-z0-9._~+/=-]+)"
)

URL_USERINFO_RE = re.compile(
    r"(?i)(?P<prefix>\b[a-z][a-z0-9+.-]*://[^/@\s:]+:)(?P<value>[^/@\s]+)(?P<suffix>@)"
)

HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "proxy_authorization",
    "proxyauthorization",
    "cookie",
    "set-cookie",
    "x-auth-token",
    "x_auth_token",
    "xauthtoken",
    "x-api-key",
    "x_api_key",
    "xapikey",
}
CANONICAL_HEADER_KEYS = {header.replace("_", "-") for header in HEADER_KEYS}

# A bundle is often copied outside the system that produced it.  Credential
# redaction alone is not enough for a shareable report: access logs commonly
# contain client addresses, browser fingerprints, host names, MAC addresses,
# and serial-like identifiers.  Keep this second policy separate from the
# analysis redaction above so routing can still use those values internally.
PUBLIC_ID_KEYS = (
    "asset_tag",
    "asset-tag",
    "assetTag",
    "board_id",
    "board-id",
    "boardId",
    "board_no",
    "board-no",
    "boardNo",
    "board_number",
    "board-number",
    "boardNumber",
    "board_part_number",
    "board-part-number",
    "boardPartNumber",
    "bn",
    "part_num",
    "part-num",
    "partNum",
    "part_number",
    "part-number",
    "partNumber",
    "partnumber",
    "part_no",
    "part-no",
    "partNo",
    "material_code",
    "material-code",
    "materialCode",
    "material_no",
    "material-no",
    "materialNo",
    "product_part_number",
    "product-part-number",
    "productPartNumber",
    "card_part_number",
    "card-part-number",
    "cardPartNumber",
    "original_part_num",
    "original-part-num",
    "originalPartNum",
    "original_part_number",
    "original-part-number",
    "originalPartNumber",
    "pn",
    "client",
    "client_id",
    "client-id",
    "clientId",
    "client_ip",
    "client-ip",
    "clientIp",
    "device_id",
    "device-id",
    "deviceId",
    "deviceSerial",
    "deviceSerialNumber",
    "host",
    "host_name",
    "host-name",
    "hostName",
    "hostname",
    "mac",
    "mac_address",
    "mac-address",
    "macAddress",
    "node_id",
    "node-id",
    "nodeId",
    "remote_addr",
    "remote-addr",
    "remoteAddr",
    "serial",
    "serial_no",
    "serial-no",
    "serialNo",
    "serial_number",
    "serial-number",
    "serialNumber",
    "sn",
    "user",
    "user_name",
    "user-name",
    "userName",
    "username",
    "user_agent",
    "user-agent",
    "userAgent",
)
_PUBLIC_ID_KEY_ALTERNATION = "|".join(
    re.escape(key) for key in sorted(PUBLIC_ID_KEYS, key=len, reverse=True)
)
PUBLIC_ID_ASSIGNMENT_RE = re.compile(
    rf"(?<![A-Za-z0-9_-])(?P<prefix>(?:--?)?[\"']?"
    rf"(?:(?:[A-Za-z][A-Za-z0-9]*[_-])+)?(?:{_PUBLIC_ID_KEY_ALTERNATION})"
    rf"[\"']?\s*[:=]\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;\]})]+)",
    re.IGNORECASE,
)
PUBLIC_ID_DELIMITED_LABEL_RE = re.compile(
    r"(?i)(?P<prefix>\b(?:serial\s+(?:number|no\.?)|device\s+serial(?:\s+number)?|"
    r"asset\s+tag|(?:original\s+)?(?:board|product|card|material)\s+"
    r"(?:part\s+)?(?:number|no\.?)|(?:original\s+)?part\s+(?:number|no\.?))"
    r"\s*[:=]\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;\]}]+)"
)
PUBLIC_ID_SHORT_LABEL_RE = re.compile(
    r"(?i)(?P<prefix>\b(?:s\s*/\s*n|b\s*/\s*n|p\s*/\s*n)"
    r"(?:(?:\s*[:=]\s*)|\s+))"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;\]}]+)"
)
PUBLIC_ASSET_CONTEXT_RE = re.compile(
    r"(?i)(?P<prefix>\bunit[ \t]+)\S+(?P<suffix>[ \t]+linked[ \t]+to[ \t]+connector\b)"
    r"|(?P<serial_prefix>\bSN\()[^)\r\n]+(?P<serial_suffix>\))"
)
PUBLIC_USER_AGENT_RE = re.compile(
    r"(?i)(?P<prefix>\b(?:user-agent|x-forwarded-for|remote_addr|remote-addr)\s*[:=]\s*)"
    r"(?P<value>[^\r\n]+)"
)
PUBLIC_QUOTED_USER_AGENT_RE = re.compile(
    r"(?i)(?P<quote>[\"'])(?P<value>(?:Mozilla|curl|Wget|python-requests|PostmanRuntime|"
    r"Go-http-client)/[^\"'\r\n]*)(?P=quote)"
)
PUBLIC_BARE_USER_AGENT_RE = re.compile(
    r"(?i)\b(?:curl|Wget|python-requests|PostmanRuntime|Go-http-client|okhttp|"
    r"Apache-HttpClient|node-fetch|libcurl)/[^\s,;]+"
)
# Some BMC inventory tables print a material number as an unlabeled pipe-
# delimited cell (for example ``| 02314EWC |``).  Keep the rule tied to that
# table shape so ordinary text, revisions, and bundle-relative paths are not
# rewritten merely because they contain the same character pattern.
PUBLIC_TABULAR_PART_NUMBER_RE = re.compile(
    r"(?P<prefix>\|\s*)\d{5}[A-Za-z]{3}(?P<suffix>\s*\|)"
)
PUBLIC_AUTH_PRINCIPAL_RE = re.compile(
    r"(?i)(?P<prefix>\b(?:login|authentication)\s+failed\s+for\s+)(?:user\s+)?"
    r"(?P<value>[A-Za-z0-9_.@+-]{1,128})(?:\(\d+\))?"
)
PUBLIC_PRINCIPAL_LABEL_RE = re.compile(
    r"(?i)(?P<prefix>\b(?:user(?:name)?|account|principal)\s+)"
    r"(?P<value>[A-Za-z0-9_.@+-]{1,128})(?:\(\d+\))?"
)
PUBLIC_MAC_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![A-Za-z0-9])"
)
PUBLIC_DOTTED_MAC_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}(?![A-Za-z0-9])"
)
PUBLIC_CSV_PRINCIPAL_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(?P<prefix>(?:ssh|telnet|http|https|snmp),)"
    r"(?P<value>[A-Za-z][A-Za-z0-9_.@+-]{0,127})"
    r"(?P<suffix>,(?:iam|auth|account|user)(?![A-Za-z0-9_]))"
)
PUBLIC_UUID_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-"
    r"[89AaBb][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12})(?![A-Za-z0-9])"
)
PUBLIC_IPV4_RE = re.compile(
    r"(?<![A-Za-z0-9])(?P<address>(?:\d{1,3}\.){3}\d{1,3})(?P<port>:\d{1,5})?(?![A-Za-z0-9])"
)
# The callback validates candidates with ipaddress so timestamps and ordinary
# colon-separated counters are left untouched.
PUBLIC_IP_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:\[[0-9A-Fa-f:.]+(?:%[A-Za-z0-9_.-]+)?\]|"
    r"[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(?:%[A-Za-z0-9_.-]+)?)(?![A-Za-z0-9])"
)
PUBLIC_URL_AUTHORITY_RE = re.compile(
    r"(?i)(?P<prefix>\b(?:https?|ssh|scp)://)(?P<authority>[^/\s]+)"
)
PUBLIC_PRINCIPAL_HOST_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.+-])(?P<principal>[A-Za-z0-9_.+-]{1,128})@"
    r"(?P<host>[A-Za-z0-9.-]{1,253})(?![A-Za-z0-9_.-])"
)
PUBLIC_HOST_CONTEXT_RE = re.compile(
    r"(?i)(?P<prefix>\b(?:dns\s+lookup|host(?:name)?|failed\s+on|running\s+on)\s+"
    r"(?:for\s+)?)(?P<host>(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63})(?![A-Za-z0-9.-])"
)
PUBLIC_LOCAL_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"/(?:root|tmp|var|data|opt|etc|srv|usr|mnt|run|dev|Users|home|workspace|proc|sys)"
    r"(?:/[A-Za-z0-9._+@=-]+)*(?![A-Za-z0-9._+@=-])"
    r"|/(?!redfish(?:/|$)|UI/Rest(?:/|$)|api(?:/|$)|odata(?:/|$)|"
    r"xyz/openbmc_project(?:/|$)|org/openbmc(?:/|$)|bmc(?:/|$))"
    r"(?:[A-Za-z0-9._+@=-]+/)+[A-Za-z0-9._+@=-]+(?![A-Za-z0-9._+@=-])"
    r"|[A-Za-z]:\\[^\s,;]+"
    r"|\\\\[A-Za-z0-9._-]+\\[^\s,;]+)",
    re.IGNORECASE,
)
PUBLIC_SINGLE_PATH_CONTEXT_RE = re.compile(
    r"(?i)(?P<prefix>\b(?:at|under|from|to|path|file|directory|dir|location|root|mount|"
    r"open(?:ed)?|read(?:ing)?|writ(?:e|ing)|stat|access(?:ing)?|extract(?:ed|ing)?|"
    r"cop(?:y|ied|ying))\s*(?:[:=]|\s)\s*)"
    r"(?P<path>/(?!redfish(?:/|$)|UI/Rest(?:/|$)|api(?:/|$)|odata(?:/|$)|"
    r"xyz/openbmc_project(?:/|$)|org/openbmc(?:/|$)|bmc(?:/|$))"
    r"[A-Za-z._+@=-][A-Za-z0-9._+@=-]*(?:/[A-Za-z0-9._+@=-]+)*)"
)


def _redact_public_assignments(value: str) -> tuple[str, bool]:
    def replace(match: re.Match[str]) -> str:
        raw_value = match.group("value")
        quote = raw_value[0] if raw_value[:1] in "\"'" else ""
        replacement = f"{quote}{REDACTED_VALUE}{quote}" if quote else REDACTED_VALUE
        return f"{match.group('prefix')}{replacement}"

    redacted, count = PUBLIC_ID_ASSIGNMENT_RE.subn(replace, value)
    redacted, delimited_label_count = PUBLIC_ID_DELIMITED_LABEL_RE.subn(replace, redacted)
    redacted, short_label_count = PUBLIC_ID_SHORT_LABEL_RE.subn(replace, redacted)
    redacted, asset_context_count = PUBLIC_ASSET_CONTEXT_RE.subn(
        lambda match: (
            f"{match.group('prefix') or match.group('serial_prefix')}"
            f"{REDACTED_VALUE}-asset"
            f"{match.group('suffix') or match.group('serial_suffix')}"
        ),
        redacted,
    )
    # User-Agent values frequently contain spaces and therefore need a
    # remainder-of-line replacement rather than the token-oriented rule above.
    redacted, header_count = PUBLIC_USER_AGENT_RE.subn(
        lambda match: f"{match.group('prefix')}{REDACTED_VALUE}",
        redacted,
    )
    redacted, quoted_ua_count = PUBLIC_QUOTED_USER_AGENT_RE.subn(
        lambda match: f"{match.group('quote')}{REDACTED_VALUE}-user-agent{match.group('quote')}",
        redacted,
    )
    redacted, bare_ua_count = PUBLIC_BARE_USER_AGENT_RE.subn(
        REDACTED_VALUE + "-user-agent",
        redacted,
    )
    redacted, part_number_count = PUBLIC_TABULAR_PART_NUMBER_RE.subn(
        lambda match: f"{match.group('prefix')}{REDACTED_VALUE}-part{match.group('suffix')}",
        redacted,
    )
    redacted, auth_principal_count = PUBLIC_AUTH_PRINCIPAL_RE.subn(
        lambda match: f"{match.group('prefix')}{REDACTED_VALUE}-principal",
        redacted,
    )
    redacted, principal_count = PUBLIC_PRINCIPAL_LABEL_RE.subn(
        lambda match: f"{match.group('prefix')}{REDACTED_VALUE}-principal",
        redacted,
    )
    redacted, host_count = PUBLIC_HOST_CONTEXT_RE.subn(
        lambda match: f"{match.group('prefix')}{REDACTED_VALUE}-host",
        redacted,
    )
    redacted, csv_principal_count = PUBLIC_CSV_PRINCIPAL_RE.subn(
        lambda match: f"{match.group('prefix')}{REDACTED_VALUE}-principal{match.group('suffix')}",
        redacted,
    )
    return redacted, (
        count
        + delimited_label_count
        + short_label_count
        + asset_context_count
        + header_count
        + quoted_ua_count
        + bare_ua_count
        + part_number_count
        + auth_principal_count
        + principal_count
        + host_count
        + csv_principal_count
    ) > 0


def _redact_public_network_literals(value: str) -> tuple[str, bool]:
    def replace_ipv4(match: re.Match[str]) -> str:
        address = match.group("address")
        try:
            ipaddress.ip_address(address)
        except ValueError:
            return match.group(0)
        return f"{REDACTED_VALUE}-ip{match.group('port') or ''}"

    redacted, ipv4_count = PUBLIC_IPV4_RE.subn(replace_ipv4, value)

    def replace_ip_candidate(match: re.Match[str]) -> str:
        raw = match.group(0)
        candidate = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
        candidate = candidate.split("%", 1)[0]
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            return raw
        if parsed.version != 6:
            return raw
        return f"[{REDACTED_VALUE}-ip6]" if raw.startswith("[") else f"{REDACTED_VALUE}-ip6"

    redacted, ipv6_count = PUBLIC_IP_CANDIDATE_RE.subn(replace_ip_candidate, redacted)
    redacted, mac_count = PUBLIC_MAC_RE.subn(REDACTED_VALUE + "-mac", redacted)
    redacted, dotted_mac_count = PUBLIC_DOTTED_MAC_RE.subn(REDACTED_VALUE + "-mac", redacted)
    redacted, uuid_count = PUBLIC_UUID_RE.subn(REDACTED_VALUE + "-id", redacted)
    return redacted, (ipv4_count + ipv6_count + mac_count + dotted_mac_count + uuid_count) > 0


def redact_public_text(value: str) -> tuple[str, bool]:
    """Redact credentials and common host/device identifiers for sharing.

    This is intentionally a presentation-layer policy.  The analyzer calls
    :func:`redact_sensitive_text` while routing and parsing so problem terms
    are not changed before they are scored; callers should apply this helper
    only to the final report or other externally visible text.
    """

    if not isinstance(value, str) or not value:
        return value, False
    redacted, _ = redact_sensitive_text(value)
    redacted, _ = _redact_public_assignments(redacted)
    redacted, _ = _redact_public_network_literals(redacted)
    redacted, _ = PUBLIC_PRINCIPAL_HOST_RE.subn(
        f"{REDACTED_VALUE}-principal@{REDACTED_VALUE}-host",
        redacted,
    )

    def replace_url(match: re.Match[str]) -> str:
        authority = match.group("authority")
        # Preserve an explicit port because it is useful for diagnosis while
        # hiding userinfo and the target host itself.
        port = ""
        if authority.rsplit("@", 1)[-1].count(":") == 1:
            suffix = authority.rsplit(":", 1)[-1]
            if suffix.isdigit():
                port = f":{suffix}"
        return f"{match.group('prefix')}{REDACTED_VALUE}-host{port}"

    redacted, _ = PUBLIC_URL_AUTHORITY_RE.subn(replace_url, redacted)
    redacted, _ = PUBLIC_LOCAL_PATH_RE.subn(f"{REDACTED_VALUE}-path", redacted)
    redacted, _ = PUBLIC_SINGLE_PATH_CONTEXT_RE.subn(
        lambda match: f"{match.group('prefix')}{REDACTED_VALUE}-path",
        redacted,
    )
    return redacted, redacted != value


def _is_header_key(key: str) -> bool:
    normalized = key.casefold().replace("_", "-")
    return any(
        normalized == header or normalized.endswith(f"-{header}")
        for header in CANONICAL_HEADER_KEYS
    )


def _key_name(prefix: str) -> str:
    """Return the normalized key represented by an assignment prefix."""

    key = prefix.split(":", 1)[0].split("=", 1)[0]
    return key.strip().lstrip("-").strip("\"'").casefold()


def _consume_quoted(value: str, start: int, quote: str) -> int:
    """Return the first position after a quoted value.

    Malformed input is treated conservatively: the rest of the line is
    considered sensitive instead of exposing a possible credential after an
    unmatched quote.
    """

    escaped = False
    for index in range(start + 1, len(value)):
        character = value[index]
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == quote:
            return index + 1
        if character in "\r\n":
            return index
    return len(value)


def _consume_balanced(value: str, start: int) -> int:
    """Consume a JSON-like object/list value without parsing untrusted data."""

    opening = value[start]
    closing = "}" if opening == "{" else "]"
    depth = 0
    quote = ""
    escaped = False
    for index in range(start, len(value)):
        character = value[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            continue
        if character in "\"'":
            quote = character
            continue
        if character == opening:
            depth += 1
        elif character == closing:
            depth -= 1
            if depth == 0:
                return index + 1
        elif character in "\r\n":
            break
    return len(value)


def _consume_unquoted(value: str, start: int, key: str) -> int:
    """Find a conservative end for an unquoted assignment value."""

    # Header values such as ``Cookie: a=b; session=secret`` and
    # ``Authorization: Bearer secret`` are all credential-bearing.  Consuming
    # the remainder avoids leaving a second cookie pair or a token after the
    # first whitespace-delimited word.
    if _is_header_key(key):
        newline = value.find("\n", start)
        return len(value) if newline < 0 else newline

    index = start
    while index < len(value):
        character = value[index]
        if character in "\r\n,;}]&":
            break
        if character.isspace():
            break
        index += 1
    end = index
    # Keep the separator whitespace in the output, while avoiding a run of
    # spaces inside the replacement itself.
    while end > start and value[end - 1].isspace():
        end -= 1
    return end


def _consume_value(value: str, start: int, key: str) -> int:
    if start >= len(value):
        return start
    if value[start] in "\"'":
        return _consume_quoted(value, start, value[start])
    if value[start] in "[{":
        return _consume_balanced(value, start)
    return _consume_unquoted(value, start, key)


def _redact_assignments(value: str) -> tuple[str, bool]:
    pieces: list[str] = []
    cursor = 0
    changed = False
    for match in SENSITIVE_ASSIGNMENT_RE.finditer(value):
        if match.start() < cursor:
            continue
        value_start = match.end()
        key = _key_name(match.group("prefix"))
        value_end = _consume_value(value, value_start, key)
        if value_end <= value_start:
            continue
        pieces.append(value[cursor:value_start])
        prefix_text = match.group("prefix").lstrip()
        json_key = prefix_text.startswith('"')
        if json_key and value_start < len(value) and value[value_start] not in "\"'":
            # Keep JSON syntactically valid when the original value was a
            # number, boolean, null, object, or array.
            pieces.append(f'"{REDACTED_VALUE}"')
        elif value_start < len(value) and value[value_start] in "\"'":
            quote = value[value_start]
            pieces.append(f"{quote}{REDACTED_VALUE}{quote}")
        else:
            pieces.append(REDACTED_VALUE)
        cursor = value_end
        changed = True
    if not changed:
        return value, False
    pieces.append(value[cursor:])
    return "".join(pieces), True


def _redact_auth_schemes(value: str) -> tuple[str, bool]:
    redacted, count = AUTH_SCHEME_RE.subn(
        lambda match: f"{match.group('scheme')} {REDACTED_VALUE}",
        value,
    )
    return redacted, count > 0


def _redact_cli_options(value: str) -> tuple[str, bool]:
    def replace(match: re.Match[str]) -> str:
        raw_value = match.group("value")
        quote = raw_value[0] if raw_value[:1] in "\"'" else ""
        replacement = f"{quote}{REDACTED_VALUE}{quote}" if quote else REDACTED_VALUE
        return f"{match.group('prefix')}{replacement}"

    redacted, count = CLI_SECRET_OPTION_RE.subn(replace, value)
    return redacted, count > 0


def _redact_url_userinfo(value: str) -> tuple[str, bool]:
    redacted, count = URL_USERINFO_RE.subn(
        lambda match: f"{match.group('prefix')}{REDACTED_VALUE}{match.group('suffix')}",
        value,
    )
    return redacted, count > 0


def redact_sensitive_text(value: str) -> tuple[str, bool]:
    """Return ``value`` with credential-like values replaced.

    This function is intentionally idempotent and safe for arbitrary decoded
    log text.  It does not attempt to classify whether a line is an error; it
    only enforces the confidentiality boundary before downstream matching,
    structured parsing, and report rendering.
    """

    if not isinstance(value, str) or not value:
        return value, False
    redacted, _ = _redact_cli_options(value)
    redacted, _ = _redact_assignments(redacted)
    auth_redacted, _ = _redact_auth_schemes(redacted)
    url_redacted, _ = _redact_url_userinfo(auth_redacted)
    return url_redacted, url_redacted != value


__all__ = ["REDACTED_VALUE", "redact_sensitive_text", "redact_public_text"]
