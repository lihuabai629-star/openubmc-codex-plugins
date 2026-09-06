"""Stable public-to-runtime capability names shared by Runtime projections."""

CAPABILITY_ALIASES = {
    "ssh": "ssh_transport",
    "telnet": "remote_log_file",
    "mdbctl": "mdbctl",
    "busctl": "busctl",
    "dbus": "dbus_env",
    "alarms": "active_alarm_endpoint_verified",
}
CAPABILITY_STATES = frozenset({"available", "unavailable", "not_checked"})
