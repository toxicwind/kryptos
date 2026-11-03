#!/usr/bin/env bash
# keyring-guard — kill any gnome-keyring-daemon that stole org.freedesktop.secrets
#                from the systemd-owned daemon (anomaly: 2026-11-03 rogue ring).
#
# ROOT CAUSE (2026-11-03): an ad-hoc unlock script spawned
#   gnome-keyring-daemon --unlock --replace
# whose orphaned process (PPID=1) won the bus-name race against the
# systemd gnome-keyring-daemon.service instance. The rogue served an EMPTY
# ring under org.freedesktop.secrets — every keyring consumer silently read
# zero items while the real (seeded) ring sat on disk unused.
#
# GUARD CONTRACT:
#  1. The bus name org.freedesktop.secrets MUST be owned by the MainPID of
#     gnome-keyring-daemon.service (systemd user unit).
#  2. Any OTHER gnome-keyring-daemon process holding the name is killed
#     (SIGTERM); the systemd daemon re-acquires automatically.
#  3. Exit codes: 0 = healthy or repaired, 1 = stolen and could not repair.
#
# Run mode: ad-hoc, from bin-verify.sh, or a pitchfork timer. Never spawns
# `--replace` itself (that is the failure mode this guard exists to stop).

set -u
SERVICE_UNIT="gnome-keyring-daemon.service"
BUS_NAME="org.freedesktop.secrets"

main_pid="$(systemctl --user show "$SERVICE_UNIT" -p MainPID --value 2>/dev/null)"
if [ -z "$main_pid" ] || [ "$main_pid" = "0" ]; then
	echo "keyring-guard: systemd unit $SERVICE_UNIT has no MainPID — cannot arbitrate" >&2
	exit 1
fi

owner_pid="$(busctl --user status "$BUS_NAME" 2>/dev/null | sed -n 's/^PID=\([0-9]*\)$/\1/p' | head -1)"

if [ -z "$owner_pid" ]; then
	echo "keyring-guard: no one owns $BUS_NAME (daemon down?) — attempting restart" >&2
	systemctl --user restart "$SERVICE_UNIT"
	exit $?
fi

if [ "$owner_pid" = "$main_pid" ]; then
	echo "keyring-guard: healthy — $BUS_NAME owned by systemd daemon (pid $main_pid)"
	exit 0
fi

# A rogue holds the name. Kill it; systemd daemon re-claims.
rogue_cmd="$(tr '\0' ' ' < "/proc/$owner_pid/cmdline" 2>/dev/null | cut -c1-120)"
echo "keyring-guard: ROGUE daemon pid $owner_pid holds $BUS_NAME: ${rogue_cmd:-<unreadable>}" >&2
kill "$owner_pid" 2>/dev/null
sleep 2

if kill -0 "$owner_pid" 2>/dev/null; then
	echo "keyring-guard: rogue survived SIGTERM, escalating to SIGKILL" >&2
	kill -9 "$owner_pid" 2>/dev/null
	sleep 1
fi

new_owner="$(busctl --user status "$BUS_NAME" 2>/dev/null | sed -n 's/^PID=\([0-9]*\)$/\1/p' | head -1)"
if [ "$new_owner" = "$main_pid" ]; then
	echo "keyring-guard: repaired — $BUS_NAME back on systemd daemon (pid $main_pid)"
	exit 0
fi
echo "keyring-guard: FAILED to restore $BUS_NAME to pid $main_pid (owner now: ${new_owner:-none})" >&2
exit 1
