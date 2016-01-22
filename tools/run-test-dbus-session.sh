#!/bin/sh

if ! which dbus-run-session &>/dev/null; then
    eval `dbus-launch --sh-syntax`
    trap "kill $DBUS_SESSION_BUS_PID" EXIT
    "$@"
    exit $?
fi

dbus-run-session -- "$@"
