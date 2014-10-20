#!/bin/sh

# Spawn DBus if there's none
if [ -z "$DBUS_SESSION_BUS_ADDRESS" ]; then
    eval `dbus-launch --sh-syntax`
    trap "kill $DBUS_SESSION_BUS_PID" EXIT
fi

"$@"
