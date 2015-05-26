#!/bin/sh

# Spawn DBus
eval `dbus-launch --sh-syntax`
trap "kill $DBUS_SESSION_BUS_PID" EXIT

"$@"
