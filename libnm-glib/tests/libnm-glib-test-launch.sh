#!/bin/sh

if [ -z "$DBUS_SESSION_BUS_ADDRESS" ]; then
    exec dbus-launch --exit-with-session "$@"
else
    exec "$@"
fi
