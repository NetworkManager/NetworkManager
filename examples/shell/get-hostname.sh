#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2011 Red Hat, Inc.
#

#
# Call Get() method on org.freedesktop.DBus.Properties interface to get Hostname
# property of /org/freedesktop/NetworkManager/Settings object
#

SERVICE_NAME="org.freedesktop.NetworkManager"
OBJECT_PATH="/org/freedesktop/NetworkManager/Settings"
METHOD="org.freedesktop.DBus.Properties.Get"


dbus-send --system --print-reply --dest=$SERVICE_NAME $OBJECT_PATH $METHOD \
          string:"org.freedesktop.NetworkManager.Settings" string:"Hostname" | \
sed  -n 's/.*"\([^"]*\)".*/\1/p'


# The same with glib's gdbus
# gdbus call --system --dest $SERVICE_NAME --object-path $OBJECT_PATH --method $METHOD \
#      "org.freedesktop.NetworkManager.Settings" "Hostname"


# The same with qt's qdbus
# qdbus --system $SERVICE_NAME $OBJECT_PATH $METHOD \
#      "org.freedesktop.NetworkManager.Settings" "Hostname"

