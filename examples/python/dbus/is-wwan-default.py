#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2011 - 2012 Red Hat, Inc.
#

import dbus, sys

# This example indicates whether the default network connection is known to be WWAN

bus = dbus.SystemBus()

# Exit early if NetworkManager is not running
proxy = bus.get_object("org.freedesktop.DBus", "/org/freedesktop/DBus")
busdaemon = dbus.Interface(proxy, "org.freedesktop.DBus")
if not busdaemon.NameHasOwner("org.freedesktop.NetworkManager"):
    print("NetworkManager not running")
    sys.exit(1)

# Get a proxy for the NetworkManager object
proxy = bus.get_object(
    "org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager"
)
props = dbus.Interface(proxy, "org.freedesktop.DBus.Properties")

# Shortcut #1, for NM 1.0
try:
    ctype = props.Get("org.freedesktop.NetworkManager", "PrimaryConnectionType")
    if ctype == "":
        print("No active connection")
    elif ctype in ["gsm", "cdma", "bluetooth"]:
        print("WWAN is default")
    else:
        print("WWAN is not default")
        sys.exit(0)

except KeyError:
    pass
