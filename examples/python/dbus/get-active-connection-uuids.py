#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2010 Red Hat, Inc.
#

import dbus

# This example lists all of the active connections
# the system is connected to and prints it out

bus = dbus.SystemBus()

# Get a proxy for the base NetworkManager object
m_proxy = bus.get_object(
    "org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager"
)
mgr_props = dbus.Interface(m_proxy, "org.freedesktop.DBus.Properties")

# Find all active connections
active = mgr_props.Get("org.freedesktop.NetworkManager", "ActiveConnections")

for a in active:
    a_proxy = bus.get_object("org.freedesktop.NetworkManager", a)

    a_props = dbus.Interface(a_proxy, "org.freedesktop.DBus.Properties")

    # Grab the connection object path so we can get all the connection's settings
    connection_path = a_props.Get(
        "org.freedesktop.NetworkManager.Connection.Active", "Connection"
    )
    c_proxy = bus.get_object("org.freedesktop.NetworkManager", connection_path)
    connection = dbus.Interface(
        c_proxy, "org.freedesktop.NetworkManager.Settings.Connection"
    )
    settings = connection.GetSettings()
    print(
        "%s (%s) - %s"
        % (
            settings["connection"]["id"],
            settings["connection"]["uuid"],
            settings["connection"]["type"],
        )
    )

if len(active) == 0:
    print("No active connections")
