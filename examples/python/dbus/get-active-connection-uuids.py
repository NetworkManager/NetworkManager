#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright (C) 2010 Red Hat, Inc.
#

import dbus

# This example takes a device interface name as a parameter and tells
# NetworkManager to disconnect that device, closing down any network
# connection it may have

bus = dbus.SystemBus()

# Get a proxy for the base NetworkManager object
m_proxy = bus.get_object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager")
manager = dbus.Interface(m_proxy, "org.freedesktop.NetworkManager")
mgr_props = dbus.Interface(m_proxy, "org.freedesktop.DBus.Properties")

s_proxy = bus.get_object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/Settings")
settings = dbus.Interface(s_proxy, "org.freedesktop.NetworkManager.Settings")

# Find the device the user wants to disconnect
active = mgr_props.Get("org.freedesktop.NetworkManager", "ActiveConnections")
for a in active:
    a_proxy = bus.get_object("org.freedesktop.NetworkManager", a)

    # Get the UUID directly; apps could use this to perform certain operations
    # based on which network you're connected too
    a_props = dbus.Interface(a_proxy, "org.freedesktop.DBus.Properties")
    uuid = a_props.Get("org.freedesktop.NetworkManager.Connection.Active", "Uuid")

    # Grab the connection object path so we can get all the connection's settings
    connection_path = a_props.Get("org.freedesktop.NetworkManager.Connection.Active", "Connection")
    c_proxy = bus.get_object("org.freedesktop.NetworkManager", connection_path)
    connection = dbus.Interface(c_proxy, "org.freedesktop.NetworkManager.Settings.Connection")
    settings = connection.GetSettings()
    print("%s (%s) - %s" % (settings['connection']['id'], uuid, settings['connection']['type']))

if len(active) == 0:
    print("No active connections")

