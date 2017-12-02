#!/usr/bin/env python
# -*- Mode: python; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2010 Red Hat, Inc.
#

import dbus, sys

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

