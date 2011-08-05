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
proxy = bus.get_object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager")
manager = dbus.Interface(proxy, "org.freedesktop.NetworkManager")
settings = dbus.Interface(proxy, "org.freedesktop.NetworkManager.Settings")
mgr_props = dbus.Interface(proxy, "org.freedesktop.DBus.Properties")

# Find the device the user wants to disconnect
active = mgr_props.Get("org.freedesktop.NetworkManager", "ActiveConnections")
for a in active:
    a_proxy = bus.get_object("org.freedesktop.NetworkManager", a)
    a_props = dbus.Interface(a_proxy, "org.freedesktop.DBus.Properties")
    uuid = prop_iface.Get("org.freedesktop.NetworkManager.Connection.Active", "Uuid")
    connection = settings.GetConnectionByUuid(uuid)
    print "%s (%s)" % (connection['connection']['id'], uuid)

if len(active) == 0:
    print "No active connections"

