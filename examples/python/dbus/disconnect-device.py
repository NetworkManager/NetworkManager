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

if len(sys.argv) != 2:
    raise Exception("Usage: %s <interface>" % sys.argv[0])

bus = dbus.SystemBus()

# Get a proxy for the base NetworkManager object
proxy = bus.get_object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager")
manager = dbus.Interface(proxy, "org.freedesktop.NetworkManager")

dpath = None

# Find the device the user wants to disconnect
devices = manager.GetDevices()
for d in devices:
    dev_proxy = bus.get_object("org.freedesktop.NetworkManager", d)
    prop_iface = dbus.Interface(dev_proxy, "org.freedesktop.DBus.Properties")
    iface = prop_iface.Get("org.freedesktop.NetworkManager.Device", "Interface")
    if iface == sys.argv[1]:
        dpath = d
        break

if not dpath or not len(dpath):
    raise Exception("NetworkManager knows nothing about %s" % sys.argv[1])

dev_proxy = bus.get_object("org.freedesktop.NetworkManager", dpath)
dev_iface = dbus.Interface(dev_proxy, "org.freedesktop.NetworkManager.Device")
prop_iface = dbus.Interface(dev_proxy, "org.freedesktop.DBus.Properties")

# Make sure the device is connected before we try to disconnect it
state = prop_iface.Get("org.freedesktop.NetworkManager.Device", "State")
if state <= 3:
    raise Exception("Device %s isn't connected" % sys.argv[1])

# Tell NM to disconnect it
dev_iface.Disconnect()

