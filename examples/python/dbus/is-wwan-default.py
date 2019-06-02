#!/usr/bin/env python
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
# Copyright (C) 2011 - 2012 Red Hat, Inc.
#

import dbus, sys

# This example indicates whether the default network connection is known to be WWAN

NM_DEVICE_TYPE_MODEM = 8
NM_DEVICE_TYPE_BLUETOOTH = 5
NM_SERVICE_NAME = "org.freedesktop.NetworkManager"
NM_MANAGER_IFACE = "org.freedesktop.NetworkManager"
DBUS_PROPS_IFACE = "org.freedesktop.DBus.Properties"

NM_ACTIVE_CONNECTION_INTERFACE = "org.freedesktop.NetworkManager.Connection.Active"

bus = dbus.SystemBus()

# Exit early if NetworkManager is not running
proxy = bus.get_object("org.freedesktop.DBus", "/org/freedesktop/DBus")
busdaemon = dbus.Interface(proxy, "org.freedesktop.DBus")
if not busdaemon.NameHasOwner(NM_SERVICE_NAME):
    print("NetworkManager not running")
    sys.exit(1)

# Get a proxy for the NetworkManager object
proxy = bus.get_object(NM_SERVICE_NAME, "/org/freedesktop/NetworkManager")
manager = dbus.Interface(proxy, NM_MANAGER_IFACE)
props = dbus.Interface(proxy, DBUS_PROPS_IFACE)

def found_connection_type(ctype):
    if ctype == '':
        print("No active connection")
    elif ctype in ["gsm", "cdma", "bluetooth"]:
        print("WWAN is default")
    else:
        print("WWAN is not default")
        sys.exit(0)

# Shortcut #1, for NM 1.0
try:
    ctype = props.Get(NM_MANAGER_IFACE, "PrimaryConnectionType")
    found_connection_type(ctype)
except KeyError:
    pass

# Shortcut #2, for NM 0.9.10
try:
    primary = props.Get(NM_MANAGER_IFACE, "PrimaryConnection")
    if not primary:
        found_connection_type('')
    primary_proxy = bus.get_object(NM_SERVICE_NAME, primary)
    primary_props = dbus.Interface(primary_proxy, DBUS_PROPS_IFACE)
    ctype = primary_props.Get(NM_ACTIVE_CONNECTION_INTERFACE, "Type")
    found_connection_type(ctype)
except KeyError:
    pass

# Fallback for NM 0.9.8 and earlier; look through all active network
# connections for the default one
default_is_wwan = False
active = props.Get(NM_MANAGER_IFACE, "ActiveConnections")
for a in active:
    a_proxy = bus.get_object(NM_SERVICE_NAME, a)
    a_props = dbus.Interface(a_proxy, DBUS_PROPS_IFACE)
    all_props = a_props.GetAll(NM_ACTIVE_CONNECTION_INTERFACE)

    # Ignore this network connection if it's not default for IPv4 or IPv6
    if all_props["Default"] == False and all_props["Default6"] == False:
        continue

    dev_path = all_props["Devices"][0]
    dev_proxy = bus.get_object(NM_SERVICE_NAME, dev_path)
    dev_props = dbus.Interface(dev_proxy, DBUS_PROPS_IFACE)
    devtype = dev_props.Get("org.freedesktop.NetworkManager.Device", "DeviceType")
    if devtype == NM_DEVICE_TYPE_MODEM or devtype == NM_DEVICE_TYPE_BLUETOOTH:
        default_is_wwan = True
        break

if default_is_wwan:
    print("WWAN is default")
else:
    print("WWAN is not default")

