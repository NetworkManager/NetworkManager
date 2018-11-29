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
# Copyright (C) 2009 Novell, Inc.
# Copyright (C) 2009 Red Hat, Inc.
#

# Run this script without any arguments to list the available connection uuids.

# The uuid of the connection to activate
CONNECTION_UUID="ac6dc9b2-85ef-4311-83d8-add5d7db3f59"

# UID to use. Note that NM only allows the owner of the connection to activate it.
#UID=1000
UID=0

import sys
import os
import dbus
from dbus.mainloop.glib import DBusGMainLoop
import gobject

DBusGMainLoop(set_as_default=True)

def get_connections():
    bus = dbus.SystemBus()
    proxy = bus.get_object('org.freedesktop.NetworkManager', '/org/freedesktop/NetworkManager/Settings')
    iface = dbus.Interface(proxy, dbus_interface='org.freedesktop.NetworkManager.Settings')
    return iface.ListConnections()


def get_connection_by_uuid(uuid):
    bus = dbus.SystemBus()
    for c in get_connections():
        proxy = bus.get_object('org.freedesktop.NetworkManager', c)
        iface = dbus.Interface(proxy, dbus_interface='org.freedesktop.NetworkManager.Settings.Connection')
        settings = iface.GetSettings()
        if settings['connection']['uuid'] == uuid:
            return c

    return None


def list_uuids():
    bus = dbus.SystemBus()
    for c in get_connections():
        proxy = bus.get_object('org.freedesktop.NetworkManager', c)
        iface = dbus.Interface(proxy, dbus_interface='org.freedesktop.NetworkManager.Settings.Connection')
        settings = iface.GetSettings()
        conn = settings['connection']
        print("%s - %s (%s)" % (conn['uuid'], conn['id'], conn['type']))


def get_active_connection_path(uuid):
    bus = dbus.SystemBus()
    proxy = bus.get_object('org.freedesktop.NetworkManager', '/org/freedesktop/NetworkManager')
    iface = dbus.Interface(proxy, dbus_interface='org.freedesktop.DBus.Properties')
    active_connections = iface.Get('org.freedesktop.NetworkManager', 'ActiveConnections')
    all_connections = get_connections()

    for a in active_connections:
        proxy = bus.get_object('org.freedesktop.NetworkManager', a)
        iface = dbus.Interface(proxy, dbus_interface='org.freedesktop.DBus.Properties')
        path = iface.Get('org.freedesktop.NetworkManager.Connection.Active', 'Connection')

        proxy = bus.get_object('org.freedesktop.NetworkManager', path)
        iface = dbus.Interface(proxy, dbus_interface='org.freedesktop.NetworkManager.Settings.Connection')
        settings = iface.GetSettings()

        if settings['connection']['uuid'] == uuid:
            return a

    return None


def get_wifi_device_path():
    bus = dbus.SystemBus()
    proxy = bus.get_object('org.freedesktop.NetworkManager', '/org/freedesktop/NetworkManager')
    iface = dbus.Interface(proxy, dbus_interface='org.freedesktop.NetworkManager')
    devices = iface.GetDevices()
    for d in devices:
        proxy = bus.get_object('org.freedesktop.NetworkManager', d)
        iface = dbus.Interface(proxy, dbus_interface='org.freedesktop.DBus.Properties')
        devtype = iface.Get('org.freedesktop.NetworkManager.Device', 'DeviceType')
        if devtype == 2:
            return d
    return None

def activate_connection(connection_path, device_path):

    def reply_handler(opath):
        print("Success: device activating")
        sys.exit(0)

    def error_handler(*args):
        sys.stderr.write("Error activating device: %s\n" % args)
        sys.exit(1)

    bus = dbus.SystemBus()
    proxy = bus.get_object('org.freedesktop.NetworkManager', '/org/freedesktop/NetworkManager')
    iface = dbus.Interface(proxy, dbus_interface='org.freedesktop.NetworkManager')
    iface.ActivateConnection('org.freedesktop.NetworkManager',
                             connection_path,
                             device_path,
                             "/",
                             reply_handler=reply_handler,
                             error_handler=error_handler)


# Change the UID first if required
if UID != 0:
    os.setuid(UID)

# Are we configured?
if not len(CONNECTION_UUID):
    print("missing connection UUID")
    sys.exit(0)

connection_path = get_connection_by_uuid(CONNECTION_UUID)
if not connection_path:
    # Configured VPN connection is not known to NM, check CONNECTION_UUID.
    print("couldn't find the connection")
    sys.exit(1)

device_path = get_wifi_device_path()
if not device_path:
    print("no Wi-Fi device found")
    sys.exit(1)

# Is it already activated?
if get_active_connection_path(CONNECTION_UUID):
    print("already connected")
    sys.exit(0)

print("Activating connection...")
activate_connection(connection_path, device_path)
loop = gobject.MainLoop()
loop.run()

