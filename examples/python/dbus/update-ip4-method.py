#!/usr/bin/env python
# -*- Mode: Python; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
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
# Copyright (C) 2014 Red Hat, Inc.
#

#
# This example updates a connection's IPv4 method with the Update() method.
#
# Configuration settings are described at
# https://developer.gnome.org/NetworkManager/0.9/ref-settings.html
#

import socket, struct, dbus, sys

def ip_to_int(ip_string):
    return struct.unpack("=I", socket.inet_aton(ip_string))[0]


if len(sys.argv) < 3:
    print "Usage: %s <uuid> <auto|static> [address prefix gateway]" % sys.argv[0]
    sys.exit(1)

method = sys.argv[2]
if method == "static" and len(sys.argv) < 5:
    print "Usage: %s %s static address prefix [gateway]" % (sys.argv[0], sys.argv[1])
    sys.exit(1)

# Convert method to NM method
if method == "static":
    method = "manual"

bus = dbus.SystemBus()
proxy = bus.get_object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/Settings")
settings = dbus.Interface(proxy, "org.freedesktop.NetworkManager.Settings")

for c_path in settings.ListConnections():
    c_proxy = bus.get_object("org.freedesktop.NetworkManager", c_path)
    c_obj = dbus.Interface(c_proxy, "org.freedesktop.NetworkManager.Settings.Connection")
    c_settings = c_obj.GetSettings()

    # Look for the requested connection UUID
    if c_settings['connection']['uuid'] != sys.argv[1]:
        continue

    # add IPv4 setting if it doesn't yet exist
    if not c_settings.has_key('ipv4'):
        c_settings['ipv4'] = {}

    # set the method and change properties
    c_settings['ipv4']['method'] = method
    if method == "auto":
        # remove addresses
    	c_settings['ipv4']['addresses'] = dbus.Array([], signature=dbus.Signature('au'))
    elif method == "manual":
        # Add the static IP address, prefix, and (optional) gateway
        gw = 0
        if len(sys.argv) == 6:
            gw = ip_to_int(sys.argv[5])
        addr = dbus.Array([ip_to_int(sys.argv[3]), dbus.UInt32(int(sys.argv[4])), gw], signature=dbus.Signature('u'))
        c_settings['ipv4']['addresses'] = dbus.Array([addr], signature=dbus.Signature('au'))

    # Save all the updated settings back to NetworkManager
    c_obj.Update(c_settings)
    break

sys.exit(0)

