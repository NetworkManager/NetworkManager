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
# Copyright (C) 2010 - 2012 Red Hat, Inc.
#

#
# This example adds a new ethernet connection via the AddConnection()
# D-Bus call, using backward-compatible settings, so it will work with
# both old and new versions of NetworkManager. Compare
# add-connection.py, which only supports NM 1.0 and later.
#
# Configuration settings are described at
# https://developer.gnome.org/NetworkManager/1.0/ref-settings.html
#

import socket, struct, dbus, uuid

# Helper functions
def ip_to_int(ip_string):
    return struct.unpack("=I", socket.inet_aton(ip_string))[0]

def int_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("=I", ip_int))

s_wired = dbus.Dictionary({'duplex': 'full'})
s_con = dbus.Dictionary({
            'type': '802-3-ethernet',
            'uuid': str(uuid.uuid4()),
            'id': 'MyConnectionExample'})

addr1 = dbus.Array([ip_to_int("10.1.2.3"), dbus.UInt32(8L), ip_to_int("10.1.2.1")], signature=dbus.Signature('u'))
s_ip4 = dbus.Dictionary({
            'addresses': dbus.Array([addr1], signature=dbus.Signature('au')),
            'method': 'manual'})

s_ip6 = dbus.Dictionary({'method': 'ignore'})

con = dbus.Dictionary({
    '802-3-ethernet': s_wired,
    'connection': s_con,
    'ipv4': s_ip4,
    'ipv6': s_ip6})


print "Creating connection:", s_con['id'], "-", s_con['uuid']

bus = dbus.SystemBus()
proxy = bus.get_object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/Settings")
settings = dbus.Interface(proxy, "org.freedesktop.NetworkManager.Settings")

settings.AddConnection(con)

