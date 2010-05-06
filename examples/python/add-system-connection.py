#!/bin/env python
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

import dbus

s_wired = dbus.Dictionary({'duplex': 'full'})
s_con = dbus.Dictionary({
            'type': '802-3-ethernet',
            'uuid': '7371bb78-c1f7-42a3-a9db-5b9566e8ca07',
            'id': 'MyConnection'})

addr1 = dbus.Array([dbus.UInt32(50462986L), dbus.UInt32(8L), dbus.UInt32(16908554L)], signature=dbus.Signature('u'))
s_ip4 = dbus.Dictionary({
            'addresses': dbus.Array([addr1], signature=dbus.Signature('au')),
            'method': 'manual'})

s_ip6 = dbus.Dictionary({'method': 'ignore'})

con = dbus.Dictionary({
    '802-3-ethernet': s_wired,
    'connection': s_con,
    'ipv4': s_ip4,
    'ipv6': s_ip6})


bus = dbus.SystemBus()

proxy = bus.get_object("org.freedesktop.NetworkManagerSystemSettings", "/org/freedesktop/NetworkManagerSettings")
settings = dbus.Interface(proxy, "org.freedesktop.NetworkManagerSettings")

settings.AddConnection(con)

