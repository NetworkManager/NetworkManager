#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright (C) 2010 - 2012 Red Hat, Inc.
#

#
# This example adds a new ethernet connection via the AddConnection()
# D-Bus call, using the new 'ipv4.address-data' and 'ipv4.gateway'
# settings introduced in NetworkManager 1.0. Compare
# add-connection-compat.py, which will work against older versions of
# NetworkManager as well.
#
# Configuration settings are described at
# https://developer.gnome.org/NetworkManager/1.0/ref-settings.html
#

import dbus, uuid

s_wired = dbus.Dictionary({'duplex': 'full'})
s_con = dbus.Dictionary({
            'type': '802-3-ethernet',
            'uuid': str(uuid.uuid4()),
            'id': 'MyConnectionExample'})

addr1 = dbus.Dictionary({
    'address': '10.1.2.3',
    'prefix': dbus.UInt32(8)})
s_ip4 = dbus.Dictionary({
            'address-data': dbus.Array([addr1], signature=dbus.Signature('a{sv}')),
            'gateway': '10.1.2.1',
            'method': 'manual'})

s_ip6 = dbus.Dictionary({'method': 'ignore'})

con = dbus.Dictionary({
    '802-3-ethernet': s_wired,
    'connection': s_con,
    'ipv4': s_ip4,
    'ipv6': s_ip6})


print("Creating connection:", s_con['id'], "-", s_con['uuid'])

bus = dbus.SystemBus()
proxy = bus.get_object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/Settings")
settings = dbus.Interface(proxy, "org.freedesktop.NetworkManager.Settings")

settings.AddConnection(con)

