#!/bin/env python

import dbus

s_wired = dbus.Dictionary({'duplex': 'full'})
s_con = dbus.Dictionary({
            'type': '802-3-ethernet',
            'uuid': '7371bb78-c1f7-42a3-a9db-5b9566e8ca07',
            'id': 'MyConnection'})

addr1 = dbus.Array([dbus.UInt32(50462986L), dbus.UInt32(0L), dbus.UInt32(16908554L)], signature=dbus.Signature('u'))
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

