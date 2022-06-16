#!/usr/bin/env python
# SPDX-License-Identifier: LGPL-2.1-or-later

import dbus, uuid

s_con = dbus.Dictionary(
    {"type": "802-11-wireless", "uuid": str(uuid.uuid4()), "id": "My-WPA3-Personal"}
)

s_wifi = dbus.Dictionary(
    {"ssid": dbus.ByteArray("wpa3wifi".encode("utf-8")), "mode": "infrastructure"}
)

s_wsec = dbus.Dictionary({"key-mgmt": "sae", "psk": "super-secret-password"})

s_ip4 = dbus.Dictionary({"method": "auto"})
s_ip6 = dbus.Dictionary({"method": "ignore"})

con = dbus.Dictionary(
    {
        "connection": s_con,
        "802-11-wireless": s_wifi,
        "802-11-wireless-security": s_wsec,
        "ipv4": s_ip4,
        "ipv6": s_ip6,
    }
)
print("Creating connection:", s_con["id"], "-", s_con["uuid"])

bus = dbus.SystemBus()
proxy = bus.get_object(
    "org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/Settings"
)
settings = dbus.Interface(proxy, "org.freedesktop.NetworkManager.Settings")

settings.AddConnection(con)
