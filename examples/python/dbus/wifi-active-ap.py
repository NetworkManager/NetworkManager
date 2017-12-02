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
# Copyright (C) 2015 Red Hat, Inc.
#

#
# This example starts or stops a wifi hotspot
#
# Configuration settings are described at
# https://developer.gnome.org/NetworkManager/1.0/ref-settings.html
#

import dbus, sys, time

bus = dbus.SystemBus()
service_name = "org.freedesktop.NetworkManager"
proxy = bus.get_object(service_name, "/org/freedesktop/NetworkManager/Settings")
settings = dbus.Interface(proxy, "org.freedesktop.NetworkManager.Settings")

if len(sys.argv) != 2:
    print("Usage: %s <ifname>" % sys.argv[0])
    sys.exit(0)

# Get the device object path based on interface name
iface = sys.argv[1]
proxy = bus.get_object(service_name, "/org/freedesktop/NetworkManager")
nm = dbus.Interface(proxy, "org.freedesktop.NetworkManager")
devpath = nm.GetDeviceByIpIface(iface)

# Get a proxy to the wifi device and get the active access point's object path
proxy = bus.get_object(service_name, devpath)
props = dbus.Interface(proxy, "org.freedesktop.DBus.Properties")
active_ap_path = props.Get("org.freedesktop.NetworkManager.Device.Wireless", "ActiveAccessPoint")
if active_ap_path == "/":
    print("%s is not currently associated" % sys.argv[1])
    sys.exit(0)

# Get the active access point's SSID and BSSID
ap_proxy = bus.get_object(service_name, active_ap_path)
ap_props = dbus.Interface(ap_proxy, "org.freedesktop.DBus.Properties")
raw_ssid = ap_props.Get("org.freedesktop.NetworkManager.AccessPoint", "Ssid")
bssid = ap_props.Get("org.freedesktop.NetworkManager.AccessPoint", "HwAddress")

# Convert the SSID from a byte array to a string, assuming ASCII encoding
ssid = ""
for c in raw_ssid:
    ssid = ssid + chr(c)

print("%s is associated to '%s' (%s)" % (sys.argv[1], ssid, bssid))

sys.exit(0)

