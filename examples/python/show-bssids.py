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
# Copyright (C) 2010 Red Hat, Inc.
#


# This example prints out all the AP BSSIDs that all WiFi devices on the
# machine can see.  Useful for location-based services like Skyhook that
# can geolocate you based on the APs you can see.

import dbus

bus = dbus.SystemBus()

# Get a proxy for the base NetworkManager object
proxy = bus.get_object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager")
manager = dbus.Interface(proxy, "org.freedesktop.NetworkManager")

all_aps = []

print "Associated APs:"

# Get all network devices
devices = manager.GetDevices()
for d in devices:
    dev_proxy = bus.get_object("org.freedesktop.NetworkManager", d)
    prop_iface = dbus.Interface(dev_proxy, "org.freedesktop.DBus.Properties")

    # Make sure the device is enabled before we try to use it
    state = prop_iface.Get("org.freedesktop.NetworkManager.Device", "State")
    if state <= 2:
        continue

    # Get device's type; we only want wifi devices
    iface = prop_iface.Get("org.freedesktop.NetworkManager.Device", "Interface")
    dtype = prop_iface.Get("org.freedesktop.NetworkManager.Device", "DeviceType")
    if dtype == 2:   # WiFi
        # Get a proxy for the wifi interface
        wifi_iface = dbus.Interface(dev_proxy, "org.freedesktop.NetworkManager.Device.Wireless")
        wifi_prop_iface = dbus.Interface(dev_proxy, "org.freedesktop.DBus.Properties")

        # Get the associated AP's object path
        connected_path = wifi_prop_iface.Get("org.freedesktop.NetworkManager.Device.Wireless", "ActiveAccessPoint")

        # Get all APs the card can see
        aps = wifi_iface.GetAccessPoints()
        for path in aps:
            ap_proxy = bus.get_object("org.freedesktop.NetworkManager", path)
            ap_prop_iface = dbus.Interface(ap_proxy, "org.freedesktop.DBus.Properties")
            bssid = ap_prop_iface.Get("org.freedesktop.NetworkManager.AccessPoint", "HwAddress")

            # Cache the BSSID
            if not bssid in all_aps:
                all_aps.append(bssid)

            # Print the current AP's BSSID
            if path == connected_path:
                print "%s (%s)" % (bssid, iface)

# and print out all APs the wifi devices can see
print"\nFound APs:"
for bssid in all_aps:
    print bssid

