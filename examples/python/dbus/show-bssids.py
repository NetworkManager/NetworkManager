#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2010 Red Hat, Inc.
#

# This example prints out all the AP BSSIDs that all Wi-Fi devices on the
# machine can see.  Useful for location-based services like Skyhook that
# can geolocate you based on the APs you can see.
#
# Note that with NetworkManager clients are required to request scanning.
# If you don't do that, the scan list may be outdated. That means, you would
# check the LastScan property, and if necessary call RequestScan() first.
# After RequestScan(), you wait until the LastScan property gets bumped again.

import dbus

bus = dbus.SystemBus()

# Get a proxy for the base NetworkManager object
proxy = bus.get_object(
    "org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager"
)
manager = dbus.Interface(proxy, "org.freedesktop.NetworkManager")

all_aps = []

print("Associated APs:")

# Get all network devices
devices = manager.GetDevices()
for d in devices:
    dev_proxy = bus.get_object("org.freedesktop.NetworkManager", d)
    prop_iface = dbus.Interface(dev_proxy, "org.freedesktop.DBus.Properties")

    # Make sure the device is enabled before we try to use it
    state = prop_iface.Get("org.freedesktop.NetworkManager.Device", "State")
    if state <= 20:  # NM_DEVICE_STATE_UNAVAILABLE
        continue

    # Get device's type; we only want wifi devices
    iface = prop_iface.Get("org.freedesktop.NetworkManager.Device", "Interface")
    dtype = prop_iface.Get("org.freedesktop.NetworkManager.Device", "DeviceType")
    if dtype == 2:  # WiFi
        # Get a proxy for the wifi interface
        wifi_iface = dbus.Interface(
            dev_proxy, "org.freedesktop.NetworkManager.Device.Wireless"
        )
        wifi_prop_iface = dbus.Interface(dev_proxy, "org.freedesktop.DBus.Properties")

        # Get the associated AP's object path
        connected_path = wifi_prop_iface.Get(
            "org.freedesktop.NetworkManager.Device.Wireless", "ActiveAccessPoint"
        )

        # Get all APs the card can see
        aps = wifi_iface.GetAccessPoints()
        for path in aps:
            ap_proxy = bus.get_object("org.freedesktop.NetworkManager", path)
            ap_prop_iface = dbus.Interface(ap_proxy, "org.freedesktop.DBus.Properties")
            bssid = ap_prop_iface.Get(
                "org.freedesktop.NetworkManager.AccessPoint", "HwAddress"
            )

            # Cache the BSSID
            if not bssid in all_aps:
                all_aps.append(bssid)

            # Print the current AP's BSSID
            if path == connected_path:
                print("%s (%s)" % (bssid, iface))

# and print out all APs the wifi devices can see
print("\nFound APs:")
for bssid in all_aps:
    print(bssid)
