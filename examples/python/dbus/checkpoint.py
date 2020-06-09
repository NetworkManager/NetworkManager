#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright (C) 2016 Red Hat, Inc.
#

import dbus, sys

# This example takes a list of device interface names as a parameter
# and tells NetworkManager to create a checkpoint on those devices. It
# is then possible to restore or destroy the checkpoint.

# Get a proxy for the base NetworkManager object
bus = dbus.SystemBus()
proxy = bus.get_object(
    "org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager"
)
manager = dbus.Interface(proxy, "org.freedesktop.NetworkManager")
allDevs = manager.GetDevices()


def Usage():
    print "Usage: %s <ROLLBACK-INTERVAL> [INTERFACE]..." % sys.argv[0]
    sys.exit(1)


def GetDevicePath(ifname):
    for dev in allDevs:
        dev_proxy = bus.get_object("org.freedesktop.NetworkManager", dev)
        prop_iface = dbus.Interface(dev_proxy, "org.freedesktop.DBus.Properties")
        interface = prop_iface.Get("org.freedesktop.NetworkManager.Device", "Interface")
        if interface == ifname:
            return dev
    return


if len(sys.argv) < 2:
    Usage()

try:
    interval = int(sys.argv[1])
except ValueError:
    Usage()

devList = []

for arg in sys.argv[2:]:
    path = GetDevicePath(arg)
    if path is None:
        raise Exception("NetworkManager knows nothing about %s" % arg)
    else:
        devList.append(path)

checkpoint = manager.CheckpointCreate(devList, interval, 1)
# DESTROY_ALL

choice = raw_input("Do you want to rollback [y/n]? ").lower()
if choice == "y":
    print "Rollback checkpoint"
    results = manager.CheckpointRollback(checkpoint)
    for d in results:
        print "  - device %s: result %u" % (d, results[d])
else:
    print "Destroy checkpoint"
    manager.CheckpointDestroy(checkpoint)
