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
# Copyright (C) 2016 Red Hat, Inc.
#

import dbus, sys

# This example takes a list of device interface names as a parameter
# and tells NetworkManager to create a checkpoint on those devices. It
# is then possible to restore or destroy the checkpoint.

# Get a proxy for the base NetworkManager object
bus = dbus.SystemBus()
proxy = bus.get_object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager")
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
    if path == None:
        raise Exception("NetworkManager knows nothing about %s" % arg)
    else:
        devList.append(path)

checkpoint = manager.CheckpointCreate(devList,
                                      interval,
                                      1); # DESTROY_ALL

choice = raw_input('Do you want to rollback [y/n]? ').lower()
if choice == 'y':
    print "Rollback checkpoint"
    results = manager.CheckpointRollback(checkpoint)
    for d in results:
        print "  - device %s: result %u" % (d, results[d])
else:
    print "Destroy checkpoint"
    manager.CheckpointDestroy(checkpoint)
