#!/usr/bin/env python
#
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
# Copyright (C) 2012 Red Hat, Inc.
#

import sys
import gi
gi.require_version('NM', '1.0')
from gi.repository import GLib, NM

#
#  This example shows how to get NMIP4Config from NMDevice after it is activated.
#
#  We listen to notify::ip4-config glib signal. This signal is trigered by D-Bus
#  PropertiesChanged for IP4Config that comes after StateChanged for NMDevice.
#

main_loop = None

def do_notify(self, property):
    print("notify: %s" % property)
    ip4cfg = self.get_ip4_config()
    if ip4cfg is not None:
        print("ip4-config: %s" % ip4cfg.get_path())
        main_loop.quit()

def state_changed(obj, arg1, arg2, arg3):
    print("State changed: New: %d, Old: %d, Reason: %d" % (arg1, arg2, arg3))
    # Device is connected
    if arg1 == 100:
        obj.connect('notify::ip4-config', do_notify)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit('Usage: %s <interface>' % sys.argv[0])
    dev_iface = sys.argv[1]

    c = NM.Client.new(None)
    dev = c.get_device_by_iface(dev_iface)
    if dev is None:
        sys.exit('Device \'%s\' not found' % dev_iface)
    print("Device: %s - %s" % (dev_iface, dev.get_device_type().value_name))
    print("---------------------------------------")

    dev.connect('state-changed', state_changed)
    main_loop = GLib.MainLoop()
    main_loop.run()

