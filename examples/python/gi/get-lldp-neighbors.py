#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright (C) 2015 Red Hat, Inc.
#

import sys
import gi
gi.require_version('NM', '1.0')
from gi.repository import GLib, NM

#  This example shows how to get a list of LLDP neighbors for a given interface.

main_loop = None

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit('Usage: %s <interface>' % sys.argv[0])
    dev_iface = sys.argv[1]

    c = NM.Client.new(None)
    dev = c.get_device_by_iface(dev_iface)
    if dev is None:
        sys.exit('Device \'%s\' not found' % dev_iface)

    neighbors = dev.get_lldp_neighbors()
    for neighbor in neighbors:
        ret, chassis = neighbor.get_attr_string_value('chassis-id')
        ret, port = neighbor.get_attr_string_value('port-id')
        print "Neighbor: %s - %s" % (chassis, port)
        for attr in neighbor.get_attr_names():
            attr_type = neighbor.get_attr_type(attr)
            if attr_type.equal(GLib.VariantType.new('s')):
                ret, value = neighbor.get_attr_string_value(attr)
                print "  %-32s: %s" % (attr, value)
            elif attr_type.equal(GLib.VariantType.new('u')):
                ret, value = neighbor.get_attr_uint_value(attr)
                print "  %-32s: %u" % (attr, value)
