#!/usr/bin/env python
#
# vim: ft=python ts=4 sts=4 sw=4 et ai
# -*- Mode: Python; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
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

import sys
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
