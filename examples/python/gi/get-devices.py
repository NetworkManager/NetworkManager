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
# Copyright (C) 2014 Red Hat, Inc.
#

# This example lists all devices, both real and placeholder ones

import gi
gi.require_version('NM', '1.0')
from gi.repository import GLib, NM

if __name__ == "__main__":
    client = NM.Client.new(None)
    devices = client.get_all_devices()

    print "Real devices"
    print "------------"
    for d in devices:
        if d.is_real():
            print "%s (%s): %s" % (d.get_iface(), d.get_type_description(), d.get_state())

    print "\nUnrealized/placeholder devices"
    print "------------------------------"
    for d in devices:
        if not d.is_real():
            print "%s (%s): %s" % (d.get_iface(), d.get_type_description(), d.get_state())

