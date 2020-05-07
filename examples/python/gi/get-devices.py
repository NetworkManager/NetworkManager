#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright (C) 2014 Red Hat, Inc.
#

# This example lists all devices, both real and placeholder ones

import gi
gi.require_version('NM', '1.0')
from gi.repository import NM

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

