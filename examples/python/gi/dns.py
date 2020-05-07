#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright (C) 2016 Red Hat, Inc.
#

import gi
gi.require_version('NM', '1.0')
from gi.repository import GLib, NM

#  This example shows how to monitor the DNS configuration

main_loop = None

def handle_config(config):
    print " ---- new configuration ----"
    for entry in config:
        print " * servers: %s" % ', '.join(map(str, entry.get_nameservers()))

        domains = entry.get_domains()
        if domains and domains[0]:
                print "   domains: %s" % ', '.join(map(str, domains))

        if entry.get_interface():
                print "   interface: %s" % entry.get_interface()

        print "   priority: %d" % entry.get_priority()

        if entry.get_vpn():
            print "   vpn: yes"

        print ""

def dns_config_changed(self, property):
    handle_config(self.get_dns_configuration())

main_loop = None

if __name__ == "__main__":
    c = NM.Client.new(None)
    c.connect("notify::dns-configuration", dns_config_changed)

    handle_config(c.get_dns_configuration())

    main_loop = GLib.MainLoop()
    main_loop.run()
