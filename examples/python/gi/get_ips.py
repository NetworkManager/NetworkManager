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
# Copyright (C) 2014 Red Hat, Inc.
#

import sys, socket, struct
from gi.repository import GLib, NetworkManager, NMClient

#
#  This example shows how to get addresses, routes and DNS information
#  from NMIP4Config and NMIP6Config (got out of NMDevice)
#

def show_addresses(self, family):
    if (family == socket.AF_INET):
       ip_cfg = self.get_ip4_config()
    else:
       ip_cfg = self.get_ip6_config()

    if ip_cfg is None:
        print("None")
        return

    nm_addresses = ip_cfg.get_addresses()
    if len(nm_addresses) == 0:
        print("None")
        return

    for nm_address in nm_addresses:
        addr = nm_address.get_address()
        prefix = nm_address.get_prefix()
        gateway = nm_address.get_gateway()

        if (family == socket.AF_INET):
            addr_struct = struct.pack("=I", addr)
            gateway_struct = struct.pack("=I", gateway)
        else:
            addr_struct = addr
            gateway_struct = gateway
        print("%s/%d  %s") % (socket.inet_ntop(family, addr_struct),
                              prefix,
                              socket.inet_ntop(family, gateway_struct))


def show_routes(self, family):
    if (family == socket.AF_INET):
       ip_cfg = self.get_ip4_config()
    else:
       ip_cfg = self.get_ip6_config()

    if ip_cfg is None:
        print("None")
        return

    nm_routes = ip_cfg.get_routes()
    if len(nm_routes) == 0:
        print("None")
        return

    for nm_route in nm_routes:
        dest = nm_route.get_dest()
        prefix = nm_route.get_prefix()
        next_hop = nm_route.get_next_hop()
        metric = nm_route.get_metric()

        if (family == socket.AF_INET):
            dest_struct = struct.pack("=I", dest)
            next_hop_struct = struct.pack("=I", next_hop)
        else:
            dest_struct = dest
            next_hop_struct = next_hop
        print("%s/%d  %s  %d") % (socket.inet_ntop(family, dest_struct),
                                  prefix,
                                  socket.inet_ntop(family, next_hop_struct),
                                  metric)


def show_dns(self, family):
    if (family == socket.AF_INET):
       ip_cfg = self.get_ip4_config()
    else:
       ip_cfg = self.get_ip6_config()

    if ip_cfg is None:
        print("None")
        return

    if (family == socket.AF_INET):
        print ("Domains: %s") % (ip_cfg.get_domains())
        print ("Searches: %s") % (ip_cfg.get_searches())
        print("Nameservers:")
        nameservers = ip_cfg.get_nameservers()
        for dns in nameservers:
            print socket.inet_ntop(family, struct.pack("=I", dns))
    else:
        print ("Domains: %s") % (ip_cfg.get_domains())
        print ("Searches: %s") % (ip_cfg.get_searches())
        print("Nameservers:")
        num = ip_cfg.get_num_nameservers()
        for i in range(0,num):
           dns = ip_cfg.get_nameserver(i)
           print socket.inet_ntop(family, dns)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit('Usage: %s <interface>' % sys.argv[0])
    dev_iface = sys.argv[1]

    c = NMClient.Client.new()
    dev = c.get_device_by_iface(dev_iface)
    if dev is None:
        sys.exit('Device \'%s\' not found' % dev_iface)
    print "Device: %s - %s" % (dev_iface, dev.get_device_type().value_name)
    print "---------------------------------------"

    print("IPv4 addresses:")
    print("---------------")
    show_addresses(dev, socket.AF_INET)
    print

    print("IPv4 routes:")
    print("------------")
    show_routes(dev, socket.AF_INET)
    print

    print "IPv6 addresses:"
    print("---------------")
    show_addresses(dev, socket.AF_INET6)
    print

    print "IPv6 routes:"
    print("------------")
    show_routes(dev, socket.AF_INET6)
    print

    print "IPv4 DNS:"
    print("------------")
    show_dns(dev, socket.AF_INET)
    print

    print "IPv6 DNS:"
    print("------------")
    show_dns(dev, socket.AF_INET6)
    print

