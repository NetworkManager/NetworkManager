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
# Copyright 2014 Red Hat, Inc.
#

import sys, socket
import gi
gi.require_version('NM', '1.0')
from gi.repository import GLib, NM

#
#  This example shows how to get addresses, routes and DNS information
#  from NMIP4Config and NMIP6Config (got out of NMDevice)
#

def show_addresses(dev, family):
    if (family == socket.AF_INET):
       ip_cfg = dev.get_ip4_config()
    else:
       ip_cfg = dev.get_ip6_config()

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

        print("%s/%d") % (addr, prefix)

def show_gateway(dev, family):
    if (family == socket.AF_INET):
        ip_cfg = dev.get_ip4_config()
    else:
        ip_cfg = dev.get_ip6_config()

    if ip_cfg is None:
        gw = "None"
    else:
        gw = ip_cfg.get_gateway()
        if gw == '':
            gw = "None"

    print(gw)

def show_routes(dev, family):
    if (family == socket.AF_INET):
       ip_cfg = dev.get_ip4_config()
    else:
       ip_cfg = dev.get_ip6_config()

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

        print("%s/%d  %s  %d") % (dest, prefix, next_hop, metric)


def show_dns(dev, family):
    if (family == socket.AF_INET):
       ip_cfg = dev.get_ip4_config()
    else:
       ip_cfg = dev.get_ip6_config()

    if ip_cfg is None:
        print("None")
        return

    print ("Nameservers: %s") % (ip_cfg.get_nameservers())
    print ("Domains: %s") % (ip_cfg.get_domains())
    print ("Searches: %s") % (ip_cfg.get_searches())
    if (family == socket.AF_INET):
        print ("WINS: %s") % (ip_cfg.get_wins_servers())


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

    print("IPv4 addresses:")
    print("---------------")
    show_addresses(dev, socket.AF_INET)
    print

    print("IPv4 gateway:")
    print("-------------")
    show_gateway(dev, socket.AF_INET)
    print

    print("IPv4 routes:")
    print("------------")
    show_routes(dev, socket.AF_INET)
    print

    print("IPv6 addresses:")
    print("---------------")
    show_addresses(dev, socket.AF_INET6)
    print

    print("IPv6 gateway:")
    print("-------------")
    show_gateway(dev, socket.AF_INET6)
    print

    print("IPv6 routes:")
    print("------------")
    show_routes(dev, socket.AF_INET6)
    print

    print("IPv4 DNS:")
    print("------------")
    show_dns(dev, socket.AF_INET)
    print

    print("IPv6 DNS:")
    print("------------")
    show_dns(dev, socket.AF_INET6)
    print

