#!/usr/bin/env python
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

#
# This example updates a connection's IPv4 method with the Update() method
# using the libnm-glib GObject-based convenience APIs.
#
# Configuration settings are described at
# https://developer.gnome.org/NetworkManager/0.9/ref-settings.html
#

from gi.repository import GLib, NetworkManager, NMClient
import sys, struct, socket

def ip_to_int(ip_string):
    return struct.unpack("=I", socket.inet_aton(ip_string))[0]

# callback function
def commit_cb(connection, error, data):
    if error is (None):
        print("The connection profile has been updated.")
    else:
        print(error)
    main_loop.quit()

def connections_read_cb(settings, data):
    uuid, method, args = data

    all_connections = settings.list_connections()
    for c in all_connections:
        if c.get_uuid() != uuid:
            continue

        # add IPv4 setting if it doesn't yet exist
        s_ip4 = c.get_setting_ip4_config()
        if not s_ip4:
            s_ip4 = NetworkManager.SettingIP4Config.new()
            c.add_setting(s_ip4)

        # set the method and change properties
        s_ip4.set_property(NetworkManager.SETTING_IP4_CONFIG_METHOD, method)
        if method == "auto":
            # remove addresses
            s_ip4.clear_addresses()
        elif method == "manual":
            # Add the static IP address, prefix, and (optional) gateway
            addr = NetworkManager.IP4Address.new()
            addr.set_address(ip_to_int(sys.argv[3]))
            addr.set_prefix(int(sys.argv[4]))
            if len(sys.argv) == 6:
                addr.set_gateway(ip_to_int(sys.argv[5]))
            s_ip4.add_address(addr)

        c.commit_changes(commit_cb, None)

if __name__ == "__main__":
    # parse and validate arguments
    if len(sys.argv) < 3:
        print "Usage: %s <uuid> <auto|static> [address prefix gateway]" % sys.argv[0]
        sys.exit(1)

    method = sys.argv[2]
    if method == "static" and len(sys.argv) < 5:
        print "Usage: %s %s static address prefix [gateway]" % (sys.argv[0], sys.argv[1])
        sys.exit(1)

    # Convert method to NM method
    if method == "static":
        method = "manual"

    main_loop = GLib.MainLoop()

    # create RemoteSettings object and attach to the "connections-read" signal
    # to wait for connections to be loaded asynchronously
    settings = NMClient.RemoteSettings.new(None)
    settings.connect('connections-read', connections_read_cb, (sys.argv[1], method, sys.argv))

    main_loop.run()

