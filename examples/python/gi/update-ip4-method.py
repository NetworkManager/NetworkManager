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
# Copyright 2014 Red Hat, Inc.
#

#
# This example updates a connection's IPv4 method with the Update() method
# using the libnm GObject-based convenience APIs.
#
# Configuration settings are described at
# https://developer.gnome.org/NetworkManager/1.0/ref-settings.html
#

import gi
gi.require_version('NM', '1.0')
from gi.repository import GLib, NM
import sys, socket

if __name__ == "__main__":
    # parse and validate arguments
    if len(sys.argv) < 3:
        print("Usage: %s <uuid> <auto|static> [address prefix gateway]" % sys.argv[0])
        sys.exit(1)

    method = sys.argv[2]
    if (method == "static" or method == "manual") and len(sys.argv) < 5:
        print("Usage: %s %s static address prefix [gateway]" % (sys.argv[0], sys.argv[1]))
        sys.exit(1)

    uuid = sys.argv[1]

    # Convert method to NM method
    if method == "static":
        method = "manual"

    main_loop = GLib.MainLoop()

    # create Client object
    client = NM.Client.new(None)

    all_connections = client.get_connections()
    for c in all_connections:
        if c.get_uuid() != uuid:
            continue

        # add IPv4 setting if it doesn't yet exist
        s_ip4 = c.get_setting_ip4_config()
        if not s_ip4:
            s_ip4 = NM.SettingIP4Config.new()
            c.add_setting(s_ip4)

        # set the method and change properties
        s_ip4.set_property(NM.SETTING_IP_CONFIG_METHOD, method)
        if method == "auto":
            # remove addresses and gateway
            s_ip4.clear_addresses()
            s_ip4.props.gateway = None
        elif method == "manual":
            # Add the static IP address, prefix, and (optional) gateway
            addr = NM.IPAddress.new(socket.AF_INET, sys.argv[3], int(sys.argv[4]))
            s_ip4.add_address(addr)
            if len(sys.argv) == 6:
                s_ip4.props.gateway = sys.argv[5]

        try:
            c.commit_changes(True, None)
            print("The connection profile has been updated.")
        except Exception as e:
            sys.stderr.write("Error: %s\n" % e)
        break

