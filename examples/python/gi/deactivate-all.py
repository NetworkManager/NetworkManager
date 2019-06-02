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
# Copyright 2015 Red Hat, Inc.
#

#
# This example deactivates all active connections (of certain type).
# It makes use of libnm via GObject introspection.
#
# Links:
# https://developer.gnome.org/libnm/1.0/
# https://wiki.gnome.org/GObjectIntrospection
# https://wiki.gnome.org/PyGObject
#

import sys
import gi
gi.require_version('NM', '1.0')
from gi.repository import NM

# supported connection types
connection_types = {
  NM.SETTING_VPN_SETTING_NAME,
  NM.SETTING_WIRELESS_SETTING_NAME,
  NM.SETTING_WIRED_SETTING_NAME,
  NM.SETTING_BOND_SETTING_NAME,
  NM.SETTING_BRIDGE_SETTING_NAME,
  NM.SETTING_TEAM_SETTING_NAME,
  NM.SETTING_INFINIBAND_SETTING_NAME,
  NM.SETTING_PPPOE_SETTING_NAME,
  NM.SETTING_ADSL_SETTING_NAME,
  NM.SETTING_BLUETOOTH_SETTING_NAME,
  NM.SETTING_WIMAX_SETTING_NAME,
  NM.SETTING_OLPC_MESH_SETTING_NAME,
  NM.SETTING_GENERIC_SETTING_NAME,
}


if __name__ == "__main__":
    if len(sys.argv) == 1:
        ctype = None
    else:
        allowed_types = ", ".join(connection_types)
        if len(sys.argv) == 2:
            ctype = sys.argv[1]
            if ctype not in connection_types:
                sys.exit('Usage: %s [<type>]\nAllowed types: %s' % (sys.argv[0], allowed_types))
        else:
            sys.exit('Usage: %s [<type>]\nAllowed types: %s' % (sys.argv[0], allowed_types))

    # create Client object
    client = NM.Client.new(None)

    # get all active connections
    connections = client.get_active_connections()

    # deactivate the connections
    for ac in connections:
        if ctype == None or ctype == ac.get_connection_type():
            sys.stdout.write("Deactivating %s (%s)" % (ac.get_id(), ac.get_uuid()))
            try:
                client.deactivate_connection(ac, None)
                sys.stdout.write("\033[32m  -> succeeded\033[0m\n")
            except Exception as e:
               sys.stderr.write("\033[31m  -> failed\033[0m (%s)\n" % e.message)

