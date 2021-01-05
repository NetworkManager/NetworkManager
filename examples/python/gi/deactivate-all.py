#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2015 Red Hat, Inc.
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

gi.require_version("NM", "1.0")
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
                sys.exit(
                    "Usage: %s [<type>]\nAllowed types: %s"
                    % (sys.argv[0], allowed_types)
                )
        else:
            sys.exit(
                "Usage: %s [<type>]\nAllowed types: %s" % (sys.argv[0], allowed_types)
            )

    # create Client object
    client = NM.Client.new(None)

    # get all active connections
    connections = client.get_active_connections()

    # deactivate the connections
    for ac in connections:
        if ctype is None or ctype == ac.get_connection_type():
            sys.stdout.write("Deactivating %s (%s)" % (ac.get_id(), ac.get_uuid()))
            try:
                client.deactivate_connection(ac, None)
                sys.stdout.write("\033[32m  -> succeeded\033[0m\n")
            except Exception as e:
                sys.stderr.write("\033[31m  -> failed\033[0m (%s)\n" % e.message)
