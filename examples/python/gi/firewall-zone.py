#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright (C) 2013 - 2014 Red Hat, Inc.
#

import sys
import gi
gi.require_version('NM', '1.0')
from gi.repository import GLib, NM

#
# This example demonstrates how to get and change firewall zone in a
# connection. It uses GObject Introspection instead of direct D-Bus calls.
# 'zone' is a property of 'connection' setting in a connection. You can't
# get/set individual properties directly. Rather you ask for the whole
# connection, change a property and update the connection back into
# NetworkManager.
# If you used D-Bus calls, you would call GetSettings() and then Update().
#
# Links:
# https://developer.gnome.org/libnm/1.0/
# https://wiki.gnome.org/GObjectIntrospection
# https://wiki.gnome.org/PyGObject
#

main_loop = None

def connection_saved(connection, error, data):
    print ("Connection '%s' saved.") % (connection.get_id())
    main_loop.quit()

if __name__ == "__main__":
    if len(sys.argv) != 2 and len(sys.argv) != 3:
        sys.exit('Usage: %s <connection name or UUID> [new zone]' % sys.argv[0])

    main_loop = GLib.MainLoop()
    client = NM.Client.new(None)
    connections = client.get_connections()

    con_name = sys.argv[1]
    if len(sys.argv) == 3:
        new_zone = sys.argv[2]
    else:
        new_zone = None

    found = False
    for c in connections:
        if c.get_id() == con_name or c.get_uuid() == con_name:
            found = True
            s_con = c.get_setting_connection()
            if new_zone is None:
                zone = s_con.get_zone()
                if zone is not None:
                    print("'%s' zone is '%s'") % (c.get_id(), zone)
                else:
                    print("'%s' zone is empty") % (c.get_id())
                main_loop.quit()
            else:
                s_con.set_property("zone", new_zone)
                c.commit_changes(connection_saved, None)
                print("'%s' zone set to '%s'") % (c.get_id(), new_zone)
            break
    if not found:
        sys.stderr.write("Error: connection '%s' not found.\n") % (con_name)
        main_loop.quit()
