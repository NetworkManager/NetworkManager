#!/usr/bin/env python
# -*- Mode: Python; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
# vim: ft=python ts=4 sts=4 sw=4 et ai
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
# Copyright (C) 2013 Red Hat, Inc.
#

import sys
from gi.repository import GLib, NetworkManager, NMClient

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
# https://developer.gnome.org/libnm-glib/0.9/
# https://wiki.gnome.org/GObjectIntrospection
# https://wiki.gnome.org/PyGObject
#

main_loop = None

def connection_saved(connection, error, data):
    print ("Connection '%s' saved.") % (connection.get_id())
    main_loop.quit()

def connections_read(settings, data):
    con_name = sys.argv[1]
    if len(sys.argv) == 3:
        new_zone = sys.argv[2]
    else:
        new_zone = None

    found = False
    connections = settings.list_connections()
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
        print ("Error: connection '%s' not found.") % (con_name)
        main_loop.quit()


if __name__ == "__main__":
    if len(sys.argv) != 2 and len(sys.argv) != 3:
        sys.exit('Usage: %s <connection name or UUID> [new zone]' % sys.argv[0])

    main_loop = GLib.MainLoop()
    settings = NMClient.RemoteSettings.new(None);

    # Connections are read asynchronously, so we have to wait for the
    # 'settings' object to tell us that all connections have been read.
    settings.connect("connections-read", connections_read, None)
    main_loop.run()

