#!/usr/bin/env python
# vim: ft=python ts=4 sts=4 sw=4 et ai
# -*- Mode: python; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
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

# This example lists currently active connections

main_loop = None

from gi.repository import GLib, NetworkManager, NMClient

def connections_read(settings):
    client = NMClient.Client.new()
    acons = client.get_active_connections()
    for ac in acons:
        rem_con = settings.get_connection_by_path(ac.get_connection())
        c_type = rem_con.get_setting_connection().get_connection_type()
        print "%s (%s) - %s" % (rem_con.get_id(), ac.get_uuid(), c_type)
    if len(acons) == 0:
       print "No active connections"
    main_loop.quit()

if __name__ == "__main__":
    main_loop = GLib.MainLoop()
    settings = NMClient.RemoteSettings.new(None);

    # connections are read asynchronously, so we need to wait for the
    # settings object to tell us that it's read all connections
    settings.connect("connections-read", connections_read)
    main_loop.run()

