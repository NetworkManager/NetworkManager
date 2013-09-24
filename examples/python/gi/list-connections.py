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
# Copyright (C) 2012 Red Hat, Inc.
#

from gi.repository import GLib, NetworkManager, NMClient

# This example asks settings service for all configured connections.
# Unfortunately, at this time since libnm-glib still makes heavy use of
# GValue and GHashTable (rather than GVariant), libnm-glib isn't fully
# usable from GObject Introspection-ready languages. Most functions will
# work fine, but e. g. nm_connection_to_hash() causes assertion failures.

main_loop = None

def print_values(setting, key, value, flags, data):
    print "  %s.%s: %s" % (setting.get_name(), key, value)

def connections_read(settings):
    connections = settings.list_connections()
    for c in connections:
        print "--- %s : %s" % (c.get_id(), c.get_path())
        c.for_each_setting_value(print_values, None)
        print "\n"
    main_loop.quit()    

if __name__ == "__main__":
    main_loop = GLib.MainLoop()
    settings = NMClient.RemoteSettings.new(None);

    # connections are read asynchronously, so we need to wait for the
    # settings object to tell us that it's read all connections
    settings.connect("connections-read", connections_read)
    main_loop.run()

