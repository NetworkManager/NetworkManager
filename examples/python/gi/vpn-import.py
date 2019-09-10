#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright 2014 Red Hat, Inc.
#

#
# This example imports a VPN connection, by loading the glib based
# VPN plugin.

import gi
gi.require_version('NM', '1.0')
from gi.repository import GLib, NM

import sys

if len(sys.argv) != 2:
    print("Expects one argument: the filename")
    sys.exit(1)
filename = sys.argv[1]

connection = None
for vpn_info in NM.VpnPluginInfo.list_load():
    print("TRY:  plugin %s" % (vpn_info.get_filename()))
    try:
        vpn_plugin = vpn_info.load_editor_plugin()
    except Exception as e:
        print("SKIP: cannot load plugin: %s" % (e))
        continue
    try:
        connection = vpn_plugin.import_(filename)
    except Exception as e:
        print("SKIP: failure to import %s" % (e))
        continue
    break

if connection is None:
    print("None of the VPN plugins was able to import \"%s\"" % (filename))
    sys.exit(1)

connection.normalize()

print("connection imported from \"%s\" using plugin \"%s\" (\"%s\", %s)" % (filename, vpn_info.get_filename(), connection.get_id(), connection.get_uuid()))

client = NM.Client.new(None)

main_loop = GLib.MainLoop()

def added_cb(client, result, data):
    try:
        client.add_connection_finish(result)
        print("The connection profile has been successfully added to NetworkManager.")
    except Exception, e:
        print("ERROR: failed to add connection: %s\n" % e)
    main_loop.quit()

client.add_connection_async(connection, True, None, added_cb, None)

main_loop.run()
