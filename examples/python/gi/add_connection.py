#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright (C) 2014 Red Hat, Inc.
#

#
# This example shows how to add a new NM connection profile.
# The code uses libnm (NM) via GObject Introspection.
#
# Documentation links:
# https://developer.gnome.org/libnm/1.0/
# https://developer.gnome.org/NetworkManager/1.0/ref-settings.html
#

import gi
gi.require_version('NM', '1.0')
from gi.repository import GLib, NM
import sys, uuid

main_loop = None

def print_values(setting, key, value, flags, data):
    print("  %s.%s: %s" % (setting.get_name(), key, value))

# create an Ethernet connection and return it
def create_profile(name):
    profile = NM.SimpleConnection.new()
    s_con = NM.SettingConnection.new()
    s_con.set_property(NM.SETTING_CONNECTION_ID, name)
    s_con.set_property(NM.SETTING_CONNECTION_UUID, str(uuid.uuid4()))
    s_con.set_property(NM.SETTING_CONNECTION_TYPE, "802-3-ethernet")

    s_wired = NM.SettingWired.new()

    s_ip4 = NM.SettingIP4Config.new()
    s_ip4.set_property(NM.SETTING_IP_CONFIG_METHOD, "auto")

    s_ip6 = NM.SettingIP6Config.new()
    s_ip6.set_property(NM.SETTING_IP_CONFIG_METHOD, "auto")

    profile.add_setting(s_con)
    profile.add_setting(s_ip4)
    profile.add_setting(s_ip6)
    profile.add_setting(s_wired)

    print("Created connection profile:")
    profile.for_each_setting_value(print_values, None)

    return profile

# callback function
def added_cb(client, result, data):
    try:
        client.add_connection_finish(result)
        print("The connection profile has been successfully added to NetworkManager.")
    except Exception as e:
        sys.stderr.write("Error: %s\n" % e)
    main_loop.quit()

if __name__ == "__main__":
    # parse arguments
    persistent = False
    if len(sys.argv) != 2 and len(sys.argv) != 3:
        sys.exit('Usage: %s <connection name> [persistent]' % sys.argv[0])
    if len(sys.argv) == 3:
        if sys.argv[2] in "persistent" and sys.argv[2][:1] == "p":
            persistent = True
        else:
            sys.exit('Usage: %s <connection name> [persistent]' % sys.argv[0])
    profile_name = sys.argv[1]

    main_loop = GLib.MainLoop()

    # create Client object
    client = NM.Client.new(None)

    # create a connection profile for NM
    con = create_profile(profile_name)

    # send the connection to NM
    client.add_connection_async(con, persistent, None, added_cb, None)

    main_loop.run()

