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
# This example shows how to add a new NM connection profile.
# The code uses libnm-util (NetworkManager) and libnm-glib (NMClient)
# via GObject Introspection.
#
# Documentation links:
# https://developer.gnome.org/libnm-glib/0.9/
# https://developer.gnome.org/libnm-util/0.9/
# https://developer.gnome.org/NetworkManager/0.9/ref-settings.html
#

from gi.repository import GLib, NetworkManager, NMClient
import sys, uuid

main_loop = None

def print_values(setting, key, value, flags, data):
    print "  %s.%s: %s" % (setting.get_name(), key, value)

# create an Ethernet connection and return it
def create_profile(name):
    profile = NetworkManager.Connection.new()
    s_con = NetworkManager.SettingConnection.new()
    s_con.set_property(NetworkManager.SETTING_CONNECTION_ID, name)
    s_con.set_property(NetworkManager.SETTING_CONNECTION_UUID, str(uuid.uuid4()))
    s_con.set_property(NetworkManager.SETTING_CONNECTION_TYPE, "802-3-ethernet")

    s_wired = NetworkManager.SettingWired.new()

    s_ip4 = NetworkManager.SettingIP4Config.new()
    s_ip4.set_property(NetworkManager.SETTING_IP4_CONFIG_METHOD, "auto")

    s_ip6 = NetworkManager.SettingIP6Config.new()
    s_ip6.set_property(NetworkManager.SETTING_IP6_CONFIG_METHOD, "auto")

    profile.add_setting(s_con)
    profile.add_setting(s_ip4)
    profile.add_setting(s_ip6)
    profile.add_setting(s_wired)

    print("Created connection profile:")
    profile.for_each_setting_value(print_values, None)

    return profile

# callback function
def added_cb(settings, con, error, data):
    if error is (None):
        print("The connection profile has been succesfully added to NetworkManager.")
    else:
        print(error)
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

    # create RemoteSettings object
    settings = NMClient.RemoteSettings.new(None);

    # create a connection profile for NM
    con = create_profile(profile_name)

    # send the connection to NM
    if persistent:
        settings.add_connection(con, added_cb, None)
    else:
        settings.add_connection_unsaved(con, added_cb, None)

    main_loop.run()

