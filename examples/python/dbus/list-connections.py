#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright (C) 2010 - 2011 Red Hat, Inc.
#

import dbus

# This example asks settings service for all configured connections.
# It also asks for secrets, demonstrating the mechanism the secrets can
# be handled with.

bus = dbus.SystemBus()

def merge_secrets(proxy, config, setting_name):
    try:
        # returns a dict of dicts mapping name::setting, where setting is a dict
        # mapping key::value.  Each member of the 'setting' dict is a secret
        secrets = proxy.GetSecrets(setting_name)

        # Copy the secrets into our connection config
        for setting in secrets:
            for key in secrets[setting]:
                config[setting_name][key] = secrets[setting][key]
    except Exception as e:
        pass

def dict_to_string(d, indent):
    # Try to trivially translate a dictionary's elements into nice string
    # formatting.
    dstr = ""
    for key in d:
        val = d[key]
        str_val = ""
        add_string = True
        if type(val) == type(dbus.Array([])):
            for elt in val:
                if type(elt) == type(dbus.Byte(1)):
                    str_val += "%s " % int(elt)
                elif type(elt) == type(dbus.String("")):
                    str_val += "%s" % elt
        elif type(val) == type(dbus.Dictionary({})):
            dstr += dict_to_string(val, indent + "    ")
            add_string = False
        else:
            str_val = val
        if add_string:
            dstr += "%s%s: %s\n" % (indent, key, str_val)
    return dstr

def connection_to_string(config):
    # dump a connection configuration to a the console
    for setting_name in config:
        print("        Setting: %s" % setting_name)
        print(dict_to_string(config[setting_name], "            "))
    print("")


def print_connections():
    # Ask the settings service for the list of connections it provides
    service_name = "org.freedesktop.NetworkManager"
    proxy = bus.get_object(service_name, "/org/freedesktop/NetworkManager/Settings")
    settings = dbus.Interface(proxy, "org.freedesktop.NetworkManager.Settings")
    connection_paths = settings.ListConnections()

    # List each connection's name, UUID, and type
    for path in connection_paths:
        con_proxy = bus.get_object(service_name, path)
        settings_connection = dbus.Interface(con_proxy, "org.freedesktop.NetworkManager.Settings.Connection")
        config = settings_connection.GetSettings()

        # Now get secrets too; we grab the secrets for each type of connection
        # (since there isn't a "get all secrets" call because most of the time
        # you only need 'wifi' secrets or '802.1x' secrets, not everything) and
        # merge that into the configuration data
        merge_secrets(settings_connection, config, '802-11-wireless')
        merge_secrets(settings_connection, config, '802-11-wireless-security')
        merge_secrets(settings_connection, config, '802-1x')
        merge_secrets(settings_connection, config, 'gsm')
        merge_secrets(settings_connection, config, 'cdma')
        merge_secrets(settings_connection, config, 'ppp')

        # Get the details of the 'connection' setting
        s_con = config['connection']
        print("    name: %s" % s_con['id'])
        print("    uuid: %s" % s_con['uuid'])
        print("    type: %s" % s_con['type'])
        print("    ------------------------------------------")
        connection_to_string(config)

    print("")

print_connections()

