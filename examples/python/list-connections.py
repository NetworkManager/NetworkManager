#!/bin/env python
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
# Copyright (C) 2010 Red Hat, Inc.
#

import dbus

# This example asks both the system settings service and the user settings
# service for all configured connections.  It also asks for secrets, demonstrating
# the mechanisms each settings service uses to prevent unauthorized access to
# a user's network passwords

bus = dbus.SystemBus()

def merge_secrets(proxy, config, setting_name):
    try:
        # returns a dict of dicts mapping name::setting, where setting is a dict
        # mapping key::value.  Each member of the 'setting' dict is a secret
        secrets = proxy.GetSecrets(setting_name, [], False)

        # Copy the secrets into our connection config
        for setting in secrets:
            for key in secrets[setting]:
                config[setting_name][key] = setting[key]
    except Exception, e:
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
        print "        Setting: %s" % setting_name
        print dict_to_string(config[setting_name], "            ")
    print ""


def print_one_services_connections(service_name, desc):
    # Ask the settings service for the list of connections it provides
    proxy = bus.get_object(service_name, "/org/freedesktop/NetworkManagerSettings")
    settings = dbus.Interface(proxy, "org.freedesktop.NetworkManagerSettings")
    connection_paths = settings.ListConnections()

    print "%s connections --------------------------------------------\n" % desc

    # List each connection's name, UUID, and type
    for path in connection_paths:
        con_proxy = bus.get_object(service_name, path)
        connection = dbus.Interface(con_proxy, "org.freedesktop.NetworkManagerSettings.Connection")
        config = connection.GetSettings()

        # Now get secrets too; we grab the secrets for each type of connection
        # (since there isn't a "get all secrets" call because most of the time
        # you only need 'wifi' secrets or '802.1x' secrets, not everything) and
        # merge that into the configuration data
        connection_secrets = dbus.Interface(con_proxy, "org.freedesktop.NetworkManagerSettings.Connection.Secrets")
        merge_secrets(connection_secrets, config, '802-11-wireless')
        merge_secrets(connection_secrets, config, '802-11-wireless-security')
        merge_secrets(connection_secrets, config, '802-1x')
        merge_secrets(connection_secrets, config, 'gsm')
        merge_secrets(connection_secrets, config, 'cdma')
        merge_secrets(connection_secrets, config, 'ppp')

        # Get the details of the 'connection' setting
	s_con = config['connection']
	print "name: %s" % s_con['id']
	print "    uuid: %s" % s_con['uuid']
	print "    type: %s" % s_con['type']
	print "    ----------------------------"
        connection_to_string(config)

    print ""

# Print out connection information for all connections
print_one_services_connections("org.freedesktop.NetworkManagerSystemSettings", "System")
print_one_services_connections("org.freedesktop.NetworkManagerUserSettings", "User")

