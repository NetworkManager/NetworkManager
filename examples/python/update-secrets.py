#!/usr/bin/env python
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
# Copyright (C) 2011 Red Hat, Inc.
#

#
# The example shows how to update secrets in a connection by means of D-Bus
# Update() method. The method replaces all previous settings with new ones
# including possible secrets.
# So, we get all settings using GetSettings() and then find out what secrets
# are associated with the connection using GetSecrets(), ask for new secret 
# values, and add them to the settings that we pass to Update().
#

import dbus
import sys

bus = dbus.SystemBus()

def change_secrets_in_one_setting(proxy, config, setting_name):
        # Add new secret values to the connection config
    try:
        # returns a dict of dicts mapping name::setting, where setting is a dict
        # mapping key::value.  Each member of the 'setting' dict is a secret
        secrets = proxy.GetSecrets(setting_name, [], False)

        # Ask user for new secrets and put them into our connection config
        for setting in secrets:
            for key in secrets[setting]:
                new_secret = raw_input ("Enter new secret for %s in %s: " % (key, setting))
                config[setting_name][key] = new_secret
    except Exception, e:
        code = str(e).split(':')[0]
        if code == "org.freedesktop.DBus.GLib.UnmappedError.NmSettingsInterfaceErrorQuark.Code5":
            sys.exit("Not able to get secrets, run as root")
        else:
            pass

def change_secrets(service_name, con_path, config):
    # Get existing secrets; we grab the secrets for each type of connection
    # (since there isn't a "get all secrets" call because most of the time
    # you only need 'wifi' secrets or '802.1x' secrets, not everything) and
    # set new values into the connection settings (config)
    con_proxy = bus.get_object(service_name, con_path)
    connection_secrets = dbus.Interface(con_proxy, "org.freedesktop.NetworkManagerSettings.Connection.Secrets")
    change_secrets_in_one_setting(connection_secrets, config, '802-11-wireless')
    change_secrets_in_one_setting(connection_secrets, config, '802-11-wireless-security')
    change_secrets_in_one_setting(connection_secrets, config, '802-1x')
    change_secrets_in_one_setting(connection_secrets, config, 'gsm')
    change_secrets_in_one_setting(connection_secrets, config, 'cdma')
    change_secrets_in_one_setting(connection_secrets, config, 'ppp')

def find_connection(name, service_name):
    # Ask the settings service for the list of connections it provides
    global con_path
    proxy = bus.get_object(service_name, "/org/freedesktop/NetworkManagerSettings")
    settings = dbus.Interface(proxy, "org.freedesktop.NetworkManagerSettings")
    connection_paths = settings.ListConnections()

    # Get the settings and look for connection's name
    for path in connection_paths:
        con_proxy = bus.get_object(service_name, path)
        connection = dbus.Interface(con_proxy, "org.freedesktop.NetworkManagerSettings.Connection")
        config = connection.GetSettings()

        # Find connection by the id
	s_con = config['connection']
        if name == s_con['id']:
            con_path = path
            return config

    return None


# Main part
con_path = None

if len(sys.argv) != 2 and len(sys.argv) != 3:
    sys.exit("Usage: %s <connection name> [user|system]" % sys.argv[0])

# Find the connection
if len(sys.argv) == 3:
    if sys.argv[2] == 'system':
        setting_service = "org.freedesktop.NetworkManagerSystemSettings"
    elif sys.argv[2] == 'user':
        setting_service = "org.freedesktop.NetworkManagerUserSettings"
    else:
        sys.exit("Usage: %s <connection name> [user|system]" % sys.argv[0])
    con = find_connection(sys.argv[1], setting_service)
else:
    setting_service = "org.freedesktop.NetworkManagerSystemSettings"
    con = find_connection(sys.argv[1], setting_service)
    if not con:
        setting_service = "org.freedesktop.NetworkManagerUserSettings"
        con = find_connection(sys.argv[1], setting_service)

if con:
    # Obtain new secrets and put then into connection dict 
    change_secrets(setting_service, con_path, con)

    # Change the connection with Update()
    proxy = bus.get_object(setting_service, con_path)
    settings = dbus.Interface(proxy, "org.freedesktop.NetworkManagerSettings.Connection")
    settings.Update(con)
else:
    sys.exit("No connection '%s' found" % sys.argv[1])

