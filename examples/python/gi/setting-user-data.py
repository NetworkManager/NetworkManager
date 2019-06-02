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
# Copyright 2017 Red Hat, Inc.

#
# set and show user-data for a connection:
#
# - Show all user data for all connections:
#   $ ./examples/python/gi/setting-user-data.py
# - Filter to show only connections with matching id or uuid
#   $ ./examples/python/gi/setting-user-data.py id my-connection
#   $ ./examples/python/gi/setting-user-data.py uuid 123e4567-e89b-12d3-a456-426655440000
# - id and uuid can be repeated to select multiple connections
#   $ ./examples/python/gi/setting-user-data.py id my-connection1 id my-other-connection
#
# - Specify the user-data keys you want to see
#   $ ./examples/python/gi/setting-user-data.py id my-connection my.user.field.1
#   $ ./examples/python/gi/setting-user-data.py id my-connection my.user.field.1 my.other.userfield
# - Prefix the field name with ~ to use a regex
#   $ ./examples/python/gi/setting-user-data.py '~^my\.user\.'
#
# - set the fields, you need to select exactly one connection
#   $ ./examples/python/gi/setting-user-data.py set id "$NAME" my.field.1 my-value1
# - delete a user-setting
#   $ ./examples/python/gi/setting-user-data.py set id "$NAME" -d my.field.1
# - set/delete multiple user data values at once
#   $ ./examples/python/gi/setting-user-data.py set id "$NAME" my.field.1 my-value1 -d my.other.field
#
# - libnm already client side rejects invalid values, like
#   $ ./examples/python/gi/setting-user-data.py set id "$NAME" invalid_name 'has-no-dot'
# - to allow client side to specify invalid values and send them to the
#   server, pass --set-gobject
#   $ ./examples/python/gi/setting-user-data.py set id "$NAME" invalid_name 'has-no-dot' --set-gobject
#

import sys
import re

import gi
gi.require_version('NM', '1.0')
from gi.repository import NM

def pr(v):
    import pprint
    pprint.pprint(v, indent=4, depth=5, width=60)

def parse_args():
    args = {
        'set': False,
        'set-gobject': False,
        'filter': [],
        'data': []
    }
    i = 1
    while i < len(sys.argv):
        a = sys.argv[i]
        if i == 1:
            if a in ['s', 'set']:
                args['set'] = True
                i += 1
                continue
            elif a in ['g', 'get']:
                args['set'] = False
                i += 1
                continue
        if a in ['id', 'uuid']:
            args['filter'].append((a, sys.argv[i+1]))
            i += 2
            continue

        if a in ['--set-gobject']:
            args['set-gobject'] = True
            i += 1
            continue

        if a == 'data':
            i += 1
            a = sys.argv[i]
        if args['set']:
            if a == '-d':
                args['data'].append((sys.argv[i+1], None))
            else:
                args['data'].append((a, sys.argv[i+1]))
            i += 2
        else:
            args['data'].append(a)
            i += 1

    return args

def connection_to_str(connection):
    return '%s (%s)' % (connection.get_id(), connection.get_uuid())

def connections_filter(connections, filter_data):
    connections = list(sorted(connections, key=connection_to_str))
    if not filter_data:
        return connections
    # we preserve the order of the selected connections. And
    # if connections are selected multiple times, we return
    # them multiple times.
    l = []
    for f in filter_data:
        if f[0] == 'id':
            for c in connections:
                if f[1] == c.get_id():
                    l.append(c)
        else:
            assert(f[0] == 'uuid')
            for c in connections:
                if f[1] == c.get_uuid():
                    l.append(c)
    return l

def print_user_data(connection, data_allow_regex, data, prefix=''):
    s_u = connection.get_setting(NM.SettingUser)
    n = 'none'
    keys_len = 0
    keys = []
    if s_u is not None:
        all_keys = s_u.get_keys()
        keys_len = len(all_keys)
        if data:
            for d in data:
                if data_allow_regex and len(d) > 0 and d[0] == '~':
                    r = re.compile(d[1:])
                    keys.extend([k for k in all_keys if r.match(k)])
                else:
                    keys.append (d)
        else:
            keys.extend(all_keys)
        n = '%s' % (keys_len)

    print('%s%s [%s]' % (prefix, connection_to_str(connection), n))
    dd = { }
    if s_u is not None:
        dd = s_u.get_property(NM.SETTING_USER_DATA)
    for k in keys:
        if s_u is not None:
            v = s_u.get_data(k)
            if v is None:
                if k in dd:
                    print('%s   INVALID:   "%s" = "%s"' % (prefix, k, dd[k]))
                else:
                    print('%s   MISSING:   "%s"' % (prefix, k))
            else:
                assert(v == dd.get(k, None))
                print('%s   SET:       "%s" = "%s"' % (prefix, k, v))
        else:
            print('%s   MISSING:  "%s"' % (prefix, k))


def do_get(connections, data):
    first_line = True
    connections = list(connections)
    if not connections:
        print('no matching connections (use id|uuid argument)')
        sys.exit(1)
    for c in connections:
        if first_line:
            first_line = False
        else:
            print('')
        print_user_data(c, True, data)

def do_set(connection, data, set_gobject):
    print_user_data(connection, False,
                    [d[0] for d in data],
                    prefix = 'BEFORE: ')
    print('')
    s_u = connection.get_setting(NM.SettingUser)
    if s_u is None:
        connection.add_setting(NM.SettingUser())
        s_u = connection.get_setting(NM.SettingUser)
    for d in data:
        key = d[0]
        val = d[1]
        if val is None:
            print(' DEL: "%s"' % (key))
        else:
            print(' SET: "%s" = "%s"' % (key, val))
        if set_gobject:
            d = s_u.get_property(NM.SETTING_USER_DATA)
            if val is None:
                d.pop(key, None)
            else:
                d[key] = val
            s_u.set_property(NM.SETTING_USER_DATA, d)
        else:
            try:
                s_u.set_data(key, val)
            except Exception as e:
                if val is None:
                    print('error deleting key "%s": %s' % (key, e))
                else:
                    print('error setting key "%s" = "%s": %s' % (key, val, e))
                sys.exit(1)


    try:
        connection.commit_changes(True, None)
    except Exception as e:
        print('failure to commit connection: %s' % (e))
        sys.exit(1)

    print('')
    print_user_data(connection, False,
                    [d[0] for d in data],
                    prefix = 'AFTER:  ')

###############################################################################

if __name__ == '__main__':
    args = parse_args()
    nm_client = NM.Client.new(None)

    connections = connections_filter(nm_client.get_connections(), args['filter'])

    if args['set']:
        if not args['data']:
            print('Requires one or more arguments to set or delete')
            sys.exit(1)
        if len(connections) != 1:
            print('To set the user-data of a connection, exactly one connection must be selected via id|uuid. Instead, %s connection matched ([%s])' %
                  (len(connections), ', '.join([connection_to_str(c) for c in connections])))
            sys.exit(1)
        do_set(connections[0], args['data'], args['set-gobject'])
    else:
        do_get(connections, args['data'])

