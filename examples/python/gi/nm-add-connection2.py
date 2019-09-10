#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright 2019 Red Hat, Inc.
#

import sys
import re

import gi
gi.require_version('NM', '1.0')
from gi.repository import GLib, NM

def find_connections(nm_client, arg_type, arg_id):
    for c in nm_client.get_connections():
        if arg_type in [None, 'id'] and c.get_id() == arg_id:
            yield c
        if arg_type in [None, 'uuid'] and c.get_uuid() == arg_id:
            yield c

def find_connection_first(nm_client, arg_type, arg_id):
    for f in find_connections(nm_client, arg_type, arg_id):
        return f

def con_to_str(con):
    s_con = con.get_setting_connection()
    return '"%s" (%s)' % (s_con.get_id(), s_con.get_uuid())

def usage():
    arg0 = sys.argv[0]
    arg0_spaced = ' ' * len(arg0)
    print('Usage: %s [ --clone ( [id] <id> | [uuid] <uuid> ) ] \\' % (arg0))
    print('       %s [ --to-disk | --in-memory ] \\' % (arg0_spaced))
    print('       %s [ --block-autoconnect ] \\' % (arg0_spaced))
    print('       %s [ --id <new-id> ] \\' % (arg0_spaced))
    print('       %s [ --uuid <new-uuid> ] \\' % (arg0_spaced))
    return 1

def die(msg, print_usage=False):
    print(msg)
    if print_usage:
        usage()
    sys.exit(1)

def main():

    main_loop = GLib.MainLoop()

    nm_client = NM.Client.new(None)

    arg_mode = None
    arg_block_autoconnect = NM.SettingsAddConnection2Flags.NONE
    arg_id = None
    arg_uuid = None

    cons = []

    argv = list(sys.argv[1:])
    while argv:
        if argv[0] == '--clone':
            match_type = None
            if len(argv) < 2:
                die('missing argument for --clone option')
            if argv[0] in ['id', 'uuid']:
                match_type = argv[0]
                if len(argv) < 3:
                    die('missing argument for "--clone %s" option' % (match_type))
                argv = argv[1:]
            if cons:
                die('cannot specify --clone argument more than once')
            cons.extend(find_connections(nm_client, match_type, argv[1]))
            if len(cons) == 0:
                die('could not find connection for "--clone %s%s"' % ((match_type or ''), argv[1]))
            if len(cons) != 1:
                die('could not find unique connection for "--clone %s%s"' % ((match_type or ''), argv[1]))
            argv = argv[2:]
            continue
        if argv[0] in ['--block-autoconnect']:
            arg_block_autoconnect = NM.SettingsAddConnection2Flags.BLOCK_AUTOCONNECT
            argv = argv[1:]
            continue
        if argv[0] in ['--to-disk', '--in-memory']:
            if argv[0] == '--to-disk':
                v = NM.SettingsAddConnection2Flags.TO_DISK
            elif argv[0] == '--in-memory':
                v = NM.SettingsAddConnection2Flags.IN_MEMORY
            else:
                assert(False)
            if arg_mode is not None:
                die('duplicate storage modes ("%s")' % (argv[0]))
            arg_mode = v
            argv = argv[1:]
            continue
        if argv[0] in ['--id']:
            if len(argv) < 2:
                die('missing argument for --id option')
            arg_id = argv[1]
            argv = argv[2:]
            continue
        if argv[0] in ['--uuid']:
            if len(argv) < 2:
                die('missing argument for --uuid option')
            arg_uuid = argv[1]
            argv = argv[2:]
            continue
        die('unknown argument "%s"' % (argv[0]))

    if len(cons) != 1:
        die('missing --clone argument', True)

    con = cons[0]

    con2 = NM.SimpleConnection.new_clone(con)

    s_con = con2.get_setting_connection()
    if arg_id:
        s_con.set_property(NM.SETTING_CONNECTION_ID, arg_id)
    s_con.set_property(NM.SETTING_CONNECTION_UUID, arg_uuid or NM.utils_uuid_generate())

    result = {}
    def _add_connection2_cb(cl, async_result, user_data):
        try:
            c, r = nm_client.add_connection2_finish(async_result)
        except Exception as e:
            result['error'] = e
        else:
            result['result'] = r
            result['connection'] = c
        main_loop.quit()

    nm_client.add_connection2(con2.to_dbus(NM.ConnectionSerializationFlags.ALL),
                                (arg_mode if arg_mode is not None else NM.SettingsAddConnection2Flags.TO_DISK)
                              | arg_block_autoconnect,
                              None,
                              False,
                              None,
                              _add_connection2_cb,
                              None)

    main_loop.run()

    if 'error' in result:
        die('update connection %s failed [%s]: %s' % (con_to_str(con2), ' '.join(sys.argv), result['error']))

    print('update connection %s succeeded [%s]: %s, %s' % (con_to_str(con2), ' '.join(sys.argv), result['connection'].get_path(), result['result']))

if __name__ == '__main__':
    main()
