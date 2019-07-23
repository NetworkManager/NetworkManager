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
    print('Usage: %s [[id] <id>]' % (sys.argv[0]))
    print('       %s [[uuid] <uuid>]' % (sys.argv[0]))
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
    arg_block_autoconnect = NM.SettingsUpdate2Flags.NONE
    arg_volatile = NM.SettingsUpdate2Flags.NONE
    arg_no_reapply = NM.SettingsUpdate2Flags.NONE

    cons = []

    argv = list(sys.argv[1:])
    while argv:
        if argv[0] in ['id', 'uuid']:
            if cons:
                die('cannot specify multiple connections')
            if len(argv) < 2:
                die('missing argument for "%s" specifier' % (argv[0]))
            cons.extend(find_connections(nm_client, argv[0], argv[1]))
            if len(cons) == 0:
                die('could not find connection for "%s %s"' % (argv[0], argv[1]))
            if len(cons) != 1:
                die('could not find unique connection for "%s %s"' % (argv[0], argv[1]))
            argv = argv[2:]
            continue
        if argv[0] in ['--block-autoconnect']:
            arg_block_autoconnect = NM.SettingsUpdate2Flags.BLOCK_AUTOCONNECT
            argv = argv[1:]
            continue
        if argv[0] in ['--volatile']:
            arg_volatile = NM.SettingsUpdate2Flags.VOLATILE
            argv = argv[1:]
            continue
        if argv[0] in ['--no-reapply']:
            arg_no_reapply = NM.SettingsUpdate2Flags.NO_REAPPLY
            argv = argv[1:]
            continue
        if argv[0] in ['--to-disk', '--in-memory', '--in-memory-detached', '--in-memory-only']:
            if argv[0] == '--to-disk':
                v = NM.SettingsUpdate2Flags.TO_DISK
            elif argv[0] == '--in-memory':
                v = NM.SettingsUpdate2Flags.IN_MEMORY
            elif argv[0] == '--in-memory-detached':
                v = NM.SettingsUpdate2Flags.IN_MEMORY_DETACHED
            elif argv[0] == '--in-memory-only':
                v = NM.SettingsUpdate2Flags.IN_MEMORY_ONLY
            elif argv[0] == '--keep':
                v = NM.SettingsUpdate2Flags.NONE
            else:
                assert(False)
            if arg_mode is not None:
                die('duplicate storage modes ("%s")' % (argv[0]))
            arg_mode = v
            argv = argv[1:]
            continue
        if cons:
            die('unknown argument "%s"' % (argv[0]))
        cons.extend(find_connections(nm_client, None, argv[0]))
        if len(cons) == 0:
           die('could not find connection for "%s"' % (argv[0]))
        if len(cons) != 1:
           die('could not find unique connection for "%s"' % (argv[0]))
        argv = argv[1:]
        continue

    if len(cons) != 1:
        die('missing connection argument', True)

    con = cons[0]

    con2 = NM.SimpleConnection.new_clone(con)

    result = {}
    def _update2_cb(con, async_result, user_data):
        try:
            r = con.update2_finish(async_result)
        except Exception as e:
            result['error'] = e
        else:
            result['result'] = r
        main_loop.quit()

    con.update2(con2.to_dbus(NM.ConnectionSerializationFlags.ALL),
                  (arg_mode if arg_mode is not None else NM.SettingsUpdate2Flags.NONE)
                | arg_block_autoconnect
                | arg_volatile
                | arg_no_reapply,
                None,
                None,
                _update2_cb,
                None)

    main_loop.run()

    if 'error' in result:
        die('update connection %s failed [%s]: %s' % (con_to_str(con2), ' '.join(sys.argv), result['error']))

    print('update connection %s succeeded [%s]: %s' % (con_to_str(con2), ' '.join(sys.argv), result['result']))

if __name__ == '__main__':
    main()
