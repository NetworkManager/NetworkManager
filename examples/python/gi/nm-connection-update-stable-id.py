#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright (C) 2017 Red Hat, Inc.
#

#
# This example updates a connection's stable-id by appending -#number.

import sys
import re

import gi
gi.require_version('NM', '1.0')
from gi.repository import GLib, NM

def usage():
    print('Usage: %s [[id] <id>]' % (sys.argv[0]))
    print('       %s [[uuid] <uuid>]' % (sys.argv[0]))
    return 1

def find_connection(nm_client, arg_type, arg_id):
    for c in nm_client.get_connections():
        if arg_type in [None, 'id'] and c.get_id() == arg_id:
            return c
        if arg_type in [None, 'uuid'] and c.get_uuid() == arg_id:
            return c

def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        return usage()
    if len(sys.argv) == 3:
        arg_type = sys.argv[1]
        arg_id = sys.argv[2]
        if arg_type not in ['id', 'uuid']:
            return usage()
    else:
        arg_type = None
        arg_id = sys.argv[1]
    arg_log = '%s"%s"' % ((' with %s ' % (arg_type)) if arg_type else '', arg_id)

    main_loop = GLib.MainLoop()

    nm_client = NM.Client.new(None)

    con = find_connection(nm_client, arg_type, arg_id)
    if con is None:
        print('could not find a connection %s' % (arg_log))
        return 1

    s_con = con.get_setting_connection()
    if s_con is None:
        print('connection %s has no [connection] setting' % (arg_log))
        return 1

    arg_log = '"%s" (%s)' % (s_con.get_id(), s_con.get_uuid())

    stable_id = s_con.get_stable_id()
    if not stable_id:
        print('connection %s has no stable-id set' % (arg_log))
        return 1

    re_match = re.search('\A(.*)-([0-9]+)\Z', stable_id)
    if not re_match:
        stable_id = stable_id + '-1'
    else:
        stable_id = re_match.group(1) + '-' + str(int(re_match.group(2)) + 1)

    con2 = NM.SimpleConnection.new_clone(con)
    s_con = con2.get_setting_connection()
    s_con.set_property(NM.SETTING_CONNECTION_STABLE_ID, stable_id)

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
                NM.SettingsUpdate2Flags.BLOCK_AUTOCONNECT,
                None,
                None,
                _update2_cb,
                None)

    main_loop.run()

    if 'error' in result:
        print('update connection %s failed: %s' % (arg_log, result['error']))
        return 1

    print('update connection %s succeeded: %s' % (arg_log, result['result']))
    print('set stable-id to "%s"' % (stable_id))
    return 0

if __name__ == '__main__':
    sys.exit(main())
