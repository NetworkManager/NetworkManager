#!/usr/bin/env python

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# Copyright 2017 Red Hat, Inc.

import sys

import gi
gi.require_version('NM', '1.0')
from gi.repository import GLib, NM

import os

###############################################################################

def usage():
    print("Usage: %s [COMMAND [ARG]...]" % sys.argv[0])
    print("")
    print(" COMMANDS:  [show]")
    print("            create TIMEOUT [--destroy-all|--delete-new-connections|--disconnect-new-devices|--allow-overlapping|DEV]...")
    print("            destroy PATH|NUMBER")
    print("            rollback PATH|NUMBER")
    print("            adjust-rollback-timeout PATH|NUMBER TIMEOUT")
    print("")
    sys.exit(1)

def show(c, ts = None):
    cr = c.get_created()
    rt = c.get_rollback_timeout()
    print("%s:" % c.get_path())
    print("  created: %u%s" % (cr, "" if ts is None else (" (%s sec ago)" % ((ts - cr) / 1000.0))))
    if rt == 0:
        print("  timeout: infinity")
    else:
        print("  timeout: %u seconds%s" % (rt, "" if ts is None else (" (circa %s sec left)" % ((cr + (rt * 1000) - ts) / 1000.0))))
    print("  devices: %s" % (' '.join(sorted(map(lambda x: x.get_iface(), c.get_devices())))))

def find_checkpoint(client, path):
    for c in client.get_checkpoints():
        if c.get_path() == path:
            return c
    return None

def validate_path(path, client):
    try:
        num = int(path)
        path = "/org/freedesktop/NetworkManager/Checkpoint/%u" % (num)
    except Exception as e:
        pass

    if not path or path[0] != '/':
        sys.exit('Invalid checkpoint path \"%s\"' % (path))

    if client is not None:
        checkpoint = find_checkpoint(client, path)
        if checkpoint is None:
            print('WARNING: no checkpoint with path "%s" found' % (path))

    return path

def do_create(client):
    flags = NM.CheckpointCreateFlags.NONE
    if len(sys.argv) < 3:
        sys.exit("Failed: missing argument timeout")

    timeout = int(sys.argv[2])
    devices = []
    for arg in sys.argv[3:]:
        if arg == '--destroy-all':
            flags |= NM.CheckpointCreateFlags.DESTROY_ALL
        elif arg == '--delete-new-connections':
            flags |= NM.CheckpointCreateFlags.DELETE_NEW_CONNECTIONS
        elif arg == '--disconnect-new-devices':
            flags |= NM.CheckpointCreateFlags.DISCONNECT_NEW_DEVICES
        elif arg == '--allow-overlapping':
            flags |= NM.CheckpointCreateFlags.ALLOW_OVERLAPPING
        else:
            d = client.get_device_by_iface(arg)
            if d is None:
                sys.exit("Unknown device %s" % arg)
            devices.append(d)

    def create_cb(client, result, data):
        try:
            checkpoint = client.checkpoint_create_finish(result)
            print("%s" % checkpoint.get_path())
        except Exception as e:
            sys.stderr.write("Failed: %s\n" % e.message)
        main_loop.quit()

    client.checkpoint_create(devices, timeout, flags, None, create_cb, None)

def do_destroy(client):
    if len(sys.argv) < 3:
        sys.exit("Missing checkpoint path")

    path = validate_path(sys.argv[2], client)

    def destroy_cb(client, result, data):
        try:
            if client.checkpoint_destroy_finish(result) == True:
                print("Success")
        except Exception as e:
            sys.stderr.write("Failed: %s\n" % e.message)
        main_loop.quit()

    client.checkpoint_destroy(path, None, destroy_cb, None)

def do_rollback(client):
    if len(sys.argv) < 3:
        sys.exit("Missing checkpoint path")

    path = validate_path(sys.argv[2], client)

    def rollback_cb(client, result, data):
        try:
            res = client.checkpoint_rollback_finish(result)
            for path in res:
                d = client.get_device_by_path(path)
                if d is None:
                    iface = path
                else:
                    iface = d.get_iface()
                print("%s => %s" % (iface, "OK" if res[path] == 0 else "ERROR"))
        except Exception as e:
            sys.stderr.write("Failed: %s\n" % e.message)
        main_loop.quit()

    client.checkpoint_rollback(path, None, rollback_cb, None)

def do_adjust_rollback_timeout(client):
    if len(sys.argv) < 3:
        sys.exit("Missing checkpoint path")
    if len(sys.argv) < 4:
        sys.exit("Missing timeout")
    try:
        add_timeout = int(sys.argv[3])
    except:
        sys.exit("Invalid timeout")

    path = validate_path(sys.argv[2], client)

    def adjust_rollback_timeout_cb(client, result, data):
        try:
            client.checkpoint_adjust_rollback_timeout_finish(result)
            print("Success")
        except Exception as e:
            sys.stderr.write("Failed: %s\n" % e.message)
        main_loop.quit()

    client.checkpoint_adjust_rollback_timeout(path, add_timeout, None, adjust_rollback_timeout_cb, None)

def do_show(client):
    ts = NM.utils_get_timestamp_msec()
    for c in client.get_checkpoints():
        show(c, ts)

if __name__ == '__main__':
    nm_client = NM.Client.new(None)
    main_loop = GLib.MainLoop()

    if len(sys.argv) < 2 or sys.argv[1] == 'show':
        do_show(nm_client)
        sys.exit(0)
    elif sys.argv[1] == 'create':
        do_create(nm_client)
    elif sys.argv[1] == 'destroy':
        do_destroy(nm_client)
    elif sys.argv[1] == 'rollback':
        do_rollback(nm_client)
    elif sys.argv[1] == 'adjust-rollback-timeout':
        do_adjust_rollback_timeout(nm_client)
    else:
        usage()

    main_loop.run()
