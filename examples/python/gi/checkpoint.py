#!/usr/bin/env python
# -*- Mode: Python; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
# vim: ft=python ts=4 sts=4 sw=4 et ai

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

def usage():
    print "Usage: %s [COMMAND [ARG]...]" % sys.argv[0]
    print ""
    print " COMMANDS:  show"
    print "            create TIMEOUT [DEV]..."
    print "            destroy PATH|NUMBER"
    print "            rollback PATH|NUMBER"
    print
    sys.exit(1)

def create_cb(client, result, data):
    try:
        checkpoint = client.checkpoint_create_finish(result)
        print("%s" % checkpoint.get_path())
    except Exception, e:
        sys.stderr.write("Failed: %s\n" % e.message)
    main_loop.quit()

def do_create(client):
    if len(sys.argv) < 3:
        sys.exit("Failed: %s\n" % e.message)

    timeout = int(sys.argv[2])
    devices = []
    for arg in sys.argv[3:]:
        d = client.get_device_by_iface(arg)
        if d is None:
            sys.exit("Unknown device %s" % arg)
        devices.append(d)

    client.checkpoint_create_async(devices, timeout, 0, None, create_cb, None)

def destroy_cb(client, result, data):
    try:
        if client.checkpoint_destroy_finish(result) == True:
            print "Success"
    except Exception, e:
        sys.stderr.write("Failed: %s\n" % e.message)
    main_loop.quit()

def find_checkpoint(client, arg):
    try:
        num = int(arg)
        path = "/org/freedesktop/NetworkManager/Checkpoint/%u" % num
    except Exception, e:
        path = arg

    for c in client.get_checkpoints():
        if c.get_path() == path:
            return c
    return None

def do_destroy(client):
    if len(sys.argv) < 3:
        sys.exit("Missing checkpoint path")

    checkpoint = find_checkpoint(client, sys.argv[2])
    if checkpoint is None:
        sys.exit("Uknown checkpoint %s" % sys.argv[2])

    client.checkpoint_destroy_async(checkpoint, None, destroy_cb, None)

def rollback_cb(client, result, data):
    try:
        res = client.checkpoint_rollback_finish(result)
        for path in res:
            d = client.get_device_by_path(path)
            if d is None:
                iface = path
            else:
                iface = d.get_iface()
            print "%s => %s" % (iface, "OK" if res[path] == 0 else "ERROR")
    except Exception, e:
        sys.stderr.write("Failed: %s\n" % e.message)
    main_loop.quit()

def do_rollback(client):
    if len(sys.argv) < 3:
        sys.exit("Missing checkpoint path")

    checkpoint = find_checkpoint(client, sys.argv[2])
    if checkpoint is None:
        sys.exit("Uknown checkpoint %s" % sys.argv[2])

    client.checkpoint_rollback_async(checkpoint, None, rollback_cb, None)

def do_show(client):
    for c in client.get_checkpoints():
        print "%s:" % c.get_path()
        print "  created: %u" % c.get_created()
        print "  timeout: %u seconds" % c.get_rollback_timeout()
        print "  devices:", ' '.join(sorted(map(lambda x: x.get_iface(), c.get_devices())))

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
    else:
        usage()

    main_loop.run()
