#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2017 Red Hat, Inc.
#

import sys
import re

import gi

gi.require_version("NM", "1.0")
from gi.repository import GLib, NM

###############################################################################


def usage():
    print("Usage: %s [COMMAND [ARG]...]" % sys.argv[0])
    print("")
    print(" COMMANDS:  [show]")
    print(
        "            create TIMEOUT [--destroy-all|--delete-new-connections|--disconnect-new-devices|--allow-overlapping|DEV]..."
    )
    print("            destroy ['--last'|PATH|NUMBER[")
    print("            rollback ['--last'|PATH|NUMBER]")
    print("            adjust-rollback-timeout '--last'|PATH|NUMBER TIMEOUT")
    print("")
    print(" For destroy|rollback, when omitted then '--last' is the default.")
    sys.exit(1)


def show(c, ts=None):
    cr = c.get_created()
    rt = c.get_rollback_timeout()
    print("%s:" % c.get_path())
    print(
        "  created: %u%s"
        % (cr, "" if ts is None else (" (%s sec ago)" % ((ts - cr) / 1000.0)))
    )
    if rt == 0:
        print("  timeout: infinity")
    else:
        print(
            "  timeout: %u seconds%s"
            % (
                rt,
                ""
                if ts is None
                else (" (circa %s sec left)" % ((cr + (rt * 1000) - ts) / 1000.0)),
            )
        )
    print(
        "  devices: %s"
        % (" ".join(sorted(map(lambda x: x.get_iface(), c.get_devices()))))
    )


def checkpoint_path_to_num(path):
    m = re.match(r"^/org/freedesktop/NetworkManager/Checkpoint/([1-9][0-9]*)$", path)
    if m:
        return int(m.group(1))
    raise Exception(f'Unexpected D-Bus path "{path}"for checkpoint')


def find_checkpoint(nmc, path):
    for c in nmc.get_checkpoints():
        if c.get_path() == path:
            return c
    return None


def find_checkpoint_last(nmc):
    return max(
        nmc.get_checkpoints(),
        key=lambda c: checkpoint_path_to_num(c.get_path()),
        default=None,
    )


def validate_path(path, nmc):
    if path == "--last":
        c = find_checkpoint_last(nmc)
        if c is None:
            sys.exit("Has no checkpoint")
        return c.get_path()

    try:
        num = int(path)
        path = f"/org/freedesktop/NetworkManager/Checkpoint/{num}"
    except Exception as e:
        pass

    if not path or path[0] != "/":
        sys.exit('Invalid checkpoint path "%s"' % (path))

    if nmc is not None:
        checkpoint = find_checkpoint(nmc, path)
        if checkpoint is None:
            print('WARNING: no checkpoint with path "%s" found' % (path))

    return path


def validate_path_from_argv(nmc):
    assert len(sys.argv) >= 2
    if len(sys.argv) == 2:
        path = "--last"
    elif len(sys.argv) > 3:
        sys.exit("Failed: invalid extra argument")
    else:
        path = sys.argv[2]

    return validate_path(path, nmc)


def do_create(nmc):
    flags = NM.CheckpointCreateFlags.NONE
    if len(sys.argv) < 3:
        sys.exit("Failed: missing argument timeout")

    timeout = int(sys.argv[2])
    devices = []
    for arg in sys.argv[3:]:
        if arg == "--destroy-all":
            flags |= NM.CheckpointCreateFlags.DESTROY_ALL
        elif arg == "--delete-new-connections":
            flags |= NM.CheckpointCreateFlags.DELETE_NEW_CONNECTIONS
        elif arg == "--disconnect-new-devices":
            flags |= NM.CheckpointCreateFlags.DISCONNECT_NEW_DEVICES
        elif arg == "--allow-overlapping":
            flags |= NM.CheckpointCreateFlags.ALLOW_OVERLAPPING
        else:
            d = nmc.get_device_by_iface(arg)
            if d is None:
                sys.exit("Unknown device %s" % arg)
            devices.append(d)

    def create_cb(nmc, result, data):
        try:
            checkpoint = nmc.checkpoint_create_finish(result)
            print("%s" % checkpoint.get_path())
        except Exception as e:
            sys.stderr.write("Failed: %s\n" % e.message)
        main_loop.quit()

    nmc.checkpoint_create(devices, timeout, flags, None, create_cb, None)


def do_destroy(nmc):
    path = validate_path_from_argv(nmc)

    def destroy_cb(nmc, result, data):
        try:
            if nmc.checkpoint_destroy_finish(result) == True:
                print("Success")
        except Exception as e:
            sys.stderr.write("Failed: %s\n" % e.message)
        main_loop.quit()

    nmc.checkpoint_destroy(path, None, destroy_cb, None)


def do_rollback(nmc):
    path = validate_path_from_argv(nmc)

    def rollback_cb(nmc, result, data):
        try:
            res = nmc.checkpoint_rollback_finish(result)
            for path in res:
                d = nmc.get_device_by_path(path)
                if d is None:
                    iface = path
                else:
                    iface = d.get_iface()
                print("%s => %s" % (iface, "OK" if res[path] == 0 else "ERROR"))
        except Exception as e:
            sys.stderr.write("Failed: %s\n" % e.message)
        main_loop.quit()

    nmc.checkpoint_rollback(path, None, rollback_cb, None)


def do_adjust_rollback_timeout(nmc):
    if len(sys.argv) < 3:
        sys.exit("Missing checkpoint path")
    if len(sys.argv) < 4:
        sys.exit("Missing timeout")
    try:
        add_timeout = int(sys.argv[3])
    except Exception:
        sys.exit("Invalid timeout")

    path = validate_path(sys.argv[2], nmc)

    def adjust_rollback_timeout_cb(nmc, result, data):
        try:
            nmc.checkpoint_adjust_rollback_timeout_finish(result)
            print("Success")
        except Exception as e:
            sys.stderr.write("Failed: %s\n" % e.message)
        main_loop.quit()

    nmc.checkpoint_adjust_rollback_timeout(
        path, add_timeout, None, adjust_rollback_timeout_cb, None
    )


def do_show(nmc):
    ts = NM.utils_get_timestamp_msec()
    for c in nmc.get_checkpoints():
        show(c, ts)


if __name__ == "__main__":
    nmc = NM.Client.new(None)
    main_loop = GLib.MainLoop()

    if len(sys.argv) < 2 or sys.argv[1] == "show":
        do_show(nmc)
        sys.exit(0)
    elif sys.argv[1] == "create":
        do_create(nmc)
    elif sys.argv[1] == "destroy":
        do_destroy(nmc)
    elif sys.argv[1] == "rollback":
        do_rollback(nmc)
    elif sys.argv[1] == "adjust-rollback-timeout":
        do_adjust_rollback_timeout(nmc)
    else:
        usage()

    main_loop.run()
