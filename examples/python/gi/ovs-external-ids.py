#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2017, 2020 Red Hat, Inc.
#

#
# set and show OVS external-ids for a connection:
#

import sys
import os
import re
import pprint
import subprocess

import gi

gi.require_version("NM", "1.0")
from gi.repository import GLib, NM

###############################################################################

MODE_GET = "get"
MODE_SET = "set"
MODE_APPLY = "apply"


def memoize0(f):
    result = []

    def helper():
        if len(result) == 0:
            result.append(f())
        return result[0]

    return helper


def memoize(f):
    memo = {}

    def helper(x):
        if x not in memo:
            memo[x] = f(x)
        return memo[x]

    return helper


def pr(v):
    pprint.pprint(v, indent=4, depth=5, width=60)


@memoize0
def is_libnm_debug():
    return os.getenv("LIBNM_CLIENT_DEBUG") is not None


@memoize0
def can_sudo():
    try:
        return (
            subprocess.run(
                ["sudo", "-n", "true"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        )
    except:
        return False


def _print(msg=""):
    if is_libnm_debug():
        # we want to use the same logging mechanism as libnm's debug
        # logging with "LIBNM_CLIENT_DEBUG=trace,stdout".
        NM.utils_print(0, msg + "\n")
        return
    print(msg)


def mainloop_run(timeout_msec=0, mainloop=None):
    if mainloop is None:
        mainloop = GLib.MainLoop()

    timeout_id = None
    timeout_reached = []

    if timeout_msec > 0:

        def _timeout_cb(unused):
            # it can happen that the caller already quit the mainloop
            # otherwise. In that case, we don't want to signal a timeout.
            if mainloop.is_running():
                timeout_reached.append(1)
                mainloop.quit()
            return True

        timeout_id = GLib.timeout_add(timeout_msec, _timeout_cb, None)

    mainloop.run()
    if timeout_id:
        GLib.source_remove(timeout_id)
    return not timeout_reached


###############################################################################


def connection_update2(remote_connection, connection):

    mainloop = GLib.MainLoop()
    result_error = []

    def cb(c, result):
        try:
            c.update2_finish(result)
        except Exception as e:
            result_error.append(e)
        mainloop.quit()

    remote_connection.update2(
        connection.to_dbus(NM.ConnectionSerializationFlags.ALL),
        NM.SettingsUpdate2Flags.NO_REAPPLY,
        None,
        None,
        cb,
    )

    mainloop_run(mainloop=mainloop)

    if result_error:
        raise result_error[0]


def device_get_applied_connection(device):
    mainloop = GLib.MainLoop()
    rr = []

    def cb(c, result):
        try:
            con, version_id = c.get_applied_connection_finish(result)
        except Exception as e:
            rr.append(e)
        else:
            rr.append(con)
            rr.append(version_id)
        mainloop.quit()

    device.get_applied_connection_async(0, None, cb)

    mainloop_run(mainloop=mainloop)

    if len(rr) == 1:
        raise rr[0]
    return rr[0], rr[1]


def device_reapply(device, connection, version_id):

    mainloop = GLib.MainLoop()
    result_error = []

    def cb(d, result):
        try:
            d.reapply_finish(result)
        except Exception as e:
            result_error.append(e)
        mainloop.quit()

    device.reapply_async(connection, version_id, 0, None, cb)

    mainloop_run(mainloop=mainloop)

    if len(result_error) == 1:
        raise result_error[0]


def ovs_print_external_ids(prefix):
    if not can_sudo():
        _print(prefix + ": not running as root and cannot call ovs-vsctl")
        return

    cmds = [["ovs-vsctl", "show"]]
    for typ in ["Bridge", "Port", "Interface"]:
        cmds += [["ovs-vsctl", "--columns=name,external-ids", "list", typ]]

    out = ""
    for cmd in cmds:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, check=True)
        out += p.stdout.decode("utf-8") + "\n"
    out = "\n".join([prefix + s for s in out.split("\n")])
    _print(out)


###############################################################################


def usage():
    _print("%s g[et]   PROFILE [ GETTER ]" % (sys.argv[0]))
    _print("%s s[et]   PROFILE   SETTER   [--test]" % (sys.argv[0]))
    _print("%s a[pply] DEVICE    SETTER   [--test]" % (sys.argv[0]))
    _print(
        "   PROFILE :=  [id | uuid | type] STRING  |  [ ~id | ~type ] REGEX_STRING  |  STRING"
    )
    _print("   DEVICE :=  [iface] STRING")
    _print("   GETTER  := ( KEY | ~REGEX_KEY )  [... GETTER]")
    _print("   SETTER  := ( + | - | -KEY | [+]KEY VALUE ) [... SETTER]")


def die(msg, show_usage=False):
    _print("FAILED: %s" % (msg))
    if show_usage:
        usage()
    sys.exit(1)


def die_usage(msg):
    die(msg, show_usage=True)


def parse_args(argv):
    had_dash_dash = False
    args = {
        "mode": MODE_GET,
        "select_arg": None,
        "ids_arg": [],
        "do_test": False,
    }
    i = 1
    while i < len(argv):
        a = argv[i]

        if i == 1:
            if a in ["s", "set"]:
                args["mode"] = MODE_SET
            elif a in ["g", "get"]:
                args["mode"] = MODE_GET
            elif a in ["a", "apply"]:
                args["mode"] = MODE_APPLY
            else:
                die_usage("unexpected mode argument '%s'" % (a))
            i += 1
            continue

        if a == "--test":
            args["do_test"] = True
            i += 1
            continue

        if args["select_arg"] is None:
            if args["mode"] == MODE_APPLY:
                possible_selects = ["iface"]
            else:
                possible_selects = ["id", "~id", "uuid", "type", "~type"]

            if a in possible_selects:
                if i + 1 >= len(argv):
                    die_usage("'%s' requires an argument'" % (a))
                args["select_arg"] = (a, argv[i + 1])
                i += 2
                continue

            if a == "*":
                a = None
            args["select_arg"] = ("*", a)
            i += 1
            continue

        if args["mode"] == MODE_GET:
            args["ids_arg"].append(a)
            i += 1
            continue

        if not a:
            die_usage("argument should specify a external-id but is empty string")

        if a[0] == "-":
            v = (a, None)
            i += 1
        elif a == "+":
            v = (a, None)
            i += 1
        else:
            if a[0] != "+":
                a = "+" + a
            if i + 1 >= len(argv):
                die_usage("'%s' requires an argument'" % (a))
            v = (a, argv[i + 1])
            i += 2

        args["ids_arg"].append(v)

    if args["mode"] == MODE_SET:
        if not args["ids_arg"]:
            die_usage("Requires one or more external-ids to set or delete")

    return args


def device_to_str(device, show_type=False):
    if show_type:
        return "%s (%s)" % (device.get_iface(), device.get_type_desc())
    return "%s" % (device.get_iface(),)


def connection_to_str(connection, show_type=False):
    if show_type:
        return "%s (%s, %s)" % (
            connection.get_id(),
            connection.get_uuid(),
            connection.get_connection_type(),
        )
    return "%s (%s)" % (connection.get_id(), connection.get_uuid())


def devices_filter(devices, select_arg):
    devices = list(sorted(devices, key=device_to_str))
    if not select_arg:
        return devices
    # we preserve the order of the selected devices. And
    # if devices are selected multiple times, we return
    # them multiple times.
    l = []
    f = select_arg
    for d in devices:
        if f[0] == "iface":
            if f[1] == d.get_iface():
                l.append(d)
        else:
            assert f[0] == "*"
            if f[1] is None:
                l.append(d)
            else:
                if f[1] in [d.get_iface()]:
                    l.append(d)
    return l


def connections_filter(connections, select_arg):
    connections = list(sorted(connections, key=connection_to_str))
    if not select_arg:
        return connections
    # we preserve the order of the selected connections. And
    # if connections are selected multiple times, we return
    # them multiple times.
    l = []
    f = select_arg
    for c in connections:
        if f[0] == "id":
            if f[1] == c.get_id():
                l.append(c)
        elif f[0] == "~id":
            if re.match(f[1], c.get_id()):
                l.append(c)
        elif f[0] == "uuid":
            if f[1] == c.get_uuid():
                l.append(c)
        elif f[0] == "type":
            if f[1] == c.get_connection_type():
                l.append(c)
        elif f[0] == "~type":
            if re.match(f[1], c.get_connection_type()):
                l.append(c)
        else:
            assert f[0] == "*"
            if f[1] is None:
                l.append(c)
            else:
                if f[1] in [c.get_uuid(), c.get_id()]:
                    l.append(c)
    return l


def ids_select(ids, mode, ids_arg):
    ids = list(ids)
    if not ids_arg:
        return (ids, [])

    keys = set()
    requested = []
    for d in ids_arg:
        if mode == MODE_GET:
            if d[0] == "~":
                r = re.compile(d[1:])
                keys.update([k for k in ids if r.match(k)])
            else:
                keys.update([k for k in ids if k == d])
                if d not in requested:
                    requested.append(d)
        else:
            assert mode in [MODE_SET, MODE_APPLY]
            d2 = d[0]
            assert d2[0] in ["-", "+"]
            d3 = d2[1:]
            if d3 in ids:
                keys.add(d3)
    return (list([k for k in ids if k in keys]), requested)


def connection_print(connection, mode, ids_arg, dbus_path, prefix=""):
    sett = connection.get_setting(NM.SettingOvsExternalIDs)

    if sett is not None:
        all_ids = list(sett.get_data_keys())
        keys, requested = ids_select(all_ids, mode, ids_arg)
        num_str = "%s" % (len(all_ids))
    else:
        keys = []
        requested = []
        num_str = "none"

    _print(
        "%s%s [%s]" % (prefix, connection_to_str(connection, show_type=True), num_str)
    )
    if dbus_path:
        _print("%s   %s" % (prefix, dbus_path))
    if sett is not None:
        dd = sett.get_property(NM.SETTING_OVS_EXTERNAL_IDS_DATA)
    else:
        dd = {}
    for k in keys:
        v = sett.get_data(k)
        assert v is not None
        assert v == dd.get(k, None)
        _print('%s   "%s" = "%s"' % (prefix, k, v))
    for k in requested:
        _print('%s   "%s" = <unset>' % (prefix, k))


def sett_update(connection, ids_arg):

    sett = connection.get_setting(NM.SettingOvsExternalIDs)

    for d in ids_arg:
        op = d[0][0]
        key = d[0][1:]
        val = d[1]

        oldval = None
        if sett is not None:
            oldval = sett.get_data(key)

        if op == "-":
            assert val is None
            if key == "":
                if sett is None:
                    _print(" DEL: setting (ovs-external-ids group was not present)")
                else:
                    connection.remove_setting(NM.SettingOvsExternalIDs)
                    sett = None
                    _print(" DEL: setting")
                continue

            if sett is None:
                _print(' DEL: "%s" (ovs-external-ids group was not present)' % (key))
                continue
            if oldval is None:
                _print(' DEL: "%s" (id was unset)' % (key))
                continue
            _print(' DEL: "%s" (id was set to"%s")' % (key, oldval))
            sett.set_data(key, None)
            continue

        if key == "":
            assert val is None
            if sett is None:
                sett = NM.SettingOvsExternalIDs.new()
                connection.add_setting(sett)
                _print(" SET: setting (external-ids group was added)")
                continue

            _print(" SET: setting (external-ids group was present)")
            continue

        assert val is not None

        if sett is None:
            sett = NM.SettingOvsExternalIDs.new()
            connection.add_setting(sett)
            _print(
                ' SET: "%s" = "%s" (external-ids group was not present)' % (key, val)
            )
        elif oldval is None:
            _print(' SET: "%s" = "%s" (new)' % (key, val))
        elif oldval != val:
            _print(' SET: "%s" = "%s" (was "%s")' % (key, val, oldval))
        else:
            _print(' SET: "%s" = "%s" (unchanged)' % (key, val))
        sett.set_data(key, val)


def do_get(connections, ids_arg):
    first_line = True
    for c in connections:
        if first_line:
            first_line = False
        else:
            _print()
        connection_print(c, MODE_GET, ids_arg, dbus_path=c.get_path())


def do_set(nmc, connection, ids_arg, do_test):

    remote_connection = connection
    connection = NM.SimpleConnection.new_clone(remote_connection)

    connection_print(
        connection, MODE_SET, [], remote_connection.get_path(), prefix="BEFORE: "
    )
    _print()

    sett_update(connection, ids_arg)

    if do_test:
        _print()
        _print("Only show. Run without --test to set")
        return

    try:
        connection_update2(remote_connection, connection)
    except Exception as e:
        _print()
        _print("FAILURE to commit connection: %s" % (e))
        return

    # NMClient received the completion of Update2() call. It also received
    # a property changed signal that the profile changed, and it is about
    # to fetch the new value. However, that value is not yet here.
    #
    # libnm should provide a better API for this. For example, not signal
    # completion of update2() until the profile was refetched. Or, indicate
    # that the settings are dirty, so we would know how long to wait.
    #
    # Add an ugly workaround here and wait a bit.
    _print()
    _print("WORKAROUND: wait for connection to change")
    mainloop_run(timeout_msec=500)

    if remote_connection is not nmc.get_object_by_path(remote_connection.get_path()):
        _print()
        _print(
            "Connection %s no longer exists after commit"
            % (remote_connection.get_path())
        )
        return

    _print()
    connection_print(
        remote_connection, MODE_SET, [], remote_connection.get_path(), prefix="AFTER:  "
    )

    _print()
    if remote_connection.compare(connection, NM.SettingCompareFlags.EXACT):
        _print("resulting connection is as expected")
    else:
        _print("WARNING: resulting connection is not as expected")


def do_apply(nmc, device, ids_arg, do_test):

    try:
        connection_orig, version_id = device_get_applied_connection(device)
    except Exception as e:
        _print(
            'failure to get applied connection for %s: %s"' % (device_to_str(device), e)
        )
        die("The device does not seem active? Nothing to reapply")

    _print(
        "REAPPLY device %s (%s) with connection %s (version-id = %s)"
        % (
            device_to_str(device),
            NM.Object.get_path(device),
            connection_to_str(connection_orig),
            version_id,
        )
    )
    _print()

    ovs_print_external_ids("BEFORE-OVS-VSCTL: ")
    _print()

    connection = NM.SimpleConnection.new_clone(connection_orig)

    connection_print(connection, MODE_APPLY, [], device.get_path(), prefix="BEFORE: ")
    _print()

    sett_update(connection, ids_arg)

    if do_test:
        _print()
        _print("Only show. Run without --test to set")
        return

    _print()
    _print("reapply...")

    try:
        device_reapply(device, connection, version_id)
    except Exception as e:
        _print()
        _print("FAILURE to commit connection: %s" % (e))
        return

    try:
        connection_after, version_id = device_get_applied_connection(device)
    except Exception as e:
        _print(
            'failure to get applied connection after reapply for device %s: %s"'
            % (device_to_str(device), e)
        )
        die("FAILURE to get applied connection after reapply")

    _print()
    connection_print(connection, MODE_APPLY, [], device.get_path(), prefix="AFTER: ")
    _print()

    ovs_print_external_ids("AFTER-OVS-VSCTL: ")


###############################################################################

if __name__ == "__main__":

    args = parse_args(sys.argv)

    nmc = NM.Client.new(None)

    if args["mode"] == MODE_APPLY:

        devices = devices_filter(nmc.get_devices(), args["select_arg"])

        if len(devices) != 1:
            _print(
                "To apply the external-ids of a device, exactly one connection must be selected. Instead, %s devices matched ([%s])"
                % (len(devices), ", ".join([device_to_str(c) for c in devices]))
            )
            die_usage("Select unique device to apply")
        do_apply(nmc, devices[0], args["ids_arg"], do_test=args["do_test"])

    else:

        connections = connections_filter(nmc.get_connections(), args["select_arg"])

        if args["mode"] == MODE_SET:
            if len(connections) != 1:
                _print(
                    "To set the external-ids of a connection, exactly one connection must be selected via id|uuid. Instead, %s connection matched ([%s])"
                    % (
                        len(connections),
                        ", ".join([connection_to_str(c) for c in connections]),
                    )
                )
                die_usage("Select unique connection to set")
            do_set(nmc, connections[0], args["ids_arg"], do_test=args["do_test"])
        else:
            if len(connections) < 1:
                _print("No connection selected for printing the external ids")
                die_usage("Select connection to get")
            do_get(connections, args["ids_arg"])
