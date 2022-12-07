#!/usr/bin/env python
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import sys

import gi

gi.require_version("NM", "1.0")
from gi.repository import NM, GLib, Gio, GObject


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def kf_from_data(data):
    kf = GLib.KeyFile.new()
    kf.load_from_data(data, 18446744073709551615, GLib.KeyFileFlags.NONE)
    return kf


def kf_to_data(kf):
    data, l = kf.to_data()
    return data


def connection_to_kf(connection):
    return kf_to_data(NM.keyfile_write(connection, NM.KeyfileHandlerFlags.NONE))


def connection_from_kf(data):
    base_dir = os.getcwd()
    return NM.keyfile_read(kf_from_data(data), base_dir, NM.KeyfileHandlerFlags.NONE)


def connection_from_stdin():
    return connection_from_kf(sys.stdin.read())


def device_get_applied_connection(device):
    mainloop = GLib.MainLoop()
    r = []

    def cb(device, result):
        try:
            connection, version_id = device.get_applied_connection_finish(result)
        except Exception as e:
            r.append(e)
        else:
            r.append(connection)
            r.append(version_id)
        mainloop.quit()

    device.get_applied_connection_async(0, None, cb)
    mainloop.run()
    if len(r) == 1:
        raise r[0]
    connection, version_id = r
    return connection, version_id


def device_reapply(device, connection, version_id, reapply_flags):
    mainloop = GLib.MainLoop()
    r = []

    def cb(device, result):
        try:
            device.reapply_finish(result)
        except Exception as e:
            r.append(e)
        mainloop.quit()

    device.reapply_async(connection, version_id or 0, reapply_flags, None, cb)
    mainloop.run()
    if len(r) == 1:
        raise r[0]


def parse_args():
    import argparse

    parser = argparse.ArgumentParser(
        prog="device-reapply.py",
        description="Example program to interact with the applied connection",
    )

    parser.add_argument("mode", choices=["get", "reapply", "modify"])
    parser.add_argument("device")
    parser.add_argument("-V", "--version-id", type=int)
    parser.add_argument("-s", "--stdin", action="store_true")
    parser.add_argument("-p", "--preserve-external-ip", action="store_true")

    return parser.parse_args()


def main():
    args = parse_args()

    nmc = NM.Client.new()

    device = [d for d in nmc.get_devices() if d.get_iface() == args.device]
    if not device:
        raise Exception(f'Device "{args.device}" not found')
    if len(device) != 1:
        raise Exception(f'Not unique device "{args.device}" found')
    device = device[0]

    assert not args.stdin or args.mode == "modify"
    assert not args.preserve_external_ip or args.mode in ["modify", "reapply"]

    if args.mode == "get":
        connection, version_id = device_get_applied_connection(device)

        version_id_matches = args.version_id is None or args.version_id == version_id

        print(
            f'# Applied connection on "{device.get_iface()}": "{connection.get_id()}" ({connection.get_uuid()}, {connection.get_connection_type()})'
        )
        s = "" if version_id_matches else f" (expected {args.version_id})"
        print(f"# version-id={version_id}{s}")
        print(f"#")
        print(f"{connection_to_kf(connection)}")

        if not version_id_matches:
            eprint(
                f"Applied version-id does not match (expects {args.version_id} but got {version_id})"
            )
            sys.exit(1)
        sys.exit(0)

    if args.mode == "reapply":
        new_connection = None
    elif args.stdin:
        new_connection = connection_from_stdin()
    else:
        new_connection, _ = device_get_applied_connection(device)

    reapply_flags = 0
    if args.preserve_external_ip:
        reapply_flags = 1  # NM.DeviceReapplyFlags.PRESERVE_EXTERNAL_IP

    device_reapply(device, new_connection, args.version_id, reapply_flags)


if __name__ == "__main__":
    main()
