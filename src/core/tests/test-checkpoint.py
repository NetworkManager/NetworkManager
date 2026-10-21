#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time

BUS_NAME = "org.freedesktop.NetworkManager"
MANAGER_PATH = "/org/freedesktop/NetworkManager"
DISPATCHER_NAME = "org.freedesktop.nm_dispatcher"
IFACES = ("nmcheckpoint0", "nmcheckpoint1")
BRIDGE = "nmcheckpoint2"
PORT_PAIR = ("nmcheckpoint3", "nmcheckpoint4")
DEVICE_STATE_DISCONNECTED = 30
DEVICE_STATE_ACTIVATED = 100
DEVICE_STATE_DEACTIVATING = 110
AC_STATE_ACTIVATED = 2
ROLLBACK_RESULT_OK = 0


def run(*args, check=True):
    return subprocess.run(
        args,
        check=check,
        stdout=subprocess.PIPE,
        stderr=None if check else subprocess.PIPE,
        text=True,
        timeout=25,
    )


def test_checkpoint(daemon_path, mode):
    import gi

    gi.require_version("Gio", "2.0")
    from gi.repository import Gio, GLib

    assert os.geteuid() == 0
    if os.environ.get("NM_TEST_HOST_NETNS") in (None, os.readlink("/proc/self/ns/net")):
        raise SystemExit("ERROR: --inside must run in the bwrap sandbox")
    os.environ["DBUS_SYSTEM_BUS_ADDRESS"] = os.environ["DBUS_SESSION_BUS_ADDRESS"]
    os.environ["G_DEBUG"] = "fatal-warnings"
    os.environ["LC_ALL"] = "C"
    root = Path("/tmp/checkpoint-test")
    (root / "connections").mkdir()
    (root / "conf.d").mkdir()
    # PORT_PAIR is left out, so a port attached with ip becomes external.
    managed = ",".join(f"interface-name:{name}" for name in (*IFACES, BRIDGE))
    (root / "NetworkManager.conf").write_text(
        "[main]\nplugins=keyfile\nauth-polkit=false\ndns=none\n"
        "rc-manager=unmanaged\nhostname-mode=none\nno-auto-default=*\n"
        f"[keyfile]\npath={root}/connections\n"
        "unmanaged-devices=*,except:interface-name:nmcheckpoint*\n"
        f"[device-test]\nmatch-device={managed}\n"
        "managed=true\nkeep-configuration=false\n"
        "[connectivity]\ninterval=0\n"
        "[logging]\nlevel=TRACE\naudit=false\n"
    )
    run("ip", "link", "add", IFACES[0], "type", "veth", "peer", "name", IFACES[1])
    for iface in IFACES:
        run("ip", "link", "set", iface, "up")

    bus = Gio.DBusConnection.new_for_address_sync(
        os.environ["DBUS_SYSTEM_BUS_ADDRESS"],
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT
        | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
        None,
        None,
    )

    def call(method, signature, args, path=MANAGER_PATH, interface=BUS_NAME):
        result = bus.call_sync(
            BUS_NAME,
            path,
            interface,
            method,
            GLib.Variant(signature, args),
            None,
            Gio.DBusCallFlags.NONE,
            10000,
            None,
        ).unpack()
        return result[0] if result else None

    def get_property(name, path=MANAGER_PATH, interface=BUS_NAME):
        return call(
            "Get", "(ss)", (interface, name), path, "org.freedesktop.DBus.Properties"
        )

    pending = []
    dispatch_lock = threading.Lock()
    dispatch_gate = threading.Event()
    dispatch_entered = threading.Event()
    # Must match the Action2 in_args in src/nm-dispatcher/nm-dispatcher.c.
    arg_types = ["s", "a{sa{sv}}"] + ["a{sv}"] * 7 + ["s", "s"] + ["a{sv}"] * 3
    arg_types += ["b", "a{sv}"]
    dispatcher_info = Gio.DBusNodeInfo.new_for_xml(
        f'<node><interface name="{DISPATCHER_NAME}"><method name="Action2">'
        + "".join(f'<arg type="{arg}" direction="in"/>' for arg in arg_types)
        + '<arg type="a(susa{sv})" direction="out"/></method></interface></node>'
    )

    def dispatch(connection, sender, path, interface, method, parameters, invocation):
        with dispatch_lock:
            # The device stays in DEACTIVATING until pre-down returns.
            if parameters.unpack()[0] == "pre-down" and dispatch_gate.is_set():
                pending.append(invocation)
                dispatch_entered.set()
            else:
                invocation.return_value(GLib.Variant("(a(susa{sv}))", ([],)))

    bus.register_object(
        "/org/freedesktop/nm_dispatcher", dispatcher_info.interfaces[0], dispatch
    )
    bus.call_sync(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "RequestName",
        GLib.Variant("(su)", (DISPATCHER_NAME, 0)),
        None,
        Gio.DBusCallFlags.NONE,
        10000,
        None,
    )
    loop = GLib.MainLoop()
    thread = threading.Thread(target=loop.run, daemon=True)
    thread.start()

    def release_dispatcher():
        with dispatch_lock:
            dispatch_gate.clear()
            for invocation in pending:
                invocation.return_value(GLib.Variant("(a(susa{sv}))", ([],)))
            pending.clear()
            dispatch_entered.clear()

    with (root / "daemon.log").open("w") as log:
        daemon = subprocess.Popen(
            [
                daemon_path,
                "--debug",
                "--run-from-build-dir",
                f"--config={root}/NetworkManager.conf",
                f"--config-dir={root}/conf.d",
                "--system-config-dir=",
                f"--intern-config={root}/intern.conf",
                f"--state-file={root}/state",
                f"--no-auto-default={root}/no-auto-default",
                f"--pid-file={root}/nm.pid",
            ],
            stdout=log,
            stderr=log,
        )

        def wait_for(predicate):
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                assert daemon.poll() is None, daemon.returncode
                if predicate():
                    return
                time.sleep(0.05)
            raise AssertionError("timed out waiting for condition")

        try:

            def device_path(iface):
                try:
                    return call("GetDeviceByIpIface", "(s)", (iface,))
                except GLib.Error:
                    return None

            wait_for(lambda: all(device_path(iface) for iface in IFACES))
            devices = [device_path(iface) for iface in IFACES]
            single = mode.startswith("single-")
            if single:
                devices = devices[:1]
            connection = {
                "connection": {
                    "id": GLib.Variant("s", "checkpoint-test"),
                    "type": GLib.Variant("s", "802-3-ethernet"),
                    "multi-connect": GLib.Variant("i", 1 if single else 3),
                    "autoconnect": GLib.Variant("b", False),
                },
                "ipv4": {"method": GLib.Variant("s", "disabled")},
                "ipv6": {"method": GLib.Variant("s", "disabled")},
            }
            profile = call(
                "AddConnection",
                "(a{sa{sv}})",
                (connection,),
                MANAGER_PATH + "/Settings",
                BUS_NAME + ".Settings",
            )
            for device in devices:
                call("ActivateConnection", "(ooo)", (profile, device, "/"))
            device_interface = BUS_NAME + ".Device"

            def device_state(device):
                return get_property("State", device, device_interface)

            def active_connections():
                return [
                    get_property("ActiveConnection", d, device_interface)
                    for d in devices
                ]

            def all_activated():
                return all(device_state(d) == DEVICE_STATE_ACTIVATED for d in devices)

            def activate_bridge():
                bridge_connection = {
                    "connection": {
                        "id": GLib.Variant("s", "checkpoint-bridge"),
                        "type": GLib.Variant("s", "bridge"),
                        "interface-name": GLib.Variant("s", BRIDGE),
                        "autoconnect": GLib.Variant("b", False),
                    },
                    "bridge": {"stp": GLib.Variant("b", False)},
                    "ipv4": {"method": GLib.Variant("s", "disabled")},
                    "ipv6": {"method": GLib.Variant("s", "disabled")},
                }
                bridge_profile = call(
                    "AddConnection",
                    "(a{sa{sv}})",
                    (bridge_connection,),
                    MANAGER_PATH + "/Settings",
                    BUS_NAME + ".Settings",
                )
                bridge_active = call(
                    "ActivateConnection", "(ooo)", (bridge_profile, "/", "/")
                )
                wait_for(
                    lambda: get_property(
                        "State", bridge_active, BUS_NAME + ".Connection.Active"
                    )
                    == AC_STATE_ACTIVATED
                )
                return bridge_profile, bridge_active

            wait_for(all_activated)
            if mode == "unchanged":
                original_active = active_connections()
                checkpoint = call("CheckpointCreate", "(aouu)", (devices, 0, 0))
                results = call("CheckpointRollback", "(o)", (checkpoint,))
                assert results == {d: ROLLBACK_RESULT_OK for d in devices}, results
                wait_for(all_activated)
                assert (
                    active_connections() == original_active
                ), "unmodified device was reactivated"
                print("checkpoint rollback without changes passed")
            elif mode == "external-port":
                _, bridge_active = activate_bridge()
                bridge_device = device_path(BRIDGE)
                port, peer = PORT_PAIR
                run("ip", "link", "add", port, "type", "veth", "peer", "name", peer)
                run("ip", "link", "set", peer, "up")
                run("ip", "link", "set", port, "master", BRIDGE, "up")
                wait_for(lambda: device_path(port))
                port_device = device_path(port)
                wait_for(lambda: device_state(port_device) == DEVICE_STATE_ACTIVATED)
                checkpoint = call("CheckpointCreate", "(aouu)", ([bridge_device], 0, 0))
                dispatch_gate.set()
                call("DeactivateConnection", "(o)", (bridge_active,))
                assert dispatch_entered.wait(5), "pre-down dispatcher was not called"
                assert device_state(bridge_device) == DEVICE_STATE_DEACTIVATING
                results = call("CheckpointRollback", "(o)", (checkpoint,))
                assert results == {bridge_device: ROLLBACK_RESULT_OK}, results
                release_dispatcher()
                wait_for(lambda: device_state(bridge_device) == DEVICE_STATE_ACTIVATED)
                ports = run("ip", "-o", "link", "show", "master", BRIDGE).stdout
                assert port in ports, "external port was detached"
                print("checkpoint rollback of a deactivating bridge passed")
            elif mode == "recreate":
                bridge_profile, _ = activate_bridge()
                bridge_device = device_path(BRIDGE)
                bridge_ifindex = socket.if_nametoindex(BRIDGE)
                checkpoint = call("CheckpointCreate", "(aouu)", ([bridge_device], 0, 0))
                run("ip", "link", "delete", BRIDGE)
                wait_for(
                    lambda: bridge_device
                    not in get_property("Devices", checkpoint, BUS_NAME + ".Checkpoint")
                )
                run("ip", "link", "add", BRIDGE, "type", "bridge")
                assert socket.if_nametoindex(BRIDGE) != bridge_ifindex
                wait_for(lambda: device_path(BRIDGE))
                replacement = device_path(BRIDGE)
                wait_for(lambda: device_state(replacement) == DEVICE_STATE_DISCONNECTED)
                results = call("CheckpointRollback", "(o)", (checkpoint,))
                assert results == {bridge_device: ROLLBACK_RESULT_OK}, results
                wait_for(lambda: device_state(replacement) == DEVICE_STATE_ACTIVATED)
                active = get_property("ActiveConnection", replacement, device_interface)
                assert (
                    get_property("Connection", active, BUS_NAME + ".Connection.Active")
                    == bridge_profile
                )
                print("checkpoint rollback after software device replacement passed")
            else:
                timed = mode.endswith("timeout")
                original_active = active_connections()
                checkpoint = call("CheckpointCreate", "(aouu)", (devices, 0, 0))
                dispatch_gate.set()
                call("DeactivateConnection", "(o)", (original_active[0],))
                assert dispatch_entered.wait(5), "pre-down dispatcher was not called"
                assert device_state(devices[0]) == DEVICE_STATE_DEACTIVATING
                if timed:
                    call("CheckpointAdjustRollbackTimeout", "(ou)", (checkpoint, 1))
                    wait_for(lambda: checkpoint not in get_property("Checkpoints"))
                else:
                    results = call("CheckpointRollback", "(o)", (checkpoint,))
                    assert results == {d: ROLLBACK_RESULT_OK for d in devices}, results
                release_dispatcher()
                wait_for(all_activated)
                current_active = active_connections()
                assert current_active[0] != original_active[0]
                assert (
                    current_active[1:] == original_active[1:]
                ), "unmodified device was reactivated"
                assert (
                    get_property(
                        "Connection", current_active[0], BUS_NAME + ".Connection.Active"
                    )
                    == profile
                )
                assert checkpoint not in get_property("Checkpoints")
                print(f"checkpoint {'timed' if timed else 'explicit'} rollback passed")
        except BaseException:
            log.flush()
            print((root / "daemon.log").read_text())
            raise
        finally:
            release_dispatcher()
            daemon.terminate()
            try:
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()
            loop.quit()
            thread.join()
            bus.close_sync(None)
    return 0


def main():
    if sys.argv[1] == "--inside":
        return test_checkpoint(*sys.argv[2:])
    for program in ("bwrap", "dbus-run-session", "ip"):
        if not shutil.which(program):
            print(f"SKIP: required program {program} is unavailable")
            return 77
    try:
        import gi
    except ImportError:
        print("SKIP: Python GObject introspection is unavailable")
        return 77
    probe = run(
        "bwrap",
        "--unshare-all",
        "--uid",
        "0",
        "--gid",
        "0",
        "--ro-bind",
        "/",
        "/",
        "true",
        check=False,
    )
    if probe.returncode:
        print(f"SKIP: isolated namespaces unavailable: {probe.stderr.strip()}")
        return 77
    daemon_path, state_dir, run_dir, mode = sys.argv[1:]
    source_root = Path(__file__).resolve().parents[3]
    build_root = Path(daemon_path).resolve().parents[2]
    # The daemon creates NMSTATEDIR and NMRUNDIR. When they are not on the
    # tmpfs mounts below (e.g. -Dprefix=$PWD/INST in CI), mount a tmpfs on
    # their deepest existing ancestor.
    mounts = set()
    for path in map(Path, (state_dir, run_dir)):
        rebound = path.is_relative_to(source_root) or path.is_relative_to(build_root)
        if not rebound and path.parts[1] in ("run", "var", "tmp"):
            continue
        while not path.exists():
            path = path.parent
        if source_root.is_relative_to(path) or build_root.is_relative_to(path):
            print(f"SKIP: cannot make {state_dir} and {run_dir} writable")
            return 77
        mounts.add(path)
    os.environ["NM_TEST_HOST_NETNS"] = os.readlink("/proc/self/ns/net")
    sandbox = [
        "bwrap",
        "--unshare-all",
        "--uid",
        "0",
        "--gid",
        "0",
        "--die-with-parent",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "CAP_NET_ADMIN",
        "--cap-add",
        "CAP_NET_RAW",
        "--ro-bind",
        "/",
        "/",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/var",
        "--tmpfs",
        "/tmp",
        "--ro-bind",
        str(source_root),
        str(source_root),
        "--ro-bind",
        str(build_root),
        str(build_root),
    ]
    for path in sorted(mounts):
        sandbox += ["--tmpfs", str(path)]
    sandbox += [
        "--dir",
        state_dir,
        "--dir",
        run_dir,
        "--dir",
        "/tmp/checkpoint-test",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
    ]
    for name in (
        "DBUS_SYSTEM_BUS_ADDRESS",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR",
        "LD_PRELOAD",
        "PYTHONOPTIMIZE",
    ):
        sandbox += ["--unsetenv", name]
    return subprocess.run(
        sandbox
        + [
            "dbus-run-session",
            "--",
            sys.executable,
            str(Path(__file__).resolve()),
            "--inside",
            daemon_path,
            mode,
        ],
        timeout=90,
    ).returncode


if __name__ == "__main__":
    sys.exit(main())
