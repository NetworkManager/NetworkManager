#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright (C) 2020 Red Hat, Inc.

# This example performs a scan of Wi-Fi P2P peers and connects to one
# of them.

import sys
import uuid
import gi

gi.require_version("NM", "1.0")
from gi.repository import GLib, NM

main_loop = None
client = None


def create_profile(name, peer_mac):
    profile = NM.SimpleConnection.new()

    s_con = NM.SettingConnection.new()
    s_con.set_property(NM.SETTING_CONNECTION_ID, name)
    s_con.set_property(NM.SETTING_CONNECTION_UUID, str(uuid.uuid4()))
    s_con.set_property(NM.SETTING_CONNECTION_TYPE, "wifi-p2p")
    s_con.set_property(NM.SETTING_CONNECTION_AUTOCONNECT, False)

    s_ip4 = NM.SettingIP4Config.new()
    s_ip4.set_property(NM.SETTING_IP_CONFIG_METHOD, "auto")

    s_ip6 = NM.SettingIP6Config.new()
    s_ip6.set_property(NM.SETTING_IP_CONFIG_METHOD, "auto")

    s_wifi_p2p = NM.SettingWifiP2P.new()
    s_wifi_p2p.set_property(NM.SETTING_WIFI_P2P_PEER, peer_mac)
    s_wifi_p2p.set_property(
        NM.SETTING_WIFI_P2P_WFD_IES,
        GLib.Bytes.new(b"\x00\x00\x06\x00\x90\x1c\x44\x00\xc8"),
    )

    profile.add_setting(s_con)
    profile.add_setting(s_ip4)
    profile.add_setting(s_ip6)
    profile.add_setting(s_wifi_p2p)

    return profile


def activated_cb(client, result, data):
    try:
        client.add_and_activate_connection2_finish(result)
        print(" * Connection profile activated successfully")
    except Exception as e:
        sys.stderr.write("Error: %s\n" % e)
    main_loop.quit()


def scan_timeout_cb(device):
    peers = device.get_peers()
    if len(peers) == 0:
        main_loop.quit()
        sys.exit("No peer found")

    print("\n   {:20} {:30} {:3} {:30}".format("MAC", "Name", "Sig", "Wfd-IEs"))
    for p in peers:
        if p.get_wfd_ies() is not None:
            ies = p.get_wfd_ies().get_data().hex()
        else:
            ies = ""
        print(
            "   {:20} {:30} {:3} {:30}".format(
                p.get_hw_address(), p.get_name(), p.get_strength(), ies
            )
        )
    print("")

    # Connect to first peer
    profile = create_profile("P2P-connection", peers[0].get_hw_address())
    client.add_and_activate_connection2(
        profile, device, "/", GLib.Variant("a{sv}", {}), None, activated_cb, None
    )
    print(
        " * Connecting to peer {} using profile '{}'".format(
            peers[0].get_hw_address(), profile.get_id()
        )
    )


def start_find_cb(device, async_result, user_data):
    try:
        device.start_find_finish(async_result)
    except Exception as e:
        sys.stderr.write("Error: %s\n" % e)
        main_loop.quit()

    print(" * Scanning on device {}...".format(device.get_iface()))
    GLib.timeout_add(10000, scan_timeout_cb, device)


if __name__ == "__main__":
    client = NM.Client.new(None)
    device = None

    devices = client.get_devices()
    for d in devices:
        if d.get_device_type() == NM.DeviceType.WIFI_P2P:
            device = d
            break

    if device is None:
        sys.exit("No Wi-Fi P2P device found")

    device.start_find(GLib.Variant("a{sv}", {}), None, start_find_cb, None)

    main_loop = GLib.MainLoop()
    main_loop.run()
