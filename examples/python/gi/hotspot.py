#!/usr/bin/env python
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This example creates a Wi-Fi hotspot (Access Point) and monitors
# stations connecting/disconnecting.
#
# Usage: hotspot.py [SSID] [PASSWORD]

import signal
import sys
import uuid

import gi

gi.require_version("NM", "1.0")
from gi.repository import GLib, NM

main_loop = None
client = None


def create_hotspot_profile(device, ssid, password):
    """Create a Wi-Fi hotspot connection profile."""
    profile = NM.SimpleConnection.new()

    # Connection settings
    s_con = NM.SettingConnection.new()
    s_con.set_property(NM.SETTING_CONNECTION_ID, f"Hotspot {ssid}")
    s_con.set_property(NM.SETTING_CONNECTION_UUID, str(uuid.uuid4()))
    s_con.set_property(NM.SETTING_CONNECTION_TYPE, "802-11-wireless")
    s_con.set_property(NM.SETTING_CONNECTION_AUTOCONNECT, False)
    s_con.set_property(NM.SETTING_CONNECTION_INTERFACE_NAME, device.get_iface())

    # Wireless settings
    s_wifi = NM.SettingWireless.new()
    s_wifi.set_property(NM.SETTING_WIRELESS_SSID, GLib.Bytes.new(ssid.encode("utf-8")))
    s_wifi.set_property(NM.SETTING_WIRELESS_MODE, "ap")

    # Wireless security settings
    s_wsec = NM.SettingWirelessSecurity.new()
    s_wsec.set_property(NM.SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk")
    s_wsec.set_property(NM.SETTING_WIRELESS_SECURITY_PSK, password)
    s_wsec.add_proto("rsn")
    s_wsec.add_pairwise("ccmp")
    s_wsec.add_group("ccmp")

    # IPv4 settings
    s_ip4 = NM.SettingIP4Config.new()
    s_ip4.set_property(NM.SETTING_IP_CONFIG_METHOD, "shared")

    # IPv6 settings
    s_ip6 = NM.SettingIP6Config.new()
    s_ip6.set_property(NM.SETTING_IP_CONFIG_METHOD, "disabled")

    profile.add_setting(s_con)
    profile.add_setting(s_wifi)
    profile.add_setting(s_wsec)
    profile.add_setting(s_ip4)
    profile.add_setting(s_ip6)

    return profile


def print_stations(device):
    """Print the list of connected stations."""
    stations = device.get_stations()
    if stations is None or len(stations) == 0:
        print("  No stations connected")
    else:
        print(f"  {len(stations)} station(s) connected:")
        for station in stations:
            print(f"    - {station.get_address()}")


def on_stations_changed(device, pspec):
    """Callback when the Stations property changes."""
    print("\n[Stations changed]")
    print_stations(device)
    print()


def activated_cb(client, result, device):
    """Callback when the connection is activated."""
    try:
        ac, _ = client.add_and_activate_connection2_finish(result)
        print(f" * Hotspot activated successfully on {device.get_iface()}")
        print(f" * Active connection path: {ac.get_path()}")
        print()

        # Subscribe to Stations property changes
        device.connect("notify::stations", on_stations_changed)

        print("[Initial stations]")
        print_stations(device)
        print()
        print("Monitoring stations... (Press Ctrl-C to quit)")
        print()

    except Exception as e:
        sys.stderr.write(f"Error activating hotspot: {e}\n")
        main_loop.quit()


def sigint_handler(sig, frame):
    """Handle Ctrl-C."""
    print("\n\nShutting down...")
    main_loop.quit()


def main():
    global main_loop, client

    # Default SSID and password
    ssid = "MyHotspot"
    password = "password123"

    if len(sys.argv) >= 2:
        ssid = sys.argv[1]
    if len(sys.argv) >= 3:
        password = sys.argv[2]

    if len(password) < 8:
        sys.exit("Error: Password must be at least 8 characters")

    # Set up Ctrl-C handler
    signal.signal(signal.SIGINT, sigint_handler)

    # Create NM client
    client = NM.Client.new(None)

    # Find the first Wi-Fi device
    device = None
    for d in client.get_devices():
        if d.get_device_type() == NM.DeviceType.WIFI:
            device = d
            break

    if device is None:
        sys.exit("No Wi-Fi device found")

    print(f" * Found Wi-Fi device: {device.get_iface()}")

    # Check if device supports AP mode
    caps = device.get_capabilities()
    if not (caps & NM.DeviceWifiCapabilities.AP):
        sys.exit(f"Error: Device {device.get_iface()} does not support AP mode")

    print(f" * Creating hotspot with SSID: {ssid}")

    # Create the hotspot profile
    profile = create_hotspot_profile(device, ssid, password)

    # Activate the hotspot
    client.add_and_activate_connection2(
        profile,
        device,
        "/",
        GLib.Variant("a{sv}", {}),
        None,
        activated_cb,
        device,
    )

    main_loop = GLib.MainLoop()
    main_loop.run()


if __name__ == "__main__":
    main()
