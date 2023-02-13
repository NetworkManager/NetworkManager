#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2013 Red Hat, Inc.
#

import locale
import math
import os
import re
import time

import gi

gi.require_version("NM", "1.0")
from gi.repository import NM, GLib, Gio

SCAN_THRESHOLD_MSEC = 10000

#
# This example lists Wi-Fi access points NetworkManager scanned on Wi-Fi devices.
# It calls libnm functions using GObject introspection.
#
# Note the second line of the file: coding=utf-8
# It is necessary because we use unicode characters and python would produce
# an error without it: http://www.python.org/dev/peps/pep-0263/
#

NM80211Mode = getattr(NM, "80211Mode")
NM80211ApFlags = getattr(NM, "80211ApFlags")
NM80211ApSecurityFlags = getattr(NM, "80211ApSecurityFlags")

main_loop = GLib.MainLoop()


def gflags_to_str(flags_type, value):
    if value == 0:
        return "none"
    str = ""
    for n in sorted(dir(flags_type)):
        if not re.search("^[A-Z0-9_]+$", n):
            continue
        flag_value = getattr(flags_type, n)
        if value & flag_value:
            value &= ~flag_value
            str += " " + n
            if value == 0:
                break
    if value:
        str += " (0x%0x)" % (value,)
    return str.lstrip()


def genum_to_str(enum_type, value):
    for n in sorted(dir(enum_type)):
        if not re.search("^[A-Z0-9_]+$", n):
            continue
        enum_value = getattr(enum_type, n)
        if value == enum_value:
            return n
    return "(%d" % (value,)


def ap_security_flags_to_security(flags, wpa_flags, rsn_flags):
    str = ""
    if (flags & NM80211ApFlags.PRIVACY) and (wpa_flags == 0) and (rsn_flags == 0):
        str = str + " WEP"
    if wpa_flags != 0:
        str = str + " WPA1"
    if rsn_flags != 0:
        str = str + " WPA2"
    if (wpa_flags & NM80211ApSecurityFlags.KEY_MGMT_802_1X) or (
        rsn_flags & NM80211ApSecurityFlags.KEY_MGMT_802_1X
    ):
        str = str + " 802.1X"
    return str.lstrip()


def ap_get_ssid(ap):
    if ap is None:
        return "not connected"
    ssid = ap.get_ssid()
    if ssid is None:
        return "no ssid"
    return '"%s"' % (NM.utils_ssid_to_utf8(ssid.get_data()),)


def print_device_info(device):
    if device.get_client() is None:
        last_scan = "device disappeared"
    else:
        t = device.get_last_scan()
        if t == 0:
            last_scan = "no scan completed"
        else:
            t = (NM.utils_get_timestamp_msec() - t) / 1000.0
            last_scan = "%0.2f sec ago" % (t,)
            if device_needs_scan(device):
                last_scan += " (stale)"

    ap = device.get_active_access_point()
    if ap is None:
        active_ap = "none"
    else:
        active_ap = "%s (%s)" % (ap_get_ssid(ap), ap.get_path())

    print("Device:     %s" % (device.get_iface(),))
    print("D-Bus path: %s" % (NM.Object.get_path(device),))
    print("Driver:     %s" % (device.get_driver(),))
    print("Active AP:  %s" % (active_ap,))
    print("Last scan:  %s" % (last_scan,))


def print_ap_info(ap):
    strength = ap.get_strength()
    frequency = ap.get_frequency()
    flags = ap.get_flags()
    wpa_flags = ap.get_wpa_flags()
    rsn_flags = ap.get_rsn_flags()

    t = ap.get_last_seen()
    if t < 0:
        last_seen = "never"
    else:
        t = time.clock_gettime(time.CLOCK_BOOTTIME) - t
        last_seen = "%s sec ago" % (math.ceil(t),)

    print("  - D-Bus path: %s" % (ap.get_path(),))
    print("    SSID:       %s" % (ap_get_ssid(ap),))
    print("    BSSID:      %s" % (ap.get_bssid(),))
    print("    Last seen:  %s" % (last_seen,))
    print("    Frequency:  %s" % (frequency,))
    print("    Channel:    %s" % (NM.utils_wifi_freq_to_channel(frequency),))
    print("    Mode:       %s" % (genum_to_str(NM80211Mode, ap.get_mode()),))
    print("    Flags:      %s" % (gflags_to_str(NM80211ApFlags, flags),))
    print("    WPA flags:  %s" % (gflags_to_str(NM80211ApSecurityFlags, wpa_flags),))
    print("    RSN flags:  %s" % (gflags_to_str(NM80211ApSecurityFlags, rsn_flags),))
    print(
        "    Security:   %s"
        % (ap_security_flags_to_security(flags, wpa_flags, rsn_flags),)
    )
    print(
        "    Strength:   %s%% : %s"
        % (
            strength,
            NM.utils_wifi_strength_bars(strength),
        )
    )


def device_needs_scan(device):
    if device.get_client() is None:
        # the device got deleted. We can forget about it.
        return False
    t = device.get_last_scan()
    return t == 0 or t < NM.utils_get_timestamp_msec() - SCAN_THRESHOLD_MSEC


def device_ensure_scanned(device):
    if os.getenv("NO_SCAN") == "1":
        return

    if not device_needs_scan(device):
        return

    # kick off a new scan.
    device.request_scan_async(None)

    def cb():
        main_loop.quit()

    timeout_source = GLib.timeout_source_new(10 * 1000)
    timeout_source.set_callback(cb)
    timeout_source.attach(main_loop.get_context())

    def cb(device, prop):
        if not device_needs_scan(device):
            main_loop.quit()

    device.connect("notify", cb)

    main_loop.run()

    timeout_source.destroy()


def main():
    # Python apparently doesn't call setlocale() on its own? We have to call this or else
    # NM.utils_wifi_strength_bars() will think the locale is ASCII-only, and return the
    # fallback characters rather than the unicode bars
    locale.setlocale(locale.LC_ALL, "")

    nmc = NM.Client.new(None)
    devs = nmc.get_devices()

    is_first = True
    for device in devs:
        if device.get_device_type() != NM.DeviceType.WIFI:
            continue

        if not is_first:
            print("")
        else:
            is_first = False

        device_ensure_scanned(device)
        print_device_info(device)
        for ap in device.get_access_points():
            print_ap_info(ap)


if __name__ == "__main__":
    main()
