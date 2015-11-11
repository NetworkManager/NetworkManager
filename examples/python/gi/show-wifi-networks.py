#!/usr/bin/env python
# coding=utf-8
# -*- Mode: Python; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
# vim: ft=python ts=4 sts=4 sw=4 et ai
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2013 Red Hat, Inc.
#

import locale
import gi
gi.require_version('NM', '1.0')
from gi.repository import NM

#
# This example lists Wi-Fi access points NetworkManager scanned on Wi-Fi devices.
# It calls libnm functions using GObject introspection.
#
# Note the second line of the file: coding=utf-8
# It is necessary because we use unicode characters and python would produce
# an error without it: http://www.python.org/dev/peps/pep-0263/
#

def clamp(value, minvalue, maxvalue):
    return max(minvalue, min(value, maxvalue))

def ssid_to_utf8(ap):
    ssid = ap.get_ssid()
    if not ssid:
        return ""
    return NM.utils_ssid_to_utf8(ap.get_ssid().get_data())

def print_device_info(device):
    active_ap = dev.get_active_access_point()
    ssid = None
    if active_ap is not None:
        ssid = ssid_to_utf8(active_ap)
    info = "Device: %s | Driver: %s | Active AP: %s" % (dev.get_iface(), dev.get_driver(), ssid)
    print info
    print '=' * len(info)

def mode_to_string(mode):
    if mode == getattr(NM, '80211Mode').INFRA:
        return "INFRA"
    if mode == getattr(NM, '80211Mode').ADHOC:
        return "ADHOC"
    if mode == getattr(NM, '80211Mode').AP:
        return "AP"
    return "UNKNOWN"

def flags_to_string(flags):
    if flags & getattr(NM, '80211ApFlags').PRIVACY:
        return "PRIVACY"
    return "NONE"

def security_flags_to_string(flags):
    NM_AP_FLAGS = getattr(NM, '80211ApSecurityFlags')
    str = ""
    if flags & NM_AP_FLAGS.PAIR_WEP40:
        str = str + " PAIR_WEP40"
    if flags & NM_AP_FLAGS.PAIR_WEP104:
        str = str + " PAIR_WEP104"
    if flags & NM_AP_FLAGS.PAIR_TKIP:
        str = str + " PAIR_TKIP"
    if flags & NM_AP_FLAGS.PAIR_CCMP:
        str = str + " PAIR_CCMP"
    if flags & NM_AP_FLAGS.GROUP_WEP40:
        str = str + " GROUP_WEP40"
    if flags & NM_AP_FLAGS.GROUP_WEP104:
        str = str + " GROUP_WEP104"
    if flags & NM_AP_FLAGS.GROUP_TKIP:
        str = str + " GROUP_TKIP"
    if flags & NM_AP_FLAGS.GROUP_CCMP:
        str = str + " GROUP_CCMP"
    if flags & NM_AP_FLAGS.KEY_MGMT_PSK:
        str = str + " KEY_MGMT_PSK"
    if flags & NM_AP_FLAGS.KEY_MGMT_802_1X:
        str = str + " KEY_MGMT_802_1X"
    if str:
        return str.lstrip()
    else:
        return "NONE"

def flags_to_security(flags, wpa_flags, rsn_flags):
    str = ""
    if ((flags & getattr(NM, '80211ApFlags').PRIVACY) and
        (wpa_flags == 0) and (rsn_flags == 0)):
        str = str  + " WEP"
    if wpa_flags != 0:
        str = str + " WPA1"
    if rsn_flags != 0:
        str = str + " WPA2"
    if ((wpa_flags & getattr(NM, '80211ApSecurityFlags').KEY_MGMT_802_1X) or
        (rsn_flags & getattr(NM, '80211ApSecurityFlags').KEY_MGMT_802_1X)):
        str = str + " 802.1X"
    return str.lstrip()

def print_ap_info(ap):
    strength = ap.get_strength()
    frequency = ap.get_frequency()
    flags = ap.get_flags()
    wpa_flags = ap.get_wpa_flags()
    rsn_flags = ap.get_rsn_flags()
    print "SSID:      %s"      % (ssid_to_utf8(ap))
    print "BSSID:     %s"      % (ap.get_bssid())
    print "Frequency: %s"      % (frequency)
    print "Channel:   %s"      % (NM.utils_wifi_freq_to_channel(frequency))
    print "Mode:      %s"      % (mode_to_string(ap.get_mode()))
    print "Flags:     %s"      % (flags_to_string(flags))
    print "WPA flags: %s"      % (security_flags_to_string(wpa_flags))
    print "RSN flags: %s"      % (security_flags_to_string(rsn_flags))
    print "Security:  %s"      % (flags_to_security(flags, wpa_flags, rsn_flags))
    print "Strength:  %s %s%%" % (NM.utils_wifi_strength_bars(strength), strength)
    print

if __name__ == "__main__":
    # Python apparently doesn't call setlocale() on its own? We have to call this or else
    # NM.utils_wifi_strength_bars() will think the locale is ASCII-only, and return the
    # fallback characters rather than the unicode bars
    locale.setlocale(locale.LC_ALL, '')

    nmc = NM.Client.new(None)
    devs = nmc.get_devices()

    for dev in devs:
        if dev.get_device_type() == NM.DeviceType.WIFI:
            print_device_info(dev)
            for ap in dev.get_access_points():
                print_ap_info(ap)

